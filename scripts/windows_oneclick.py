#!/usr/bin/env python3
"""Windows-friendly one-click provisioning workflow for PrivateTunnel."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Dict

from core.ssh_utils import (
    SSHAttempt,
    SmartSSHError,
    ask_key_path,
    pick_default_key,
    smart_push_script,
    smart_ssh,
    wait_port_open,
)
from core.vultr_api import (
    VultrAPIError,
    create_instance as api_create_instance,
    ensure_ssh_key,
    pick_snapshot,
    wait_instance_ready,
)
DEFAULT_REGION = "nrt"
DEFAULT_PLAN = "vc2-1c-1gb"
DEFAULT_LABEL = "privatetunnel-oc"


def _prompt(text: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{text}{suffix}: ").strip()
    if not value and default is not None:
        return default
    return value


def _read_pubkey(pubkey_path: Path) -> str:
    if pubkey_path.is_dir():
        raise RuntimeError(f"公钥路径是目录，请指定文件：{pubkey_path}")
    if not pubkey_path.exists():
        raise RuntimeError(
            textwrap.dedent(
                f"""
                未找到公钥文件：{pubkey_path}
                请使用 `ssh-keygen -t ed25519` 生成密钥对，或设置环境变量 PUBKEY_PATH 指向现有的 .pub 文件。
                """
            ).strip()
        )
    content = pubkey_path.read_text(encoding="utf-8").strip()
    if not content:
        raise RuntimeError(f"公钥文件为空：{pubkey_path}")
    return content


def _default_pubkey_path() -> Path:
    env = os.environ.get("PUBKEY_PATH")
    if env:
        return Path(env).expanduser()
    home = Path(os.path.expandvars(r"%USERPROFILE%"))
    if "%" in str(home):
        home = Path.home()
    candidates = [
        home / ".ssh" / "id_ed25519.pub",
        home / ".ssh" / "id_rsa.pub",
    ]
    for candidate in candidates:
        if candidate.is_file() and candidate.stat().st_size > 0:
            return candidate
    return candidates[0]


def _prompt_private_key() -> Path:
    env_override = os.environ.get("PRIVATE_KEY_PATH")
    if env_override:
        default = str(Path(env_override).expanduser())
    else:
        default = pick_default_key()

    selected = ask_key_path(default)
    return Path(selected).expanduser()


def _artifacts_dir() -> Path:
    path = Path("artifacts")
    path.mkdir(exist_ok=True)
    return path


def _known_hosts_path() -> Path:
    known_hosts = _artifacts_dir() / "known_hosts"
    if not known_hosts.exists():
        known_hosts.touch()
    return known_hosts


def _reset_host_key(ip: str) -> Path:
    known_hosts = _known_hosts_path()
    commands = [
        ["ssh-keygen", "-R", ip],
        ["ssh-keygen", "-R", ip, "-f", str(known_hosts)],
    ]
    for cmd in commands:
        try:
            subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            continue
    return known_hosts


def _scp_download(
    ip: str,
    private_key_path: Path,
    remote_path: str,
    local_path: Path,
    known_hosts_file: Path,
) -> bool:
    try:
        result = subprocess.run(
            [
                "scp",
                "-i",
                str(private_key_path),
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-o",
                f"UserKnownHostsFile={known_hosts_file}",
                f"root@{ip}:{remote_path}",
                str(local_path),
            ],
            check=False,
        )
    except FileNotFoundError:
        raise RuntimeError("未找到 scp 客户端，请确认已安装 OpenSSH 工具。") from None
    if result.returncode != 0:
        print(f"⚠️ 下载 {remote_path} 失败，scp 返回码：{result.returncode}")
        return False
    print(f"✓ 已下载 {remote_path} → {local_path}")
    return True


def _ensure_local_qrcode(conf_path: Path, png_path: Path) -> None:
    if png_path.exists():
        return
    try:
        import qrcode  # type: ignore
    except Exception as exc:  # pragma: no cover - optional dependency at runtime
        raise RuntimeError("服务器二维码生成失败，本地也无法导入 qrcode 模块。") from exc

    data = conf_path.read_text(encoding="utf-8")
    img = qrcode.make(data)
    img.save(png_path)
    print(f"✓ 已使用本地 qrcode 生成二维码：{png_path}")


def _write_instance_artifact(payload: Dict[str, object]) -> None:
    path = _artifacts_dir() / "instance.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"🗂  已写入 {path}")


def _record_server_info(ip: str, provision_result: dict) -> None:
    payload = {
        "ip": ip,
        "server_pub": provision_result.get("server_pub", ""),
        "port": provision_result.get("port", 51820),
    }
    path = _artifacts_dir() / "server.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"🗂  已写入 {path}")


def create_vps_flow(api_key: str) -> Dict[str, object]:
    print("=== 1/3 创建 Vultr 实例 ===")
    region = _prompt("Region", DEFAULT_REGION)
    plan = _prompt("Plan", DEFAULT_PLAN)

    snapshot_env = os.environ.get("VULTR_SNAPSHOT_ID", "").strip() or None
    ssh_key_name = os.environ.get("VULTR_SSHKEY_NAME", "PrivateTunnelKey").strip() or "PrivateTunnelKey"

    pubkey_path = _default_pubkey_path()
    try:
        pubkey_line = _read_pubkey(pubkey_path)
    except RuntimeError as exc:
        print(f"❌ {exc}")
        sys.exit(1)

    print(f"使用公钥文件：{pubkey_path}")
    sshkey_id = ensure_ssh_key(api_key, pubkey_line, ssh_key_name)
    snapshot_id = pick_snapshot(api_key, snapshot_env)

    print("→ 发送创建实例请求 ...")
    instance = api_create_instance(
        api_key,
        region=region,
        plan=plan,
        sshkey_ids=[sshkey_id],
        snapshot_id=snapshot_id,
        label=DEFAULT_LABEL,
    )
    instance_id = instance.get("id")
    if not instance_id:
        raise VultrAPIError("创建实例返回缺少 id。")

    ready = wait_instance_ready(api_key, instance_id, timeout=900)
    ip = ready.get("main_ip") or ready.get("ip")
    if not ip:
        raise VultrAPIError("等待实例运行时未获得 IP 地址。")
    print(f"✅ 实例就绪：{ip}")

    artifact_payload: Dict[str, object] = {
        "id": instance_id,
        "ip": ip,
        "region": region,
        "plan": plan,
        "snapshot_id": snapshot_id or "",
        "sshkey_id": sshkey_id,
        "sshkey_ids": [sshkey_id],
        "sshkey_name": ssh_key_name,
        "pubkey_path": str(pubkey_path),
        "created_at": ready.get("date_created"),
    }
    _write_instance_artifact(artifact_payload)
    artifact_payload["pubkey_line"] = pubkey_line
    return artifact_payload


def _contains_permission_denied(text: str) -> bool:
    lowered = text.lower()
    return "permission denied" in lowered and "publickey" in lowered


def _diagnose_attempts(attempts: list[SSHAttempt]) -> bool:
    for att in attempts:
        joined = " ".join(filter(None, [att.error, att.stderr, att.stdout]))
        if joined and _contains_permission_denied(joined):
            return True
    return False


def _manual_console_instructions(pubkey_line: str) -> str:
    escaped = pubkey_line.replace("'", "'\"'\"'")
    commands = textwrap.dedent(
        f"""
        mkdir -p /root/.ssh && chmod 700 /root/.ssh
        echo '{escaped}' >> /root/.ssh/authorized_keys
        chmod 600 /root/.ssh/authorized_keys
        """
    ).strip()
    return commands


def post_boot_verify_ssh(
    ip: str,
    private_key_path: Path,
    pubkey_line: str,
    known_hosts_file: Path,
) -> None:
    print("\n=== 2/3 校验 SSH 免密 ===")
    while True:
        print("→ 测试免密登录 ...")
        try:
            result = smart_ssh(
                ip,
                "root",
                private_key_path,
                "true",
                known_hosts_file=str(known_hosts_file),
            )
        except SmartSSHError as exc:
            permission_issue = _diagnose_attempts(exc.attempts)
            if permission_issue:
                print("⚠️ 仍提示 Permission denied (publickey)。")
                commands = _manual_console_instructions(pubkey_line)
                print("\n请打开 Vultr 控制台（View Console）粘贴以下 3 行命令：\n")
                print(commands)
                choice = input("执行完毕后按回车继续，或输入 Q 退出: ").strip().lower()
                if choice == "q":
                    raise RuntimeError("用户取消：SSH 验证失败。")
                continue
            raise
        else:
            if result.returncode == 0:
                print(f"✅ SSH 连接成功（backend={result.backend}, rc={result.returncode}）")
                return
            output = (result.stderr or result.stdout or "").strip()
            if _contains_permission_denied(output):
                print("⚠️ ssh.exe 返回 Permission denied (publickey)。")
                commands = _manual_console_instructions(pubkey_line)
                print("\n请在控制台执行以下命令后回车重试：\n")
                print(commands)
                continue
            raise RuntimeError(f"SSH 返回码 {result.returncode}，输出：{output}")


def deploy_wireguard(ip: str, private_key_path: Path) -> None:
    print("\n=== 3/3 部署 WireGuard ===")
    known_hosts_file = _reset_host_key(ip)
    print(f"→ 已刷新 {known_hosts_file} 中的 host key 缓存。")
    print("→ 等待 SSH 端口 22 就绪 ...")
    if not wait_port_open(ip, 22, timeout=120):
        raise RuntimeError("SSH 端口未就绪（实例可能还在初始化或防火墙未放行 22）。")

    print("→ 校验远端连通性 ...")
    try:
        check_result = smart_ssh(
            ip,
            "root",
            private_key_path,
            "uname -a",
            known_hosts_file=str(known_hosts_file),
        )
    except SmartSSHError as exc:
        joined_attempts = []
        for att in exc.attempts:
            detail = " ".join(filter(None, [att.error, att.stderr, att.stdout])).strip()
            joined_attempts.append(f"{att.backend}: {detail}")
        hint = "\n".join(filter(None, joined_attempts))
        message = "无法通过 SSH 测试远端连通性。请确认私钥有效且放行了 22 端口。"
        if hint:
            message = f"{message}\n排查信息：\n{hint}"
        raise RuntimeError(message) from exc
    if check_result.returncode != 0:
        output = (check_result.stderr or check_result.stdout or "").strip()
        raise RuntimeError(
            f"远端命令执行失败，退出码：{check_result.returncode}。输出：{output}"
        )
    print("✅ 远端连通性正常，开始执行 WireGuard 安装脚本 ...")

    wg_install_script = r"""#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt update -y
apt install -y wireguard wireguard-tools qrencode iptables-persistent

mkdir -p /etc/wireguard
umask 077

# 生成服务端密钥
wg genkey | tee /etc/wireguard/server.private | wg pubkey > /etc/wireguard/server.public
SERVER_PRIV=$(cat /etc/wireguard/server.private)

# 写配置
cat >/etc/wireguard/wg0.conf <<'EOF'
[Interface]
Address = 10.6.0.1/24
ListenPort = 51820
PrivateKey = __SERVER_PRIV__
SaveConfig = true
EOF
sed -i "s|__SERVER_PRIV__|${SERVER_PRIV}|" /etc/wireguard/wg0.conf

# 开启转发 & NAT
sysctl -w net.ipv4.ip_forward=1 >/dev/null
WAN_IF=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
iptables -t nat -C POSTROUTING -s 10.6.0.0/24 -o "$WAN_IF" -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -s 10.6.0.0/24 -o "$WAN_IF" -j MASQUERADE
# 持久化（容错）
if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save || true
elif [ -d /etc/iptables ]; then
  iptables-save > /etc/iptables/rules.v4 || true
fi

systemctl enable wg-quick@wg0
systemctl restart wg-quick@wg0

echo "=== wg0 status ==="
wg show || true
"""

    rc = smart_push_script(
        ip,
        str(private_key_path),
        wg_install_script,
        known_hosts_file=str(known_hosts_file),
    )
    if rc != 0:
        raise RuntimeError(f"远端执行部署脚本失败，退出码：{rc}")

    print("→ WireGuard 服务已部署，继续添加客户端 ...")

    add_peer_script = r"""#!/usr/bin/env bash
set -euo pipefail

apt install -y qrencode

CLIENT_NAME="iphone"
CLIENT_DIR="/etc/wireguard/clients/${CLIENT_NAME}"
mkdir -p "${CLIENT_DIR}"
umask 077

wg genkey | tee "${CLIENT_DIR}/${CLIENT_NAME}.private" | wg pubkey > "${CLIENT_DIR}/${CLIENT_NAME}.public"
CLIENT_PRIV=$(cat "${CLIENT_DIR}/${CLIENT_NAME}.private")
CLIENT_PUB=$(cat "${CLIENT_DIR}/${CLIENT_NAME}.public")

# 取服务端公钥与对外地址
SERVER_PUB=$(cat /etc/wireguard/server.public)
ENDPOINT="$(curl -4 -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}'):51820"

# 将客户端作为 peer 加到服务器
wg set wg0 peer "${CLIENT_PUB}" allowed-ips 10.6.0.2/32
wg-quick save wg0 || true

# 生成客户端配置
cat > "${CLIENT_DIR}/${CLIENT_NAME}.conf" <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIV}
Address = 10.6.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = ${SERVER_PUB}
AllowedIPs = 0.0.0.0/0
Endpoint = ${ENDPOINT}
PersistentKeepalive = 25
EOF

echo "=== QR below ==="
qrencode -t ANSIUTF8 < "${CLIENT_DIR}/${CLIENT_NAME}.conf" || true
qrencode -o /root/iphone.png -s 8 -m 2 < "${CLIENT_DIR}/${CLIENT_NAME}.conf" || true
"""

    rc2 = smart_push_script(
        ip,
        str(private_key_path),
        add_peer_script,
        known_hosts_file=str(known_hosts_file),
    )
    if rc2 != 0:
        raise RuntimeError(f"添加客户端/生成二维码失败，退出码：{rc2}")

    print("→ 尝试读取服务端公钥 ...")
    server_pub = ""
    try:
        pub_result = smart_ssh(
            ip,
            "root",
            private_key_path,
            "cat /etc/wireguard/server.public",
            known_hosts_file=str(known_hosts_file),
        )
    except SmartSSHError as exc:  # pragma: no cover - network dependent
        print(f"⚠️ 读取服务端公钥失败：{exc}")
    else:
        if pub_result.returncode == 0:
            server_pub = (pub_result.stdout or "").strip()
        else:
            output = (pub_result.stderr or pub_result.stdout or "").strip()
            print(f"⚠️ 读取服务端公钥失败：{output}")

    if server_pub:
        _record_server_info(ip, {"server_pub": server_pub, "port": 51820})

    artifacts_dir = _artifacts_dir()
    conf_local = artifacts_dir / "iphone.conf"
    png_local = artifacts_dir / "iphone.png"

    conf_ok = _scp_download(
        ip,
        private_key_path,
        "/etc/wireguard/clients/iphone/iphone.conf",
        conf_local,
        known_hosts_file,
    )
    if not conf_ok or not conf_local.exists():
        raise RuntimeError("下载客户端配置失败，请手动检查 /etc/wireguard/clients/iphone/iphone.conf。")

    png_ok = _scp_download(ip, private_key_path, "/root/iphone.png", png_local, known_hosts_file)
    if not png_ok:
        print("⚠️ 远端二维码 PNG 下载失败，尝试本地生成 ...")
        _ensure_local_qrcode(conf_local, png_local)

    if not png_local.exists():
        _ensure_local_qrcode(conf_local, png_local)

    print("✅ WireGuard 部署完成，并已生成 iPhone 客户端二维码（终端输出 & artifacts/iphone.png）。")


def main() -> None:
    api_key = os.environ.get("VULTR_API_KEY", "").strip()
    if not api_key:
        print("❌ 未设置环境变量 VULTR_API_KEY，流程终止。")
        sys.exit(1)

    try:
        instance = create_vps_flow(api_key)
    except VultrAPIError as exc:
        print(f"❌ 创建实例失败：{exc}")
        sys.exit(1)

    private_key_path = _prompt_private_key()
    print(f"✓ 使用私钥：{private_key_path}")

    known_hosts_file = _reset_host_key(instance["ip"])

    try:
        post_boot_verify_ssh(
            instance["ip"],
            private_key_path,
            instance["pubkey_line"],
            known_hosts_file,
        )
    except Exception as exc:  # noqa: BLE001 - interactive flow
        print(f"❌ SSH 验证失败：{exc}")
        sys.exit(1)

    try:
        deploy_wireguard(instance["ip"], private_key_path)
    except Exception as exc:  # noqa: BLE001 - interactive flow
        print(f"❌ WireGuard 部署失败：{exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()

