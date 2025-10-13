#!/usr/bin/env python3
"""Windows-friendly one-click provisioning workflow for PrivateTunnel."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import textwrap
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from core.ssh_utils import (
    SSHAttempt,
    SmartSSHError,
    ask_key_path,
    pick_default_key,
    smart_push_script,
    smart_ssh,
    wait_port_open,
)
from core.tools.vultr_manager import (
    VultrError,
    create_instance,
    create_ssh_key,
    list_ssh_keys,
    reinstall_with_ssh_keys,
    wait_instance_active,
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
    return Path.home() / ".ssh" / "id_ed25519.pub"


def _prompt_private_key() -> Path:
    env_override = os.environ.get("PRIVATE_KEY_PATH")
    if env_override:
        default = str(Path(env_override).expanduser())
    else:
        default = pick_default_key()

    selected = ask_key_path(default)
    return Path(selected).expanduser()


def _build_user_data(pubkey_line: str) -> tuple[str, str]:
    safe_single = pubkey_line.replace("'", "''")
    escaped_pub = pubkey_line.replace("'", "'\"'\"'")
    shell_cmd = (
        "set -euo pipefail; "
        "mkdir -p /root/.ssh && chmod 700 /root/.ssh; "
        "AUTH=/root/.ssh/authorized_keys; "
        f"PUB='{escaped_pub}'; "
        "if [ ! -f \"$AUTH\" ]; then touch \"$AUTH\"; fi; "
        "grep -qxF \"$PUB\" \"$AUTH\" 2>/dev/null || echo \"$PUB\" >> \"$AUTH\"; "
        "chmod 600 \"$AUTH\""
    )
    shell_cmd = shell_cmd.replace('"', '\\"')
    cloud_config = textwrap.dedent(
        f"""
        #cloud-config
        ssh_authorized_keys:
          - '{safe_single}'
        runcmd:
          - ["/bin/bash", "-lc", "{shell_cmd}"]
        """
    ).strip()
    encoded = base64.b64encode(cloud_config.encode("utf-8")).decode("ascii")
    return encoded, cloud_config


def _choose_ssh_key(api_key: str, pubkey_line: str) -> tuple[list[str], str]:
    keys = list_ssh_keys(api_key)
    print("\n可用的 Vultr SSH Keys：")
    for idx, item in enumerate(keys, start=1):
        preview = item.get("ssh_key", "")[:60]
        print(f"  {idx}. {item.get('name', '未命名')} ({item.get('id')}) - {preview}...")
    print("  0. 自动创建新的 SSH Key（读取本地公钥）")

    while True:
        choice = _prompt("选择要注入的 SSH Key 编号", "0")
        if not choice.isdigit():
            print("❌ 请输入数字编号。")
            continue
        index = int(choice)
        if index == 0:
            name = f"PrivateTunnel-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
            print(f"→ 创建 SSH Key: {name} ...")
            created = create_ssh_key(api_key, name, pubkey_line)
            key_id = created.get("id")
            if not key_id:
                raise VultrError("创建 SSH Key 返回异常，未包含 id。")
            print(f"✅ 已创建 SSH Key: {key_id}")
            return [key_id], key_id
        if 1 <= index <= len(keys):
            key_id = keys[index - 1].get("id")
            if not key_id:
                print("❌ 该 SSH Key 缺少 id 字段，请重新选择。")
                continue
            return [key_id], key_id
        print("❌ 编号超出范围，请重新输入。")


def _write_instance_artifact(payload: Dict[str, str]) -> None:
    artifacts_dir = Path("artifacts")
    artifacts_dir.mkdir(exist_ok=True)
    path = artifacts_dir / "instance.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"🗂  已写入 {path}")


def _record_server_info(ip: str, provision_result: dict) -> None:
    artifacts_dir = Path("artifacts")
    artifacts_dir.mkdir(exist_ok=True)
    payload = {
        "ip": ip,
        "server_pub": provision_result.get("server_pub", ""),
        "port": provision_result.get("port", 51820),
    }
    path = artifacts_dir / "server.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"🗂  已写入 {path}")


def create_vps_flow(api_key: str) -> Dict[str, str]:
    print("=== 1/3 创建 Vultr 实例 ===")
    region = _prompt("Region", DEFAULT_REGION)
    plan = _prompt("Plan", DEFAULT_PLAN)
    snapshot_input = _prompt("Snapshot ID (留空则使用官方镜像)", "")
    snapshot_id = snapshot_input or None

    pubkey_path = _default_pubkey_path()
    try:
        pubkey_line = _read_pubkey(pubkey_path)
    except RuntimeError as exc:
        print(f"❌ {exc}")
        sys.exit(1)

    print(f"使用公钥文件：{pubkey_path}")
    sshkey_ids, selected_key = _choose_ssh_key(api_key, pubkey_line)

    user_data_b64, user_data_plain = _build_user_data(pubkey_line)
    print("→ 发送创建实例请求 ...")
    instance = create_instance(
        api_key,
        region=region,
        plan=plan,
        snapshot_id=snapshot_id,
        label=DEFAULT_LABEL,
        sshkey_ids=sshkey_ids,
        user_data=user_data_b64,
    )
    instance_id = instance.get("id")
    if not instance_id:
        raise VultrError("创建实例返回缺少 id。")
    print(f"实例 {instance_id} 已创建，等待 Running ...")

    ready = wait_instance_active(api_key, instance_id, timeout=900, interval=10)
    ip = ready.get("ip") or ready.get("main_ip")
    if not ip:
        raise VultrError("等待实例运行时未获得 IP 地址。")
    print(f"✅ 实例就绪：{ip}")

    artifact_payload = {
        "id": instance_id,
        "ip": ip,
        "region": region,
        "plan": plan,
        "snapshot_id": snapshot_id or "",
        "sshkey_id": selected_key,
        "sshkey_ids": sshkey_ids,
        "pubkey_path": str(pubkey_path),
        "user_data_used": "cloud-config",
        "user_data_base64": user_data_b64,
        "user_data_preview": user_data_plain,
    }
    _write_instance_artifact(artifact_payload)
    artifact_payload.update(
        {
            "pubkey_line": pubkey_line,
        }
    )
    return artifact_payload


def _contains_permission_denied(text: str) -> bool:
    lowered = text.lower()
    return "permission denied" in lowered and "publickey" in lowered


def _diagnose_attempts(attempts: List[SSHAttempt]) -> bool:
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
    api_key: str,
    instance_id: str,
    ip: str,
    private_key_path: Path,
    pubkey_line: str,
    sshkey_ids: List[str],
    user_data_b64: str,
) -> None:
    print("\n=== 2/3 校验 SSH 免密 ===")
    while True:
        print("→ 测试免密登录 ...")
        try:
            result = smart_ssh(ip, "root", private_key_path, "true")
        except SmartSSHError as exc:
            permission_issue = _diagnose_attempts(exc.attempts)
            if permission_issue:
                print("⚠️ 仍提示 Permission denied (publickey)。")
                commands = _manual_console_instructions(pubkey_line)
                print("\n请打开 Vultr 控制台（View Console）粘贴以下 3 行命令：\n")
                print(commands)
                print("\n完成后按回车继续重试。输入 R 仅重试、输入 B 执行 Reinstall SSH Keys、输入 Q 终止流程。")
                choice = input("选择 [Enter=继续] / R=重试 / B=Reinstall / Q=退出: ").strip().lower()
                if choice == "q":
                    raise RuntimeError("用户取消：SSH 验证失败。")
                if choice == "b":
                    _confirm_reinstall(api_key, instance_id, sshkey_ids, user_data_b64)
                    continue
                # Enter 或 R 均直接重试
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
                cont = input("执行完毕后按回车继续，或输入 B 触发 Reinstall: ").strip().lower()
                if cont == "b":
                    _confirm_reinstall(api_key, instance_id, sshkey_ids, user_data_b64)
                continue
            raise RuntimeError(f"SSH 返回码 {result.returncode}，输出：{output}")


def _confirm_reinstall(
    api_key: str,
    instance_id: str,
    sshkey_ids: List[str],
    user_data_b64: str,
) -> None:
    print(
        textwrap.dedent(
            """
            ⚠️ 将执行 Reinstall SSH Keys，这会 WIPE ALL DATA。
            如果实例中已有重要数据，请立即取消并手动处理！
            """
        ).strip()
    )
    confirm = input("请输入 REINSTALL 继续，或直接回车取消: ").strip().lower()
    if confirm != "reinstall":
        print("已取消重装。")
        return

    print("→ 调用 Reinstall SSH Keys ...")
    reinstall_with_ssh_keys(api_key, instance_id, sshkey_ids=sshkey_ids, user_data=user_data_b64)
    print("等待实例重新 Running ...")
    time.sleep(5)
    wait_instance_active(api_key, instance_id, timeout=900, interval=10)
    print("✅ 重装完成，继续尝试 SSH ...")


def deploy_wireguard(ip: str, private_key_path: Path) -> None:
    print("\n=== 3/3 部署 WireGuard ===")
    print("→ 等待 SSH 端口 22 就绪 ...")
    if not wait_port_open(ip, 22, timeout=120):
        raise RuntimeError("SSH 端口未就绪（实例可能还在初始化或防火墙未放行 22）。")

    print("→ 校验远端连通性 ...")
    try:
        check_result = smart_ssh(ip, "root", private_key_path, "uname -a")
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

    rc = smart_push_script(ip, str(private_key_path), wg_install_script)
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
"""

    rc2 = smart_push_script(ip, str(private_key_path), add_peer_script)
    if rc2 != 0:
        raise RuntimeError(f"添加客户端/生成二维码失败，退出码：{rc2}")

    print("→ 尝试读取服务端公钥 ...")
    server_pub = ""
    try:
        pub_result = smart_ssh(ip, "root", private_key_path, "cat /etc/wireguard/server.public")
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

    try:
        artifacts_dir = Path("artifacts")
        artifacts_dir.mkdir(exist_ok=True)
        subprocess.run(
            [
                "scp",
                "-i",
                str(private_key_path),
                f"root@{ip}:/etc/wireguard/clients/iphone/iphone.conf",
                str(artifacts_dir / "iphone.conf"),
            ],
            check=False,
        )
        print("ℹ️ 已尝试下载到 artifacts/iphone.conf")
    except FileNotFoundError:
        print("⚠️ 未找到 scp，可手动复制 /etc/wireguard/clients/iphone/iphone.conf")

    print("✅ WireGuard 部署完成，并已生成 iPhone 客户端二维码（见上方输出）。")


def main() -> None:
    api_key = os.environ.get("VULTR_API_KEY", "").strip()
    if not api_key:
        api_key = _prompt("请输入 VULTR_API_KEY", "").strip()
    if not api_key:
        print("❌ 未提供 VULTR_API_KEY，流程终止。")
        sys.exit(1)

    try:
        instance = create_vps_flow(api_key)
    except VultrError as exc:
        print(f"❌ 创建实例失败：{exc}")
        sys.exit(1)

    private_key_path = _prompt_private_key()
    print(f"✓ 使用私钥：{private_key_path}")

    try:
        post_boot_verify_ssh(
            api_key,
            instance["id"],
            instance["ip"],
            private_key_path,
            instance["pubkey_line"],
            instance["sshkey_ids"],
            instance["user_data_base64"],
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

