from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import paramiko


if os.name == "nt":
    os.system("")

BLUE = "\033[34m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
RESET = "\033[0m"


def _colorize(message: str, color: str) -> str:
    """Return ``message`` wrapped in ANSI color codes."""

    return f"{color}{message}{RESET}"


def log_info(message: str) -> None:
    """Print an informational message in blue."""

    print(_colorize(message, BLUE))


def log_success(message: str) -> None:
    """Print a success message in green."""

    print(_colorize(message, GREEN))


def log_warning(message: str) -> None:
    """Print a warning message in yellow."""

    print(_colorize(message, YELLOW))


def log_error(message: str) -> None:
    """Print an error message in red."""

    print(_colorize(message, RED))


def log_section(title: str) -> None:
    """Print a visual separator for a workflow step."""

    divider = "=" * 24
    log_info(divider)
    log_info(title)


def _run_remote_script(
    client: paramiko.SSHClient, script: str, description: str, timeout: int = 1200
) -> bool:
    """Execute ``script`` on ``client`` using ``bash`` and report errors."""

    try:
        stdin, stdout, stderr = client.exec_command("bash -s", get_pty=True, timeout=timeout)
        stdin.write(script)
        stdin.channel.shutdown_write()
        exit_code = stdout.channel.recv_exit_status()
        stdout_data = stdout.read().decode("utf-8", errors="ignore").strip()
        stderr_data = stderr.read().decode("utf-8", errors="ignore").strip()
    except Exception as exc:  # noqa: BLE001 - we want to surface any Paramiko errors
        log_error(f"❌ {description}失败：{exc}")
        return False

    if exit_code != 0:
        details = stderr_data or stdout_data or f"退出码 {exit_code}"
        log_error(f"❌ {description}失败：{details}")
        return False
    return True


def _run_remote_command(
    client: paramiko.SSHClient, command: str, description: str, timeout: int = 600
) -> bool:
    """Run a single command via Paramiko with unified error handling."""

    try:
        stdin, stdout, stderr = client.exec_command(command, get_pty=True, timeout=timeout)
        stdin.channel.shutdown_write()
        exit_code = stdout.channel.recv_exit_status()
        stdout_data = stdout.read().decode("utf-8", errors="ignore").strip()
        stderr_data = stderr.read().decode("utf-8", errors="ignore").strip()
    except Exception as exc:  # noqa: BLE001
        log_error(f"❌ {description}失败：{exc}")
        return False

    if exit_code != 0:
        details = stderr_data or stdout_data or f"退出码 {exit_code}"
        log_error(f"❌ {description}失败：{details}")
        return False
    return True


def _download_file(
    client: paramiko.SSHClient,
    remote_path: str,
    local_path: Path,
    description: str,
) -> bool:
    """Download ``remote_path`` to ``local_path`` using Paramiko SFTP."""

    try:
        with client.open_sftp() as sftp:
            local_path.parent.mkdir(parents=True, exist_ok=True)
            sftp.get(remote_path, str(local_path))
    except Exception as exc:  # noqa: BLE001
        log_error(f"❌ {description}失败：{exc}")
        return False
    return True


def create_vps() -> None:
    """Create a Vultr VPS using environment-driven defaults."""

    from core.tools.vultr_manager import (  # pylint: disable=import-outside-toplevel
        VultrError,
        create_instance,
        destroy_instance,
        list_ssh_keys,
        wait_instance_active,
    )

    log_section("🧱 Step 2: Create VPS")

    api_key = os.environ.get("VULTR_API_KEY", "")
    if not api_key:
        log_error("❌ 未检测到环境变量 VULTR_API_KEY。请先设置后重试。")
        return

    default_region = os.getenv("VULTR_REGION", "nrt")
    default_plan = os.getenv("VULTR_PLAN", "vc2-4c-8gb")
    env_snapshot_id = os.getenv("VULTR_SNAPSHOT_ID", "")
    env_sshkey_name = os.getenv("VULTR_SSHKEY_NAME", "")

    region = input(f"region [{default_region}]: ").strip() or default_region
    plan = input(f"plan [{default_plan}]: ").strip() or default_plan
    snapshot_prompt_default = env_snapshot_id or "VULTR_SNAPSHOT_ID"
    snapshot_input = input(f"snapshot_id [{snapshot_prompt_default}]: ").strip()
    snapshot_id = snapshot_input or env_snapshot_id
    sshkey_prompt_default = env_sshkey_name or "VULTR_SSHKEY_NAME"
    sshkey_input = input(f"snapshot_keyname [{sshkey_prompt_default}]: ").strip()
    snapshot_keyname = sshkey_input or env_sshkey_name

    if not snapshot_id or not snapshot_keyname:
        log_error(
            "❌ 未检测到环境变量 VULTR_SNAPSHOT_ID 或 VULTR_SSHKEY_NAME。\n"
            "请使用 setx 命令或 .env 文件进行设置。"
        )
        return

    log_info("→ 查询 SSH 公钥信息…")
    try:
        ssh_keys = list_ssh_keys(api_key)
    except VultrError as exc:
        log_error(f"❌ 创建失败：获取 SSH 公钥列表异常：{exc}")
        return

    ssh_key_id = ""
    for item in ssh_keys:
        if item.get("name") == snapshot_keyname:
            ssh_key_id = item.get("id", "")
            break

    if not ssh_key_id:
        log_error("❌ 创建失败：未找到匹配的 SSH 公钥。请检查 VULTR_SSHKEY_NAME。")
        return

    log_info("→ 创建实例中…")
    instance_id = ""
    try:
        instance = create_instance(
            api_key,
            region=region,
            plan=plan,
            snapshot_id=snapshot_id,
            sshkey_ids=[ssh_key_id],
        )
        instance_id = instance.get("id", "")
        if not instance_id:
            raise VultrError("Create instance returned empty id")
        log_info(f"→ 实例已创建，id={instance_id}，等待 active …")
        ready = wait_instance_active(api_key, instance_id, timeout=600, interval=10)
        ip = ready.get("ip")
        if not ip:
            raise VultrError("等待实例 active 时未获取到 IP")
        log_success(f"✅ 实例就绪：id={instance_id}  ip={ip}")
    except VultrError as exc:
        log_error(f"❌ 创建失败：{exc}")
        if instance_id:
            try:
                destroy_instance(api_key, instance_id)
                log_warning("⚠️ 已尝试清理未就绪实例。")
            except VultrError as cleanup_exc:
                log_warning(f"⚠️ 清理实例失败：{cleanup_exc}")
        return

    artifacts_dir = Path("artifacts")
    artifacts_dir.mkdir(exist_ok=True)
    Path("artifacts/instance.json").write_text(
        json.dumps({"id": instance_id, "ip": ip}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    log_success("已写入 artifacts/instance.json")


def run_doctor() -> None:
    code = subprocess.call([sys.executable, "scripts/project_doctor.py"])
    if code == 0:
        print("\n✅ 体检通过。详见 PROJECT_HEALTH_REPORT.md")
    else:
        print("\n⚠️ 体检发现问题，请按报告修复后再继续。")


def run_prune() -> None:
    code = subprocess.call([sys.executable, "scripts/prune_non_windows_only.py"])
    if code == 0:
        print("\n🧹 精简完成。请查看 PROJECT_PRUNE_REPORT.md")
    else:
        print("\n⚠️ 精简脚本返回异常，请查看输出。")
from core.ssh_utils import (
    ask_key_path,
    pick_default_key,
    wait_port_open,
)


def deploy_wireguard() -> None:
    """Deploy WireGuard onto the previously created VPS."""

    inst_path = Path("artifacts/instance.json")
    if not inst_path.exists():
        log_section("🛡 Step 3: Deploy WireGuard")
        log_error("❌ 未找到 artifacts/instance.json，请先创建 VPS。")
        return

    try:
        instance = json.loads(inst_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        log_section("🛡 Step 3: Deploy WireGuard")
        log_error(f"❌ 解析实例信息失败：{exc}")
        return

    ip = instance.get("ip")
    instance_id = instance.get("id", "")
    if not ip:
        log_section("🛡 Step 3: Deploy WireGuard")
        log_error("❌ 实例信息缺少 IP 字段，请重新创建或检查 artifacts/instance.json。")
        return

    log_section("🛡 Step 3: Deploy WireGuard")
    log_info(f"→ 目标实例：{ip}")

    default_key = pick_default_key()
    key_path = Path(ask_key_path(default_key)).expanduser()
    log_info(f"→ 使用私钥：{key_path}")

    log_info("→ 等待 SSH 端口 22 就绪…")
    if not wait_port_open(ip, 22, timeout=180):
        log_error("❌ SSH 端口未就绪（实例可能还在初始化或防火墙未放行 22）。")
        return

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=ip,
            username="root",
            key_filename=str(key_path),
            look_for_keys=False,
            timeout=30,
        )
    except Exception as exc:  # noqa: BLE001
        log_error("❌ 连接 VPS 失败，请检查私钥路径或网络。")
        log_warning(f"⚠️ 详细信息：{exc}")
        return

    try:
        log_info("→ 自动配置网络环境…")
        setup_script = """#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt update -y
apt install -y wireguard wireguard-tools qrencode iptables-persistent netfilter-persistent

mkdir -p /etc/wireguard
umask 077

if [ ! -f /etc/wireguard/server.private ]; then
  wg genkey | tee /etc/wireguard/server.private | wg pubkey > /etc/wireguard/server.public
fi
SERVER_PRIV=$(cat /etc/wireguard/server.private)

cat >/etc/wireguard/wg0.conf <<'EOF'
[Interface]
Address = 10.6.0.1/24
ListenPort = 51820
PrivateKey = __SERVER_PRIV__
SaveConfig = true
EOF

sed -i "s|__SERVER_PRIV__|${SERVER_PRIV}|g" /etc/wireguard/wg0.conf

systemctl enable wg-quick@wg0
systemctl restart wg-quick@wg0
"""
        if not _run_remote_script(client, setup_script, "网络环境初始化"):
            return

        log_info("→ 启用 ip_forward 与 NAT 转发…")
        nat_script = """#!/usr/bin/env bash
set -euo pipefail

echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-wireguard-forward.conf
sysctl -p /etc/sysctl.d/99-wireguard-forward.conf
iptables -t nat -C POSTROUTING -s 10.6.0.0/24 -o enp1s0 -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -s 10.6.0.0/24 -o enp1s0 -j MASQUERADE
netfilter-persistent save
netfilter-persistent reload
"""
        if not _run_remote_script(client, nat_script, "配置 NAT 转发"):
            return

        log_info("→ WireGuard 服务部署中…")
        verify_command = "systemctl is-active wg-quick@wg0"
        if not _run_remote_command(client, verify_command, "检查 WireGuard 服务状态"):
            return

        log_info("→ 自动生成客户端配置 /etc/wireguard/clients/iphone/iphone.conf")
        client_script = f"""#!/usr/bin/env bash
set -euo pipefail

CLIENT_DIR="/etc/wireguard/clients/iphone"
mkdir -p "${{CLIENT_DIR}}"
umask 077

wg genkey | tee "${{CLIENT_DIR}}/iphone.private" | wg pubkey > "${{CLIENT_DIR}}/iphone.public"
CLIENT_PRIV=$(cat "${{CLIENT_DIR}}/iphone.private")
CLIENT_PUB=$(cat "${{CLIENT_DIR}}/iphone.public")
SERVER_PUB=$(cat /etc/wireguard/server.public)
ENDPOINT="{ip}:51820"

if ! wg show wg0 peers | grep -q "${{CLIENT_PUB}}"; then
  wg set wg0 peer "${{CLIENT_PUB}}" allowed-ips 10.6.0.2/32
  wg-quick save wg0
fi

cat > "${{CLIENT_DIR}}/iphone.conf" <<EOF
[Interface]
PrivateKey = ${{CLIENT_PRIV}}
Address = 10.6.0.2/32
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = ${{SERVER_PUB}}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${{ENDPOINT}}
PersistentKeepalive = 25
EOF

qrencode -t PNG -o /root/iphone.png < "${{CLIENT_DIR}}/iphone.conf"
"""
        if not _run_remote_script(client, client_script, "生成客户端配置"):
            return

        log_info("→ 自动生成二维码图片 /root/iphone.png")
        # The QR image is already generated within the client script; this step verifies its existence.
        if not _run_remote_command(client, "test -f /root/iphone.png", "校验二维码文件"):
            return

        log_info("→ 下载至本地 artifacts/iphone.png")
        artifacts_dir = Path("artifacts")
        artifacts_dir.mkdir(exist_ok=True)
        qr_local = artifacts_dir / "iphone.png"
        if not _download_file(client, "/root/iphone.png", qr_local, "下载二维码图片"):
            return

        conf_local = artifacts_dir / "iphone.conf"
        _download_file(
            client,
            "/etc/wireguard/clients/iphone/iphone.conf",
            conf_local,
            "下载客户端配置",
        )

        try:
            with client.open_sftp() as sftp:
                server_pub = (
                    sftp.open("/etc/wireguard/server.public").read().decode("utf-8", errors="ignore").strip()
                )
        except Exception as exc:  # noqa: BLE001
            log_warning(f"⚠️ 读取服务端公钥失败：{exc}")
            server_pub = ""

        server_info: dict[str, Any] = {
            "id": instance_id,
            "ip": ip,
            "server_pub": server_pub,
            "client_config": str(conf_local),
            "qr_code": str(qr_local),
        }
        (artifacts_dir / "server.json").write_text(
            json.dumps(server_info, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        log_success("✅ 已生成可扫码配置文件：artifacts\\iphone.png")
    finally:
        client.close()


def main() -> None:
    while True:
        print("\n=== PrivateTunnel (Windows Only) ===")
        print("1) 运行体检")
        print("2) 创建 VPS（Vultr）")
        print("3) 部署 WireGuard（到已创建 VPS）")
        print("4) 执行项目精简（移除/归档非 Windows 代码与 CI）")
        print("q) 退出")
        choice = input("请选择: ").strip().lower()
        if choice == "1":
            run_doctor()
        elif choice == "2":
            create_vps()
        elif choice == "3":
            deploy_wireguard()
        elif choice == "4":
            run_prune()
        elif choice == "q":
            break
        else:
            print("无效选项，请重试。")


if __name__ == "__main__":
    main()
