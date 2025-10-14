from __future__ import annotations

import json
import os
import subprocess
import sys
import time
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

ROOT = Path(__file__).resolve().parent
ARTIFACTS_DIR = ROOT / "artifacts"


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


def _stream_command_output(
    stdout: paramiko.ChannelFile, stderr: paramiko.ChannelFile, show_output: bool
) -> tuple[int, str, str]:
    """Stream ``stdout``/``stderr`` until completion and return the exit code.

    Parameters
    ----------
    stdout, stderr:
        Paramiko file-like objects representing the remote command output streams.
    show_output:
        Whether to echo remote output to the local console in real-time.
    """

    channel = stdout.channel
    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []
    printed_any = False
    last_printed = ""

    while True:
        stdout_drained = True
        stderr_drained = True

        if channel.recv_ready():
            data = channel.recv(4096)
            if data:
                stdout_drained = False
                text = data.decode("utf-8", errors="ignore")
                stdout_chunks.append(text)
                if show_output:
                    print(text, end="", flush=True)
                    printed_any = True
                    last_printed = text
            else:
                stdout_drained = True

        if channel.recv_stderr_ready():
            data = channel.recv_stderr(4096)
            if data:
                stderr_drained = False
                text = data.decode("utf-8", errors="ignore")
                stderr_chunks.append(text)
                if show_output:
                    print(text, end="", flush=True)
                    printed_any = True
                    last_printed = text
            else:
                stderr_drained = True

        if channel.exit_status_ready() and stdout_drained and stderr_drained:
            break

        if stdout_drained and stderr_drained:
            time.sleep(0.1)

    exit_code = channel.recv_exit_status()
    if show_output and printed_any and not last_printed.endswith("\n"):
        print()

    stdout_data = "".join(stdout_chunks).strip()
    stderr_data = "".join(stderr_chunks).strip()
    return exit_code, stdout_data, stderr_data


def _run_remote_script(
    client: paramiko.SSHClient,
    script: str,
    description: str,
    *,
    timeout: int = 1200,
    show_output: bool = True,
) -> bool:
    """Execute ``script`` on ``client`` using ``bash`` and report errors."""

    try:
        stdin, stdout, stderr = client.exec_command("bash -s", get_pty=False, timeout=timeout)
        if not script.endswith("\n"):
            script += "\n"
        stdin.write(script)
        stdin.flush()
        stdin.channel.shutdown_write()
        stdin.close()
        exit_code, stdout_data, stderr_data = _stream_command_output(stdout, stderr, show_output)
    except Exception as exc:  # noqa: BLE001 - we want to surface any Paramiko errors
        log_error(f"❌ {description}失败：{exc}")
        return False

    if exit_code != 0:
        details = stderr_data or stdout_data or f"退出码 {exit_code}"
        log_error(f"❌ {description}失败：{details}")
        return False
    return True


def _run_remote_command(
    client: paramiko.SSHClient,
    command: str,
    description: str,
    timeout: int = 600,
    *,
    show_output: bool = True,
) -> bool:
    """Run a single command via Paramiko with unified error handling."""

    try:
        stdin, stdout, stderr = client.exec_command(command, get_pty=False, timeout=timeout)
        stdin.channel.shutdown_write()
        exit_code, stdout_data, stderr_data = _stream_command_output(stdout, stderr, show_output)
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

    env_region = os.getenv("VULTR_REGION", "").strip()
    env_plan = os.getenv("VULTR_PLAN", "").strip()
    env_snapshot_id = os.getenv("VULTR_SNAPSHOT_ID", "").strip()
    env_sshkey_name = os.getenv("VULTR_SSHKEY_NAME", "").strip()

    default_region = env_region or "nrt"
    default_plan = env_plan or "vc2-4c-8gb"

    if env_region:
        region = env_region
        log_info(f"→ 使用环境变量 VULTR_REGION={region}")
    else:
        region = input(f"region [{default_region}]: ").strip() or default_region

    if env_plan:
        plan = env_plan
        log_info(f"→ 使用环境变量 VULTR_PLAN={plan}")
    else:
        plan = input(f"plan [{default_plan}]: ").strip() or default_plan

    snapshot_id = ""
    snapshot_desc = env_snapshot_id or "VULTR_SNAPSHOT_ID"
    default_mode = "1" if env_snapshot_id else "2"
    mode_prompt = "实例来源 [1=使用快照"
    if env_snapshot_id:
        mode_prompt += f"({env_snapshot_id})"
    mode_prompt += ", 2=全新 Ubuntu 22.04]"
    mode = input(f"{mode_prompt} [{default_mode}]: ").strip() or default_mode

    use_snapshot = mode == "1"
    if use_snapshot:
        snapshot_input = input(f"snapshot_id [{snapshot_desc}]: ").strip()
        snapshot_id = snapshot_input or env_snapshot_id
        if not snapshot_id:
            log_error("❌ 请选择有效的快照 ID，或返回重新选择全新系统选项。")
            return
        if env_snapshot_id and snapshot_id == env_snapshot_id:
            log_info(f"→ 使用环境变量 VULTR_SNAPSHOT_ID={snapshot_id}")
        else:
            log_info(f"→ 使用 snapshot_id={snapshot_id}")
    else:
        if env_snapshot_id:
            log_info("→ 已选择全新 Ubuntu 22.04，将忽略环境变量 VULTR_SNAPSHOT_ID。")

    selected_keyname = env_sshkey_name
    sshkey_prompt_default = env_sshkey_name or "VULTR_SSHKEY_NAME"
    sshkey_input = input(f"ssh_keyname [{sshkey_prompt_default}]: ").strip()
    selected_keyname = sshkey_input or env_sshkey_name
    if not selected_keyname:
        log_error("❌ 未提供 SSH 公钥名称，请先在 Vultr 控制台创建 SSH 公钥。")
        return

    log_info("→ 查询 SSH 公钥信息…")
    try:
        ssh_keys = list_ssh_keys(api_key)
    except VultrError as exc:
        log_error(f"❌ 创建失败：获取 SSH 公钥列表异常：{exc}")
        return

    if not ssh_keys:
        log_error("❌ 未在 Vultr 账号中找到任何 SSH 公钥，请先添加后重试。")
        return

    default_index = 1
    for idx, item in enumerate(ssh_keys, start=1):
        name = item.get("name", "")
        log_info(f"  {idx}) {name} ({item.get('id', '')})")
        if selected_keyname and name == selected_keyname:
            default_index = idx

    default_key_desc = ssh_keys[default_index - 1].get("name", "")
    selection = input(
        f"请选择 SSH 公钥（可输入编号、名称或 ID）[默认 {default_index}:{default_key_desc}]: "
    ).strip()
    chosen_idx: int | None = None
    if not selection:
        chosen_idx = default_index
    else:
        try:
            chosen_idx = int(selection)
        except ValueError:
            normalized = selection.casefold()
            for idx, item in enumerate(ssh_keys, start=1):
                name = (item.get("name", "") or "").casefold()
                key_id = (item.get("id", "") or "").casefold()
                if normalized in {name, key_id}:
                    chosen_idx = idx
                    break
            if chosen_idx is None:
                log_error("❌ 找不到匹配的 SSH 公钥，请检查输入的编号、名称或 ID。")
                return
    if not 1 <= chosen_idx <= len(ssh_keys):
        log_error("❌ 输入的编号超出范围。")
        return

    ssh_key = ssh_keys[chosen_idx - 1]
    ssh_key_id = ssh_key.get("id", "")
    ssh_key_name = ssh_key.get("name", "")
    if not ssh_key_id:
        log_error("❌ 所选 SSH 公钥缺少 ID，请在 Vultr 控制台重新创建后再试。")
        return
    log_info(f"→ 已选择 SSH 公钥：{ssh_key_name}")

    log_info("→ 创建实例中…")
    instance_id = ""
    try:
        instance = create_instance(
            api_key,
            region=region,
            plan=plan,
            snapshot_id=snapshot_id if use_snapshot else None,
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
        log_info("→ 检测实例连通性（每分钟 ping 一次，最多 10 分钟）…")
        if wait_instance_ping(ip, timeout=600, interval=60):
            log_success("✅ 实例已可连通，可继续进行下一步部署。")
        else:
            log_warning(
                "⚠️ 在预设时间内未 Ping 通实例，但 Vultr 状态已 active。\n"
                "   可以稍后再试部署，或手动检查实例网络。"
            )
    except VultrError as exc:
        log_error(f"❌ 创建失败：{exc}")
        if instance_id:
            try:
                destroy_instance(api_key, instance_id)
                log_warning("⚠️ 已尝试清理未就绪实例。")
            except VultrError as cleanup_exc:
                log_warning(f"⚠️ 清理实例失败：{cleanup_exc}")
        return

    artifacts_dir = ARTIFACTS_DIR
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    instance_info: dict[str, Any] = {
        "id": instance_id,
        "ip": ip,
        "region": region,
        "plan": plan,
        "source": "snapshot" if use_snapshot else "os",
        "ssh_key": ssh_key_name,
        "ssh_key_name": ssh_key_name,
        "ssh_key_id": ssh_key_id,
        "ssh_key_ids": [ssh_key_id],
        "created_at": int(time.time()),
    }
    instance_file = artifacts_dir / "instance.json"
    instance_file.write_text(
        json.dumps(instance_info, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    log_success(f"已写入 {instance_file}")


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
    nuke_known_host,
    pick_default_key,
    probe_publickey_auth,
    wait_port_open,
)


def wait_instance_ping(ip: str, timeout: int = 600, interval: int = 60) -> bool:
    """Ping ``ip`` every ``interval`` seconds until reachable or timeout."""

    deadline = time.time() + timeout
    ping_command = [
        "ping",
        "-n" if os.name == "nt" else "-c",
        "1",
        ip,
    ]
    attempt = 1
    while time.time() < deadline:
        log_info(f"  ↻ 第 {attempt} 次检测：ping {ip}")
        try:
            result = subprocess.run(
                ping_command,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except subprocess.SubprocessError as exc:
            log_warning(f"⚠️ 执行 ping 命令失败：{exc}")
            time.sleep(interval)
            attempt += 1
            continue

        if result.returncode == 0:
            return True

        log_warning("⚠️ 暂未连通，继续等待实例初始化…")
        time.sleep(interval)
        attempt += 1
    return False


def deploy_wireguard() -> None:
    """Deploy WireGuard onto the previously created VPS."""

    inst_path = ARTIFACTS_DIR / "instance.json"
    if not inst_path.exists():
        log_section("🛡 Step 3: Deploy WireGuard")
        log_error(f"❌ 未找到 {inst_path}，请先创建 VPS。")
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
        log_error(f"❌ 实例信息缺少 IP 字段，请重新创建或检查 {inst_path}。")
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

    log_info("→ 校验公钥认证是否生效…")
    probe = probe_publickey_auth(ip, str(key_path))
    if not probe.success:
        details = probe.error or probe.stderr or probe.stdout
        if details:
            log_warning(f"⚠️ 公钥认证暂未生效：{details}")

        api_key = os.environ.get("VULTR_API_KEY", "").strip()
        ssh_key_ids: list[str] = []

        stored_ids = instance.get("ssh_key_ids")
        if isinstance(stored_ids, (list, tuple)):
            ssh_key_ids.extend(str(item).strip() for item in stored_ids if str(item).strip())

        fallback_id = str(instance.get("ssh_key_id", "")).strip()
        if fallback_id and fallback_id not in ssh_key_ids:
            ssh_key_ids.append(fallback_id)

        if api_key and instance_id and not ssh_key_ids:
            ssh_key_name = str(
                instance.get("ssh_key_name")
                or instance.get("ssh_key")
                or ""
            ).strip()
            if ssh_key_name:
                log_info("→ 尝试根据记录的 SSH 公钥名称匹配 Vultr 账号中的公钥…")
                from core.tools.vultr_manager import list_ssh_keys  # pylint: disable=import-outside-toplevel

                try:
                    for item in list_ssh_keys(api_key):
                        name = str(item.get("name", "")).strip()
                        key_id = str(item.get("id", "")).strip()
                        if name == ssh_key_name and key_id:
                            ssh_key_ids.append(key_id)
                            break
                except Exception as exc:  # noqa: BLE001 - surface lookup errors for troubleshooting
                    log_warning(f"⚠️ 获取 SSH 公钥列表失败：{exc}")

        ssh_key_ids = list(dict.fromkeys([item for item in ssh_key_ids if item]))

        if api_key and instance_id and ssh_key_ids:
            if ssh_key_ids != stored_ids:
                instance["ssh_key_ids"] = ssh_key_ids
                inst_path.write_text(
                    json.dumps(instance, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
        else:
            log_error("❌ SSH 公钥认证失败，且缺少触发 Reinstall SSH Keys 所需信息。")
            return

        log_info("→ 自动触发 Vultr Reinstall SSH Keys …")
        from core.tools.vultr_manager import (  # pylint: disable=import-outside-toplevel
            VultrError,
            reinstall_with_ssh_keys,
        )

        try:
            reinstall_with_ssh_keys(api_key, instance_id, sshkey_ids=ssh_key_ids)
        except VultrError as exc:  # pragma: no cover - network dependent
            log_error(f"❌ 自动触发 Reinstall SSH Keys 失败：{exc}")
            return

        log_warning("⚠️ 已自动触发 Reinstall SSH Keys，请等待约 1–2 分钟后继续。")
        time.sleep(75)

        probe = probe_publickey_auth(ip, str(key_path))
        if not probe.success:
            details = probe.error or probe.stderr or probe.stdout
            if details:
                log_warning(f"⚠️ 最近一次 SSH 输出：{details}")
            log_error("❌ 公钥认证仍失败。已自动触发 Reinstall SSH Keys，请等待约 1–2 分钟后继续。")
            return

        log_success("✅ Reinstall 后公钥认证已生效。")
    else:
        log_success("✅ 公钥认证已生效。")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    nuke_known_host(ip)
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
        log_info("→ SSH 已连接，开始部署 WireGuard…")
        setup_steps = [
            (
                "更新软件包并安装 WireGuard 组件",
                """#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y wireguard wireguard-tools qrencode iptables-persistent netfilter-persistent
""",
            ),
            (
                "初始化 WireGuard 配置目录",
                """#!/usr/bin/env bash
set -euo pipefail

mkdir -p /etc/wireguard
umask 077

if [ ! -f /etc/wireguard/server.private ]; then
  echo "→ 生成服务器私钥/公钥…"
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
""",
            ),
            (
                "启用并启动 WireGuard 服务",
                """#!/usr/bin/env bash
set -euo pipefail

systemctl enable wg-quick@wg0
systemctl restart wg-quick@wg0
""",
            ),
            (
                "配置 IP 转发与 NAT",
                """#!/usr/bin/env bash
set -euo pipefail

echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-wireguard-forward.conf
sysctl -p /etc/sysctl.d/99-wireguard-forward.conf
PRIMARY_IF=$(ip route show default 0.0.0.0/0 | awk 'NR==1 {print $5}')
if [ -z "${PRIMARY_IF}" ]; then
  PRIMARY_IF=enp1s0
fi
iptables -t nat -C POSTROUTING -s 10.6.0.0/24 -o "${PRIMARY_IF}" -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -s 10.6.0.0/24 -o "${PRIMARY_IF}" -j MASQUERADE
netfilter-persistent save
netfilter-persistent reload
""",
            ),
        ]

        for description, script in setup_steps:
            log_info(f"→ {description}…")
            if not _run_remote_script(client, script, description):
                return
            log_success(f"   完成：{description}")

        log_info("→ 检查 WireGuard 服务状态…")
        verify_command = "systemctl is-active wg-quick@wg0"
        if not _run_remote_command(client, verify_command, "检查 WireGuard 服务状态"):
            return

        log_info("→ 生成客户端配置 /etc/wireguard/clients/iphone/iphone.conf …")
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
  echo "→ 将新客户端加入服务器…"
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
        log_success("   完成：生成客户端配置")

        log_info("→ 校验二维码文件 /root/iphone.png …")
        if not _run_remote_command(client, "test -f /root/iphone.png", "校验二维码文件"):
            return

        artifacts_dir = ARTIFACTS_DIR
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        qr_local = artifacts_dir / "iphone.png"
        log_info(f"→ 下载至本地 {qr_local}")
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

        log_success(f"✅ 已生成可扫码配置文件：{qr_local}")
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
