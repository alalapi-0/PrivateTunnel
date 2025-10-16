from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import shlex
import shutil
import textwrap
from pathlib import Path
from typing import Any

if sys.version_info < (3, 8):
    raise SystemExit(
        "当前 Python 解释器版本过低。本工具至少需要 Python 3.8，请改用 python3 运行。"
    )

import paramiko

from core.port_config import resolve_listen_port


if os.name == "nt":
    os.system("")

BLUE = "\033[34m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
RESET = "\033[0m"

ROOT = Path(__file__).resolve().parent
ARTIFACTS_DIR = ROOT / "artifacts"
try:
    LISTEN_PORT, LISTEN_PORT_SOURCE = resolve_listen_port()
except ValueError as exc:
    raise SystemExit(f"无效的 WireGuard 端口配置：{exc}") from exc


PLATFORM_CHOICES = {
    "windows": "Windows",
    "macos": "macOS",
}
SELECTED_PLATFORM: str | None = None


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


def _wait_for_port_22(ip: str, *, attempts: int = 10, interval: int = 5) -> bool:
    """Probe TCP/22 on ``ip`` every ``interval`` seconds until success or ``attempts`` exhausted."""

    for attempt in range(1, attempts + 1):
        log_info(f"  ↻ 第 {attempt} 次检测：连接 {ip}:22 …")
        try:
            with socket.create_connection((ip, 22), timeout=5):
                log_success("   SSH 端口已开放。")
                return True
        except OSError as exc:
            log_warning(f"⚠️ 连接失败：{exc}")
        time.sleep(interval)
    log_error("❌ 在预设次数内未检测到 SSH 端口开放。")
    return False


def _wait_for_passwordless_ssh(ip: str, key_path: Path, *, attempts: int = 12, interval: int = 10) -> bool:
    """Attempt ``ssh root@ip true`` until passwordless login succeeds."""

    expanded = key_path.expanduser()
    if not expanded.exists():
        log_warning(f"⚠️ 找不到私钥文件：{expanded}，无法完成免密校验。")
        return False

    command = [
        "ssh",
        "-i",
        str(expanded),
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        f"root@{ip}",
        "true",
    ]

    last_stdout = ""
    last_stderr = ""
    for attempt in range(1, attempts + 1):
        log_info(f"  ↻ 第 {attempt} 次免密检测：ssh root@{ip} true")
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=45,
        )
        last_stdout = (result.stdout or "").strip()
        last_stderr = (result.stderr or "").strip()
        if result.returncode == 0:
            log_success("   免密 SSH 校验通过。")
            return True
        if last_stdout:
            log_warning(f"   stdout: {last_stdout}")
        if last_stderr:
            log_warning(f"   stderr: {last_stderr}")
        time.sleep(interval)

    log_error(
        "❌ 免密 SSH 校验失败。"
        + (f" 最近一次 stdout: {last_stdout}" if last_stdout else "")
        + (f" stderr: {last_stderr}" if last_stderr else "")
    )
    return False


def _print_manual_ssh_hint() -> None:
    """Display manual troubleshooting guidance for SSH key injection issues."""

    log_warning("⚠️ 免密连接失败，请在 Vultr 控制台使用 View Console 登录，并执行：")
    log_warning("  cat /root/.ssh/authorized_keys")
    log_warning("  chmod 700 /root/.ssh; chmod 600 /root/.ssh/authorized_keys")
    log_warning("  systemctl restart ssh")
    log_warning("然后重新运行部署。")


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
    _log_selected_platform()

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
        status_code = None
        cause = exc.__cause__
        if cause is not None:
            status_code = getattr(getattr(cause, "response", None), "status_code", None)
        if status_code == 401:
            log_error(
                "❌ 获取 SSH Key 列表失败，请检查 API Key 权限或 Access Control 白名单（IPv4/IPv6）。"
            )
        else:
            log_error(f"❌ 创建失败：获取 SSH 公钥列表异常：{exc}")
        return

    if not ssh_keys:
        log_error(
            "❌ 获取 SSH Key 列表失败，请检查 API Key 权限或 Access Control 白名单（IPv4/IPv6）。"
        )
        return

    matched_key: dict[str, Any] | None = None
    if selected_keyname:
        for item in ssh_keys:
            if item.get("name") == selected_keyname:
                matched_key = item
                break
    if matched_key is None:
        available = ", ".join(
            item.get("name", "") or item.get("id", "") or "-" for item in ssh_keys
        )
        log_error(
            "❌ 未找到名称匹配 VULTR_SSHKEY_NAME 的 SSH 公钥。请确认环境变量设置正确。\n"
            f"   当前账号可用公钥：{available}"
        )
        return

    ssh_key_id = matched_key.get("id", "")
    ssh_key_name = matched_key.get("name", "")
    ssh_public_text = matched_key.get("ssh_key", "")
    if not ssh_key_id:
        log_error("❌ 匹配到的 SSH 公钥缺少 ID，请在 Vultr 控制台重新创建后再试。")
        return
    log_info(f"→ 已选择 SSH 公钥：{ssh_key_name}")

    log_info("→ 创建实例中…")
    instance_id = ""
    ip = ""
    cloud_init: str | None = None
    if use_snapshot and ssh_public_text:
        cloud_init = (
            "#cloud-config\n"
            "users:\n"
            "  - name: root\n"
            "    ssh_authorized_keys:\n"
            f"      - {ssh_public_text}\n"
            "runcmd:\n"
            "  - systemctl restart ssh\n"
        )
    try:
        instance = create_instance(
            api_key,
            region=region,
            plan=plan,
            snapshot_id=snapshot_id if use_snapshot else None,
            sshkey_ids=[ssh_key_id],
            user_data=cloud_init,
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
        log_info("→ 执行 ssh-keygen -R 清理旧指纹…")
        subprocess.run(["ssh-keygen", "-R", ip], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log_info("→ 第一阶段：检测 SSH 端口 22 是否开放（每 5 秒，最多 10 次）…")
        key_path_default = Path.home() / ".ssh" / "id_ed25519"
        port_ready = _wait_for_port_22(ip)
        if port_ready:
            log_info("→ 第二阶段：校验免密 SSH 是否可用…")
            ssh_ready = _wait_for_passwordless_ssh(ip, key_path_default)
        else:
            ssh_ready = False
        if ssh_ready:
            log_success("✅ 免密 SSH 已生效，可继续部署 WireGuard。")
        else:
            _print_manual_ssh_hint()
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
        "cloud_init_injected": bool(cloud_init),
    }
    instance_file = artifacts_dir / "instance.json"
    instance_file.write_text(
        json.dumps(instance_info, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    log_success(f"已写入 {instance_file}")


def _log_selected_platform() -> None:
    if SELECTED_PLATFORM:
        label = PLATFORM_CHOICES.get(SELECTED_PLATFORM, SELECTED_PLATFORM)
        log_info(f"→ 当前本机系统：{label}")
    else:
        log_warning("⚠️ 尚未选择本机系统，可通过第 1 步执行环境检查。")


def _update_server_info(data: dict[str, Any]) -> None:
    artifacts_dir = ARTIFACTS_DIR
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    server_file = artifacts_dir / "server.json"
    existing: dict[str, Any] = {}
    if server_file.exists():
        try:
            existing = json.loads(server_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            existing = {}
    existing.update(data)
    server_file.write_text(
        json.dumps(existing, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _wireguard_windows_candidate_paths() -> list[Path]:
    """Return likely installation paths for WireGuard for Windows."""

    bases: list[Path] = []
    seen: set[Path] = set()
    env_keys = ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"]
    for key in env_keys:
        value = os.environ.get(key)
        if not value:
            continue
        base = Path(value) / "WireGuard"
        if base not in seen:
            seen.add(base)
            bases.append(base)

    local_appdata = os.environ.get("LOCALAPPDATA")
    if local_appdata:
        base = Path(local_appdata) / "WireGuard"
        if base not in seen:
            seen.add(base)
            bases.append(base)

    fallback_paths = [
        Path(r"C:\Program Files\WireGuard"),
        Path(r"C:\Program Files (x86)\WireGuard"),
    ]
    for base in fallback_paths:
        if base not in seen:
            seen.add(base)
            bases.append(base)

    candidates: list[Path] = []
    for base in bases:
        candidates.append(base / "WireGuard.exe")
        candidates.append(base / "wireguard.exe")
    return candidates


def _locate_wireguard_windows_executable() -> Path | None:
    """Locate the WireGuard for Windows executable if it exists."""

    for candidate in _wireguard_windows_candidate_paths():
        if candidate.is_file():
            return candidate
    binary = shutil.which("wireguard")
    if binary:
        return Path(binary)
    return None


def _install_wireguard_windows_via_powershell() -> bool:
    """Attempt to install WireGuard for Windows using PowerShell."""

    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if not powershell:
        log_warning("⚠️ 未找到 PowerShell，无法自动安装 WireGuard for Windows。")
        return False

    script = textwrap.dedent(
        r"""
        $ErrorActionPreference = "Stop"
        $installerUrl = "https://download.wireguard.com/windows-client/wireguard-installer.exe"
        $tempPath = Join-Path -Path $env:TEMP -ChildPath "wireguard-installer.exe"
        Invoke-WebRequest -Uri $installerUrl -OutFile $tempPath
        if (-Not (Test-Path $tempPath)) {
            throw "下载 WireGuard 安装程序失败：$tempPath"
        }
        Start-Process -FilePath $tempPath -ArgumentList "/install /quiet" -Verb RunAs -Wait
        """
    ).strip()

    try:
        subprocess.run(
            [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        output = (exc.stderr or exc.stdout or "").strip()
        if output:
            log_warning(
                f"⚠️ PowerShell 安装 WireGuard 失败（返回码 {exc.returncode}）。输出：{output}"
            )
        else:
            log_warning(f"⚠️ PowerShell 安装 WireGuard 失败（返回码 {exc.returncode}）。")
        return False
    except FileNotFoundError:
        log_warning("⚠️ 未找到 PowerShell，无法自动安装 WireGuard for Windows。")
        return False

    return True


def _ensure_wireguard_for_windows() -> None:
    """Ensure WireGuard for Windows is installed on the local machine."""

    if os.name != "nt":
        log_warning("⚠️ 当前环境非 Windows，无法自动安装 WireGuard for Windows。")
        return

    existing = _locate_wireguard_windows_executable()
    if existing:
        log_success(f"✅ 已检测到 WireGuard for Windows：{existing}")
        return

    log_info("→ 未检测到 WireGuard for Windows，尝试通过 PowerShell 自动安装 ...")
    if not _install_wireguard_windows_via_powershell():
        log_warning("⚠️ 自动安装 WireGuard for Windows 失败，请手动下载安装包。")
        return

    installed = _locate_wireguard_windows_executable()
    if installed:
        log_success(f"✅ WireGuard for Windows 安装完成：{installed}")
    else:
        log_warning("⚠️ 安装流程执行完毕，但未检测到 WireGuard for Windows，可手动确认。")


def _desktop_usage_tip() -> None:
    if SELECTED_PLATFORM == "windows":
        _ensure_wireguard_for_windows()
        log_info("→ 请在 WireGuard for Windows 中导入生成的 .conf 配置文件后启动隧道。")
    elif SELECTED_PLATFORM == "macos":
        log_info(
            "→ 请安装 WireGuard.app（macOS），双击配置文件或在应用内导入后连接。"
        )
    else:
        log_info(
            "→ 可在任意支持 WireGuard 的桌面客户端中导入该配置以连接 VPS。"
        )


def run_environment_check() -> None:
    global SELECTED_PLATFORM

    log_section("🩺 Step 1: 检查本机环境")
    options = {"1": "windows", "2": "macos"}
    while True:
        log_info("请选择本机系统类型：")
        log_info("  1) Windows")
        log_info("  2) macOS")
        log_info("  q) 返回主菜单")
        choice = input("系统选择: ").strip().lower()
        if choice in {"q", "quit", "exit"}:
            log_warning("⚠️ 已取消环境检查。")
            return
        if choice in options:
            SELECTED_PLATFORM = options[choice]
            break
        log_error("❌ 无效选择，请重新输入。")

    label = PLATFORM_CHOICES.get(SELECTED_PLATFORM, SELECTED_PLATFORM)
    log_info(f"→ 将针对 {label} 环境执行体检…")
    command = [
        sys.executable,
        "scripts/project_doctor.py",
        "--platform",
        SELECTED_PLATFORM,
    ]
    code = subprocess.call(command)
    if code == 0:
        log_success("✅ 体检通过。详见 PROJECT_HEALTH_REPORT.md")
    else:
        log_warning("⚠️ 体检发现问题，请按报告提示修复后再继续。")


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


def _resolve_env_default(
    *env_keys: str,
    default: str,
) -> tuple[str, str | None]:
    """Return the first non-empty environment override and its key."""

    for key in env_keys:
        value = os.environ.get(key)
        if value:
            return value.strip(), key
    return default, None


def _default_private_key_prompt() -> str:
    """Return the default SSH private key path prompt for Step 3."""

    override = os.environ.get("PT_SSH_PRIVATE_KEY", "").strip()
    if override:
        return override
    if os.name == "nt":
        username = os.environ.get("USERNAME") or os.environ.get("USER") or "User"
        return str(Path(f"C:/Users/{username}/.ssh/id_ed25519"))
    return pick_default_key()


def prepare_wireguard_access() -> None:
    """Configure WireGuard end-to-end, including client provisioning."""

    inst_path = ARTIFACTS_DIR / "instance.json"
    if not inst_path.exists():
        log_section("🛡 Step 3: 准备本机接入 VPS 网络")
        log_error(f"❌ 未找到 {inst_path}，请先创建 VPS。")
        return

    try:
        instance = json.loads(inst_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        log_section("🛡 Step 3: 准备本机接入 VPS 网络")
        log_error(f"❌ 解析实例信息失败：{exc}")
        return

    ip = instance.get("ip")
    instance_id = instance.get("id", "")
    if not ip:
        log_section("🛡 Step 3: 准备本机接入 VPS 网络")
        log_error(f"❌ 实例信息缺少 IP 字段，请重新创建或检查 {inst_path}。")
        return

    log_section("🛡 Step 3: 准备本机接入 VPS 网络")
    _log_selected_platform()
    log_info(f"→ 目标实例：{ip}")
    if LISTEN_PORT_SOURCE:
        log_info(f"→ WireGuard 监听端口：{LISTEN_PORT} （来自环境变量 {LISTEN_PORT_SOURCE}）")
    else:
        log_info(
            f"→ WireGuard 监听端口：{LISTEN_PORT} （默认值，可通过环境变量 PRIVATETUNNEL_WG_PORT/PT_WG_PORT 覆盖）"
        )

    desktop_ip, desktop_source = _resolve_env_default("PT_DESKTOP_IP", default="10.6.0.3/32")
    if desktop_source:
        log_info(f"→ 桌面客户端 IP：{desktop_ip} （来自环境变量 {desktop_source}）")
    else:
        log_info(
            "→ 桌面客户端 IP：{value} （默认值，可通过环境变量 PT_DESKTOP_IP 覆盖）".format(value=desktop_ip)
        )

    iphone_ip, iphone_source = _resolve_env_default("PT_IPHONE_IP", default="10.6.0.2/32")
    if iphone_source:
        log_info(f"→ iPhone 客户端 IP：{iphone_ip} （来自环境变量 {iphone_source}）")
    else:
        log_info(
            "→ iPhone 客户端 IP：{value} （默认值，可通过环境变量 PT_IPHONE_IP 覆盖）".format(value=iphone_ip)
        )

    dns_value, dns_source = _resolve_env_default("PT_DNS", default="1.1.1.1")
    if dns_source:
        log_info(f"→ 客户端 DNS：{dns_value} （来自环境变量 {dns_source}）")
    else:
        log_info(
            "→ 客户端 DNS：{value} （默认值，可通过环境变量 PT_DNS 覆盖）".format(value=dns_value)
        )

    allowed_ips, allowed_source = _resolve_env_default("PT_ALLOWED_IPS", default="0.0.0.0/0, ::/0")
    if allowed_source:
        log_info(f"→ 客户端 AllowedIPs：{allowed_ips} （来自环境变量 {allowed_source}）")
    else:
        log_info(
            "→ 客户端 AllowedIPs：{value} （默认值，可通过环境变量 PT_ALLOWED_IPS 覆盖）".format(
                value=allowed_ips
            )
        )

    client_mtu_raw = os.environ.get("PT_CLIENT_MTU", "").strip()
    if client_mtu_raw:
        log_info(f"→ 客户端 MTU：{client_mtu_raw} （来自环境变量 PT_CLIENT_MTU）")
    else:
        log_info("→ 客户端 MTU：未设置（可通过环境变量 PT_CLIENT_MTU 指定）")

    default_key_prompt = _default_private_key_prompt()
    key_path = Path(ask_key_path(default_key_prompt)).expanduser()
    log_info(f"→ 使用私钥：{key_path}")

    log_info("→ 执行 ssh-keygen -R 清理旧指纹…")
    subprocess.run(["ssh-keygen", "-R", ip], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    log_info("→ 第一阶段：检测 SSH 端口 22 是否开放（每 5 秒，最多 10 次）…")
    if not _wait_for_port_22(ip):
        _print_manual_ssh_hint()
        return

    log_info("→ 第二阶段：校验免密 SSH 是否可用…")
    if not _wait_for_passwordless_ssh(ip, key_path):
        _print_manual_ssh_hint()
        return

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

    server_endpoint = f"{ip}:{LISTEN_PORT}"
    desktop_ip_quoted = shlex.quote(desktop_ip)
    iphone_ip_quoted = shlex.quote(iphone_ip)
    dns_quoted = shlex.quote(dns_value)
    allowed_ips_quoted = shlex.quote(allowed_ips)
    client_mtu_quoted = shlex.quote(client_mtu_raw) if client_mtu_raw else "''"
    server_endpoint_quoted = shlex.quote(server_endpoint)

    remote_script = textwrap.dedent(
        f"""#!/usr/bin/env bash
set -euo pipefail

log() {{
  printf '%s %s\\n' "[$(date '+%Y-%m-%d %H:%M:%S')]" "$*"
}}

warn() {{
  printf '%s %s\\n' "[$(date '+%Y-%m-%d %H:%M:%S')]" "⚠️ $*" >&2
}}

err() {{
  printf '%s %s\\n' "[$(date '+%Y-%m-%d %H:%M:%S')]" "❌ $*" >&2
}}

log "=== PrivateTunnel: 开始自动化部署 WireGuard 服务端 ==="

WG_PORT={LISTEN_PORT}
DESKTOP_IP={desktop_ip_quoted}
IPHONE_IP={iphone_ip_quoted}
CLIENT_DNS={dns_quoted}
ALLOWED_IPS={allowed_ips_quoted}
CLIENT_MTU={client_mtu_quoted}
SERVER_ENDPOINT={server_endpoint_quoted}
WG_DIR=/etc/wireguard
SERVER_CONF="$WG_DIR/wg0.conf"
SERVER_PRIV="$WG_DIR/server.private"
SERVER_PUB="$WG_DIR/server.public"
CLIENT_BASE="$WG_DIR/clients"
DESKTOP_DIR="$CLIENT_BASE/desktop"
IPHONE_DIR="$CLIENT_BASE/iphone"

log "→ 准备环境并安装 WireGuard 组件"
export DEBIAN_FRONTEND=noninteractive
apt update -y
apt install -y wireguard wireguard-tools qrencode iptables-persistent netfilter-persistent curl

log "→ 启用时间同步 (timedatectl set-ntp true)"
if ! timedatectl set-ntp true; then
  warn "timedatectl set-ntp true 失败，但仍继续执行。"
fi

WAN_IF=$(ip -o -4 route show to default | awk '{{print $5}}' | head -n1)
if [ -z "$WAN_IF" ]; then
  WAN_IF=enp1s0
fi

log "→ 开启内核转发"
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-wireguard-forward.conf
sysctl -p /etc/sysctl.d/99-wireguard-forward.conf
if [ "$(sysctl -n net.ipv4.ip_forward)" != "1" ]; then
  err "未成功开启 IPv4 转发。"
  exit 1
fi

log "→ 配置 NAT 出口规则 (接口: $WAN_IF)"
iptables -t nat -D POSTROUTING -s 10.6.0.0/24 -o "$WAN_IF" -j MASQUERADE || true
iptables -t nat -A POSTROUTING -s 10.6.0.0/24 -o "$WAN_IF" -j MASQUERADE
if ! iptables -t nat -C POSTROUTING -s 10.6.0.0/24 -o "$WAN_IF" -j MASQUERADE 2>/dev/null; then
  err "未检测到 MASQUERADE 规则，请检查 iptables 配置。"
  exit 1
fi
netfilter-persistent save || true
netfilter-persistent reload || true

if command -v ufw >/dev/null 2>&1; then
  log "→ 通过 UFW 放行 ${{WG_PORT}}/udp"
  ufw allow {LISTEN_PORT}/udp || true
fi

log "→ 创建 WireGuard 配置及密钥"
umask 077
mkdir -p "$WG_DIR" "$CLIENT_BASE" "$DESKTOP_DIR" "$IPHONE_DIR"
chmod 700 "$CLIENT_BASE" "$DESKTOP_DIR" "$IPHONE_DIR"

if [ ! -f "$SERVER_PRIV" ]; then
  log "   生成服务器密钥对"
  wg genkey | tee "$SERVER_PRIV" | wg pubkey > "$SERVER_PUB"
fi
SERVER_PRIVATE=$(cat "$SERVER_PRIV")
SERVER_PUBLIC=$(cat "$SERVER_PUB")

cat > "$SERVER_CONF" <<EOF
[Interface]
Address = 10.6.0.1/24
ListenPort = $WG_PORT
PrivateKey = $SERVER_PRIVATE
SaveConfig = true
EOF
chmod 600 "$SERVER_CONF"

log "→ 启用并启动 wg-quick@wg0"
systemctl enable wg-quick@wg0
systemctl restart wg-quick@wg0

log "→ 校验 WireGuard UDP 监听端口"
if ! ss -lun | grep -q ":$WG_PORT"; then
  err "UDP 端口 $WG_PORT 未监听，请检查防火墙或服务状态。"
  exit 1
fi

log "→ 当前 wg show 状态"
wg show

generate_client() {{
  local name="$1"
  local addr="$2"
  local dir="$3"
  local __pub_var="$4"
  log "→ 生成客户端 ${name} (IP: ${addr})"
  if [ -f "$dir/${{name}}.public" ]; then
    local old_pub
    old_pub=$(cat "$dir/${{name}}.public")
    if [ -n "$old_pub" ]; then
      wg set wg0 peer "$old_pub" remove || true
    fi
  fi
  wg genkey | tee "$dir/${{name}}.private" | wg pubkey > "$dir/${{name}}.public"
  local priv
  priv=$(cat "$dir/${{name}}.private")
  local pub
  pub=$(cat "$dir/${{name}}.public")
  chmod 600 "$dir/${{name}}.private"
  wg set wg0 peer "$pub" remove || true
  wg set wg0 peer "$pub" allowed-ips "$addr"
  {{
    printf '%s\\n' '[Interface]'
    printf 'PrivateKey = %s\\n' "$priv"
    printf 'Address = %s\\n' "$addr"
    printf 'DNS = %s\\n' "$CLIENT_DNS"
    if [ -n "$CLIENT_MTU" ]; then
      printf 'MTU = %s\\n' "$CLIENT_MTU"
    fi
    printf '\n[Peer]\\n'
    printf 'PublicKey = %s\\n' "$SERVER_PUBLIC"
    printf 'AllowedIPs = %s\\n' "$ALLOWED_IPS"
    printf 'Endpoint = %s\\n' "$SERVER_ENDPOINT"
    printf 'PersistentKeepalive = 25\\n'
  }} > "$dir/${{name}}.conf"
  chmod 600 "$dir/${{name}}.conf"
  printf -v "$__pub_var" '%s' "$pub"
}}

DESKTOP_PUBLIC=""
IPHONE_PUBLIC=""
generate_client "desktop" "$DESKTOP_IP" "$DESKTOP_DIR" DESKTOP_PUBLIC
generate_client "iphone" "$IPHONE_IP" "$IPHONE_DIR" IPHONE_PUBLIC

log "→ 保存配置并重启 WireGuard"
wg-quick save wg0
systemctl restart wg-quick@wg0

log "→ 再次检查 wg show peers"
WG_OUTPUT=$(wg show)
if ! grep -q "$DESKTOP_PUBLIC" <<<"$WG_OUTPUT"; then
  err "未检测到 desktop peer 已加载。"
  printf '%s\n' "$WG_OUTPUT"
  exit 1
fi
if ! grep -q "$IPHONE_PUBLIC" <<<"$WG_OUTPUT"; then
  err "未检测到 iphone peer 已加载。"
  printf '%s\n' "$WG_OUTPUT"
  exit 1
fi
printf '%s\n' "$WG_OUTPUT"

SERVER_EXTERNAL_IP=$(curl -4 -s ifconfig.me || true)
if [ -z "$SERVER_EXTERNAL_IP" ]; then
  SERVER_EXTERNAL_IP={shlex.quote(ip)}
fi

log "→ WireGuard 服务端部署完成"
echo "SERVER_ENDPOINT=$SERVER_ENDPOINT"
echo "SERVER_EXTERNAL_IP=$SERVER_EXTERNAL_IP"
echo "SERVER_PUBLIC_KEY=$SERVER_PUBLIC"
echo "DESKTOP_IP=$DESKTOP_IP"
echo "DESKTOP_PUBLIC_KEY=$DESKTOP_PUBLIC"
echo "IPHONE_IP=$IPHONE_IP"
echo "IPHONE_PUBLIC_KEY=$IPHONE_PUBLIC"
"""
    )

    try:
        log_info("→ SSH 已连接，开始执行一键部署脚本…")
        if not _run_remote_script(client, remote_script, "部署 WireGuard 服务端"):
            return
        log_success("✅ 远端 WireGuard 已部署并登记 desktop / iphone 客户端。")
    finally:
        client.close()

    log_info("→ 再次执行 ssh-keygen -R 清理指纹…")
    subprocess.run(["ssh-keygen", "-R", ip], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # 重新建立连接以下载文件
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
        log_error("❌ 重新连接 VPS 以下载配置失败。")
        log_warning(f"⚠️ 详细信息：{exc}")
        return

    try:
        artifacts_dir = ARTIFACTS_DIR
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        desktop_conf_local = artifacts_dir / "desktop.conf"
        iphone_conf_local = artifacts_dir / "iphone.conf"
        log_info(f"→ 下载桌面端配置到 {desktop_conf_local}")
        if not _download_file(
            client,
            "/etc/wireguard/clients/desktop/desktop.conf",
            desktop_conf_local,
            "下载桌面端配置",
        ):
            return
        log_info(f"→ 下载 iPhone 配置到 {iphone_conf_local}")
        if not _download_file(
            client,
            "/etc/wireguard/clients/iphone/iphone.conf",
            iphone_conf_local,
            "下载 iPhone 配置",
        ):
            return

        server_pub = ""
        desktop_pub = ""
        iphone_pub = ""
        try:
            with client.open_sftp() as sftp:
                server_pub = (
                    sftp.open("/etc/wireguard/server.public").read().decode("utf-8", errors="ignore").strip()
                )
                desktop_pub = (
                    sftp.open("/etc/wireguard/clients/desktop/desktop.public")
                    .read()
                    .decode("utf-8", errors="ignore")
                    .strip()
                )
                iphone_pub = (
                    sftp.open("/etc/wireguard/clients/iphone/iphone.public")
                    .read()
                    .decode("utf-8", errors="ignore")
                    .strip()
                )
        except Exception as exc:  # noqa: BLE001
            log_warning(f"⚠️ 读取远端公钥信息失败：{exc}")
            server_pub = ""
            desktop_pub = ""
            iphone_pub = ""

    finally:
        client.close()

    try:
        import qrcode  # type: ignore
    except ImportError as exc:  # noqa: BLE001
        log_error(f"❌ 未安装 qrcode 包，无法生成二维码：{exc}")
        log_warning("⚠️ 请执行 `pip install qrcode[pil]` 后重试。")
        return

    try:
        iphone_conf_text = iphone_conf_local.read_text(encoding="utf-8").strip()
    except OSError as exc:  # noqa: BLE001
        log_error(f"❌ 读取 {iphone_conf_local} 失败：{exc}")
        return

    iphone_png = ARTIFACTS_DIR / "iphone.png"
    try:
        img = qrcode.make(iphone_conf_text)
        img.save(iphone_png)
    except Exception as exc:  # noqa: BLE001
        log_error(f"❌ 生成二维码失败：{exc}")
        return

    server_info: dict[str, Any] = {
        "id": instance_id,
        "ip": ip,
        "server_pub": server_pub,
        "platform": SELECTED_PLATFORM or "",
        "endpoint": server_endpoint,
        "desktop_ip": desktop_ip,
        "iphone_ip": iphone_ip,
        "desktop_public_key": desktop_pub,
        "iphone_public_key": iphone_pub,
        "desktop_config": str(desktop_conf_local),
        "iphone_config": str(iphone_conf_local),
        "iphone_qr": str(iphone_png),
        "allowed_ips": allowed_ips,
        "dns": dns_value,
    }
    _update_server_info(server_info)

    if desktop_conf_local.exists() and iphone_conf_local.exists() and iphone_png.exists():
        log_success(
            f"✅ 已生成 {desktop_conf_local}, {iphone_conf_local}, {iphone_png}"
        )
    else:
        log_warning("⚠️ 部分本地文件缺失，请检查 artifacts 目录。")

    _desktop_usage_tip()
    log_info(f"请导入 {desktop_conf_local} 并启动隧道。")


def generate_mobile_qr() -> None:
    """Generate a QR code for importing the desktop config on mobile devices."""

    log_section("📱 Step 4: 生成移动端二维码配置")
    _log_selected_platform()

    artifacts_dir = ARTIFACTS_DIR
    conf_local = artifacts_dir / "desktop.conf"
    if not conf_local.exists():
        log_error("❌ 未找到桌面端配置文件，请先执行第 3 步生成配置。")
        return

    try:
        config_text = conf_local.read_text(encoding="utf-8").strip()
    except OSError as exc:  # noqa: BLE001
        log_error(f"❌ 读取配置文件失败：{exc}")
        return

    if not config_text:
        log_error("❌ 配置文件内容为空，无法生成二维码。")
        return

    try:
        import qrcode  # type: ignore
    except ImportError as exc:  # noqa: BLE001
        log_error(f"❌ 未安装 qrcode 包：{exc}")
        log_warning("⚠️ 请执行 `pip install qrcode[pil]` 后重试。")
        return

    qr_local = artifacts_dir / "desktop.png"
    try:
        qr_local.parent.mkdir(parents=True, exist_ok=True)
        img = qrcode.make(config_text)
        img.save(qr_local)
    except Exception as exc:  # noqa: BLE001
        log_error(f"❌ 生成二维码失败：{exc}")
        return

    _update_server_info({
        "client_config": str(conf_local),
        "qr_code": str(qr_local),
    })

    log_success(f"✅ 已生成二维码：{qr_local}")
    log_info("→ 可使用手机 WireGuard 或其他支持 WireGuard 的客户端扫码导入。")


def main() -> None:
    while True:
        print("\n=== PrivateTunnel 桌面助手 ===")
        print("1) 检查本机环境（Windows/macOS）")
        print("2) 创建 VPS（Vultr）")
        print("3) 准备本机接入 VPS 网络")
        print("4) 生成移动端二维码配置")
        print("5) 执行项目精简（移除/归档非 Windows 代码与 CI）")
        print("q) 退出")
        choice = input("请选择: ").strip().lower()
        if choice == "1":
            run_environment_check()
        elif choice == "2":
            create_vps()
        elif choice == "3":
            prepare_wireguard_access()
        elif choice == "4":
            generate_mobile_qr()
        elif choice == "5":
            run_prune()
        elif choice == "q":
            break
        else:
            print("无效选项，请重试。")


if __name__ == "__main__":
    main()
