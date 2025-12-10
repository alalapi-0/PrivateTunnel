"""主程序入口：提供 Windows 一键部署 WireGuard 的交互式脚本。

本模块承担以下职责：
1. 组织交互式菜单，让零基础用户也能依序完成 Vultr 实例创建、SSH 探活、WireGuard 部署与客户端配置下载。
2. 封装 SSH、Paramiko、scp 等后端的调度逻辑，在失败时给出直观的中文提示。
3. 提供部署日志记录、网络诊断、实例销毁等辅助功能，确保在一台 Windows 机器上即可完成端到端操作。
"""

# 主线入口：Windows 端一键部署与菜单式操作的统一入口点。

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
import threading

from core.config.defaults import (
    DEFAULT_ALLOWED_IPS,
    DEFAULT_CLIENT_MTU,
    DEFAULT_DESKTOP_ADDRESS,
    DEFAULT_DNS_STRING,
    DEFAULT_IPHONE_ADDRESS,
    DEFAULT_KEEPALIVE_SECONDS,
    DEFAULT_SERVER_ADDRESS,
    DEFAULT_SUBNET_CIDR,
)
from core.project_overview import generate_project_overview
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

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


@dataclass
class SSHResult:
    """远程 SSH 命令执行的结果容器。Result of a remote SSH command execution."""

    returncode: int
    stdout: str
    stderr: str
    backend: str


@dataclass
class SSHContext:
    """封装远程 SSH 执行所需的连接参数。Connection parameters for remote SSH execution."""

    hostname: str
    key_path: Path


class DeploymentError(RuntimeError):
    """在自动化部署 WireGuard 失败时抛出的异常。Raised when the automated WireGuard deployment fails."""


@dataclass(frozen=True)
class MenuAction:
    """定义交互式菜单选项。Define an interactive menu option for the CLI."""

    key: str
    description: str
    handler: Callable[[], None]


LOG_FILE: Path | None = None
SSH_CTX: SSHContext | None = None
_PARAMIKO_CLIENT: paramiko.SSHClient | None = None
_SUBPROCESS_TEXT_KWARGS = {"text": True, "encoding": "utf-8", "errors": "replace"}


def _colorize(message: str, color: str) -> str:
    """用 ANSI 颜色编码包装文本。Return ``message`` wrapped in ANSI color codes."""

    return f"{color}{message}{RESET}"


def _log_to_file(message: str) -> None:
    """如启用则把日志写入文件。Append ``message`` to the deploy log if enabled."""

    if LOG_FILE is None:
        return
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a", encoding="utf-8") as handle:
            handle.write(f"{message}\n")
    except OSError:
        # Logging must never block deployment.
        pass


def logwrite(message: str, *, color: str | None = None) -> None:
    """打印信息（可选颜色）并写入日志。Print ``message`` (optionally colorized) and persist to the log file."""

    text = _colorize(message, color) if color else message
    print(text)
    _log_to_file(message)


def log_info(message: str) -> None:
    """以蓝色输出一般信息。Print an informational message in blue."""

    logwrite(message, color=BLUE)


def log_success(message: str) -> None:
    """以绿色输出成功提示。Print a success message in green."""

    logwrite(message, color=GREEN)


def log_warning(message: str) -> None:
    """以黄色输出警告信息。Print a warning message in yellow."""

    logwrite(message, color=YELLOW)


def log_error(message: str) -> None:
    """以红色输出错误信息。Print an error message in red."""

    logwrite(message, color=RED)


def log_section(title: str) -> None:
    """打印分隔线用于标记流程步骤。Print a visual separator for a workflow step."""

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


def _init_deploy_log() -> Path:
    """Create a timestamped deployment log inside ``artifacts``."""

    global LOG_FILE
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = ARTIFACTS_DIR / f"deploy-{timestamp}.log"
    LOG_FILE = log_path
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("w", encoding="utf-8") as handle:
            handle.write(f"# PrivateTunnel Step3 log {timestamp}\n")
    except OSError:
        # Even if writing fails, keep the path so subsequent logs still attempt writes.
        pass
    return log_path


def _set_ssh_context(hostname: str, key_path: Path) -> None:
    """Record the SSH connection context for subsequent helper calls."""

    global SSH_CTX
    _close_paramiko_client()
    SSH_CTX = SSHContext(hostname=hostname, key_path=key_path)


def _require_ssh_context() -> SSHContext:
    """Return the active SSH context or raise an internal error."""

    if SSH_CTX is None:
        raise DeploymentError("内部错误：SSH 上下文未初始化。")
    return SSH_CTX


def _close_paramiko_client() -> None:
    """Close and reset the cached Paramiko client if it exists."""

    global _PARAMIKO_CLIENT
    if _PARAMIKO_CLIENT is not None:
        try:
            _PARAMIKO_CLIENT.close()
        except Exception:  # noqa: BLE001 - best effort cleanup
            pass
        _PARAMIKO_CLIENT = None


def _load_paramiko_pkey(path: Path) -> paramiko.PKey:
    """Load an SSH private key compatible with Paramiko."""

    errors: list[str] = []
    try:
        return paramiko.Ed25519Key.from_private_key_file(str(path))
    except Exception as exc:  # noqa: BLE001 - collect and retry with other key types
        errors.append(f"Ed25519: {exc}")
    try:
        return paramiko.RSAKey.from_private_key_file(str(path))
    except Exception as exc:  # noqa: BLE001
        errors.append(f"RSA: {exc}")
    try:
        return paramiko.ECDSAKey.from_private_key_file(str(path))
    except Exception as exc:  # noqa: BLE001
        errors.append(f"ECDSA: {exc}")
    raise DeploymentError(f"无法解析私钥 {path}: {'; '.join(errors)}")


def _ensure_paramiko_client() -> paramiko.SSHClient:
    """Return a connected Paramiko SSH client, creating one if necessary."""

    global _PARAMIKO_CLIENT
    if _PARAMIKO_CLIENT is not None:
        return _PARAMIKO_CLIENT

    ctx = _require_ssh_context()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    pkey = _load_paramiko_pkey(ctx.key_path)
    try:
        client.connect(
            hostname=ctx.hostname,
            username="root",
            pkey=pkey,
            look_for_keys=False,
            timeout=60,  # 从30秒增加到60秒，适应不稳定网络
        )
        # 设置keepalive以保持连接稳定（每30秒发送一次keepalive包）
        if client.get_transport():
            client.get_transport().set_keepalive(30)
    except Exception as exc:  # noqa: BLE001
        raise DeploymentError(f"Paramiko 连接 {ctx.hostname} 失败：{exc}") from exc

    _PARAMIKO_CLIENT = client
    return client


def _log_remote_output(prefix: str, text: str) -> None:
    """Log remote stdout/stderr content line-by-line."""

    if not text:
        return
    for line in text.splitlines():
        logwrite(f"{prefix}{line}")


def _clean_known_host(ip: str) -> None:
    """Remove stale host key fingerprints for ``ip`` prior to SSH attempts."""

    log_info(f"→ 使用 ssh-keygen -R 清理旧指纹（{ip}）…")
    targets = (ip, f"[{ip}]:22")
    for target in targets:
        command = ["ssh-keygen", "-R", target]
        logwrite(f"$ {' '.join(command)}")
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                **_SUBPROCESS_TEXT_KWARGS,
                check=False,
            )
        except FileNotFoundError:
            log_warning("⚠️ 未检测到 ssh-keygen，改用内置清理逻辑。")
            break
        except subprocess.SubprocessError as exc:
            log_warning(f"⚠️ 清理 {target} 指纹失败：{exc}")
            continue
        _log_remote_output("[ssh-keygen] ", result.stdout)
        _log_remote_output("[ssh-keygen] ", result.stderr)

    try:
        nuke_known_host(ip)
    except Exception:  # noqa: BLE001 - best effort cleanup
        pass


def _monitor_deployment_progress(ip: str, key_path: Path, stop_event: threading.Event) -> None:
    """在后台监控部署进度，定期检查远程脚本状态并显示进度信息"""
    
    check_interval = 30# 每30秒检查一次
    last_status = ""
    check_count = 0
    
    ssh_executable = shutil.which("ssh") or "ssh"
    
    while not stop_event.is_set():
        try:
            check_count += 1
            # 检查部署脚本是否还在运行
            check_cmd = [
                ssh_executable,
                "-i", str(key_path),
                "-o", "BatchMode=yes",
                "-o", "ConnectTimeout=5",
                "-o", "StrictHostKeyChecking=no",
                "-o", "ServerAliveInterval=10",
                f"root@{ip}",
                "ps aux | grep -E '[b]ash.*privatetunnel-wireguard|[a]pt-get.*wireguard' | head -3 || echo '脚本未运行'"
            ]
            
            result = subprocess.run(
                check_cmd,
                capture_output=True,
                text=True,
                timeout=8,
                encoding='utf-8',
                errors='replace'
            )
            
            if result.returncode == 0:
                output = result.stdout.strip()
                if output and "脚本未运行" not in output:
                    # 提取关键信息
                    lines = output.split('\n')
                    status_lines = []
                    for line in lines[:2]:  # 只显示前2行
                        if 'apt-get' in line or 'apt' in line:
                            status_lines.append(f"  📦 [{check_count * check_interval}秒] 正在安装软件包...")
                        elif 'wireguard' in line.lower() or 'wg' in line.lower():
                            status_lines.append(f"  ⚙️ [{check_count * check_interval}秒] 正在配置 WireGuard...")
                        elif 'bash' in line or 'sh' in line:
                            status_lines.append(f"  🔄 [{check_count * check_interval}秒] 部署脚本运行中...")
                    
                    if status_lines:
                        current_status = "\n".join(status_lines)
                        if current_status != last_status:
                            # 显示状态更新
                            log_info(current_status)
                            last_status = current_status
                else:
                    # 脚本可能已完成，检查WireGuard服务
                    wg_check = subprocess.run(
                        [
                            ssh_executable,
                            "-i", str(key_path),
                            "-o", "BatchMode=yes",
                            "-o", "ConnectTimeout=5",
                            "-o", "StrictHostKeyChecking=no",
                            "-o", "ServerAliveInterval=10",
                            f"root@{ip}",
                            "systemctl is-active wg-quick@wg0 2>/dev/null || echo 'inactive'"
                        ],
                        capture_output=True,
                        text=True,
                        timeout=8,
                        encoding='utf-8',
                        errors='replace'
                    )
                    if wg_check.returncode == 0:
                        wg_status = wg_check.stdout.strip()
                        if wg_status == "active":
                            log_success("  ✅ WireGuard 服务已启动")
                            break
        except Exception as exc:
            # 监控过程中的错误不影响主流程，但可以记录
            if check_count % 6 == 0:  # 每60秒才显示一次错误，避免刷屏
                pass  # 静默处理，不显示错误
        finally:
            # 等待下一次检查
            if not stop_event.wait(check_interval):
                continue
            break


def _ssh_run(command: str, *, timeout: int = 900, description: str | None = None, max_retries: int = 1) -> SSHResult:
    """Execute ``command`` on the remote host via OpenSSH with Paramiko fallback.
    
    Args:
        command: Command to execute
        timeout: Timeout for each attempt
        description: Description for error messages
        max_retries: Maximum number of retries (default: 1, meaning no retry)
    """

    ctx = _require_ssh_context()
    ssh_executable = shutil.which("ssh")
    
    # 检查是否有SSH代理配置
    ssh_proxy = os.environ.get("SSH_PROXY", "").strip()
    proxy_command = None
    if ssh_proxy:
        # 支持格式：user@host:port 或 host:port (SOCKS代理)
        if "@" in ssh_proxy:
            proxy_command = f"ssh -W %h:%p {ssh_proxy}"
        else:
            # SOCKS代理，需要nc命令
            proxy_command = f"nc -X 5 -x {ssh_proxy} %h %p"
    
    ssh_cmd = [
        ssh_executable or "ssh",
        "-i",
        str(ctx.key_path),
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "ServerAliveInterval=30",
        "-o",
        "ServerAliveCountMax=10",
        "-o",
        "ConnectTimeout=60",  # 从30秒增加到60秒，适应不稳定网络
    ]
    
    # 如果有代理，添加ProxyCommand
    if proxy_command:
        ssh_cmd.extend(["-o", f"ProxyCommand={proxy_command}"])
        log_info(f"→ 使用SSH代理：{ssh_proxy}")
    
    ssh_cmd.extend([
        f"root@{ctx.hostname}",
        command,
    ])

    last_error = None
    for attempt in range(1, max_retries + 1):
        if ssh_executable:
            logwrite(f"$ {' '.join(ssh_cmd)}" + (f" (尝试 {attempt}/{max_retries})" if max_retries > 1 else ""))
            try:
                completed = subprocess.run(
                    ssh_cmd,
                    capture_output=True,
                    **_SUBPROCESS_TEXT_KWARGS,
                    timeout=timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                last_error = DeploymentError(f"远端命令超时：{description or command}")
                if attempt < max_retries:
                    log_warning(f"⚠️ SSH命令超时（尝试 {attempt}/{max_retries}），5秒后重试…")
                    time.sleep(5)
                    continue
                raise last_error
            except OSError as exc:
                last_error = DeploymentError(f"调用 OpenSSH 失败：{exc}")
                if attempt < max_retries:
                    log_warning(f"⚠️ SSH连接失败（尝试 {attempt}/{max_retries}），5秒后重试…")
                    time.sleep(5)
                    continue
                log_warning(f"⚠️ 调用 OpenSSH 失败：{exc}，将尝试 Paramiko 回退。")
            else:
                _log_remote_output("[stdout] ", completed.stdout)
                _log_remote_output("[stderr] ", completed.stderr)
                if completed.returncode != 0:
                    details = completed.stderr.strip() or completed.stdout.strip() or f"退出码 {completed.returncode}"
                    last_error = DeploymentError(
                        f"远端命令失败（{description or command}）：{details}"
                    )
                    if attempt < max_retries:
                        log_warning(f"⚠️ SSH命令失败（尝试 {attempt}/{max_retries}），5秒后重试…")
                        time.sleep(5)
                        continue
                    raise last_error
                return SSHResult(
                    returncode=completed.returncode,
                    stdout=completed.stdout,
                    stderr=completed.stderr,
                    backend="openssh",
                )
    
    # 如果所有重试都失败，尝试Paramiko回退
    if last_error:
        log_warning(f"⚠️ OpenSSH 所有重试均失败，尝试 Paramiko 回退…")

    # Paramiko回退（也支持重试）
    last_paramiko_error = None
    for attempt in range(1, max_retries + 1):
        try:
            client = _ensure_paramiko_client()
            logwrite(f"(paramiko) $ {command}" + (f" (尝试 {attempt}/{max_retries})" if max_retries > 1 else ""))
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            break
        except Exception as exc:  # noqa: BLE001
            last_paramiko_error = exc
            if attempt < max_retries:
                log_warning(f"⚠️ Paramiko 连接失败（尝试 {attempt}/{max_retries}），5秒后重试…")
                _close_paramiko_client()  # 关闭旧连接
                time.sleep(5)
                continue
            raise DeploymentError(f"Paramiko 执行命令失败：{exc}") from exc

    try:
        exit_code, stdout_data, stderr_data = _stream_command_output(stdout, stderr, show_output=False)
    finally:
        try:
            stdin.close()
        except Exception:  # noqa: BLE001
            pass

    _log_remote_output("[stdout] ", stdout_data)
    _log_remote_output("[stderr] ", stderr_data)
    if exit_code != 0:
        details = stderr_data.strip() or stdout_data.strip() or f"退出码 {exit_code}"
        raise DeploymentError(f"远端命令失败（{description or command}）：{details}")

    return SSHResult(returncode=exit_code, stdout=stdout_data, stderr=stderr_data, backend="paramiko")


def _download_with_scp(remote_path: str, local_path: Path, *, timeout: int = 300) -> bool:
    """Download ``remote_path`` via ``scp`` if available."""

    ctx = _require_ssh_context()
    scp_executable = shutil.which("scp")
    if scp_executable is None:
        log_warning("⚠️ 未检测到 scp，可使用 Paramiko SFTP 回退。")
        return False

    local_path.parent.mkdir(parents=True, exist_ok=True)
    
    # 检查是否有SSH代理配置（与_ssh_run保持一致）
    ssh_proxy = os.environ.get("SSH_PROXY", "").strip()
    proxy_command = None
    if ssh_proxy:
        if "@" in ssh_proxy:
            proxy_command = f"ssh -W %h:%p {ssh_proxy}"
        else:
            proxy_command = f"nc -X 5 -x {ssh_proxy} %h %p"
    
    scp_cmd = [
        scp_executable,
        "-i",
        str(ctx.key_path),
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "ConnectTimeout=60",  # 增加连接超时时间
    ]
    
    # 如果有代理，添加ProxyCommand
    if proxy_command:
        scp_cmd.extend(["-o", f"ProxyCommand={proxy_command}"])
    
    scp_cmd.extend([
        f"root@{ctx.hostname}:{remote_path}",
        str(local_path),
    ])
    logwrite(f"$ {' '.join(scp_cmd)}")
    try:
        result = subprocess.run(
            scp_cmd,
            capture_output=True,
            **_SUBPROCESS_TEXT_KWARGS,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        log_warning(f"⚠️ scp 传输超时：{remote_path}")
        return False
    except OSError as exc:
        log_warning(f"⚠️ 无法执行 scp：{exc}")
        return False

    _log_remote_output("[scp stdout] ", result.stdout)
    _log_remote_output("[scp stderr] ", result.stderr)
    if result.returncode != 0:
        log_warning(f"⚠️ scp 返回码 {result.returncode}：{remote_path}")
        return False
    return True


def _download_with_paramiko(remote_path: str, local_path: Path) -> None:
    """Download ``remote_path`` using Paramiko SFTP."""

    client = _ensure_paramiko_client()
    local_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with client.open_sftp() as sftp:
            sftp.get(remote_path, str(local_path))
    except Exception as exc:  # noqa: BLE001
        raise DeploymentError(f"SFTP 下载 {remote_path} 失败：{exc}") from exc


def _download_artifact(remote_path: str, local_path: Path) -> None:
    """Download ``remote_path`` to ``local_path`` with scp fallback to SFTP.

    Raises ``DeploymentError`` when both transports fail.
    """

    if _download_with_scp(remote_path, local_path):
        return

    log_warning(f"⚠️ scp 下载失败，改用 Paramiko SFTP：{remote_path}")
    try:
        _download_with_paramiko(remote_path, local_path)
    except DeploymentError as exc:
        raise DeploymentError(
            f"下载远端文件失败（{remote_path} → {local_path}）：scp 与 SFTP 均失败。详情：{exc}"
        ) from exc


def _ensure_remote_artifact(remote_path: str, description: str) -> None:
    """Ensure ``remote_path`` exists and is non-empty on the server."""

    check_cmd = f"test -s {shlex.quote(remote_path)} && echo OK || echo MISSING"
    result = _ssh_run(
        f"bash -lc {shlex.quote(check_cmd)}",
        timeout=60,
        description=f"校验远端文件 {remote_path}",
        max_retries=3,  # 增加重试次数，文件校验很重要
    )
    if "OK" not in result.stdout:
        raise DeploymentError(
            f"远端未生成{description}（{remote_path}），请查看部署日志与 /etc/wireguard/clients。"
        )


def deploy_wireguard_remote_script(
    listen_port: int,
    desktop_ip: str,
    iphone_ip: str,
    server_ip: str,
    dns_servers: str,
    allowed_ips: str,
    desktop_mtu: str,
    keepalive: str,
    enable_v2ray: bool = False,
    v2ray_port: int = 443,
    v2ray_uuid: str | None = None,
) -> str:
    """Return the shell script that configures WireGuard end-to-end on the server.
    
    Args:
        listen_port: WireGuard 监听端口
        desktop_ip: 桌面客户端 IP 地址
        iphone_ip: iPhone 客户端 IP 地址
        server_ip: 服务器 IP 地址
        dns_servers: DNS 服务器地址
        allowed_ips: 允许的 IP 地址范围
        desktop_mtu: 桌面客户端 MTU
        keepalive: Keepalive 间隔
        enable_v2ray: 是否启用 V2Ray 流量伪装
        v2ray_port: V2Ray 监听端口（默认 443）
        v2ray_uuid: V2Ray UUID（如果为 None 则在脚本中生成）
    """

    return textwrap.dedent(
        """
        #!/usr/bin/env bash
        set -euo pipefail

        log()  {{ printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }}
        warn() {{ printf '[%s] ⚠️ %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }}
        err()  {{ printf '[%s] ❌ %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }}

        export DEBIAN_FRONTEND=noninteractive
        # 跳过NVIDIA驱动的交互式安装，避免阻塞脚本执行
        export NVIDIA_INSTALLER_OPTIONS="--no-questions --accept-license --no-backup"
        export NVIDIA_DRIVER_SKIP_INSTALL=1
        # 禁用NVIDIA驱动的自动安装触发器
        export NVIDIA_AUTO_INSTALL=no

        WG_PORT=${{WG_PORT:-{listen_port}}}
        WG_DIR=/etc/wireguard
        SERVER_CONF="$WG_DIR/wg0.conf"
        SERVER_PRIV="$WG_DIR/server.private"
        SERVER_PUB_FILE="$WG_DIR/server.public"
        CLIENT_BASE="$WG_DIR/clients"
        DESKTOP_DIR="$CLIENT_BASE/desktop"
        IPHONE_DIR="$CLIENT_BASE/iphone"
        DESKTOP_IP="${{PT_DESKTOP_IP:-{desktop_ip}}}"
        IPHONE_IP="${{PT_IPHONE_IP:-{iphone_ip}}}"
        DNS_SERVERS="${{PT_DNS:-{dns_servers}}}"
        ALLOWED_IPS="${{PT_ALLOWED_IPS:-{allowed_ips}}}"
        DESKTOP_MTU="${{PT_CLIENT_MTU:-{desktop_mtu}}}"
        KEEPALIVE="${{PT_KEEPALIVE:-{keepalive}}}"
        SERVER_FALLBACK_IP="$(ip -o -4 addr show dev \"$(ip -o -4 route show to default | awk '{{print $5}}' | head -n1)\" | awk '{{print $4}}' | cut -d/ -f1 | head -n1)"
        
        # V2Ray 配置变量
        ENABLE_V2RAY="${{PT_ENABLE_V2RAY:-{enable_v2ray}}}"
        V2RAY_PORT="${{PT_V2RAY_PORT:-{v2ray_port}}}"
        V2RAY_UUID="${{PT_V2RAY_UUID:-{v2ray_uuid}}}"
        V2RAY_DIR=/usr/local/etc/v2ray
        V2RAY_CONFIG="$V2RAY_DIR/config.json"

        log "安装 WireGuard 组件"
        
        # 彻底禁用NVIDIA驱动自动安装（必须在apt操作之前）
        log "彻底禁用NVIDIA驱动自动安装"
        # 标记所有NVIDIA相关包为hold，防止自动安装或升级
        for pkg in $(dpkg -l | grep -E "^ii.*nvidia" | awk '{{print $2}}' 2>/dev/null); do
          apt-mark hold "$pkg" 2>/dev/null || true
        done
        # 禁用NVIDIA驱动的post-install脚本
        if [ -f /usr/lib/nvidia/post-install ]; then
          chmod -x /usr/lib/nvidia/post-install || true
          mv /usr/lib/nvidia/post-install /usr/lib/nvidia/post-install.disabled 2>/dev/null || true
        fi
        # 设置环境变量彻底跳过NVIDIA驱动安装
        export NVIDIA_INSTALLER_OPTIONS="--no-questions --accept-license --no-backup --skip-depmod --no-nvidia-modprobe"
        export NVIDIA_DRIVER_SKIP_INSTALL=1
        export NVIDIA_AUTO_INSTALL=no
        export DEBIAN_FRONTEND=noninteractive
        
        # 等待dpkg锁释放（如果有其他apt操作正在进行）
        wait_for_dpkg_lock() {{
          local max_wait=300  # 最长等待5分钟
          local waited=0
          local interval=5
          
          while [ $waited -lt $max_wait ]; do
            # 检查锁文件是否被占用
            if ! lsof /var/lib/dpkg/lock-frontend >/dev/null 2>&1 && \
               ! lsof /var/lib/dpkg/lock >/dev/null 2>&1; then
              # 检查是否有apt/dpkg进程在运行
              if ! pgrep -x apt-get >/dev/null 2>&1 && ! pgrep -x dpkg >/dev/null 2>&1; then
                # 锁已释放且无进程运行
                return 0
              fi
            fi
            
            # 检查是否有apt/dpkg进程在运行
            local apt_pid=$(pgrep -x apt-get 2>/dev/null | head -1)
            if [ -n "$apt_pid" ]; then
              log "检测到其他apt-get进程（PID: $apt_pid）正在运行，等待其完成…（已等待 $waited 秒）"
            fi
            
            sleep $interval
            waited=$((waited + interval))
          done
          
          warn "等待dpkg锁释放超时（$max_wait 秒），继续尝试安装…"
          return 1
        }}
        
        wait_for_dpkg_lock || true

        apt_retry() {{
          local desc="$1"
          shift
          local cmd=("$@")

          for i in {{1..10}}; do
            log "执行 apt 操作（第 ${{i}} 次）：${{desc}}"
            if "${{cmd[@]}}"; then
              log "apt 操作成功：${{desc}}"
              return 0
            fi

            warn "apt 命令失败，可能是 dpkg 锁或网络问题，等待 10 秒后重试…"
            sleep 10
          done

          err "apt 操作多次重试仍失败：${{desc}}"
          return 1
        }}

        apt_retry "apt-get update" apt-get update -y
        
        apt_retry "安装 wireguard 及相关组件" apt-get install -y --no-install-recommends \
          wireguard wireguard-tools qrencode iptables-persistent netfilter-persistent curl

        # 可选：安装 V2Ray（用于流量伪装）
        if [ "${{ENABLE_V2RAY}}" = "true" ] || [ "${{ENABLE_V2RAY}}" = "1" ]; then
          log "安装 V2Ray 用于流量伪装"
          
          # 检查是否已安装 V2Ray
          if command -v v2ray >/dev/null 2>&1; then
            log "V2Ray 已安装，跳过安装步骤"
          else
            # 使用官方安装脚本
            log "下载 V2Ray 安装脚本"
            if ! curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh -o /tmp/install-v2ray.sh; then
              err "下载 V2Ray 安装脚本失败"
              exit 1
            fi
            
            log "执行 V2Ray 安装"
            bash /tmp/install-v2ray.sh --version latest || {{
              err "V2Ray 安装失败"
              exit 1
            }}
            
            # 清理临时文件
            rm -f /tmp/install-v2ray.sh
            
            log "V2Ray 安装完成"
          fi
          
          # 检查 V2Ray 服务
          if systemctl list-unit-files | grep -q v2ray.service; then
            log "V2Ray systemd 服务已存在"
          else
            warn "V2Ray systemd 服务未找到，可能需要手动配置"
          fi
        else
          log "跳过 V2Ray 安装（未启用）"
        fi

        log "开启 IPv4/IPv6 转发并持久化"
        sysctl -w net.ipv4.ip_forward=1
        sysctl -w net.ipv6.conf.all.forwarding=1
        echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard-forward.conf
        echo 'net.ipv6.conf.all.forwarding=1' > /etc/sysctl.d/99-wireguard-forward6.conf
        
        log "优化网络性能参数（UDP 缓冲区、BBR 拥塞控制、连接跟踪）"
        cat > /etc/sysctl.d/99-wireguard-optimize.conf <<EOF
# WireGuard 网络优化参数
# 增强 UDP 缓冲区配置
net.core.rmem_max = 268435456
net.core.wmem_max = 268435456
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.udp_rmem_min = 131072
net.ipv4.udp_wmem_min = 131072
net.ipv4.udp_mem = 786432 1048576 2097152

# UDP MTU 探测和优化
net.ipv4.udp_mtu_probe = 1
net.ipv4.ip_no_pmtu_disc = 0
net.ipv4.tcp_mtu_probing = 1

# NAT 和连接跟踪优化（如果系统支持）
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_tcp_timeout_established = 86400
net.netfilter.nf_conntrack_udp_timeout = 60
net.netfilter.nf_conntrack_udp_timeout_stream = 180

# 网络接口和路由优化
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# 网络队列和调度优化
net.core.netdev_max_backlog = 5000
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_slow_start_after_idle = 0

# BBR 拥塞控制（已有）
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq

# WireGuard 特定优化
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.ip_local_port_range = 10000 65535
EOF
        sysctl --system || true
        
        # 检查并加载连接跟踪模块（如果支持）
        log "检查连接跟踪模块支持"
        if modprobe -n nf_conntrack >/dev/null 2>&1; then
          log "检测到 nf_conntrack 支持，尝试加载模块"
          modprobe nf_conntrack 2>/dev/null || true
          # 重新应用 sysctl 以确保连接跟踪参数生效
          sysctl -w net.netfilter.nf_conntrack_max=262144 >/dev/null 2>&1 || true
        else
          log "系统不支持 nf_conntrack，跳过连接跟踪优化（不影响 WireGuard 功能）"
        fi

        # 配置 V2Ray（如果启用）
        if [ "${{ENABLE_V2RAY}}" = "true" ] || [ "${{ENABLE_V2RAY}}" = "1" ]; then
          log "配置 V2Ray 服务器"
          
          # 创建 V2Ray 配置目录
          mkdir -p "$V2RAY_DIR" /var/log/v2ray
          chmod 755 "$V2RAY_DIR" /var/log/v2ray
          
          # 生成 UUID（如果未提供）
          if [ -z "$V2RAY_UUID" ]; then
            log "生成 V2Ray UUID"
            V2RAY_UUID=$(cat /proc/sys/kernel/random/uuid)
          fi
          
          # 生成自签名 TLS 证书（用于测试，生产环境建议使用真实证书）
          log "生成 TLS 证书"
          mkdir -p /etc/v2ray
          if [ ! -f /etc/v2ray/cert.pem ] || [ ! -f /etc/v2ray/key.pem ]; then
            if ! command -v openssl >/dev/null 2>&1; then
              log "安装 openssl"
              apt_retry "安装 openssl" apt-get install -y openssl
            fi
            openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
              -keyout /etc/v2ray/key.pem \
              -out /etc/v2ray/cert.pem \
              -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" \
              2>/dev/null || {{
              err "OpenSSL 证书生成失败"
              exit 1
            }}
            chmod 600 /etc/v2ray/key.pem
            chmod 644 /etc/v2ray/cert.pem
            log "TLS 证书已生成"
          else
            log "TLS 证书已存在，跳过生成"
          fi
          
          # 生成 V2Ray 配置（使用 Python 脚本）
          log "生成 V2Ray 配置文件"
          python3 <<PYTHON_EOF
import json
import sys

config = {{
    "log": {{
        "loglevel": "warning",
        "access": "/var/log/v2ray/access.log",
        "error": "/var/log/v2ray/error.log"
    }},
    "inbounds": [{{
        "port": $V2RAY_PORT,
        "protocol": "vmess",
        "settings": {{
            "clients": [{{
                "id": "$V2RAY_UUID",
                "alterId": 0,
                "security": "auto"
            }}],
            "disableInsecureEncryption": True
        }},
        "streamSettings": {{
            "network": "ws",
            "security": "tls",
            "wsSettings": {{
                "path": "/ray",
                "headers": {{}}
            }},
            "tlsSettings": {{
                "certificates": [{{
                    "certificateFile": "/etc/v2ray/cert.pem",
                    "keyFile": "/etc/v2ray/key.pem"
                }}],
                "minVersion": "1.2",
                "maxVersion": "1.3"
            }}
        }}
    }}],
    "outbounds": [{{
        "protocol": "freedom",
        "settings": {{}}
    }}]
}}

with open("$V2RAY_CONFIG", "w") as f:
    json.dump(config, f, indent=2)
PYTHON_EOF
          
          if [ ! -f "$V2RAY_CONFIG" ]; then
            err "V2Ray 配置文件生成失败"
            exit 1
          fi
          
          chmod 600 "$V2RAY_CONFIG"
          log "V2Ray 配置文件已生成: $V2RAY_CONFIG"
          log "V2Ray UUID: $V2RAY_UUID"
          log "V2Ray 端口: $V2RAY_PORT"
          log "V2Ray WebSocket 路径: /ray"
        fi

        WAN_IF=$(ip -o -4 route show to default | awk '{{print $5}}' | head -n1)
        if [ -z "${{WAN_IF:-}}" ]; then
          err "ERROR: Failed to detect WAN interface"
          exit 1
        fi
        log "检测到默认路由接口: $WAN_IF"

        log "刷新并写入 NAT/FORWARD/INPUT 规则"
        iptables -t nat -D POSTROUTING -s {subnet_cidr} -o "$WAN_IF" -j MASQUERADE 2>/dev/null || true
        iptables -t nat -C POSTROUTING -s {subnet_cidr} -o "$WAN_IF" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s {subnet_cidr} -o "$WAN_IF" -j MASQUERADE
        iptables -D FORWARD -i wg0 -o "$WAN_IF" -j ACCEPT 2>/dev/null || true
        iptables -C FORWARD -i wg0 -o "$WAN_IF" -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i wg0 -o "$WAN_IF" -j ACCEPT
        iptables -D FORWARD -i "$WAN_IF" -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
        iptables -C FORWARD -i "$WAN_IF" -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "$WAN_IF" -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
        iptables -D INPUT -p udp --dport "$WG_PORT" -j ACCEPT 2>/dev/null || true
        iptables -C INPUT -p udp --dport "$WG_PORT" -j ACCEPT 2>/dev/null || \
        iptables -I INPUT -p udp --dport "$WG_PORT" -j ACCEPT

        if command -v ufw >/dev/null 2>&1; then
          if ufw status | grep -qi "Status: active"; then
            ufw allow "$WG_PORT"/udp || true
            ufw route allow in on wg0 out on "$WAN_IF" || true
            ufw route allow in on "$WAN_IF" out on wg0 || true
            ufw reload || true
          fi
        fi

        netfilter-persistent save || true
        netfilter-persistent reload || true

        umask 077
        mkdir -p "$CLIENT_BASE" "$DESKTOP_DIR" "$IPHONE_DIR"
        chmod 700 "$CLIENT_BASE" "$DESKTOP_DIR" "$IPHONE_DIR"

        if [ ! -f "$SERVER_PRIV" ]; then
          log "生成服务器密钥对"
          wg genkey | tee "$SERVER_PRIV" | wg pubkey > "$SERVER_PUB_FILE"
        fi
        SERVER_PRIVATE=$(cat "$SERVER_PRIV")

        cat >"$SERVER_CONF" <<CFG
[Interface]
Address = {server_address}
ListenPort = $WG_PORT
PrivateKey = $SERVER_PRIVATE
SaveConfig = true
CFG
        chmod 600 "$SERVER_CONF"

        systemctl enable wg-quick@wg0
        systemctl restart wg-quick@wg0

        sleep 1

        CURRENT_PORT="$(wg show wg0 listen-port 2>/dev/null | tr -d '[:space:]' || true)"
        if [ -z "$CURRENT_PORT" ] || [ "$CURRENT_PORT" = "0" ]; then
          warn "未检测到 WireGuard 监听端口，尝试设置为 $WG_PORT…"
          if ! output=$(wg set wg0 listen-port "$WG_PORT" 2>&1); then
            warn "wg set 调整监听端口失败：$output"
          fi
          sleep 1
          CURRENT_PORT="$(wg show wg0 listen-port 2>/dev/null | tr -d '[:space:]' || true)"
        fi

        if [ "$CURRENT_PORT" != "$WG_PORT" ]; then
          warn "WireGuard 当前监听端口为 $CURRENT_PORT，尝试使用 wg setconf 强制写入 $WG_PORT…"
          TMP_CFG="$(mktemp)"
          cat >"$TMP_CFG" <<FORCE
[Interface]
PrivateKey = $SERVER_PRIVATE
ListenPort = $WG_PORT
FORCE
          if ! output=$(wg setconf wg0 "$TMP_CFG" 2>&1); then
            warn "wg setconf 强制监听端口失败：$output"
          fi
          rm -f "$TMP_CFG"
          sleep 1
          CURRENT_PORT="$(wg show wg0 listen-port 2>/dev/null | tr -d '[:space:]' || true)"
        fi

        if [ "$CURRENT_PORT" != "$WG_PORT" ]; then
          in_use_msg=""
          if ss -lun 2>/dev/null | grep -q ":$WG_PORT"; then
            in_use_msg=" (检测到其他进程占用 $WG_PORT/udp)"
          fi
          err "ERROR: WireGuard 实际监听端口 ($CURRENT_PORT) 与期望值 ($WG_PORT) 不符$in_use_msg"
          wg show wg0 || true
          ss -lun || true
          systemctl status wg-quick@wg0 --no-pager -l || true
          exit 1
        fi

        if ss -lun 2>/dev/null | grep -q ":$WG_PORT"; then
          log "确认 UDP $WG_PORT 已监听"
        else
          warn "ss 未检测到 UDP $WG_PORT 监听，继续后续步骤 (wg show 正常)"
        fi

        SERVER_PUBLIC_KEY=$(wg show wg0 public-key)
        SERVER_ENDPOINT_IP=$(curl -4 -s ifconfig.me || true)
        if [ -z "$SERVER_ENDPOINT_IP" ]; then
          SERVER_ENDPOINT_IP="$SERVER_FALLBACK_IP"
        fi
        ENDPOINT="${{SERVER_ENDPOINT_IP}}:${{WG_PORT}}"

        ensure_client_keys() {{
          local name="$1"
          local dir="$2"
          local priv_file="$dir/${{name}}_private.key"
          local pub_file="$dir/${{name}}_public.key"
          if [ ! -f "$priv_file" ]; then
            wg genkey | tee "$priv_file" | wg pubkey > "$pub_file"
          else
            cat "$priv_file" | wg pubkey > "$pub_file"
          fi
          chmod 600 "$priv_file" "$pub_file"
        }}

        ensure_client_keys "desktop" "$DESKTOP_DIR"
        ensure_client_keys "iphone" "$IPHONE_DIR"

        DESKTOP_PRIV=$(cat "$DESKTOP_DIR/desktop_private.key")
        DESKTOP_PUB=$(cat "$DESKTOP_DIR/desktop_public.key")
        cat >"$DESKTOP_DIR/desktop.conf" <<CFG
[Interface]
PrivateKey = $DESKTOP_PRIV
Address = $DESKTOP_IP
DNS = $DNS_SERVERS
MTU = $DESKTOP_MTU

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
AllowedIPs = $ALLOWED_IPS
Endpoint = $ENDPOINT
PersistentKeepalive = $KEEPALIVE
CFG
        chmod 600 "$DESKTOP_DIR/desktop.conf"

        IPHONE_PRIV=$(cat "$IPHONE_DIR/iphone_private.key")
        IPHONE_PUB=$(cat "$IPHONE_DIR/iphone_public.key")
        cat >"$IPHONE_DIR/iphone.conf" <<CFG
[Interface]
PrivateKey = $IPHONE_PRIV
Address = $IPHONE_IP
DNS = $DNS_SERVERS

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
AllowedIPs = $ALLOWED_IPS
Endpoint = $ENDPOINT
PersistentKeepalive = $KEEPALIVE
CFG
        chmod 600 "$IPHONE_DIR/iphone.conf"

        # 生成 V2Ray 客户端配置（如果启用）
        if [ "${{ENABLE_V2RAY}}" = "true" ] || [ "${{ENABLE_V2RAY}}" = "1" ]; then
          log "生成 V2Ray 客户端配置"
          
          # V2Ray 客户端配置目录
          V2RAY_CLIENT_DIR="$CLIENT_BASE/v2ray"
          mkdir -p "$V2RAY_CLIENT_DIR"
          chmod 700 "$V2RAY_CLIENT_DIR"
          
          # 确保 V2RAY_UUID 已生成（在服务器配置阶段应该已生成，但以防万一）
          if [ -z "$V2RAY_UUID" ]; then
            V2RAY_UUID=$(cat /proc/sys/kernel/random/uuid)
          fi
          
          # 生成桌面端 V2Ray 配置
          cat >"$V2RAY_CLIENT_DIR/desktop.json" <<V2RAY_CFG
{{
  "log": {{
    "loglevel": "warning"
  }},
  "inbounds": [{{
    "port": 10808,
    "protocol": "socks",
    "settings": {{
      "auth": "noauth",
      "udp": true
    }},
    "tag": "socks-in"
  }}, {{
    "port": 10809,
    "protocol": "http",
    "settings": {{}},
    "tag": "http-in"
  }}],
  "outbounds": [{{
    "protocol": "vmess",
    "settings": {{
      "vnext": [{{
        "address": "$SERVER_ENDPOINT_IP",
        "port": $V2RAY_PORT,
        "users": [{{
          "id": "$V2RAY_UUID",
          "alterId": 0,
          "security": "auto"
        }}]
      }}]
    }},
    "streamSettings": {{
      "network": "ws",
      "security": "tls",
      "wsSettings": {{
        "path": "/ray"
      }},
      "tlsSettings": {{
        "allowInsecure": true,
        "serverName": "$SERVER_ENDPOINT_IP"
      }}
    }},
    "tag": "proxy"
  }}, {{
    "protocol": "freedom",
    "settings": {{}},
    "tag": "direct"
  }}],
  "routing": {{
    "domainStrategy": "IPIfNonMatch",
    "rules": [{{
      "type": "field",
      "inboundTag": ["socks-in", "http-in"],
      "outboundTag": "proxy"
    }}]
  }}
}}
V2RAY_CFG
          
          # 生成 iPhone 端 V2Ray 配置（简化版）
          cat >"$V2RAY_CLIENT_DIR/iphone.json" <<V2RAY_CFG
{{
  "log": {{
    "loglevel": "warning"
  }},
  "inbounds": [{{
    "port": 10808,
    "protocol": "socks",
    "settings": {{
      "auth": "noauth",
      "udp": true
    }}
  }}],
  "outbounds": [{{
    "protocol": "vmess",
    "settings": {{
      "vnext": [{{
        "address": "$SERVER_ENDPOINT_IP",
        "port": $V2RAY_PORT,
        "users": [{{
          "id": "$V2RAY_UUID",
          "alterId": 0,
          "security": "auto"
        }}]
      }}]
    }},
    "streamSettings": {{
      "network": "ws",
      "security": "tls",
      "wsSettings": {{
        "path": "/ray"
      }},
      "tlsSettings": {{
        "allowInsecure": true,
        "serverName": "$SERVER_ENDPOINT_IP"
      }}
    }}
  }}]
}}
V2RAY_CFG
          
          chmod 600 "$V2RAY_CLIENT_DIR"/*.json 2>/dev/null || true
          
          # 生成 VMess URL（用于客户端快速导入）
          # 格式：vmess://base64(json)
          V2RAY_VMESS_JSON=$(cat <<VMESS_JSON
{{
  "v": "2",
  "ps": "PrivateTunnel-V2Ray",
  "add": "$SERVER_ENDPOINT_IP",
  "port": "$V2RAY_PORT",
  "id": "$V2RAY_UUID",
  "aid": "0",
  "scy": "auto",
  "net": "ws",
  "type": "none",
  "host": "",
  "path": "/ray",
  "tls": "tls",
  "sni": "$SERVER_ENDPOINT_IP"
}}
VMESS_JSON
          )
          
          # Base64 编码（需要 base64 命令）
          if command -v base64 >/dev/null 2>&1; then
            V2RAY_VMESS_URL="vmess://$(echo -n "$V2RAY_VMESS_JSON" | base64 -w 0)"
          else
            # 如果没有 base64 命令，使用 Python
            V2RAY_VMESS_URL=$(python3 <<PYTHON_EOF
import json
import base64
import sys

vmess_data = {{
    "v": "2",
    "ps": "PrivateTunnel-V2Ray",
    "add": "$SERVER_ENDPOINT_IP",
    "port": "$V2RAY_PORT",
    "id": "$V2RAY_UUID",
    "aid": "0",
    "scy": "auto",
    "net": "ws",
    "type": "none",
    "host": "",
    "path": "/ray",
    "tls": "tls",
    "sni": "$SERVER_ENDPOINT_IP"
}}

json_str = json.dumps(vmess_data, separators=(',', ':'))
encoded = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
print(f"vmess://{{encoded}}")
PYTHON_EOF
            )
          fi
          echo "$V2RAY_VMESS_URL" > "$V2RAY_CLIENT_DIR/vmess-url.txt"
          chmod 600 "$V2RAY_CLIENT_DIR/vmess-url.txt"
          
          log "V2Ray 客户端配置已生成："
          log "  桌面：$V2RAY_CLIENT_DIR/desktop.json"
          log "  iPhone：$V2RAY_CLIENT_DIR/iphone.json"
          log "  VMess URL：$V2RAY_CLIENT_DIR/vmess-url.txt"
        fi

        wg set wg0 peer "$DESKTOP_PUB" remove 2>/dev/null || true
        wg set wg0 peer "$DESKTOP_PUB" allowed-ips "$DESKTOP_IP"
        wg set wg0 peer "$IPHONE_PUB" remove 2>/dev/null || true
        wg set wg0 peer "$IPHONE_PUB" allowed-ips "$IPHONE_IP"

        wg-quick save wg0
        systemctl restart wg-quick@wg0

        qrencode -o "$IPHONE_DIR/iphone.png" -s 8 -m 2 <"$IPHONE_DIR/iphone.conf" || true

        missing=0
        for f in "$DESKTOP_DIR/desktop.conf" "$IPHONE_DIR/iphone.conf" "$IPHONE_DIR/iphone.png"; do
          if [ ! -s "$f" ]; then
            err "文件未生成或为空：$f"
            missing=1
          fi
        done
        if [ "$missing" -ne 0 ]; then
          ls -l "$DESKTOP_DIR" "$IPHONE_DIR" || true
          exit 1
        fi

        log "验证配置文件："
        ls -lh "$DESKTOP_DIR" "$IPHONE_DIR" || true

        log "WireGuard 已配置完毕，客户端文件路径："
        log "  桌面：$DESKTOP_DIR/desktop.conf"
        log "  iPhone：$IPHONE_DIR/iphone.conf"
        log "  iPhone二维码：$IPHONE_DIR/iphone.png"

        printf 'SERVER_PUBLIC_KEY=%s\n' "$SERVER_PUBLIC_KEY"
        printf 'DESKTOP_PUBLIC_KEY=%s\n' "$DESKTOP_PUB"
        printf 'IPHONE_PUBLIC_KEY=%s\n' "$IPHONE_PUB"
        printf 'ENDPOINT=%s\n' "$ENDPOINT"
        printf 'WAN_IF=%s\n' "$WAN_IF"
        
        # V2Ray 信息（如果启用）
        if [ "${{ENABLE_V2RAY}}" = "true" ] || [ "${{ENABLE_V2RAY}}" = "1" ]; then
          printf 'V2RAY_ENABLED=true\n'
          printf 'V2RAY_PORT=%s\n' "$V2RAY_PORT"
          printf 'V2RAY_UUID=%s\n' "$V2RAY_UUID"
          printf 'V2RAY_WS_PATH=/ray\n'
          printf 'V2RAY_SERVER_IP=%s\n' "$SERVER_ENDPOINT_IP"
        else
          printf 'V2RAY_ENABLED=false\n'
        fi

        cat <<SUMMARY
──────────────────────────────
[WireGuard 已配置完毕]
服务器：
  公钥：$SERVER_PUBLIC_KEY
  端点：$ENDPOINT
客户端：
  桌面：/etc/wireguard/clients/desktop/desktop.conf
  iPhone：/etc/wireguard/clients/iphone/iphone.conf
  iPhone二维码：/etc/wireguard/clients/iphone/iphone.png
──────────────────────────────
        SUMMARY
        """
    ).format(
        listen_port=listen_port,
        desktop_ip=desktop_ip,
        iphone_ip=iphone_ip,
        server_ip=server_ip,
        dns_servers=dns_servers,
        allowed_ips=allowed_ips,
        desktop_mtu=desktop_mtu,
        keepalive=keepalive,
        enable_v2ray="true" if enable_v2ray else "false",
        v2ray_port=v2ray_port,
        v2ray_uuid=v2ray_uuid or "",
        subnet_cidr=DEFAULT_SUBNET_CIDR,
        server_address=DEFAULT_SERVER_ADDRESS,
    ).strip()

def _wait_for_port_22(ip: str, *, timeout: int = 1200, interval: int = 20) -> bool:
    """Probe TCP/22 on ``ip`` every ``interval`` seconds until success or ``timeout`` seconds elapsed.
    
    Args:
        ip: Target IP address
        timeout: Maximum time to wait in seconds (default: 1200 = 20 minutes)
        interval: Time between attempts in seconds (default: 20)
    """
    start_time = time.time()
    deadline = start_time + timeout
    attempt = 1
    
    while time.time() < deadline:
        elapsed_seconds = int(time.time() - start_time)
        remaining_seconds = int(deadline - time.time())
        log_info(f"  ↻ 第 {attempt} 次检测：连接 {ip}:22 … (已等待 {elapsed_seconds}秒，剩余 {remaining_seconds}秒)")
        try:
            with socket.create_connection((ip, 22), timeout=5):
                log_success("   SSH 端口已开放。")
                return True
        except OSError as exc:
            log_warning(f"⚠️ 连接失败：{exc}")
        
        # 检查是否还有时间继续尝试
        if time.time() + interval >= deadline:
            break
        time.sleep(interval)
        attempt += 1
    
    log_error(f"❌ 在 {timeout} 秒（{timeout // 60} 分钟）内未检测到 SSH 端口开放。")
    return False


def _wait_for_passwordless_ssh(ip: str, key_path: Path, *, timeout: int = 1200, interval: int = 10) -> bool:
    """Attempt ``ssh root@ip true`` until passwordless login succeeds or timeout.
    
    Args:
        ip: Target IP address
        key_path: Path to SSH private key
        timeout: Maximum time to wait in seconds (default: 1200 = 20 minutes)
        interval: Time between attempts in seconds (default: 10)
    """
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

    deadline = time.time() + timeout
    attempt = 1
    last_stdout = ""
    last_stderr = ""
    
    while time.time() < deadline:
        elapsed_seconds = int(time.time() - (deadline - timeout))
        remaining_seconds = int(deadline - time.time())
        log_info(f"  ↻ 第 {attempt} 次免密检测：ssh root@{ip} true (已等待 {elapsed_seconds}秒，剩余 {remaining_seconds}秒)")
        try:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                **_SUBPROCESS_TEXT_KWARGS,
                timeout=45,
            )
        except subprocess.TimeoutExpired as exc:
            last_stdout = (exc.stdout or "").strip()
            last_stderr = (exc.stderr or "").strip()
            log_warning("   ssh 命令在 45 秒内未返回，可能受到网络限制或服务器尚未就绪。")
            if last_stdout:
                log_warning(f"   stdout: {last_stdout}")
            if last_stderr:
                log_warning(f"   stderr: {last_stderr}")
        else:
            # 处理正常返回的结果
            last_stdout = (result.stdout or "").strip()
            last_stderr = (result.stderr or "").strip()
            if result.returncode == 0:
                log_success("   免密 SSH 校验通过。")
                return True
            if last_stdout:
                log_warning(f"   stdout: {last_stdout}")
            if last_stderr:
                log_warning(f"   stderr: {last_stderr}")
        
        # 检查是否还有时间继续尝试
        if time.time() + interval >= deadline:
            break
        time.sleep(interval)
        attempt += 1

    log_error(
        f"❌ 在 {timeout} 秒（{timeout // 60} 分钟）内免密 SSH 校验失败。"
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


def create_vps() -> None:
    """Create a Vultr VPS using environment-driven defaults."""

    from core.tools.vultr_manager import (  # pylint: disable=import-outside-toplevel
        VultrError,
        create_instance,
        destroy_instance,
        list_snapshots,
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

    snapshot_id = ""
    default_mode = "1" if env_snapshot_id else "2"
    mode_prompt = "实例来源 [1=使用快照"
    if env_snapshot_id:
        mode_prompt += f"({env_snapshot_id})"
    mode_prompt += ", 2=全新 Ubuntu 22.04]"
    mode = input(f"{mode_prompt} [{default_mode}]: ").strip() or default_mode

    use_snapshot = mode == "1"
    if use_snapshot:
        snapshots_cache: list[dict[str, Any]] | None = None
        while True:
            if snapshots_cache is None:
                log_info("→ 查询快照列表…")
                try:
                    snapshots_cache = list_snapshots(api_key)
                except VultrError as exc:
                    log_error(f"❌ 获取快照列表失败：{exc}")
                    retry = input("是否重试获取快照列表？[Y/n]: ").strip().lower()
                    if retry in {"", "y", "yes"}:
                        snapshots_cache = None
                        continue
                    log_error("❌ 无法获取快照列表，已中止创建流程。")
                    return
                if not snapshots_cache:
                    log_warning("⚠️ 当前账号没有可用快照。")
                    log_warning("   请在 Vultr 控制台创建快照后重试，或选择全新 Ubuntu 22.04。")
                    return
            log_info("→ 当前账号可用快照：")
            for index, item in enumerate(snapshots_cache, start=1):
                snap_id = item.get("id", "") or "-"
                description = (item.get("description") or "").strip() or "-"
                created = (item.get("date_created") or "").strip() or "-"
                size_val = item.get("size_gigabytes") or item.get("size")
                size_text = f"{size_val} GB" if size_val else "-"
                marker = " (默认)" if snap_id == env_snapshot_id and env_snapshot_id else ""
                log_info(
                    f"   {index}. {snap_id} | {description} | 创建时间: {created} | 大小: {size_text}{marker}"
                )

            prompt_default = env_snapshot_id or "编号/ID"
            snapshot_input = input(
                f"请选择快照 (输入编号或快照ID，?=刷新列表) [{prompt_default}]: "
            ).strip()
            command = snapshot_input.lower()
            if command in {"?", "help", "h", "ls", "list", "show", "刷新", "重新加载"}:
                snapshots_cache = None
                continue
            if not snapshot_input and env_snapshot_id:
                snapshot_id = env_snapshot_id
            elif snapshot_input.isdigit():
                selection = int(snapshot_input)
                if 1 <= selection <= len(snapshots_cache):
                    snapshot_id = snapshots_cache[selection - 1].get("id", "") or ""
                else:
                    log_error("❌ 无效的编号，请重新输入。")
                    continue
            else:
                snapshot_id = snapshot_input

            if not snapshot_id:
                log_error("❌ 请选择有效的快照 ID，或返回重新选择全新系统选项。")
                continue
            if env_snapshot_id and snapshot_id == env_snapshot_id:
                log_info(f"→ 使用环境变量 VULTR_SNAPSHOT_ID={snapshot_id}")
            else:
                log_info(f"→ 使用 snapshot_id={snapshot_id}")
            break
    else:
        if env_snapshot_id:
            log_info("→ 已选择全新 Ubuntu 22.04，将忽略环境变量 VULTR_SNAPSHOT_ID。")

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
        log_info("→ 第一阶段：检测 SSH 端口 22 是否开放（每 20 秒，最长等待 20 分钟）…")
        key_path_default = Path.home() / ".ssh" / "id_ed25519"
        port_ready = _wait_for_port_22(ip, interval=20)
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
    # 解析节点优先级和权重（如果启用多节点）
    use_multi_node = os.environ.get("PT_MULTI_NODE", "").strip().lower() in ("true", "1", "yes")
    node_priority = int(os.environ.get("PT_NODE_PRIORITY", "1"))
    node_weight = int(os.environ.get("PT_NODE_WEIGHT", "100"))

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

    # 如果启用多节点，添加节点配置
    if use_multi_node:
        instance_info["priority"] = node_priority
        instance_info["weight"] = node_weight
        log_info(f"→ 节点优先级：{node_priority}，权重：{node_weight}")

    instance_file = artifacts_dir / "instance.json"
    instance_file.write_text(
        json.dumps(instance_info, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    log_success(f"已写入 {instance_file}")


def inspect_vps_inventory() -> None:
    """Inspect existing Vultr instances and optionally destroy them."""

    from core.tools.vultr_manager import (  # pylint: disable=import-outside-toplevel
        VultrError,
        destroy_instance,
        list_instances,
    )

    log_section("🧾 Step 4: 检查 Vultr 实例")
    _log_selected_platform()

    api_key = os.environ.get("VULTR_API_KEY", "").strip()
    if not api_key:
        log_error("❌ 未检测到环境变量 VULTR_API_KEY。请先设置后重试。")
        return

    log_info("→ 正在查询账户下的实例…")
    try:
        instances = list_instances(api_key)
    except VultrError as exc:
        log_error(f"❌ 查询实例失败：{exc}")
        return

    if not instances:
        log_success("✅ 当前账户没有任何 Vultr 实例。")
        return

    def describe_instance(index: int, instance: dict[str, Any]) -> str:
        instance_id = instance.get("id", "")
        label = instance.get("label") or "-"
        region = instance.get("region")
        if isinstance(region, dict):
            region_code = region.get("code") or region.get("id") or ""
        else:
            region_code = str(region or "")
        main_ip = instance.get("main_ip") or "-"
        status = instance.get("status") or "-"
        power_status = instance.get("power_status") or "-"
        return (
            f"{index}) id={instance_id} | label={label} | region={region_code or '-'} | "
            f"ip={main_ip} | status={status}/{power_status}"
        )

    while True:
        log_info("→ 当前账号存在以下实例：")
        for idx, item in enumerate(instances, start=1):
            log_info(describe_instance(idx, item))

        choice = input("输入序号销毁实例，或直接回车返回主菜单: ").strip().lower()
        if choice in {"", "q", "quit", "exit"}:
            log_info("→ 已退出实例检查，不执行销毁操作。")
            return
        if not choice.isdigit():
            log_error("❌ 无效选择，请输入列表中的序号或直接回车退出。")
            continue

        index = int(choice)
        if index < 1 or index > len(instances):
            log_error("❌ 序号超出范围，请重试。")
            continue

        target = instances[index - 1]
        instance_id = target.get("id", "")
        label = target.get("label") or instance_id or "实例"
        confirm = input(f"确认销毁实例 {label}? (y/N): ").strip().lower()
        if confirm not in {"y", "yes"}:
            log_info("→ 已取消销毁。")
            continue

        if not instance_id:
            log_error("❌ 目标实例缺少 ID，无法执行销毁。")
            continue

        try:
            destroy_instance(api_key, instance_id)
        except VultrError as exc:
            log_error(f"❌ 销毁实例失败：{exc}")
            continue

        log_success(f"✅ 已提交销毁实例 {instance_id}。")
        instances.pop(index - 1)
        if not instances:
            log_success("✅ 当前账户已无其他 Vultr 实例。")
            return


def _log_selected_platform() -> None:
    if SELECTED_PLATFORM:
        label = PLATFORM_CHOICES.get(SELECTED_PLATFORM, SELECTED_PLATFORM)
        log_info(f"→ 当前本机系统：{label}")
    else:
        log_warning("⚠️ 尚未选择本机系统，可通过第 1 步执行环境检查。")


def _update_server_info(data: dict[str, Any]) -> None:
    """更新服务器信息，支持多节点。Update server info, supporting multi-node."""
    artifacts_dir = ARTIFACTS_DIR
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    # 多节点模式：使用 MultiNodeManager
    use_multi_node = os.environ.get("PT_MULTI_NODE", "").strip().lower() in ("true", "1", "yes")

    if use_multi_node:
        from core.tools.multi_node_manager import MultiNodeManager, NodeStatus

        manager = MultiNodeManager()
        instance_id = data.get("id", "")

        if instance_id:
            # 从 instance.json 获取基础信息
            instance_file = artifacts_dir / "instance.json"
            instance_data = {}
            if instance_file.exists():
                try:
                    instance_data = json.loads(instance_file.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    pass

            # 创建或更新节点
            node_id = f"node-{instance_id[:8]}"
            node = manager.add_node_from_instance(
                instance_id=instance_id,
                ip=data.get("ip", instance_data.get("ip", "")),
                region=instance_data.get("region", "unknown"),
                plan=instance_data.get("plan", "unknown"),
                priority=int(data.get("priority", instance_data.get("priority", 1))),
                weight=int(data.get("weight", instance_data.get("weight", 100))),
                node_id=node_id,
            )

            # 更新节点详细信息
            metadata = {
                "wan_interface": data.get("wan_interface"),
                "desktop_config": data.get("desktop_config"),
                "iphone_config": data.get("iphone_config"),
                "v2ray_enabled": data.get("v2ray_enabled", False),
                "v2ray_port": data.get("v2ray_port"),
                "v2ray_uuid": data.get("v2ray_uuid"),
            }

            manager.update_node_info(
                node_id=node_id,
                server_pub=data.get("server_pub"),
                endpoint=data.get("endpoint"),
                metadata=metadata,
            )

            # 设置节点状态为活跃
            manager.update_node_status(node_id, NodeStatus.ACTIVE)

            log_info(f"→ 节点信息已更新到多节点配置：{node_id}")
    else:
        # 单节点模式：保持原有逻辑（向后兼容）
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
            **_SUBPROCESS_TEXT_KWARGS,
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


def manage_nodes() -> None:
    """管理多节点配置。Manage multi-node configuration."""
    from core.tools.multi_node_manager import MultiNodeManager, NodeStatus

    log_section("🔧 多节点管理")

    use_multi_node = os.environ.get("PT_MULTI_NODE", "").strip().lower() in ("true", "1", "yes")
    if not use_multi_node:
        log_warning("⚠️ 多节点模式未启用")
        log_info("→ 提示：设置环境变量 PT_MULTI_NODE=true 启用多节点模式")
        return

    manager = MultiNodeManager()
    nodes = manager.get_all_nodes()

    if not nodes:
        log_info("ℹ️ 当前没有配置任何节点")
        return

    log_info("→ 当前节点列表：")
    for idx, node in enumerate(nodes, 1):
        status_icon = "✅" if node.status == NodeStatus.ACTIVE else "⚠️"
        default_mark = " (默认)" if manager.config and manager.config.default_node_id == node.id else ""
        log_info(f"  {idx}. {status_icon} {node.id} | {node.ip} | {node.region} | "
                f"优先级:{node.priority} 权重:{node.weight} | {node.status.value}{default_mark}")

    log_info("")
    log_info("操作选项：")
    log_info("  1) 设置默认节点")
    log_info("  2) 更新节点状态")
    log_info("  3) 删除节点")
    log_info("  q) 返回")

    choice = input("请选择: ").strip().lower()

    if choice == "1":
        # 设置默认节点
        node_choice = input(f"请选择节点编号 [1-{len(nodes)}]: ").strip()
        try:
            node_idx = int(node_choice)
            if 1 <= node_idx <= len(nodes):
                selected_node = nodes[node_idx - 1]
                if manager.config:
                    manager.config.set_default_node(selected_node.id)
                    manager.save()
                    log_success(f"✅ 已设置 {selected_node.id} 为默认节点")
                else:
                    log_error("❌ 配置管理器未初始化")
            else:
                log_error("❌ 无效的节点编号")
        except ValueError:
            log_error("❌ 无效输入")

    elif choice == "2":
        # 更新节点状态
        node_choice = input(f"请选择节点编号 [1-{len(nodes)}]: ").strip()
        try:
            node_idx = int(node_choice)
            if 1 <= node_idx <= len(nodes):
                selected_node = nodes[node_idx - 1]
                log_info("可用状态：")
                log_info("  1) active - 活跃")
                log_info("  2) inactive - 非活跃")
                log_info("  3) failing - 故障")
                log_info("  4) maintenance - 维护中")
                status_choice = input("请选择状态 [1-4]: ").strip()
                status_map = {
                    "1": NodeStatus.ACTIVE,
                    "2": NodeStatus.INACTIVE,
                    "3": NodeStatus.FAILING,
                    "4": NodeStatus.MAINTENANCE,
                }
                if status_choice in status_map:
                    new_status = status_map[status_choice]
                    manager.update_node_status(selected_node.id, new_status)
                    log_success(f"✅ 已更新节点 {selected_node.id} 状态为 {new_status.value}")
                else:
                    log_error("❌ 无效的状态选择")
            else:
                log_error("❌ 无效的节点编号")
        except ValueError:
            log_error("❌ 无效输入")

    elif choice == "3":
        # 删除节点
        node_choice = input(f"请选择要删除的节点编号 [1-{len(nodes)}]: ").strip()
        try:
            node_idx = int(node_choice)
            if 1 <= node_idx <= len(nodes):
                selected_node = nodes[node_idx - 1]
                confirm = input(f"确认删除节点 {selected_node.id} ({selected_node.ip})? [y/N]: ").strip().lower()
                if confirm in ("y", "yes"):
                    if manager.config:
                        if manager.config.remove_node(selected_node.id):
                            manager.save()
                            log_success(f"✅ 已删除节点 {selected_node.id}")
                        else:
                            log_error("❌ 删除节点失败")
                    else:
                        log_error("❌ 配置管理器未初始化")
                else:
                    log_info("已取消删除")
            else:
                log_error("❌ 无效的节点编号")
        except ValueError:
            log_error("❌ 无效输入")

    elif choice == "q":
        return


def check_nodes_health() -> None:
    """检查所有节点健康状态。Check all nodes health."""
    from core.tools.multi_node_manager import MultiNodeManager, NodeStatus
    from core.tools.node_health_checker import NodeHealthChecker

    log_section("🏥 节点健康检查")

    use_multi_node = os.environ.get("PT_MULTI_NODE", "").strip().lower() in ("true", "1", "yes")
    if not use_multi_node:
        log_warning("⚠️ 多节点模式未启用")
        log_info("→ 提示：设置环境变量 PT_MULTI_NODE=true 启用多节点模式")
        return

    manager = MultiNodeManager()
    nodes = manager.get_all_nodes()

    if not nodes:
        log_info("ℹ️ 当前没有配置任何节点")
        return

    log_info(f"→ 开始检查 {len(nodes)} 个节点...")

    # 获取 WireGuard 端口
    from core.port_config import resolve_listen_port
    wg_port, _ = resolve_listen_port()

    checker = NodeHealthChecker()
    results = manager.check_all_nodes(wireguard_port=wg_port)

    log_info("")
    log_info("健康检查结果：")
    log_info("=" * 60)

    for node in nodes:
        metrics = results.get(node.id)
        if metrics:
            status_icon = "✅" if metrics.overall_healthy else "❌"
            latency_str = f"{metrics.latency_ms:.2f}ms" if metrics.latency_ms else "N/A"

            log_info(f"{status_icon} {node.id} ({node.ip})")
            log_info(f"   延迟：{latency_str}")
            log_info(f"   ICMP: {'✅' if metrics.icmp_success else '❌'} | "
                    f"TCP: {'✅' if metrics.tcp_success else '❌'} | "
                    f"HTTPS: {'✅' if metrics.https_success else '❌'} | "
                    f"DNS: {'✅' if metrics.dns_success else '❌'} | "
                    f"WireGuard: {'✅' if metrics.wireguard_handshake else '❌'}")
            log_info(f"   状态：{node.status.value}")
            log_info("")

    # 检查是否需要故障转移
    default_node = manager.get_default_node()
    if default_node:
        default_metrics = results.get(default_node.id)
        if default_metrics and not default_metrics.overall_healthy:
            log_warning(f"⚠️ 默认节点 {default_node.id} 不健康")
            backup = manager.switch_to_backup_node(default_node.id, wg_port)
            if backup:
                log_success(f"✅ 已自动切换到备用节点：{backup.id} ({backup.ip})")
            else:
                log_error("❌ 未找到可用的备用节点")
    else:
        log_error("❌ 无效选择")


def smart_node_selection() -> None:
    """智能节点选择。Smart node selection."""
    from core.tools.multi_node_manager import MultiNodeManager, NodeStatus
    from core.tools.smart_routing import SmartRouter, RoutingStrategy, NodeScore

    log_section("🧠 智能节点选择")

    use_multi_node = os.environ.get("PT_MULTI_NODE", "").strip().lower() in ("true", "1", "yes")
    if not use_multi_node:
        log_warning("⚠️ 多节点模式未启用")
        log_info("→ 提示：设置环境变量 PT_MULTI_NODE=true 启用多节点模式")
        return

    manager = MultiNodeManager()
    nodes = manager.get_all_nodes()

    if not nodes:
        log_info("ℹ️ 当前没有配置任何节点")
        return

    # 选择选路策略
    log_info("请选择选路策略：")
    log_info("  1) 延迟优先（latency_first）- 选择延迟最低的节点")
    log_info("  2) 权重优先（weight_first）- 选择权重最高的节点")
    log_info("  3) 优先级优先（priority_first）- 选择优先级最高的节点")
    log_info("  4) 平衡模式（balanced）- 综合考虑多个因素")
    log_info("  5) 混合模式（hybrid）- 智能混合策略")

    strategy_map = {
        "1": RoutingStrategy.LATENCY_FIRST,
        "2": RoutingStrategy.WEIGHT_FIRST,
        "3": RoutingStrategy.PRIORITY_FIRST,
        "4": RoutingStrategy.BALANCED,
        "5": RoutingStrategy.HYBRID,
    }

    choice = input("请选择策略 [1-5，默认 4]: ").strip() or "4"
    strategy = strategy_map.get(choice, RoutingStrategy.BALANCED)

    log_info(f"→ 使用策略：{strategy.value}")

    # 获取 WireGuard 端口
    from core.port_config import resolve_listen_port

    wg_port, _ = resolve_listen_port()

    # 执行智能选路
    log_info("→ 正在分析节点...")
    router = SmartRouter(strategy=strategy)
    best_node, best_score, all_scores = router.select_best_node(nodes, wg_port)

    if not best_node:
        log_error("❌ 未找到可用节点")
        return

    # 显示结果
    log_info("")
    log_info("=" * 60)
    log_info("智能选路结果：")
    log_info("=" * 60)
    log_info(f"✅ 推荐节点：{best_node.id} ({best_node.ip})")
    log_info(f"   区域：{best_node.region}")
    log_info(f"   优先级：{best_node.priority}，权重：{best_node.weight}")
    if best_score:
        log_info(f"   综合评分：{best_score.overall_score:.2f}/100")
        log_info(f"   延迟评分：{best_score.latency_score:.2f}/100")
        log_info(f"   权重评分：{best_score.weight_score:.2f}/100")
        log_info(f"   优先级评分：{best_score.priority_score:.2f}/100")
        log_info(f"   健康评分：{best_score.health_score:.2f}/100")

    log_info("")
    log_info("所有节点评分：")
    for node in sorted(
        nodes,
        key=lambda n: all_scores.get(n.id, NodeScore(n.id)).overall_score,
        reverse=True,
    ):
        score = all_scores.get(node.id)
        if score:
            log_info(
                f"  {node.id}: {score.overall_score:.2f}分 "
                f"(延迟:{score.latency_score:.1f} 权重:{score.weight_score:.1f} "
                f"优先级:{score.priority_score:.1f} 健康:{score.health_score:.1f})"
            )

    # 询问是否设置为默认节点
    confirm = input(f"\n是否将 {best_node.id} 设置为默认节点？[y/N]: ").strip().lower()
    if confirm in ("y", "yes"):
        manager.config.set_default_node(best_node.id)
        manager.save()
        log_success(f"✅ 已设置 {best_node.id} 为默认节点")


def launch_gui() -> None:
    """打开可视化界面以操作各项功能。"""

    try:
        import tkinter as tk
        from tkinter import messagebox, scrolledtext, simpledialog
    except Exception as exc:  # noqa: BLE001 - 捕获所有异常以保证 CLI 可继续执行
        log_error(f"❌ 无法加载图形界面组件：{exc}")
        return

    import builtins
    import contextlib
    import io

    window = tk.Tk()
    window.title("PrivateTunnel 桌面助手 - 图形界面")

    text_area = scrolledtext.ScrolledText(window, wrap=tk.WORD, width=100, height=30, state=tk.DISABLED)
    text_area.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

    button_frame = tk.Frame(window)
    button_frame.pack(fill=tk.X, padx=12, pady=(0, 12))

    def append_output(message: str) -> None:
        text_area.configure(state=tk.NORMAL)
        text_area.insert(tk.END, message)
        text_area.see(tk.END)
        text_area.configure(state=tk.DISABLED)

    @contextlib.contextmanager
    def patched_streams() -> Any:
        buffer = io.StringIO()
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        sys.stdout = buffer
        sys.stderr = buffer
        try:
            yield buffer
        finally:
            sys.stdout = original_stdout
            sys.stderr = original_stderr

    @contextlib.contextmanager
    def patched_input() -> Any:
        original_input = builtins.input

        def gui_input(prompt: str = "") -> str:
            response = simpledialog.askstring("输入", prompt, parent=window)
            if response is None:
                return ""
            return response

        builtins.input = gui_input
        try:
            yield
        finally:
            builtins.input = original_input

    def run_action(action: Any, description: str) -> None:
        append_output(f"\n=== {description} ===\n")
        window.update_idletasks()
        try:
            with patched_streams() as buffer:
                with patched_input():
                    action()
        except SystemExit as exc:
            append_output(f"程序退出：{exc}\n")
        except Exception as exc:  # noqa: BLE001
            append_output(f"❌ {description} 失败：{exc}\n")
            messagebox.showerror("错误", f"{description} 失败：{exc}")
        else:
            output = buffer.getvalue()
            if output:
                append_output(output)
            messagebox.showinfo("完成", f"{description} 已完成。")

    actions = [
        ("检查本机环境（Windows/macOS）", run_environment_check, "检查本机环境"),
        ("创建 VPS（Vultr）", create_vps, "创建 VPS"),
        ("准备本机接入 VPS 网络", prepare_wireguard_access, "准备本机接入 VPS 网络"),
        ("检查账户中的 Vultr 实例", inspect_vps_inventory, "检查账户中的 Vultr 实例"),
    ]

    for label, func, description in actions:
        button = tk.Button(button_frame, text=label, command=lambda f=func, d=description: run_action(f, d))
        button.pack(fill=tk.X, pady=3)

    tk.Button(button_frame, text="关闭", command=window.destroy).pack(fill=tk.X, pady=(12, 0))

    window.mainloop()


def _load_instance_for_diagnostics() -> tuple[str, Path] | None:
    """Return the Vultr instance IP recorded on disk, if any."""

    inst_path = ARTIFACTS_DIR / "instance.json"
    if not inst_path.exists():
        return None

    try:
        data = json.loads(inst_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:  # noqa: BLE001 - diagnostics best-effort
        log_warning(f"⚠️ 无法读取 {inst_path}：{exc}，跳过网络排查。")
        return None

    ip = str(data.get("ip", "")).strip()
    if not ip:
        log_warning(f"⚠️ {inst_path} 缺少 IP 字段，跳过网络排查。")
        return None

    return ip, inst_path


def _diagnostic_ping(ip: str) -> bool:
    """Run a single ping against ``ip`` and report the outcome."""

    log_info(f"→ 排查步骤：ping {ip}")
    ping_cmd = ["ping", "-n" if os.name == "nt" else "-c", "1", ip]
    try:
        # Windows ping命令输出使用GBK编码，需要特殊处理
        if os.name == "nt":
            result = subprocess.run(  # noqa: S603
                ping_cmd,
                check=False,
                capture_output=True,
                text=True,
                encoding="gbk",
                errors="replace",
                timeout=20,
            )
        else:
            result = subprocess.run(  # noqa: S603
                ping_cmd,
                check=False,
                capture_output=True,
                **_SUBPROCESS_TEXT_KWARGS,
                timeout=20,
            )
    except subprocess.SubprocessError as exc:
        log_error(f"❌ 无法执行 ping：{exc}")
        log_info("→ 请确认本机允许发起 ICMP 请求或尝试改用稳定的国际出口网络。")
        return False

    if result.returncode == 0:
        log_success("✅ ping 成功，本地可以访问该实例。")
        return True

    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    log_error("❌ ping 失败，可能是网络抖动或运营商屏蔽 ICMP。")
    if stdout:
        log_warning(f"   输出: {stdout}")
    if stderr:
        log_warning(f"   错误: {stderr}")
    log_info("→ 建议：检查当前出口网络、关闭可能干扰的代理/防火墙，或稍后重试。")
    return False


def _diagnostic_port_22(ip: str) -> bool:
    """Attempt to establish a TCP connection to ``ip:22`` once."""

    log_info(f"→ 排查步骤：检测 {ip}:22 是否开放")
    try:
        with socket.create_connection((ip, 22), timeout=5):
            log_success("✅ TCP/22 可达，SSH 端口开放。")
            return True
    except OSError as exc:
        log_error(f"❌ 无法连通 {ip}:22：{exc}")
        log_info(
            "→ 建议：确认 VPS 正在运行，并检查云防火墙、本地防火墙或出口线路是否放行 TCP/22。"
        )
        return False


def _resolve_diagnostic_key_path() -> Path | None:
    """Return a reasonable private-key path for diagnostic SSH probes."""

    override = os.environ.get("PT_SSH_PRIVATE_KEY", "").strip()
    candidates: list[Path] = []
    if override:
        candidates.append(Path(override).expanduser())
    default_prompt = _default_private_key_prompt()
    if default_prompt:
        candidates.append(Path(default_prompt).expanduser())

    for candidate in candidates:
        if candidate.exists() and candidate.is_file() and candidate.stat().st_size > 0:
            return candidate
    return None


def _diagnostic_passwordless_ssh(ip: str, key_path: Path) -> bool:
    """Attempt a single passwordless SSH probe with ``key_path``."""

    log_info(f"→ 排查步骤：使用 {key_path} 验证免密 SSH")
    result = probe_publickey_auth(
        ip,
        key_path,
        retries=1,
        interval=0,
        timeout=15,
    )
    if result.success:
        log_success("✅ 免密 SSH 正常，可直接部署 WireGuard。")
        return True

    log_error("❌ 免密 SSH 验证失败。")
    if result.error:
        log_warning(f"   error: {result.error}")
    if result.stderr:
        log_warning(f"   stderr: {result.stderr}")
    if result.stdout and result.stdout != "ok":
        log_warning(f"   stdout: {result.stdout}")
    log_info("→ 建议：确认 Vultr 实例已注入正确公钥，或通过控制台登录执行授权命令。")
    _print_manual_ssh_hint()
    return False


def _run_network_diagnostics(ip: str) -> bool:
    """Run connectivity diagnostics against the recorded Vultr instance."""

    log_section("🌐 网络连通性排查")
    overall_ok = True

    if not _diagnostic_ping(ip):
        overall_ok = False

    port_ok = _diagnostic_port_22(ip)
    if not port_ok:
        overall_ok = False

    key_path = _resolve_diagnostic_key_path()
    if key_path and port_ok:
        if not _diagnostic_passwordless_ssh(ip, key_path):
            overall_ok = False
    elif not key_path:
        log_warning("⚠️ 未找到可用的私钥文件，跳过免密 SSH 验证。")

    return overall_ok


def _check_vultr_instances() -> None:
    """检查Vultr账户中是否有实例，如果没有则提示创建。"""

    api_key = os.environ.get("VULTR_API_KEY", "").strip()
    if not api_key:
        log_warning("⚠️ 未检测到环境变量 VULTR_API_KEY，跳过Vultr实例检查。")
        log_info("→ 提示：如需创建VPS，请先设置 VULTR_API_KEY 环境变量。")
        return

    try:
        from core.tools.vultr_manager import (  # pylint: disable=import-outside-toplevel
            VultrError,
            list_instances,
        )
    except ImportError:
        log_warning("⚠️ 无法导入Vultr管理模块，跳过实例检查。")
        return

    log_info("→ 正在检查Vultr账户中的实例…")
    try:
        instances = list_instances(api_key)
    except VultrError as exc:
        error_msg = str(exc)
        # 检查是否是网络超时或连接问题
        if any(keyword in error_msg.lower() for keyword in ["timeout", "timed out", "connection", "read timed out"]):
            log_warning("⚠️ 无法连接到Vultr API（网络超时或连接失败）")
            log_info("→ 可能的原因：")
            log_info("  1. 网络连接不稳定或被限制")
            log_info("  2. 需要配置代理才能访问外网")
            log_info("→ 解决方案：")
            log_info("  1. 设置代理环境变量（如：$env:ALL_PROXY='http://127.0.0.1:7890'）")
            log_info("  2. 使用代理后重新运行程序")
            log_info("  3. 或稍后网络恢复时重试")
            # 检查是否已配置代理
            from core.proxy_utils import is_proxy_configured  # pylint: disable=import-outside-toplevel
            if not is_proxy_configured():
                log_info("→ 提示：当前未配置代理，如果无法直连外网，建议配置代理。")
        elif "401" in error_msg or "unauthorized" in error_msg.lower():
            log_warning("⚠️ Vultr API 认证失败")
            log_info("→ 提示：请检查 VULTR_API_KEY 是否正确，或确认API Key是否有查询实例的权限。")
        else:
            log_warning(f"⚠️ 查询Vultr实例失败：{error_msg}")
            log_info("→ 提示：请检查 VULTR_API_KEY 是否正确，或稍后重试。")
        return

    if not instances:
        log_success("ℹ️ 当前Vultr账户中没有任何实例。")
        log_info("→ 建议：请执行第2步「创建 VPS（Vultr）」来创建新的VPS实例。")
    else:
        log_success(f"✅ 检测到 {len(instances)} 个Vultr实例。")
        # 检查是否有本地记录的实例
        local_instance = _load_instance_for_diagnostics()
        if local_instance:
            ip, inst_path = local_instance
            # 检查这个IP是否在Vultr实例列表中
            instance_found = any(
                inst.get("main_ip") == ip for inst in instances
            )
            if instance_found:
                log_info(f"→ 本地记录的实例 {ip} 在Vultr账户中存在。")
            else:
                log_warning(f"⚠️ 本地记录的实例 {ip} 在Vultr账户中未找到，可能已被删除。")
                log_info("→ 建议：请重新创建VPS实例或更新本地记录。")


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
        log_success("✅ 本地环境体检通过。详见 PROJECT_HEALTH_REPORT.md")
    else:
        log_warning("⚠️ 本地环境体检发现问题，请按报告提示修复后再继续。")
        return

    # 检查Vultr账户中的实例
    log_info("")
    _check_vultr_instances()


from core.ssh_utils import (
    ask_key_path,
    nuke_known_host,
    pick_default_key,
    probe_publickey_auth,
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
                **_SUBPROCESS_TEXT_KWARGS,
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


def view_connection_report() -> None:
    """查看连接质量报告。View connection quality report."""
    from core.tools.connection_monitor import ConnectionMonitor
    from core.tools.connection_stats import ConnectionSession

    log_section("📊 连接质量报告")

    stats_dir = ARTIFACTS_DIR / "connection_stats"

    if not stats_dir.exists():
        log_info("ℹ️ 暂无连接统计数据")
        log_info("→ 提示：设置环境变量 PT_ENABLE_MONITORING=true 启用监控")
        return

    # 查找会话文件
    session_files = list(stats_dir.glob("session-*.json"))

    if not session_files:
        log_info("ℹ️ 暂无会话记录")
        return

    # 按时间排序
    session_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)

    log_info(f"→ 找到 {len(session_files)} 个会话记录")
    log_info("")
    log_info("最近会话：")

    for idx, session_file in enumerate(session_files[:10], 1):
        try:
            session_data = json.loads(session_file.read_text(encoding="utf-8"))
            session_id = session_data.get("session_id", "unknown")
            node_id = session_data.get("node_id", "unknown")
            duration = session_data.get("duration", 0)
            avg_latency = session_data.get("avg_latency_ms")

            latency_str = f"{avg_latency:.2f}ms" if avg_latency else "N/A"
            hours = duration // 3600
            minutes = (duration % 3600) // 60
            log_info(
                f"  {idx}. {session_id[:8]}... | 节点:{node_id} | "
                f"时长:{hours}h{minutes}m | 延迟:{latency_str}"
            )
        except Exception as exc:
            log_warning(f"  {idx}. 读取失败：{exc}")

    # 选择会话查看详情
    if len(session_files) > 0:
        choice = input(f"\n请选择会话查看详情 [1-{min(10, len(session_files))}, q退出]: ").strip()

        if choice.lower() != "q":
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(session_files):
                    session_file = session_files[idx]
                    session_data = json.loads(session_file.read_text(encoding="utf-8"))

                    # 生成报告
                    session = ConnectionSession.from_dict(session_data)
                    node_ip = "unknown"  # 可以从配置中获取

                    monitor = ConnectionMonitor(
                        node_id=session.node_id,
                        node_ip=node_ip,
                    )
                    report = monitor.generate_report(session_id=session.session_id)

                    if "error" in report:
                        log_error(f"❌ {report['error']}")
                        return

                    # 显示报告
                    log_info("")
                    log_info("=" * 60)
                    log_info("连接质量报告")
                    log_info("=" * 60)
                    log_info(f"会话 ID: {report['session_id']}")
                    log_info(f"节点 ID: {report['node_id']}")
                    duration = report["duration"]
                    hours = duration // 3600
                    minutes = (duration % 3600) // 60
                    log_info(f"持续时间: {hours}h{minutes}m")
                    log_info("")
                    log_info("统计摘要：")
                    summary = report["summary"]
                    log_info(
                        f"  平均延迟: {summary['avg_latency_ms']:.2f}ms"
                        if summary["avg_latency_ms"]
                        else "  平均延迟: N/A"
                    )
                    log_info(
                        f"  最大延迟: {summary['max_latency_ms']:.2f}ms"
                        if summary["max_latency_ms"]
                        else "  最大延迟: N/A"
                    )
                    log_info(
                        f"  最小延迟: {summary['min_latency_ms']:.2f}ms"
                        if summary["min_latency_ms"]
                        else "  最小延迟: N/A"
                    )
                    log_info(f"  平均丢包率: {summary['avg_packet_loss']*100:.2f}%")
                    log_info(f"  最大丢包率: {summary['max_packet_loss']*100:.2f}%")
                    log_info(f"  重连次数: {summary['total_reconnects']}")
                    log_info(f"  发送字节: {summary['total_tx_bytes']:,}")
                    log_info(f"  接收字节: {summary['total_rx_bytes']:,}")
                    log_info("")
                    log_info(f"质量评分: {report['quality_score']:.2f}/100")
            except (ValueError, IndexError, KeyError) as exc:
                log_error(f"❌ 读取报告失败：{exc}")


def view_parameter_recommendations() -> None:
    """查看参数调整建议。View parameter recommendations."""
    from core.tools.adaptive_params import AdaptiveParameterTuner, ParameterSet
    from core.tools.connection_stats import ConnectionSession

    log_section("🔧 参数调整建议")

    stats_dir = ARTIFACTS_DIR / "connection_stats"

    if not stats_dir.exists():
        log_info("ℹ️ 暂无连接统计数据")
        log_info("→ 提示：设置环境变量 PT_ENABLE_MONITORING=true 启用监控")
        return

    # 查找最近的会话
    session_files = list(stats_dir.glob("session-*.json"))
    if not session_files:
        log_info("ℹ️ 暂无会话记录")
        return

    session_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)
    latest_session_file = session_files[0]

    try:
        session_data = json.loads(latest_session_file.read_text(encoding="utf-8"))
        session = ConnectionSession.from_dict(session_data)

        # 确定节点 ID
        node_id = session.node_id

        # 获取建议
        tuner = AdaptiveParameterTuner(node_id)
        recommendations = tuner.get_recommendations(session)

        # 显示建议
        log_info("=" * 60)
        log_info("当前参数：")
        current = recommendations["current"]
        log_info(f"  Keepalive: {current['keepalive']} 秒")
        log_info(f"  MTU: {current['mtu']}")
        log_info("")
        log_info("建议参数：")
        suggested = recommendations["suggested"]
        log_info(f"  Keepalive: {suggested['keepalive']} 秒")
        log_info(f"  MTU: {suggested['mtu']}")
        log_info("")
        log_info(f"调整原因：{recommendations['reason']}")
        log_info("")

        # 显示调整历史
        if tuner.adjustment_history:
            log_info("最近调整历史：")
            for adj in tuner.adjustment_history[-5:]:  # 最近 5 次
                success_icon = "✅" if adj.success else "❌"
                log_info(f"  {success_icon} {adj.reason}")
                log_info(f"    Keepalive: {adj.old_params.keepalive} → {adj.new_params.keepalive}")
                log_info(f"    MTU: {adj.old_params.mtu} → {adj.new_params.mtu}")

        # 询问是否应用
        if recommendations["changes"]["keepalive"] or recommendations["changes"]["mtu"]:
            confirm = input("\n是否应用建议的参数？[y/N]: ").strip().lower()
            if confirm in ("y", "yes"):
                new_params = ParameterSet.from_dict(suggested)
                adjustment = tuner.apply_adjustment(new_params, recommendations["reason"])
                log_success("✅ 参数已更新，请重新部署配置")
                log_info(f"   调整 ID: {adjustment.adjustment_id[:8]}")
    except Exception as exc:
        log_error(f"❌ 获取建议失败：{exc}")


def test_chatgpt_connection() -> None:
    """测试 ChatGPT 连接。Test ChatGPT connection."""
    from core.tools.chatgpt_optimizer import ChatGPTOptimizer
    from core.tools.multi_node_manager import MultiNodeManager
    
    log_section("🧪 ChatGPT 连接测试")
    
    # 确定节点
    use_multi_node = os.environ.get("PT_MULTI_NODE", "").strip().lower() in ("true", "1", "yes")
    
    if use_multi_node:
        manager = MultiNodeManager()
        default_node = manager.get_default_node()
        
        if not default_node:
            log_error("❌ 未找到默认节点")
            return
        
        node_ip = default_node.ip
        log_info(f"→ 使用节点：{default_node.id} ({node_ip})")
    else:
        # 单节点模式
        inst_path = ARTIFACTS_DIR / "instance.json"
        if not inst_path.exists():
            log_error("❌ 未找到实例信息")
            return
        
        try:
            instance = json.loads(inst_path.read_text(encoding="utf-8"))
            node_ip = instance.get("ip")
            if not node_ip:
                log_error("❌ 实例信息缺少 IP")
                return
        except Exception as exc:
            log_error(f"❌ 读取实例信息失败：{exc}")
            return
    
    # 获取 WireGuard 端口
    from core.port_config import resolve_listen_port
    wg_port, _ = resolve_listen_port()
    
    # 创建优化器
    optimizer = ChatGPTOptimizer(
        node_ip=node_ip,
        wireguard_port=wg_port,
    )
    
    # 1. 解析域名
    log_info("→ 步骤 1: 解析 ChatGPT 域名...")
    try:
        domain_results = optimizer.resolve_chatgpt_domains()
        
        log_info(f"→ 解析结果：")
        for domain, info in domain_results["domains"].items():
            if info.get("resolved"):
                ips = info.get("ips", [])
                log_info(f"  ✅ {domain}: {', '.join(ips[:3])}{'...' if len(ips) > 3 else ''}")
            else:
                log_warning(f"  ❌ {domain}: 解析失败 - {info.get('error', 'Unknown')}")
    except Exception as exc:
        log_error(f"❌ 域名解析失败：{exc}")
        return
    
    # 2. 测试连接
    log_info("")
    log_info("→ 步骤 2: 测试 ChatGPT API 连接...")
    
    test_urls = [
        ("OpenAI API", "https://api.openai.com/v1/models"),
        ("ChatGPT Web", "https://chat.openai.com"),
    ]
    
    for name, url in test_urls:
        log_info(f"→ 测试 {name} ({url})...")
        try:
            result = optimizer.test_chatgpt_connectivity(url)
            
            if result["success"]:
                log_success(f"  ✅ 连接成功（延迟：{result['latency_ms']:.1f}ms，状态码：{result['status_code']}）")
            else:
                log_error(f"  ❌ 连接失败：{result.get('error', 'Unknown')}")
        except Exception as exc:
            log_error(f"  ❌ 测试失败：{exc}")
    
    # 3. 获取优化建议
    log_info("")
    log_info("→ 步骤 3: 获取优化建议...")
    
    # 获取当前参数
    try:
        keepalive = int(os.environ.get("PT_KEEPALIVE", str(DEFAULT_KEEPALIVE_SECONDS)))
        mtu = int(os.environ.get("PT_CLIENT_MTU", str(DEFAULT_CLIENT_MTU)))
        
        recommendations = optimizer.optimize_for_chatgpt(keepalive, mtu)
        
        log_info("→ 优化建议：")
        log_info(f"   Keepalive: {keepalive} → {recommendations['keepalive']}")
        log_info(f"   MTU: {mtu} → {recommendations['mtu']}")
        log_info(f"   原因: {recommendations['reason']}")
    except Exception as exc:
        log_warning(f"⚠️ 获取优化建议失败：{exc}")
    
    # 4. 生成分流配置
    log_info("")
    log_info("→ 步骤 4: 生成分流配置...")
    try:
        split_config = optimizer.generate_split_config()
        log_success(f"✅ 分流配置已生成：{split_config}")
    except Exception as exc:
        log_error(f"❌ 生成分流配置失败：{exc}")


def _check_and_auto_configure_instances() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """检查账户中的实例，返回已配置和未配置的实例列表。
    
    Returns:
        (configured_instances, unconfigured_instances): 已配置和未配置的实例列表
    """
    from core.tools.vultr_manager import list_instances, VultrError
    from core.tools.multi_node_manager import MultiNodeManager
    
    api_key = os.environ.get("VULTR_API_KEY", "").strip()
    if not api_key:
        log_warning("⚠️ 未检测到环境变量 VULTR_API_KEY，无法自动检查实例")
        return [], []
    
    try:
        log_info("→ 正在检查 Vultr 账户中的实例...")
        instances = list_instances(api_key)
        if not instances:
            log_info("ℹ️ 账户中没有任何实例")
            return [], []
        
        # 过滤出活跃实例
        active_instances = [
            inst for inst in instances
            if inst.get("main_ip") and inst.get("status") == "active"
        ]
        
        if not active_instances:
            log_info("ℹ️ 账户中没有活跃的实例")
            return [], []
        
        log_info(f"→ 找到 {len(active_instances)} 个活跃实例")
        
        # 检查多节点配置
        use_multi_node = os.environ.get("PT_MULTI_NODE", "").strip().lower() in ("true", "1", "yes")
        configured_instance_ids = set()
        
        if use_multi_node:
            manager = MultiNodeManager()
            nodes = manager.get_all_nodes()
            configured_instance_ids = {node.instance_id for node in nodes if node.instance_id}
        
        # 检查每个实例是否已部署 WireGuard
        configured_instances = []
        unconfigured_instances = []
        
        for inst in active_instances:
            instance_id = inst.get("id", "")
            ip = inst.get("main_ip", "")
            
            if not instance_id or not ip:
                continue
            
            # 检查是否已在节点配置中
            is_in_node_config = instance_id in configured_instance_ids
            
            # 检查是否已部署 WireGuard（通过 SSH 检查）
            is_wireguard_deployed = False
            if is_in_node_config:
                # 如果在节点配置中，尝试检查 WireGuard 状态
                try:
                    # 尝试使用默认路径，如果不存在则跳过检查
                    default_key_path = Path.home() / ".ssh" / "id_ed25519"
                    if not default_key_path.exists():
                        default_key_path = Path.home() / ".ssh" / "id_rsa"
                    if default_key_path.exists():
                        # 尝试 SSH 检查 WireGuard 服务
                        try:
                            _set_ssh_context(ip, default_key_path)
                            wg_check_cmd = "systemctl is-active wg-quick@wg0 2>/dev/null || echo 'inactive'"
                            wg_result = _ssh_run(wg_check_cmd, timeout=10, description="检查WireGuard服务", max_retries=1)
                            is_wireguard_deployed = wg_result.stdout.strip() == "active"
                        except Exception:
                            # SSH 检查失败，假设未部署
                            is_wireguard_deployed = False
                except Exception:
                    pass
            
            if is_in_node_config and is_wireguard_deployed:
                configured_instances.append(inst)
                log_info(f"  ✅ {instance_id[:8]}... ({ip}) - 已配置节点且已部署 WireGuard")
            else:
                unconfigured_instances.append(inst)
                if is_in_node_config:
                    log_info(f"  ⚠️ {instance_id[:8]}... ({ip}) - 已配置节点但未部署 WireGuard")
                else:
                    log_info(f"  ⚠️ {instance_id[:8]}... ({ip}) - 未配置节点")
        
        return configured_instances, unconfigured_instances
        
    except VultrError as exc:
        log_warning(f"⚠️ 无法从 Vultr API 获取实例：{exc}")
        return [], []
    except Exception as exc:
        log_warning(f"⚠️ 检查实例时出错：{exc}")
        return [], []
def _deploy_wireguard_to_instance(
    ip: str,
    instance_id: str,
    region: str,
    plan: str,
    enable_chatgpt_mode: bool,
    use_multi_node: bool,
) -> None:
    """为单个实例部署 WireGuard。
    
    Args:
        ip: 实例 IP 地址
        instance_id: 实例 ID
        region: 区域
        plan: 配置方案
        enable_chatgpt_mode: 是否启用 ChatGPT 模式
        use_multi_node: 是否使用多节点模式
    """
    # 获取配置参数（使用环境变量或默认值）
    desktop_ip, _ = _resolve_env_default("PT_DESKTOP_IP", default=DEFAULT_DESKTOP_ADDRESS)
    iphone_ip, _ = _resolve_env_default("PT_IPHONE_IP", default=DEFAULT_IPHONE_ADDRESS)
    dns_value, _ = _resolve_env_default("PT_DNS", default=DEFAULT_DNS_STRING)
    allowed_ips, _ = _resolve_env_default("PT_ALLOWED_IPS", default=DEFAULT_ALLOWED_IPS)
    
    # 解析 Keepalive 和 MTU
    enable_adaptive = os.environ.get("PT_ENABLE_ADAPTIVE", "").strip().lower() in ("true", "1", "yes")
    if enable_adaptive:
        from core.tools.adaptive_params import AdaptiveParameterTuner
        adaptive_node_id = instance_id[:8] if instance_id else "default"
        tuner = AdaptiveParameterTuner(adaptive_node_id)
        current_params = tuner.current_params
        keepalive_value = str(current_params.keepalive)
        desktop_mtu = str(current_params.mtu)
    else:
        keepalive_value, _ = _resolve_env_default(
            "PT_KEEPALIVE", default=str(DEFAULT_KEEPALIVE_SECONDS)
        )
        desktop_mtu = os.environ.get("PT_CLIENT_MTU", "").strip() or str(DEFAULT_CLIENT_MTU)
    
    # V2Ray 配置
    enable_v2ray = os.environ.get("PT_ENABLE_V2RAY", "").strip().lower() in ("true", "1", "yes")
    if enable_v2ray:
        v2ray_port_raw = os.environ.get("PT_V2RAY_PORT", "").strip()
        v2ray_port = int(v2ray_port_raw) if v2ray_port_raw and v2ray_port_raw.isdigit() else 443
        v2ray_uuid = os.environ.get("PT_V2RAY_UUID", "").strip() or None
    else:
        v2ray_port = 443
        v2ray_uuid = None
    
    # 如果启用 ChatGPT 模式，进行优化（简化版，不进行交互式提示）
    if enable_chatgpt_mode:
        from core.tools.chatgpt_optimizer import ChatGPTOptimizer
        optimizer = ChatGPTOptimizer(node_ip=ip, wireguard_port=LISTEN_PORT)
        try:
            current_keepalive = (
                int(keepalive_value)
                if keepalive_value.isdigit()
                else DEFAULT_KEEPALIVE_SECONDS
            )
            current_mtu = int(desktop_mtu) if desktop_mtu.isdigit() else DEFAULT_CLIENT_MTU
            recommendations = optimizer.optimize_for_chatgpt(
                current_keepalive=current_keepalive,
                current_mtu=current_mtu,
            )
            keepalive_value = str(recommendations["keepalive"])
            desktop_mtu = str(recommendations["mtu"])
        except Exception:
            pass  # 优化失败时使用原值
    
    # 获取 SSH 私钥
    default_key_prompt = _default_private_key_prompt()
    key_path = Path(ask_key_path(default_key_prompt)).expanduser()
    
    # 检查 SSH 连接
    try:
        _clean_known_host(ip)
    except Exception:
        pass
    
    log_info(f"→ 检查 SSH 连接...")
    if not _wait_for_port_22(ip, interval=20):
        raise DeploymentError(f"未检测到 VPS SSH 端口开放: {ip}")
    
    if not _wait_for_passwordless_ssh(ip, key_path):
        raise DeploymentError(f"免密 SSH 校验失败: {ip}")
    
    log_success(f"✅ SSH 连接正常")
    
    # 部署 WireGuard
    _set_ssh_context(ip, key_path)
    remote_script = deploy_wireguard_remote_script(
        LISTEN_PORT,
        desktop_ip,
        iphone_ip,
        ip,
        dns_value,
        allowed_ips,
        desktop_mtu,
        keepalive_value,
        enable_v2ray=enable_v2ray,
        v2ray_port=v2ray_port,
        v2ray_uuid=v2ray_uuid,
    )
    
    script_payload = (
        "cat <<'EOS' >/tmp/privatetunnel-wireguard.sh\n"
        f"{remote_script}\n"
        "EOS\n"
    )
    
    env_dict = {
        "WG_PORT": str(LISTEN_PORT),
        "PT_DESKTOP_IP": desktop_ip,
        "PT_IPHONE_IP": iphone_ip,
        "PT_DNS": dns_value,
        "PT_ALLOWED_IPS": allowed_ips,
        "PT_CLIENT_MTU": desktop_mtu,
        "PT_KEEPALIVE": keepalive_value,
    }
    if enable_v2ray:
        env_dict["PT_ENABLE_V2RAY"] = "true"
        env_dict["PT_V2RAY_PORT"] = str(v2ray_port)
        if v2ray_uuid:
            env_dict["PT_V2RAY_UUID"] = v2ray_uuid
    
    env_parts = [
        f"{key}={shlex.quote(value)}"
        for key, value in env_dict.items()
        if value
    ]
    env_prefix = " ".join(env_parts)
    
    log_file = "/tmp/privatetunnel-wireguard.log"
    pid_file = "/tmp/privatetunnel-wireguard.pid"
    
    # 上传脚本
    _ssh_run(script_payload, timeout=60, description="上传部署脚本", max_retries=3)
    
    # 启动脚本
    start_cmd = (
        f"{env_prefix + ' ' if env_prefix else ''}nohup bash /tmp/privatetunnel-wireguard.sh "
        f"> {log_file} 2>&1 & echo $! > {pid_file}"
    )
    log_info("→ 开始部署 WireGuard...")
    _ssh_run(start_cmd, timeout=60, description="启动部署脚本", max_retries=3)
    
    time.sleep(2)
    
    # 等待部署完成（简化版，不显示详细进度）
    max_wait_time = 3600
    check_interval = 15
    start_time = time.time()
    
    while time.time() - start_time < max_wait_time:
        elapsed = int(time.time() - start_time)
        
        # 检查 WireGuard 服务状态
        try:
            wg_check_cmd = "systemctl is-active wg-quick@wg0 2>/dev/null || echo 'inactive'"
            wg_result = _ssh_run(wg_check_cmd, timeout=20, description="检查WireGuard服务", max_retries=1)
            if wg_result.stdout.strip() == "active":
                log_success(f"✅ WireGuard 部署完成（耗时 {elapsed} 秒）")
                break
        except Exception:
            pass
        
        if elapsed % 60 == 0:  # 每分钟显示一次进度
            log_info(f"  ⏱️ 部署中... ({elapsed}秒)")
        
        time.sleep(check_interval)
    else:
        raise DeploymentError(f"部署超时（{max_wait_time}秒）")
    
    # 下载配置文件并更新服务器信息
    log_info("→ 获取服务器配置信息...")
    try:
        server_info_cmd = (
            "SERVER_PUB=$(wg show wg0 public-key 2>/dev/null || echo '') && "
            "ENDPOINT_IP=$(curl -4 -s ifconfig.me 2>/dev/null || echo '') && "
            "WAN_IF=$(ip -o -4 route show to default | awk '{print $5}' | head -n1) && "
            "echo \"SERVER_PUB=$SERVER_PUB|ENDPOINT_IP=$ENDPOINT_IP|WAN_IF=$WAN_IF\""
        )
        info_result = _ssh_run(server_info_cmd, timeout=30, description="获取服务器信息", max_retries=2)
        
        server_info = {}
        for item in info_result.stdout.strip().split("|"):
            if "=" in item:
                key, value = item.split("=", 1)
                server_info[key.lower()] = value
        
        server_pub = server_info.get("server_pub", "")
        endpoint_ip = server_info.get("endpoint_ip", ip)
        wan_interface = server_info.get("wan_if", "")
        
        endpoint = f"{endpoint_ip}:{LISTEN_PORT}" if endpoint_ip else None
        
        # 更新服务器信息
        server_data = {
            "id": instance_id,
            "ip": ip,
            "server_pub": server_pub,
            "endpoint": endpoint,
            "wan_interface": wan_interface,
        }
        
        if use_multi_node:
            from core.tools.multi_node_manager import MultiNodeManager, NodeStatus
            manager = MultiNodeManager()
            node_id = f"node-{instance_id[:8]}"
            
            manager.update_node_info(
                node_id=node_id,
                server_pub=server_pub,
                endpoint=endpoint,
            )
            manager.update_node_status(node_id, NodeStatus.ACTIVE)
        else:
            _update_server_info(server_data)
        
        log_success("✅ 服务器信息已更新")
    except Exception as exc:
        log_warning(f"⚠️ 更新服务器信息失败: {exc}")


def prepare_wireguard_access() -> None:
    """Configure WireGuard end-to-end, including client provisioning."""

    # 检查是否启用 ChatGPT 专用模式
    enable_chatgpt_mode = os.environ.get("PT_CHATGPT_MODE", "").strip().lower() in ("true", "1", "yes")

    # 检查是否启用多节点模式
    use_multi_node = os.environ.get("PT_MULTI_NODE", "").strip().lower() in ("true", "1", "yes")
    
    # 首先检查账户中的实例
    log_section("🔍 检查 Vultr 账户实例状态")
    configured_instances, unconfigured_instances = _check_and_auto_configure_instances()
    
    if configured_instances:
        log_success(f"✅ {len(configured_instances)} 个实例已配置完成")
    
    if unconfigured_instances:
        log_info(f"→ 发现 {len(unconfigured_instances)} 个未配置的实例，将自动进行配置...")
        
        # 根据实例数量决定配置方式
        if len(unconfigured_instances) == 1:
            log_info("→ 单个实例模式：将配置单个节点")
            # 如果只有一个实例且未启用多节点，使用单节点模式
            if not use_multi_node:
                log_info("→ 提示：当前未启用多节点模式，将使用单节点模式")
        else:
            log_info(f"→ 多实例模式：将为 {len(unconfigured_instances)} 个实例分别配置节点")
            # 如果有多个实例，自动启用多节点模式
            if not use_multi_node:
                log_info("→ 自动启用多节点模式（检测到多个实例）")
                use_multi_node = True
                os.environ["PT_MULTI_NODE"] = "true"
        
        # 为每个未配置的实例自动部署
        for idx, inst in enumerate(unconfigured_instances, 1):
            instance_id = inst.get("id", "")
            ip = inst.get("main_ip", "")
            region_obj = inst.get("region", {})
            if isinstance(region_obj, dict):
                region = region_obj.get("code") or region_obj.get("id") or "unknown"
            else:
                region = str(region_obj or "unknown")
            plan = inst.get("plan", "unknown")
            
            log_info("")
            log_section(f"📦 配置实例 {idx}/{len(unconfigured_instances)}: {instance_id[:8]}... ({ip})")
            
            # 如果启用多节点，先创建节点
            if use_multi_node:
                from core.tools.multi_node_manager import MultiNodeManager
                manager = MultiNodeManager()
                node_priority = int(os.environ.get("PT_NODE_PRIORITY", str(idx)))
                node_weight = int(os.environ.get("PT_NODE_WEIGHT", "100"))
                
                node = manager.add_node_from_instance(
                    instance_id=instance_id,
                    ip=ip,
                    region=region,
                    plan=plan,
                    priority=node_priority,
                    weight=node_weight,
                )
                log_success(f"✅ 已创建节点: {node.id}")
            
            # 部署 WireGuard（调用原有的部署逻辑，但针对当前实例）
            try:
                _deploy_wireguard_to_instance(ip, instance_id, region, plan, enable_chatgpt_mode, use_multi_node)
                log_success(f"✅ 实例 {instance_id[:8]}... 配置完成")
            except Exception as exc:
                log_error(f"❌ 实例 {instance_id[:8]}... 配置失败: {exc}")
                log_info("→ 将继续配置其他实例...")
        
        log_info("")
        log_success("✅ 所有实例配置完成！")
        return

    if use_multi_node:
        from core.tools.multi_node_manager import MultiNodeManager, NodeStatus

        if enable_chatgpt_mode:
            log_section("🛡 Step 3: 准备本机接入 VPS 网络（多节点模式 + ChatGPT 专用）")
        else:
            log_section("🛡 Step 3: 准备本机接入 VPS 网络（多节点模式）")

        manager = MultiNodeManager()
        nodes = manager.get_all_nodes()

        if not nodes:
            # 尝试从 instance.json 或 Vultr API 自动创建节点
            log_info("→ 未找到节点配置，尝试从已有实例自动创建节点...")
            
            # 方法1：从本地 instance.json 创建节点
            instance_file = ARTIFACTS_DIR / "instance.json"
            if instance_file.exists():
                try:
                    instance_data = json.loads(instance_file.read_text(encoding="utf-8"))
                    instance_id = instance_data.get("id", "")
                    ip = instance_data.get("ip", "")
                    region = instance_data.get("region", "unknown")
                    plan = instance_data.get("plan", "unknown")
                    priority = int(instance_data.get("priority", 1))
                    weight = int(instance_data.get("weight", 100))
                    
                    if instance_id and ip:
                        node = manager.add_node_from_instance(
                            instance_id=instance_id,
                            ip=ip,
                            region=region,
                            plan=plan,
                            priority=priority,
                            weight=weight,
                        )
                        log_success(f"✅ 已从本地记录自动创建节点: {node.id} ({ip})")
                        nodes = manager.get_all_nodes()
                except (json.JSONDecodeError, KeyError, ValueError) as exc:
                    log_warning(f"⚠️ 读取 instance.json 失败: {exc}")
            
            # 方法2：如果仍然没有节点，尝试从 Vultr API 获取实例
            if not nodes:
                api_key = os.environ.get("VULTR_API_KEY", "").strip()
                if api_key:
                    try:
                        from core.tools.vultr_manager import list_instances, VultrError
                        log_info("→ 尝试从 Vultr API 获取实例...")
                        instances = list_instances(api_key)
                        if instances:
                            # 使用第一个活跃实例
                            active_instances = [
                                inst for inst in instances
                                if inst.get("main_ip") and inst.get("status") == "active"
                            ]
                            if active_instances:
                                inst = active_instances[0]
                                instance_id = inst.get("id", "")
                                ip = inst.get("main_ip", "")
                                region_obj = inst.get("region", {})
                                if isinstance(region_obj, dict):
                                    region = region_obj.get("code") or region_obj.get("id") or "unknown"
                                else:
                                    region = str(region_obj or "unknown")
                                plan = inst.get("plan", "unknown")
                                
                                if instance_id and ip:
                                    node = manager.add_node_from_instance(
                                        instance_id=instance_id,
                                        ip=ip,
                                        region=region,
                                        plan=plan,
                                        priority=1,
                                        weight=100,
                                    )
                                    log_success(f"✅ 已从 Vultr API 自动创建节点: {node.id} ({ip})")
                                    nodes = manager.get_all_nodes()
                            else:
                                log_warning("⚠️ Vultr账户中没有活跃的实例")
                        else:
                            log_warning("⚠️ Vultr账户中没有任何实例")
                    except VultrError as exc:
                        log_warning(f"⚠️ 无法从 Vultr API 获取实例: {exc}")
                    except Exception as exc:
                        log_warning(f"⚠️ 获取实例时出错: {exc}")
            
            # 如果仍然没有节点，显示友好的提示
            if not nodes:
                log_error("❌ 未找到任何节点配置。")
                log_info("→ 解决方案：")
                log_info("  1. 如果已创建VPS但未启用多节点模式，请先执行第2步「创建 VPS（Vultr）」并启用多节点模式")
                log_info("  2. 或者手动添加节点到 artifacts/multi-node.json")
                log_info("  3. 或者设置环境变量 PT_MULTI_NODE=false 使用单节点模式")
                return

        # 显示可用节点
        log_info("→ 可用节点列表：")
        for idx, node in enumerate(nodes, 1):
            status_icon = "✅" if node.status == NodeStatus.ACTIVE else "⚠️"
            log_info(f"  {idx}. {status_icon} {node.id} | {node.ip} | {node.region} | "
                    f"优先级:{node.priority} 权重:{node.weight} | {node.status.value}")

        # 选择节点
        default_node = manager.get_default_node()

        # 检查是否启用智能选路
        use_smart_routing = os.environ.get("PT_SMART_ROUTING", "").strip().lower() in ("true", "1", "yes")
        routing_strategy = os.environ.get("PT_ROUTING_STRATEGY", "balanced").strip().lower()
        selected_node = None

        if use_smart_routing:
            log_info("→ 使用智能选路选择节点...")
            from core.tools.smart_routing import SmartRouter, RoutingStrategy

            try:
                strategy = RoutingStrategy(routing_strategy)
                router = SmartRouter(strategy=strategy)

                from core.port_config import resolve_listen_port

                wg_port, _ = resolve_listen_port()

                best_node, best_score, all_scores = router.select_best_node(
                    nodes,
                    wireguard_port=wg_port,
                )

                if best_node:
                    selected_node = best_node
                    log_success(f"✅ 智能选路推荐：{selected_node.id} ({selected_node.ip})")
                    if best_score:
                        log_info(f"   综合评分：{best_score.overall_score:.2f}/100")
                else:
                    log_warning("⚠️ 智能选路未找到节点，使用手动选择")
                    use_smart_routing = False
            except (ImportError, ValueError) as exc:
                log_warning(f"⚠️ 智能选路失败：{exc}，使用手动选择")
                use_smart_routing = False

        if not use_smart_routing or selected_node is None:
            # 手动选择节点（原有逻辑）
            if default_node:
                default_idx = next((i for i, n in enumerate(nodes, 1) if n.id == default_node.id), 1)
            else:
                default_idx = 1

            choice = input(f"请选择节点 [1-{len(nodes)}, 默认 {default_idx}]: ").strip()
            if not choice:
                selected_idx = default_idx
            else:
                try:
                    selected_idx = int(choice)
                    if not 1 <= selected_idx <= len(nodes):
                        log_error("❌ 无效选择")
                        return
                except ValueError:
                    log_error("❌ 无效输入")
                    return

            selected_node = nodes[selected_idx - 1]
            log_info(f"→ 已选择节点：{selected_node.id} ({selected_node.ip})")

        # 如果启用多节点，执行健康检查
        from core.tools.node_health_checker import NodeHealthChecker

        log_info(f"→ 检查节点 {selected_node.id} 健康状态…")
        checker = NodeHealthChecker()

        # 从节点信息中获取 WireGuard 端口
        # 如果节点有 endpoint，提取端口；否则使用默认端口
        wg_port = None
        if selected_node.endpoint:
            try:
                _, port_str = selected_node.endpoint.rsplit(":", 1)
                wg_port = int(port_str)
            except (ValueError, AttributeError):
                pass

        if wg_port is None:
            wg_port = LISTEN_PORT

        metrics = checker.check_node(
            ip=selected_node.ip,
            wireguard_port=wg_port,
        )

        # 显示健康检查结果
        log_info(f"→ 健康检查结果：")
        log_info(f"   延迟：{metrics.latency_ms:.2f}ms" if metrics.latency_ms else "   延迟：N/A")
        log_info(f"   ICMP：{'✅' if metrics.icmp_success else '❌'}")
        log_info(f"   TCP (SSH)：{'✅' if metrics.tcp_success else '❌'}")
        log_info(f"   HTTPS：{'✅' if metrics.https_success else '❌'}")
        log_info(f"   DNS：{'✅' if metrics.dns_success else '❌'}")
        log_info(f"   WireGuard：{'✅' if metrics.wireguard_handshake else '❌'}")
        log_info(f"   整体状态：{'✅ 健康' if metrics.overall_healthy else '❌ 不健康'}")

        # 更新节点状态
        if metrics.overall_healthy:
            manager.update_node_status(selected_node.id, NodeStatus.ACTIVE, metrics.latency_ms)
        else:
            manager.update_node_status(selected_node.id, NodeStatus.FAILING, metrics.latency_ms)

            # 如果节点不健康，尝试故障转移
            log_warning(f"⚠️ 节点 {selected_node.id} 健康检查失败")
            backup = manager.switch_to_backup_node(selected_node.id, wg_port)

            if backup:
                log_info(f"→ 自动切换到备用节点：{backup.id} ({backup.ip})")
                selected_node = backup
            else:
                log_warning("⚠️ 未找到可用的备用节点")
                confirm = input("是否继续使用当前节点？[y/N]: ").strip().lower()
                if confirm not in ("y", "yes"):
                    return

        # 使用选中节点的信息
        ip = selected_node.ip
        instance_id = selected_node.instance_id
        selected_node_id = selected_node.id  # 保存节点 ID 供后续使用

        # 检查节点状态
        if selected_node.status != NodeStatus.ACTIVE:
            log_warning(f"⚠️ 节点状态为 {selected_node.status.value}，可能无法正常连接")
            confirm = input("是否继续？[y/N]: ").strip().lower()
            if confirm not in ("y", "yes"):
                return
    else:
        selected_node_id = None  # 单节点模式下没有 selected_node_id
        # 单节点模式：保持原有逻辑
        inst_path = ARTIFACTS_DIR / "instance.json"
        instance = None
        
        # 尝试从本地文件加载
        if inst_path.exists():
            try:
                instance = json.loads(inst_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                log_warning(f"⚠️ 解析 {inst_path} 失败：{exc}，将尝试从 Vultr API 获取实例")
                instance = None
        
        # 如果本地文件不存在或解析失败，尝试从 Vultr API 获取
        if not instance:
            api_key = os.environ.get("VULTR_API_KEY", "").strip()
            if api_key:
                try:
                    from core.tools.vultr_manager import list_instances, VultrError
                    log_info("→ 本地记录不存在，尝试从 Vultr API 获取实例...")
                    instances = list_instances(api_key)
                    if instances:
                        # 使用第一个活跃实例
                        active_instances = [
                            inst for inst in instances
                            if inst.get("main_ip") and inst.get("status") == "active"
                        ]
                        if active_instances:
                            inst = active_instances[0]
                            instance = {
                                "id": inst.get("id", ""),
                                "ip": inst.get("main_ip", ""),
                                "region": inst.get("region", {}).get("code") if isinstance(inst.get("region"), dict) else str(inst.get("region", "")),
                                "plan": inst.get("plan", ""),
                            }
                            log_success(f"✅ 已从 Vultr API 获取实例：{instance['ip']}")
                            # 保存到本地文件以便后续使用
                            inst_path.parent.mkdir(parents=True, exist_ok=True)
                            inst_path.write_text(
                                json.dumps(instance, ensure_ascii=False, indent=2),
                                encoding="utf-8",
                            )
                            log_info(f"→ 已保存实例信息到 {inst_path}")
                        else:
                            log_warning("⚠️ Vultr账户中没有活跃的实例")
                    else:
                        log_warning("⚠️ Vultr账户中没有任何实例")
                except VultrError as exc:
                    log_warning(f"⚠️ 无法从 Vultr API 获取实例：{exc}")
                except Exception as exc:
                    log_warning(f"⚠️ 获取实例时出错：{exc}")
        
        # 如果仍然没有实例信息，显示错误
        if not instance:
            log_section("🛡 Step 3: 准备本机接入 VPS 网络")
            log_error(f"❌ 未找到实例信息。")
            log_info("→ 可能的原因：")
            log_info("  1. 本地记录文件不存在或已损坏")
            log_info("  2. Vultr账户中没有实例")
            log_info("  3. 无法连接到 Vultr API（可能需要配置代理）")
            log_info("→ 解决方案：")
            log_info("  1. 执行第2步「创建 VPS（Vultr）」创建新实例")
            log_info("  2. 或手动创建 artifacts/instance.json 文件")
            return

        ip = instance.get("ip")
        instance_id = instance.get("id", "")
        if not ip:
            log_section("🛡 Step 3: 准备本机接入 VPS 网络")
            log_error(f"❌ 实例信息缺少 IP 字段，请重新创建或检查 {inst_path}。")
            return

        if enable_chatgpt_mode:
            log_section("🛡 Step 3: 准备本机接入 VPS 网络（ChatGPT 专用模式）")
        else:
            log_section("🛡 Step 3: 准备本机接入 VPS 网络")
    _log_selected_platform()

    deploy_log_path = _init_deploy_log()
    log_info(f"→ 本次部署日志：{deploy_log_path}")

    log_info(f"→ 目标实例：{ip}")
    if LISTEN_PORT_SOURCE:
        log_info(f"→ WireGuard 监听端口：{LISTEN_PORT} （来自环境变量 {LISTEN_PORT_SOURCE}）")
    else:
        log_info(
            f"→ WireGuard 监听端口：{LISTEN_PORT} （默认值，可通过环境变量 PRIVATETUNNEL_WG_PORT/PT_WG_PORT 覆盖）"
        )

    desktop_ip, desktop_source = _resolve_env_default("PT_DESKTOP_IP", default=DEFAULT_DESKTOP_ADDRESS)
    if desktop_source:
        log_info(f"→ 桌面客户端 IP：{desktop_ip} （来自环境变量 {desktop_source}）")
    else:
        log_info(
            "→ 桌面客户端 IP：{value} （默认值，可通过环境变量 PT_DESKTOP_IP 覆盖）".format(value=desktop_ip)
        )

    iphone_ip, iphone_source = _resolve_env_default("PT_IPHONE_IP", default=DEFAULT_IPHONE_ADDRESS)
    if iphone_source:
        log_info(f"→ iPhone 客户端 IP：{iphone_ip} （来自环境变量 {iphone_source}）")
    else:
        log_info(
            "→ iPhone 客户端 IP：{value} （默认值，可通过环境变量 PT_IPHONE_IP 覆盖）".format(value=iphone_ip)
        )

    dns_value, dns_source = _resolve_env_default("PT_DNS", default=DEFAULT_DNS_STRING)
    if dns_source:
        log_info(f"→ 客户端 DNS：{dns_value} （来自环境变量 {dns_source}）")
    else:
        log_info(
            "→ 客户端 DNS：{value} （默认值，可通过环境变量 PT_DNS 覆盖）".format(value=dns_value)
        )

    allowed_ips, allowed_source = _resolve_env_default("PT_ALLOWED_IPS", default=DEFAULT_ALLOWED_IPS)
    if allowed_source:
        log_info(f"→ 客户端 AllowedIPs：{allowed_ips} （来自环境变量 {allowed_source}）")
    else:
        log_info(
            "→ 客户端 AllowedIPs：{value} （默认值，可通过环境变量 PT_ALLOWED_IPS 覆盖）".format(
                value=allowed_ips
            )
        )

    # 解析 PersistentKeepalive 参数
    enable_adaptive = os.environ.get("PT_ENABLE_ADAPTIVE", "").strip().lower() in ("true", "1", "yes")

    if enable_adaptive:
        # 自适应模式：从历史记录加载参数
        from core.tools.adaptive_params import AdaptiveParameterTuner

        # 确定节点 ID
        adaptive_node_id = None
        if use_multi_node and 'selected_node_id' in locals() and selected_node_id:
            adaptive_node_id = selected_node_id
        else:
            adaptive_node_id = instance_id[:8] if instance_id else "default"

        tuner = AdaptiveParameterTuner(adaptive_node_id)
        current_params = tuner.current_params

        keepalive_value = str(current_params.keepalive)
        desktop_mtu = str(current_params.mtu)

        log_info(f"→ 自适应参数模式已启用")
        log_info(f"→ 当前 Keepalive：{keepalive_value} 秒（自适应调整）")
        log_info(f"→ 当前 MTU：{desktop_mtu}（自适应调整）")
    else:
        # 手动模式：从环境变量或默认值
        keepalive_value, keepalive_source = _resolve_env_default(
            "PT_KEEPALIVE", default=str(DEFAULT_KEEPALIVE_SECONDS)
        )
        if keepalive_source:
            log_info(f"→ 客户端 Keepalive：{keepalive_value} 秒 （来自环境变量 {keepalive_source}）")
        else:
            log_info(f"→ 客户端 Keepalive：{keepalive_value} 秒（默认值，可通过环境变量 PT_KEEPALIVE 覆盖）")

        # 验证 keepalive 值有效性
        try:
            keepalive_int = int(keepalive_value)
            if not 0 <= keepalive_int <= 65535:
                log_warning(
                    "⚠️ Keepalive 值 {value} 超出有效范围 (0-65535)，将使用默认值 {default}".format(
                        value=keepalive_int, default=DEFAULT_KEEPALIVE_SECONDS
                    )
                )
                keepalive_value = str(DEFAULT_KEEPALIVE_SECONDS)
        except ValueError:
            log_warning(
                "⚠️ Keepalive 值 '{value}' 无效，将使用默认值 {default}".format(
                    value=keepalive_value, default=DEFAULT_KEEPALIVE_SECONDS
                )
            )
            keepalive_value = str(DEFAULT_KEEPALIVE_SECONDS)

        client_mtu_raw = os.environ.get("PT_CLIENT_MTU", "").strip()
        if client_mtu_raw:
            desktop_mtu = client_mtu_raw
            log_info(f"→ 客户端 MTU：{desktop_mtu} （来自环境变量 PT_CLIENT_MTU）")
        else:
            desktop_mtu = str(DEFAULT_CLIENT_MTU)
            log_info(
                "→ 客户端 MTU：{value}（默认值，可通过环境变量 PT_CLIENT_MTU 覆盖）".format(
                    value=desktop_mtu
                )
            )

    # V2Ray 配置参数
    enable_v2ray_raw = os.environ.get("PT_ENABLE_V2RAY", "").strip().lower()
    enable_v2ray = enable_v2ray_raw in ("true", "1", "yes")
    if enable_v2ray:
        log_info(f"→ V2Ray 流量伪装：已启用")
        
        v2ray_port_raw = os.environ.get("PT_V2RAY_PORT", "").strip()
        if v2ray_port_raw:
            try:
                v2ray_port = int(v2ray_port_raw)
                log_info(f"→ V2Ray 端口：{v2ray_port} （来自环境变量 PT_V2RAY_PORT）")
            except ValueError:
                log_warning(f"⚠️ V2RAY_PORT 值 '{v2ray_port_raw}' 无效，将使用默认值 443")
                v2ray_port = 443
        else:
            v2ray_port = 443
            log_info("→ V2Ray 端口：443（默认值，可通过环境变量 PT_V2RAY_PORT 覆盖）")
        
        v2ray_uuid = os.environ.get("PT_V2RAY_UUID", "").strip()
        if v2ray_uuid:
            log_info(f"→ V2Ray UUID：已通过环境变量 PT_V2RAY_UUID 指定")
        else:
            v2ray_uuid = None  # 将在服务器端生成
            log_info("→ V2Ray UUID：将在服务器端自动生成")
    else:
        log_info("→ V2Ray 流量伪装：未启用（可通过环境变量 PT_ENABLE_V2RAY=true 启用）")
        v2ray_port = 443
        v2ray_uuid = None

    # 如果启用 ChatGPT 模式，进行优化
    if enable_chatgpt_mode:
        from core.tools.chatgpt_optimizer import ChatGPTOptimizer
        
        log_info("")
        log_info("→ ChatGPT 专用模式已启用，正在优化连接...")
        
        optimizer = ChatGPTOptimizer(
            node_ip=ip,
            wireguard_port=LISTEN_PORT,
        )
        
        # 解析 ChatGPT 域名
        log_info("→ 解析 ChatGPT 域名...")
        try:
            domain_results = optimizer.resolve_chatgpt_domains()
            resolved_count = sum(1 for d in domain_results["domains"].values() if d.get("resolved"))
            log_info(f"→ 已解析 {resolved_count}/{len(domain_results['domains'])} 个域名")
        except Exception as exc:
            log_warning(f"⚠️ 域名解析失败：{exc}")
        
        # 测试连接
        log_info("→ 测试 ChatGPT 连接性...")
        try:
            connectivity = optimizer.test_chatgpt_connectivity()
            if connectivity["success"]:
                log_success(f"✅ ChatGPT 连接正常（延迟：{connectivity['latency_ms']:.1f}ms）")
            else:
                log_warning(f"⚠️ ChatGPT 连接测试失败：{connectivity.get('error', 'Unknown')}")
        except Exception as exc:
            log_warning(f"⚠️ 连接测试失败：{exc}")
        
        # 获取优化建议
        log_info("→ 获取参数优化建议...")
        try:
            current_keepalive = (
                int(keepalive_value)
                if keepalive_value.isdigit()
                else DEFAULT_KEEPALIVE_SECONDS
            )
            current_mtu = int(desktop_mtu) if desktop_mtu.isdigit() else DEFAULT_CLIENT_MTU
            
            recommendations = optimizer.optimize_for_chatgpt(
                current_keepalive=current_keepalive,
                current_mtu=current_mtu,
            )
            
            if recommendations["keepalive"] != current_keepalive or recommendations["mtu"] != current_mtu:
                log_info(f"→ 建议调整参数：")
                log_info(f"   Keepalive: {current_keepalive} → {recommendations['keepalive']}")
                log_info(f"   MTU: {current_mtu} → {recommendations['mtu']}")
                log_info(f"   原因: {recommendations['reason']}")
                
                confirm = input("是否应用 ChatGPT 优化参数？[Y/n]: ").strip().lower()
                if confirm not in ("n", "no"):
                    keepalive_value = str(recommendations["keepalive"])
                    desktop_mtu = str(recommendations["mtu"])
                    log_success("✅ 已应用 ChatGPT 优化参数")
            else:
                log_info("→ 当前参数已适合 ChatGPT，无需调整")
        except Exception as exc:
            log_warning(f"⚠️ 获取优化建议失败：{exc}")
        
        # 生成分流配置
        log_info("→ 生成分流配置文件...")
        try:
            split_config = optimizer.generate_split_config()
            log_success(f"✅ 分流配置已生成：{split_config}")
            log_info("→ 提示：将此配置部署到服务器以启用 ChatGPT 分流")
        except Exception as exc:
            log_warning(f"⚠️ 生成分流配置失败：{exc}")
        
        log_info("")

    default_key_prompt = _default_private_key_prompt()
    key_path = Path(ask_key_path(default_key_prompt)).expanduser()
    log_info(f"→ 使用私钥：{key_path}")

    try:
        _clean_known_host(ip)
    except Exception as exc:  # noqa: BLE001 - cleanup is best effort
        log_warning(f"⚠️ 清理 known_hosts 时出现问题：{exc}")

    try:
        log_info("→ 第一阶段：检测 SSH 端口 22 是否开放（每 20 秒，最长等待 20 分钟）…")
        if not _wait_for_port_22(ip, interval=20):
            _print_manual_ssh_hint()
            raise DeploymentError("未检测到 VPS SSH 端口开放。")

        log_info("→ 第二阶段：校验免密 SSH 是否可用…")
        if not _wait_for_passwordless_ssh(ip, key_path):
            _print_manual_ssh_hint()
            raise DeploymentError("免密 SSH 校验失败，请确认公钥已写入 VPS。")

        log_success("✅ 公钥认证已生效。")

        _set_ssh_context(ip, key_path)
        remote_script = deploy_wireguard_remote_script(
            LISTEN_PORT,
            desktop_ip,
            iphone_ip,
            ip,
            dns_value,
            allowed_ips,
            desktop_mtu,
            keepalive_value,
            enable_v2ray=enable_v2ray,
            v2ray_port=v2ray_port,
            v2ray_uuid=v2ray_uuid,
        )
        script_payload = (
            "cat <<'EOS' >/tmp/privatetunnel-wireguard.sh\n"
            f"{remote_script}\n"
            "EOS\n"
        )
        env_dict = {
            "WG_PORT": str(LISTEN_PORT),
            "PT_DESKTOP_IP": desktop_ip,
            "PT_IPHONE_IP": iphone_ip,
            "PT_DNS": dns_value,
            "PT_ALLOWED_IPS": allowed_ips,
            "PT_CLIENT_MTU": desktop_mtu,
            "PT_KEEPALIVE": keepalive_value,
        }
        if enable_v2ray:
            env_dict["PT_ENABLE_V2RAY"] = "true"
            env_dict["PT_V2RAY_PORT"] = str(v2ray_port)
            if v2ray_uuid:
                env_dict["PT_V2RAY_UUID"] = v2ray_uuid
        
        env_parts = [
            f"{key}={shlex.quote(value)}"
            for key, value in env_dict.items()
            if value
        ]
        env_prefix = " ".join(env_parts)
        # 使用nohup后台执行脚本，然后定期检查状态
        log_file = "/tmp/privatetunnel-wireguard.log"
        pid_file = "/tmp/privatetunnel-wireguard.pid"
        
        # 先上传脚本（增加重试机制）
        upload_cmd = script_payload
        _ssh_run(upload_cmd, timeout=60, description="上传部署脚本", max_retries=3)
        
        # 后台启动脚本（增加重试机制）
        start_cmd = (
            f"{env_prefix + ' ' if env_prefix else ''}nohup bash /tmp/privatetunnel-wireguard.sh "
            f"> {log_file} 2>&1 & echo $! > {pid_file}"
        )
        log_info("→ 开始部署 WireGuard 服务端（后台执行模式）…")
        log_info("→ 脚本已在后台启动，正在监控部署进度…")
        log_info("")
        
        _ssh_run(start_cmd, timeout=60, description="启动部署脚本", max_retries=3)
        
        # 等待脚本启动
        time.sleep(2)
        
        # 定期检查部署状态
        max_wait_time = 3600  # 最长等待1小时
        # 根据网络环境调整检查间隔（可通过环境变量覆盖）
        check_interval = int(os.environ.get("PT_DEPLOY_CHECK_INTERVAL", "30"))  # 从15秒增加到30秒
        start_time = time.time()
        result: SSHResult | None = None
        last_status = ""  # 记录上次显示的状态，避免重复
        check_count = 0
        consecutive_failures = 0  # 连续失败次数
        max_consecutive_failures = 20  # 允许连续失败20次（约10分钟）
        
        while time.time() - start_time < max_wait_time:
            elapsed = int(time.time() - start_time)
            remaining = int(max_wait_time - (time.time() - start_time))
            check_count += 1
            
            try:
                # 检查进程是否还在运行（增加重试机制）
                check_pid_cmd = f"test -f {pid_file} && cat {pid_file} || echo ''"
                pid_result = _ssh_run(check_pid_cmd, timeout=20, description="检查进程ID", max_retries=2)
                consecutive_failures = 0  # 成功时重置计数器
                pid = pid_result.stdout.strip()
                
                if pid:
                    # 检查进程是否还在运行（增加重试机制）
                    check_process_cmd = f"ps -p {pid} > /dev/null 2>&1 && echo 'running' || echo 'stopped'"
                    process_result = _ssh_run(check_process_cmd, timeout=20, description="检查进程状态", max_retries=2)
                    is_running = "running" in process_result.stdout
                    
                    if not is_running:
                        # 进程已结束，读取日志（增加重试机制）
                        log_info(f"  ⏱️ [{elapsed}秒] 部署脚本执行完成，正在读取结果…")
                        log_cmd = f"cat {log_file} 2>/dev/null || echo ''"
                        log_result = _ssh_run(log_cmd, timeout=60, description="读取部署日志", max_retries=3)
                        result = SSHResult(
                            returncode=0,
                            stdout=log_result.stdout,
                            stderr=log_result.stderr,
                            backend="openssh"
                        )
                        break
                    else:
                        # 进程还在运行，读取最新日志（增加重试机制，但失败时不影响主流程）
                        log_cmd = f"tail -n 20 {log_file} 2>/dev/null || echo ''"
                        try:
                            log_result = _ssh_run(log_cmd, timeout=20, description="读取最新日志", max_retries=2)
                        except DeploymentError:
                            # 读取日志失败不影响主流程，继续等待
                            if check_count % 4 == 0:  # 每2分钟显示一次
                                log_warning(f"  ⚠️ [{elapsed}秒] 无法读取日志（网络可能不稳定），继续等待…")
                            time.sleep(check_interval)
                            continue
                        current_log = log_result.stdout
                        
                        # 显示最新日志内容
                        if current_log:
                            lines = current_log.split('\n')
                            # 提取关键日志行（包含时间戳、状态信息等）
                            important_lines = []
                            for line in lines:
                                line = line.strip()
                                if not line:
                                    continue
                                # 显示包含时间戳、状态标记或关键信息的行
                                if any(marker in line for marker in ['[20', 'log', 'warn', 'err', '✅', '⚠️', '❌', '安装', '配置', 'WireGuard', 'apt-get', 'systemctl']):
                                    important_lines.append(line)
                            
                            if important_lines:
                                # 只显示最后几条重要日志，避免刷屏
                                display_lines = important_lines[-2:]  # 只显示最后2行
                                for line in display_lines:
                                    if line and line not in last_status:
                                        log_info(f"    {line}")
                                        last_status = line if len(last_status) < 100 else ""  # 限制状态缓存大小
                            else:
                                # 如果没有重要日志，显示简单状态
                                if check_count % 4 == 0:  # 每60秒显示一次简单状态
                                    log_info(f"  ⏱️ [{elapsed}秒] 部署进行中（剩余约 {remaining}秒）…")
                else:
                    # PID文件不存在，可能脚本已经完成（增加重试机制）
                    log_info(f"  ⏱️ [{elapsed}秒] 检查部署状态…")
                    log_cmd = f"cat {log_file} 2>/dev/null || echo ''"
                    try:
                        log_result = _ssh_run(log_cmd, timeout=60, description="读取部署日志", max_retries=3)
                    except DeploymentError:
                        # 读取失败时继续等待
                        if check_count % 4 == 0:
                            log_warning(f"  ⚠️ [{elapsed}秒] 无法读取日志，继续等待…")
                        time.sleep(check_interval)
                        continue
                    if log_result.stdout.strip():
                        result = SSHResult(
                            returncode=0,
                            stdout=log_result.stdout,
                            stderr=log_result.stderr,
                            backend="openssh"
                        )
                        break
                    else:
                        # 日志文件不存在或为空，继续等待
                        log_info(f"  ⏱️ [{elapsed}秒] 等待脚本启动…")
                
                # 检查WireGuard服务状态（增加重试机制）
                wg_check_cmd = "systemctl is-active wg-quick@wg0 2>/dev/null || echo 'inactive'"
                try:
                    wg_result = _ssh_run(wg_check_cmd, timeout=20, description="检查WireGuard服务", max_retries=2)
                except DeploymentError:
                    # 检查失败时继续等待，不立即失败
                    if check_count % 4 == 0:
                        log_warning(f"  ⚠️ [{elapsed}秒] 无法检查WireGuard服务状态，继续等待…")
                    time.sleep(check_interval)
                    continue
                if wg_result.stdout.strip() == "active":
                    log_success(f"  ✅ [{elapsed}秒] WireGuard 服务已启动！")
                    # 读取完整日志（增加重试机制）
                    log_cmd = f"cat {log_file} 2>/dev/null || echo ''"
                    log_result = _ssh_run(log_cmd, timeout=60, description="读取完整日志", max_retries=3)
                    result = SSHResult(
                        returncode=0,
                        stdout=log_result.stdout,
                        stderr=log_result.stderr,
                        backend="openssh"
                    )
                    break
                    
            except DeploymentError as exc:
                consecutive_failures += 1
                if consecutive_failures >= max_consecutive_failures:
                    # 连续失败太多次，可能网络完全不可用
                    log_error(f"❌ 连续 {max_consecutive_failures} 次检查失败，网络可能完全不可用")
                    log_error(f"   建议：1) 检查网络连接 2) 使用代理（设置环境变量 SSH_PROXY） 3) 手动SSH到VPS完成部署")
                    raise DeploymentError(f"网络连接不稳定，无法完成部署检查（连续失败 {consecutive_failures} 次）") from exc
                
                # 记录错误但继续等待（减少日志输出频率）
                if check_count % 4 == 0:  # 每2分钟显示一次
                    log_warning(f"  ⚠️ [{elapsed}秒] 检查失败（{consecutive_failures}/{max_consecutive_failures}）：{exc}，继续等待…")
            except Exception as exc:
                consecutive_failures += 1
                if check_count % 4 == 0:
                    log_warning(f"  ⚠️ [{elapsed}秒] 检查状态时出错：{exc}，继续等待…")
            
            # 等待下一次检查
            time.sleep(check_interval)
        else:
            # 超时
            log_error(f"❌ 部署超时（{max_wait_time}秒）")
            log_error("   可能原因：1) 网络连接不稳定 2) NVIDIA驱动安装阻塞 3) 部署脚本执行时间过长")
            log_error("   建议：1) 使用代理（设置环境变量 SSH_PROXY） 2) 手动SSH到VPS检查部署状态")
            try:
                log_cmd = f"tail -n 50 {log_file} 2>/dev/null || echo '无法读取日志'"
                log_result = _ssh_run(log_cmd, timeout=60, description="读取超时前的日志", max_retries=3)
                raise DeploymentError(
                    f"部署超时（{max_wait_time}秒）。最后日志：\n{log_result.stdout[:500]}"
                )
            except Exception as exc:
                raise DeploymentError(
                    f"部署超时（{max_wait_time}秒），且无法读取日志：{exc}"
                ) from exc
        
        # 清理临时文件（清理失败不影响主流程，但也要支持重试）
        try:
            cleanup_cmd = f"rm -f {pid_file} {log_file} /tmp/privatetunnel-wireguard.sh"
            _ssh_run(cleanup_cmd, timeout=20, description="清理临时文件", max_retries=2)
        except Exception:
            pass  # 清理失败不影响主流程
        
        log_info("")  # 空行分隔

        if result is None:
            raise DeploymentError("部署过程中未能获取结果，请检查远程服务器状态。")

        summary: dict[str, str] = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            prefixes = ("SERVER_", "DESKTOP_", "IPHONE_", "ENDPOINT=", "WAN_IF=", "V2RAY_")
            if any(line.startswith(prefix) for prefix in prefixes):
                key, _, value = line.partition("=")
                summary[key] = value.strip()

        server_pub = summary.get("SERVER_PUBLIC_KEY", "")
        desktop_pub = summary.get("DESKTOP_PUBLIC_KEY", "")
        iphone_pub = summary.get("IPHONE_PUBLIC_KEY", "")
        endpoint = summary.get("ENDPOINT", f"{ip}:{LISTEN_PORT}")
        wan_if = summary.get("WAN_IF", "")
        
        # 从部署输出中提取 V2Ray 信息
        v2ray_enabled = summary.get("V2RAY_ENABLED", "false").lower() == "true"
        v2ray_port = summary.get("V2RAY_PORT", "")
        v2ray_uuid = summary.get("V2RAY_UUID", "")

        log_success("✅ 远端 WireGuard 已成功部署并完成 NAT/转发配置。")
        if wan_if:
            log_info(f"→ 外网接口：{wan_if}")

        artifacts_dir = ARTIFACTS_DIR
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        desktop_conf_local = artifacts_dir / "desktop.conf"
        iphone_conf_local = artifacts_dir / "iphone.conf"
        iphone_png_local = artifacts_dir / "iphone.png"

        remote_desktop_conf = "/etc/wireguard/clients/desktop/desktop.conf"
        remote_iphone_conf = "/etc/wireguard/clients/iphone/iphone.conf"
        remote_iphone_png = "/etc/wireguard/clients/iphone/iphone.png"

        log_info("→ 校验远端桌面端配置是否生成…")
        _ensure_remote_artifact(remote_desktop_conf, "桌面端配置文件")
        log_info("→ 校验远端 iPhone 配置是否生成…")
        _ensure_remote_artifact(remote_iphone_conf, "iPhone 配置文件")
        log_info("→ 校验远端 iPhone 二维码是否生成…")
        _ensure_remote_artifact(remote_iphone_png, "iPhone 二维码")

        log_info(f"→ 下载桌面端配置到 {desktop_conf_local}")
        try:
            _download_artifact(remote_desktop_conf, desktop_conf_local)
        except DeploymentError as exc:
            raise DeploymentError(
                "下载桌面端配置失败，请手动检查 /etc/wireguard/clients/desktop/desktop.conf。"
            ) from exc

        log_info(f"→ 下载 iPhone 配置到 {iphone_conf_local}")
        try:
            _download_artifact(remote_iphone_conf, iphone_conf_local)
        except DeploymentError as exc:
            raise DeploymentError(
                "下载 iPhone 配置失败，请手动检查 /etc/wireguard/clients/iphone/iphone.conf。"
            ) from exc

        log_info(f"→ 下载 iPhone 二维码到 {iphone_png_local}")
        try:
            _download_artifact(remote_iphone_png, iphone_png_local)
        except DeploymentError as exc:
            raise DeploymentError(
                "下载 iPhone 二维码失败，请检查远端 /etc/wireguard/clients/iphone/iphone.png。"
            ) from exc

        log_success(f"✅ 已下载 iPhone 二维码：{iphone_png_local}")

        # 下载 V2Ray 客户端配置（如果启用）
        enable_v2ray_check = os.environ.get("PT_ENABLE_V2RAY", "").strip().lower() in ("true", "1", "yes")
        if enable_v2ray_check:
            log_info("→ 下载 V2Ray 客户端配置…")
            
            v2ray_client_dir = artifacts_dir / "v2ray"
            v2ray_client_dir.mkdir(parents=True, exist_ok=True)
            
            # 下载桌面端 V2Ray 配置
            remote_v2ray_desktop = "/etc/wireguard/clients/v2ray/desktop.json"
            v2ray_desktop_local = v2ray_client_dir / "desktop.json"
            try:
                _ensure_remote_artifact(remote_v2ray_desktop, "桌面端 V2Ray 配置")
                _download_artifact(remote_v2ray_desktop, v2ray_desktop_local)
                log_success(f"✅ 已下载桌面端 V2Ray 配置：{v2ray_desktop_local}")
            except DeploymentError as exc:
                log_warning(f"⚠️ 下载桌面端 V2Ray 配置失败：{exc}")
            
            # 下载 iPhone 端 V2Ray 配置
            remote_v2ray_iphone = "/etc/wireguard/clients/v2ray/iphone.json"
            v2ray_iphone_local = v2ray_client_dir / "iphone.json"
            try:
                _ensure_remote_artifact(remote_v2ray_iphone, "iPhone V2Ray 配置")
                _download_artifact(remote_v2ray_iphone, v2ray_iphone_local)
                log_success(f"✅ 已下载 iPhone V2Ray 配置：{v2ray_iphone_local}")
            except DeploymentError as exc:
                log_warning(f"⚠️ 下载 iPhone V2Ray 配置失败：{exc}")
            
            # 下载 VMess URL
            remote_vmess_url = "/etc/wireguard/clients/v2ray/vmess-url.txt"
            vmess_url_local = v2ray_client_dir / "vmess-url.txt"
            try:
                _ensure_remote_artifact(remote_vmess_url, "VMess URL")
                _download_artifact(remote_vmess_url, vmess_url_local)
                log_success(f"✅ 已下载 VMess URL：{vmess_url_local}")
            except DeploymentError as exc:
                log_warning(f"⚠️ 下载 VMess URL 失败：{exc}")

        for path in (desktop_conf_local, iphone_conf_local, iphone_png_local):
            if not path.exists():
                raise DeploymentError(f"本地文件缺失：{path}")

        def _rel(path: Path) -> str:
            try:
                return str(path.relative_to(ROOT))
            except ValueError:
                return str(path)

        log_success("✅ WireGuard 部署完成，并已下载客户端配置：")
        log_success(f"   - {desktop_conf_local}")
        log_success(f"   - {iphone_conf_local}")
        log_success(f"   - {iphone_png_local}")
        log_success(f"✅ Windows 客户端配置：{_rel(desktop_conf_local)}")
        log_success(f"✅ iPhone 配置：{_rel(iphone_conf_local)}")
        log_success(f"✅ iPhone 二维码：{_rel(iphone_png_local)}")

        server_info: dict[str, Any] = {
            "id": instance_id,
            "ip": ip,
            "server_pub": server_pub,
            "platform": SELECTED_PLATFORM or "",
            "endpoint": endpoint,
            "desktop_ip": desktop_ip,
            "iphone_ip": iphone_ip,
            "desktop_public_key": desktop_pub,
            "iphone_public_key": iphone_pub,
            "desktop_config": str(desktop_conf_local),
            "iphone_config": str(iphone_conf_local),
            "iphone_qr": str(iphone_png_local),
            "allowed_ips": allowed_ips,
            "dns": dns_value,
            "deploy_log": str(deploy_log_path),
            "v2ray_enabled": v2ray_enabled,
        }
        if wan_if:
            server_info["wan_interface"] = wan_if
        
        if v2ray_enabled:
            server_info["v2ray_port"] = v2ray_port
            server_info["v2ray_uuid"] = v2ray_uuid
            server_info["v2ray_ws_path"] = "/ray"
            # V2Ray 配置文件路径
            v2ray_client_dir = artifacts_dir / "v2ray"
            if (v2ray_client_dir / "desktop.json").exists():
                server_info["v2ray_desktop_config"] = str(v2ray_client_dir / "desktop.json")
            if (v2ray_client_dir / "iphone.json").exists():
                server_info["v2ray_iphone_config"] = str(v2ray_client_dir / "iphone.json")
            if (v2ray_client_dir / "vmess-url.txt").exists():
                server_info["v2ray_vmess_url"] = str(v2ray_client_dir / "vmess-url.txt")
        _update_server_info(server_info)

        log_info("验证指南：")
        log_info(f"  1. Windows 打开 WireGuard 导入 {_rel(desktop_conf_local)} 并连接。")
        log_info("  2. 连接后运行：curl -4 ifconfig.me / curl -6 ifconfig.me，应显示 VPS 公网地址。")
        log_info(
            "  3. 若能获取公网 IP 但无法上网，请检查代理/安全软件；如丢包，可继续使用默认 MTU={value}。".format(
                value=DEFAULT_CLIENT_MTU
            )
        )
        
        # V2Ray 使用指南（如果启用）
        if enable_v2ray_check:
            v2ray_client_dir = artifacts_dir / "v2ray"
            log_info("")
            log_info("=" * 50)
            log_info("V2Ray 客户端使用指南：")
            log_info("=" * 50)
            log_info("")
            log_info("📱 Windows 客户端：")
            log_info("  1. 下载 V2RayN 或 V2RayNG：")
            log_info("     - V2RayN: https://github.com/2dust/v2rayN/releases")
            log_info("     - V2RayNG: https://github.com/2dust/v2rayNG/releases")
            log_info("  2. 导入配置文件：")
            if (v2ray_client_dir / "desktop.json").exists():
                log_info(f"     - 方式1：导入 JSON 文件 {_rel(v2ray_client_dir / 'desktop.json')}")
            if (v2ray_client_dir / "vmess-url.txt").exists():
                log_info(f"     - 方式2：导入 VMess URL（从 {_rel(v2ray_client_dir / 'vmess-url.txt')} 复制）")
            log_info("  3. 启动 V2Ray 客户端，设置系统代理或浏览器代理")
            log_info("  4. 测试连接：访问 https://www.google.com")
            log_info("")
            log_info("📱 iPhone 客户端：")
            log_info("  1. 安装 Shadowrocket 或 Quantumult X（需要美区 App Store）")
            log_info("  2. 导入配置：")
            if (v2ray_client_dir / "iphone.json").exists():
                log_info(f"     - 方式1：导入 JSON 文件 {_rel(v2ray_client_dir / 'iphone.json')}")
            if (v2ray_client_dir / "vmess-url.txt").exists():
                log_info(f"     - 方式2：扫描 VMess URL 二维码（从 {_rel(v2ray_client_dir / 'vmess-url.txt')} 生成）")
            log_info("  3. 启用代理并测试连接")
            log_info("")
            log_info("⚠️  注意：")
            log_info("  - V2Ray 和 WireGuard 是独立的代理方案")
            log_info("  - V2Ray 用于流量伪装，WireGuard 用于 VPN 连接")
            log_info("  - 可以同时使用，也可以单独使用 V2Ray")
            log_info("  - 使用自签名证书，首次连接需要接受证书警告")
            log_info("")

        _desktop_usage_tip()
        log_info(f"→ 部署日志已保存至 {deploy_log_path}")

        # 如果启用连接监控，启动监控
        enable_monitoring = os.environ.get("PT_ENABLE_MONITORING", "").strip().lower() in ("true", "1", "yes")

        if enable_monitoring:
            from core.tools.connection_monitor import ConnectionMonitor
            from core.tools.connection_stats import ConnectionMetrics

            log_info("")
            log_section("📊 启动连接质量监控")

            # 确定节点 ID
            monitor_node_id = None
            if use_multi_node and selected_node_id:
                monitor_node_id = selected_node_id
            else:
                # 单节点模式，使用实例 ID
                monitor_node_id = instance_id[:8] if instance_id else "default"

            monitor = ConnectionMonitor(
                node_id=monitor_node_id,
                node_ip=ip,
                wireguard_port=LISTEN_PORT,
                check_interval=int(os.environ.get("PT_MONITOR_INTERVAL", "30")),
                enable_adaptive=enable_adaptive,  # 启用自适应调整
            )

            # 设置回调
            def on_metrics_update(metrics: ConnectionMetrics):
                log_info(
                    f"📊 连接指标更新：延迟={metrics.latency_ms:.2f}ms, "
                    f"丢包率={metrics.packet_loss_rate*100:.2f}%"
                    if metrics.latency_ms
                    else f"📊 连接指标更新：延迟=N/A, 丢包率={metrics.packet_loss_rate*100:.2f}%"
                )

            def on_quality_degraded(metrics: ConnectionMetrics):
                log_warning(
                    f"⚠️ 连接质量下降：延迟={metrics.latency_ms:.2f}ms, "
                    f"丢包率={metrics.packet_loss_rate*100:.2f}%"
                    if metrics.latency_ms
                    else f"⚠️ 连接质量下降：延迟=N/A, 丢包率={metrics.packet_loss_rate*100:.2f}%"
                )

            def on_params_adjusted(info: dict[str, Any]):
                adjustment = info["adjustment"]
                log_info(f"🔧 参数已自动调整：")
                log_info(f"   Keepalive: {adjustment['old_params']['keepalive']} → {adjustment['new_params']['keepalive']}")
                log_info(f"   MTU: {adjustment['old_params']['mtu']} → {adjustment['new_params']['mtu']}")
                log_info(f"   原因: {adjustment['reason']}")
                log_warning("⚠️ 请重新部署配置以应用新参数")

            monitor.on_metrics_update = on_metrics_update
            monitor.on_quality_degraded = on_quality_degraded
            if enable_adaptive:
                monitor.on_params_adjusted = on_params_adjusted

            monitor.start_monitoring()

            # 保存监控器引用（可选，用于后续停止）
            # 可以保存到全局变量或配置中

            log_success("✅ 连接质量监控已启动")
            if enable_adaptive:
                log_success("✅ 自适应参数调整已启用")
            log_info("→ 提示：设置环境变量 PT_ENABLE_MONITORING=true 启用监控")
            log_info("→ 提示：设置环境变量 PT_ENABLE_ADAPTIVE=true 启用自适应调整")
            log_info(f"→ 监控间隔：{monitor.check_interval} 秒")
            log_info(f"→ 统计数据目录：{monitor.data_dir}")
    except DeploymentError as exc:
        log_error(f"❌ 部署失败：{exc}")
        log_info(f"→ 详细日志：{deploy_log_path}")
    finally:
        _close_paramiko_client()
        global SSH_CTX
        SSH_CTX = None


MENU_ACTIONS: tuple[MenuAction, ...] = (
    MenuAction("1", "检查本机环境（Windows/macOS）", run_environment_check),
    MenuAction("2", "创建 VPS（Vultr）", create_vps),
    MenuAction("3", "准备本机接入 VPS 网络", prepare_wireguard_access),
    MenuAction("4", "检查账户中的 Vultr 实例", inspect_vps_inventory),
    MenuAction("5", "打开图形界面", launch_gui),
    MenuAction("6", "多节点管理", manage_nodes),
    MenuAction("7", "节点健康检查", check_nodes_health),
    MenuAction("8", "智能节点选择", smart_node_selection),
    MenuAction("9", "连接质量报告", view_connection_report),
    MenuAction("10", "参数调整建议", view_parameter_recommendations),
    MenuAction("11", "ChatGPT 连接测试", test_chatgpt_connection),
)

EXIT_CHOICES = {"q", "quit", "exit"}


def _print_main_menu() -> None:
    """Render the interactive menu in a consistent order."""

    print("\n=== PrivateTunnel 桌面助手 ===")
    for action in MENU_ACTIONS:
        print(f"{action.key}) {action.description}")
    print("q) 退出")


def main() -> None:
    try:
        overview_path = generate_project_overview(ROOT, ARTIFACTS_DIR / "project_overview.md")
        log_info(f"→ 已生成项目功能概览：{overview_path}")
    except Exception as exc:  # noqa: BLE001 - 后台任务失败不应阻止主流程
        log_warning(f"⚠️ 生成项目功能概览失败：{exc}")

    while True:
        _print_main_menu()
        choice = input("请选择: ").strip().lower()
        if choice in EXIT_CHOICES:
            break
        for action in MENU_ACTIONS:
            if choice == action.key:
                action.handler()
                break
        else:
            print("无效选项，请重试。")


if __name__ == "__main__":
    main()
