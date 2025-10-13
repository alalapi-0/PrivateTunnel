"""Utilities for working with SSH connections and private keys."""

from __future__ import annotations

import os
import platform
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

import paramiko


class SSHKeyLoadError(RuntimeError):
    """Raised when a private key cannot be parsed."""


class SmartSSHError(RuntimeError):
    """Raised when both Paramiko and ``ssh.exe`` backends fail."""

    def __init__(self, message: str, attempts: List["SSHAttempt"]):
        super().__init__(message)
        self.attempts = attempts


@dataclass
class SSHAttempt:
    """Metadata about one backend attempt."""

    backend: str
    error: str
    stdout: str = ""
    stderr: str = ""
    returncode: Optional[int] = None


@dataclass
class SSHResult:
    """Return value for :func:`smart_ssh`."""

    backend: str
    returncode: int
    stdout: str
    stderr: str


def _candidate_keys() -> Iterable[type[paramiko.PKey]]:
    """Yield supported Paramiko key classes in preferred order."""

    return (
        paramiko.Ed25519Key,
        paramiko.ECDSAKey,
        paramiko.RSAKey,
    )


def load_private_key(path: str | os.PathLike[str]) -> paramiko.PKey:
    """Load a private key from ``path``.

    Keys are attempted in the order Ed25519 → ECDSA → RSA.  DSA keys are
    deliberately unsupported because Paramiko 3.x removed ``DSSKey``.
    """

    key_path = Path(path).expanduser()
    if key_path.is_dir():
        raise SSHKeyLoadError(f"给定的私钥路径是目录：{key_path}")

    if not key_path.exists():
        raise SSHKeyLoadError(f"私钥文件不存在：{key_path}")

    errors: list[str] = []
    for key_cls in _candidate_keys():
        try:
            return key_cls.from_private_key_file(str(key_path))
        except paramiko.PasswordRequiredException as exc:
            raise SSHKeyLoadError("私钥受口令保护，请先解锁或改用密码登录。") from exc
        except paramiko.SSHException as exc:
            errors.append(str(exc))

    joined = "; ".join(filter(None, errors)) or "未知错误"
    raise SSHKeyLoadError(f"无法解析私钥文件 {key_path}: {joined}")


def smart_ssh(
    host: str,
    username: str,
    key_path: str | os.PathLike[str],
    command: str,
    *,
    port: int = 22,
    timeout: int = 20,
    ssh_executable: Optional[str] = None,
) -> SSHResult:
    """Execute ``command`` on ``host`` using either Paramiko or ``ssh.exe``.

    The function first tries Paramiko.  If Paramiko fails (for example due to a
    transport negotiation issue), it falls back to invoking the local ``ssh``
    binary.  The first backend that executes the command successfully is
    returned.  If both backends fail an exception is raised containing the
    individual errors.
    """

    key_path = Path(key_path).expanduser()
    if key_path.is_dir():
        raise SmartSSHError(f"私钥路径指向目录：{key_path}", [])

    attempts: List[SSHAttempt] = []

    # 1. Try Paramiko
    try:
        pkey = load_private_key(key_path)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                host,
                port=port,
                username=username,
                pkey=pkey,
                allow_agent=False,
                look_for_keys=False,
                timeout=timeout,
                banner_timeout=timeout,
                auth_timeout=timeout,
            )
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            _ = stdin.channel  # keep reference to avoid premature close
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            rc = stdout.channel.recv_exit_status()
            return SSHResult("paramiko", rc, out, err)
        finally:
            client.close()
    except Exception as exc:  # noqa: BLE001 - intentionally broad for fallback
        attempts.append(SSHAttempt("paramiko", str(exc)))

    # 2. Fallback to system ssh
    if ssh_executable is None:
        ssh_executable = "ssh.exe" if platform.system().lower().startswith("win") else "ssh"

    ssh_cmd = [
        ssh_executable,
        "-i",
        str(key_path),
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-p",
        str(port),
        f"{username}@{host}",
        command,
    ]

    try:
        proc = subprocess.run(
            ssh_cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout if timeout > 0 else None,
        )
        return SSHResult("ssh.exe", proc.returncode, proc.stdout, proc.stderr)
    except FileNotFoundError as exc:
        attempts.append(SSHAttempt("ssh.exe", f"找不到 ssh 客户端：{exc}"))
    except subprocess.TimeoutExpired as exc:
        attempts.append(SSHAttempt("ssh.exe", f"ssh.exe 超时：{exc}", returncode=None))
    except Exception as exc:  # noqa: BLE001 - fallback diagnostics
        attempts.append(SSHAttempt("ssh.exe", str(exc)))

    error_lines = [f"{att.backend}: {att.error}" for att in attempts]
    raise SmartSSHError("SSH 调用失败；详见 attempts", attempts) from None


__all__ = [
    "SSHAttempt",
    "SSHKeyLoadError",
    "SSHResult",
    "SmartSSHError",
    "load_private_key",
    "smart_ssh",
]

