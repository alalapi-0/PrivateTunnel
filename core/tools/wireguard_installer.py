"""WireGuard provisioning helpers."""

from __future__ import annotations

from dataclasses import dataclass
import json
import socket
import textwrap
from typing import Optional

import paramiko


@dataclass
class _CommandResult:
    exit_status: int
    stdout: str
    stderr: str


class WireGuardProvisionError(RuntimeError):
    """Raised when provisioning fails."""


def _load_private_key(path: str) -> paramiko.PKey:
    errors: list[str] = []
    for key_cls in (
        paramiko.RSAKey,
        paramiko.ECDSAKey,
        paramiko.Ed25519Key,
        paramiko.DSSKey,
    ):
        try:
            return key_cls.from_private_key_file(path)
        except FileNotFoundError as exc:  # pragma: no cover - file missing
            raise WireGuardProvisionError(f"私钥文件不存在: {path}") from exc
        except paramiko.PasswordRequiredException as exc:
            raise WireGuardProvisionError(
                "私钥受口令保护，请先解锁或改用密码登录。"
            ) from exc
        except paramiko.SSHException as exc:
            errors.append(str(exc))
    joined = "; ".join(errors) or "未知错误"
    raise WireGuardProvisionError(f"无法解析私钥文件 {path}: {joined}")


def _run(client: paramiko.SSHClient, command: str) -> _CommandResult:
    stdin, stdout, stderr = client.exec_command(command)
    _ = stdin.channel  # keep reference so GC does not close channel early
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    exit_status = stdout.channel.recv_exit_status()
    return _CommandResult(exit_status, out, err)


def _run_checked(client: paramiko.SSHClient, command: str, description: str) -> str:
    result = _run(client, command)
    if result.exit_status != 0:
        err_tail = (result.stderr or result.stdout)[-600:]
        raise WireGuardProvisionError(
            f"远端执行失败：{description}\n命令: {command}\n输出: {err_tail.strip()}"
        )
    return result.stdout


def provision(
    ip: str,
    username: str = "root",
    password: Optional[str] = None,
    pkey_path: Optional[str] = None,
    port: int = 22,
    timeout: int = 20,
) -> dict:
    """Provision WireGuard on a remote instance via SSH."""

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    pkey: Optional[paramiko.PKey] = None
    if pkey_path:
        pkey = _load_private_key(pkey_path)

    try:
        client.connect(
            ip,
            port=port,
            username=username,
            password=password,
            pkey=pkey,
            allow_agent=False,
            look_for_keys=False,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
        )
    except paramiko.AuthenticationException as exc:  # pragma: no cover - network
        raise WireGuardProvisionError(
            "SSH 认证失败，请检查密码/私钥是否正确，以及本机是否允许访问目标 22 端口。"
        ) from exc
    except (paramiko.SSHException, socket.error) as exc:  # pragma: no cover - network
        raise WireGuardProvisionError(
            f"无法建立 SSH 连接：{exc}. 请确认实例可达且防火墙已放行 22 端口。"
        ) from exc

    try:
        setup_script = textwrap.dedent(
            """
            set -euo pipefail
            export DEBIAN_FRONTEND=noninteractive
            apt update -y
            apt install -y wireguard wireguard-tools qrencode iptables-persistent
            mkdir -p /etc/wireguard
            umask 077
            wg genkey | tee /etc/wireguard/server.private | wg pubkey > /etc/wireguard/server.public
            SERVER_PRIV=$(cat /etc/wireguard/server.private)
            cat >/etc/wireguard/wg0.conf <<EOF
            [Interface]
            Address = 10.6.0.1/24
            ListenPort = 51820
            PrivateKey = ${SERVER_PRIV}
            SaveConfig = true
            EOF
            sysctl -w net.ipv4.ip_forward=1
            WAN_IF=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
            iptables -t nat -C POSTROUTING -s 10.6.0.0/24 -o "$WAN_IF" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.6.0.0/24 -o "$WAN_IF" -j MASQUERADE
            netfilter-persistent save || true
            systemctl enable wg-quick@wg0
            systemctl restart wg-quick@wg0
            """
        )
        _run_checked(
            client,
            f"bash -lc {json.dumps(setup_script)}",
            "执行 WireGuard 部署脚本",
        )

        status_out = _run_checked(
            client,
            "systemctl is-active wg-quick@wg0",
            "检查 WireGuard 服务状态",
        ).strip()
        if status_out != "active":
            raise WireGuardProvisionError(
                f"WireGuard 服务未处于 active 状态（当前: {status_out}）。"
            )

        _run_checked(
            client,
            "ss -lun | grep -m1 ':51820'",
            "验证 UDP 端口 51820 是否监听",
        )

        server_pub = _run_checked(
            client,
            "cat /etc/wireguard/server.public",
            "读取服务端公钥",
        ).strip()

        return {"server_pub": server_pub, "port": 51820}
    except WireGuardProvisionError as exc:
        hints = (
            "排查建议：\n"
            "- 检查密码/私钥是否正确且拥有 600 权限\n"
            "- 确认本机到 VPS 的 22 端口连通，必要时检查防火墙\n"
            "- 登录 VPS 手动执行安装步骤以获取更多提示"
        )
        message = str(exc)
        if "排查建议" not in message:
            message = f"{message}\n{hints}"
        raise WireGuardProvisionError(message) from None
    except Exception as exc:  # pragma: no cover - defensive
        raise WireGuardProvisionError(f"部署过程中出现未预期错误：{exc}") from exc
    finally:
        client.close()

