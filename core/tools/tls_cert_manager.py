from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class TLSCertInfo:
    cert_path: Path
    key_path: Path


class TLSCertManager:
    """Manage TLS certificate lifecycle on the remote host."""

    def __init__(self, ssh_client, cert_dir: str):
        self.ssh = ssh_client
        self.cert_dir = Path(cert_dir)

    def _remote_path(self, filename: str) -> Path:
        return self.cert_dir / filename

    def ensure_cert_for_domain(self, domain: str, use_self_signed: bool = True) -> TLSCertInfo:
        """Ensure certificate and key exist for ``domain``.

        The initial implementation relies on a self-signed certificate. A future
        iteration can extend this method to request certificates from ACME
        providers such as Let's Encrypt.
        """

        cert_path = self._remote_path(f"{domain}.crt")
        key_path = self._remote_path(f"{domain}.key")

        logger.info("检查 TLS 证书：%s", cert_path)
        sftp = self.ssh.open_sftp()
        try:
            sftp.stat(str(cert_path))
            sftp.stat(str(key_path))
            logger.info("证书已存在，复用现有文件")
            return TLSCertInfo(cert_path=cert_path, key_path=key_path)
        except FileNotFoundError:
            logger.info("未找到现有证书，准备生成自签名证书")
        finally:
            sftp.close()

        if not use_self_signed:
            raise RuntimeError("未实现的证书获取方式：ACME/Let’s Encrypt TODO")

        commands = [
            f"mkdir -p {self.cert_dir}",
            (
                "openssl req -x509 -nodes -days 365 -newkey rsa:2048 "
                f"-keyout {key_path} -out {cert_path} -subj \"/CN={domain}\""
            ),
            f"chmod 600 {key_path}",
            f"chmod 644 {cert_path}",
        ]

        for command in commands:
            logger.info("远程执行：%s", command)
            stdin, stdout, stderr = self.ssh.exec_command(command)
            exit_code = stdout.channel.recv_exit_status()
            if exit_code != 0:
                error = stderr.read().decode("utf-8", "ignore")
                logger.error("生成证书失败：%s", error)
                raise RuntimeError(f"生成自签名证书失败: {error}")

        logger.info("自签名证书已生成：%s", cert_path)
        return TLSCertInfo(cert_path=cert_path, key_path=key_path)
