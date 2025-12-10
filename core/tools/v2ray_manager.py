from __future__ import annotations

import logging
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .v2ray_config import generate_v2ray_config_json, generate_v2ray_server_config

logger = logging.getLogger(__name__)


@dataclass
class V2RayServerConfigParams:
    listen_port: int
    domain: str
    tls_cert_path: Path
    tls_key_path: Path
    ws_path: str = "/ws"
    uuid: Optional[str] = None


class V2RayManager:
    def __init__(self, ssh_client, config_dir: str = "/etc/v2ray"):
        self.ssh = ssh_client
        self.config_dir = config_dir

    def ensure_installed(self) -> bool:
        """Ensure V2Ray binary is present, installing via official script if needed."""

        check_cmd = "command -v v2ray >/dev/null 2>&1"
        stdin, stdout, stderr = self.ssh.exec_command(check_cmd)
        if stdout.channel.recv_exit_status() == 0:
            logger.info("检测到 V2Ray 已安装，跳过安装步骤")
            return True

        install_cmd = (
            "bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)"
        )
        logger.info("V2Ray 未安装，开始安装：%s", install_cmd)
        stdin, stdout, stderr = self.ssh.exec_command(install_cmd)
        exit_code = stdout.channel.recv_exit_status()
        if exit_code != 0:
            logger.error("V2Ray 安装失败：%s", stderr.read().decode("utf-8", "ignore"))
            return False

        logger.info("V2Ray 安装完成")
        return True

    def generate_server_config(self, params: V2RayServerConfigParams) -> str:
        config_dict = generate_v2ray_server_config(
            listen_port=params.listen_port,
            domain=params.domain,
            tls_cert_path=str(params.tls_cert_path),
            tls_key_path=str(params.tls_key_path),
            ws_path=params.ws_path,
            uuid=params.uuid,
        )
        return generate_v2ray_config_json(config_dict)

    def write_server_config(self, config_json: str) -> None:
        remote_path = Path(self.config_dir) / "config.json"
        logger.info("写入 V2Ray 配置到 %s", remote_path)
        sftp = self.ssh.open_sftp()
        try:
            sftp.mkdir(str(Path(self.config_dir)), mode=0o755)
        except OSError:
            pass
        finally:
            sftp.close()

        command = f"cat > {shlex.quote(str(remote_path))} <<'EOF'\n{config_json}\nEOF"
        stdin, stdout, stderr = self.ssh.exec_command(command)
        exit_code = stdout.channel.recv_exit_status()
        if exit_code != 0:
            error = stderr.read().decode("utf-8", "ignore")
            logger.error("写入 V2Ray 配置失败：%s", error)
            raise RuntimeError(f"写入 V2Ray 配置失败: {error}")

    def restart_service(self) -> bool:
        logger.info("重启 V2Ray 服务")
        stdin, stdout, stderr = self.ssh.exec_command("systemctl restart v2ray.service")
        exit_code = stdout.channel.recv_exit_status()
        if exit_code != 0:
            logger.error("systemctl restart v2ray 失败：%s", stderr.read().decode("utf-8", "ignore"))
            return False
        return True

    def check_health(self) -> bool:
        logger.info("检查 V2Ray 服务健康状态")
        stdin, stdout, stderr = self.ssh.exec_command("systemctl is-active v2ray.service")
        if stdout.channel.recv_exit_status() != 0:
            logger.error("V2Ray 服务未处于 active 状态：%s", stderr.read().decode("utf-8", "ignore"))
            return False
        logger.info("V2Ray systemd 状态正常")
        return True
