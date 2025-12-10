"""V2Ray 配置生成器。V2Ray configuration generator."""

from __future__ import annotations

import ipaddress
import json
import logging
import uuid
from typing import Any

logger = logging.getLogger(__name__)


def _warn_if_ip(value: str) -> None:
    """Log a warning when an IP is used where a domain is expected."""

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return
    logger.warning("V2Ray SNI/Host 建议使用域名，但收到 IP：%s", value)


def generate_v2ray_uuid() -> str:
    """生成 V2Ray UUID。Generate a V2Ray UUID."""

    return str(uuid.uuid4())


def generate_v2ray_server_config(
    listen_port: int,
    domain: str,
    tls_cert_path: str,
    tls_key_path: str,
    ws_path: str = "/ws",
    uuid: str | None = None,
) -> dict[str, Any]:
    """生成 V2Ray 服务器端配置（WebSocket + TLS）。"""

    _warn_if_ip(domain)

    if uuid is None:
        uuid = generate_v2ray_uuid()

    config = {
        "log": {
            "loglevel": "warning",
            "access": "/var/log/v2ray/access.log",
            "error": "/var/log/v2ray/error.log",
        },
        "inbounds": [
            {
                "port": listen_port,
                "protocol": "vmess",
                "settings": {
                    "clients": [
                        {
                            "id": uuid,
                            "alterId": 0,
                            "security": "auto",
                        }
                    ],
                    "disableInsecureEncryption": True,
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "tls",
                    "wsSettings": {
                        "path": ws_path,
                        "headers": {"Host": domain},
                    },
                    "tlsSettings": {
                        "serverName": domain,
                        "certificates": [
                            {
                                "certificateFile": tls_cert_path,
                                "keyFile": tls_key_path,
                            }
                        ],
                        "minVersion": "1.2",
                        "maxVersion": "1.3",
                        "cipherSuites": "",
                    },
                },
            }
        ],
        "outbounds": [
            {
                "protocol": "freedom",
                "settings": {},
            }
        ],
        "routing": {"domainStrategy": "AsIs", "rules": []},
    }

    return config


def generate_v2ray_config_json(config: dict[str, Any], indent: int = 2) -> str:
    """将 V2Ray 配置转换为 JSON 字符串。"""

    return json.dumps(config, indent=indent, ensure_ascii=False)
