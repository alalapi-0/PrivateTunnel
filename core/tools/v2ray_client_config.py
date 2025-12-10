"""V2Ray 客户端配置生成器。V2Ray client configuration generator."""

from __future__ import annotations

import base64
import ipaddress
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def _warn_if_ip(value: str) -> None:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return
    logger.warning("V2Ray host/sni 建议使用域名，但收到 IP：%s", value)


def generate_v2ray_client_config(
    server_domain: str,
    server_port: int,
    uuid: str,
    ws_path: str = "/ws",
    local_socks_port: int = 10808,
    local_http_port: int = 10809,
) -> dict[str, Any]:
    """生成 V2Ray 客户端配置。"""

    _warn_if_ip(server_domain)

    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "port": local_socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "tag": "socks-in",
            },
            {
                "port": local_http_port,
                "protocol": "http",
                "settings": {},
                "tag": "http-in",
            },
        ],
        "outbounds": [
            {
                "protocol": "vmess",
                "settings": {
                    "vnext": [
                        {
                            "address": server_domain,
                            "port": server_port,
                            "users": [
                                {
                                    "id": uuid,
                                    "alterId": 0,
                                    "security": "auto",
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "tls",
                    "wsSettings": {"path": ws_path, "headers": {"Host": server_domain}},
                    "tlsSettings": {"allowInsecure": True, "serverName": server_domain},
                },
                "tag": "proxy",
            },
            {"protocol": "freedom", "settings": {}, "tag": "direct"},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["socks-in", "http-in"],
                    "outboundTag": "proxy",
                }
            ],
        },
    }

    return config


def generate_vmess_url(
    server_domain: str,
    server_port: int,
    uuid: str,
    ws_path: str = "/ws",
    remark: str = "PrivateTunnel-V2Ray",
) -> str:
    """生成 VMess URL。"""

    _warn_if_ip(server_domain)

    vmess_json = {
        "v": "2",
        "ps": remark,
        "add": server_domain,
        "port": str(server_port),
        "id": uuid,
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": server_domain,
        "path": ws_path,
        "tls": "tls",
        "sni": server_domain,
    }

    json_str = json.dumps(vmess_json, separators=(",", ":"))
    encoded = base64.b64encode(json_str.encode("utf-8")).decode("utf-8")

    return f"vmess://{encoded}"


def save_v2ray_config(config: dict[str, Any], filepath: str) -> None:
    """保存 V2Ray 配置到文件。"""

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
