"""V2Ray 客户端配置生成器。V2Ray client configuration generator."""

from __future__ import annotations

import base64
import ipaddress
import json
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


def _warn_if_ip(value: str) -> None:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return
    logger.warning("V2Ray host/sni 建议使用域名，但收到 IP：%s", value)


def _effective_host(server_domain: str, front_domain: Optional[str]) -> str:
    return front_domain or server_domain


def generate_v2ray_client_config(
    server_domain: str,
    server_port: int,
    ws_path: str,
    uuid: str,
    front_domain: Optional[str] = None,
    local_socks_port: int = 10808,
    local_http_port: int = 10809,
) -> dict[str, Any]:
    """生成 V2Ray 客户端配置。"""

    effective_host = _effective_host(server_domain, front_domain)
    _warn_if_ip(effective_host)

    logger.info(
        "v2ray client config generated: real_domain=%s, front_domain=%s, port=%s, ws_path=%s",
        server_domain,
        front_domain,
        server_port,
        ws_path,
    )

    config = {
        "log": {"loglevel": "warning"},
        "pt_metadata": {
            "real_domain": server_domain,
            "front_domain": front_domain,
        },
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
                            "address": effective_host,
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
                    "wsSettings": {"path": ws_path, "headers": {"Host": effective_host}},
                    "tlsSettings": {"allowInsecure": True, "serverName": effective_host},
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
    front_domain: Optional[str] = None,
) -> str:
    """生成 VMess URL。"""

    effective_host = _effective_host(server_domain, front_domain)
    _warn_if_ip(effective_host)

    vmess_json = {
        "v": "2",
        "ps": remark,
        "add": effective_host,
        "port": str(server_port),
        "id": uuid,
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": effective_host,
        "path": ws_path,
        "tls": "tls",
        "sni": effective_host,
        "real": server_domain,
    }

    json_str = json.dumps(vmess_json, separators=(",", ":"))
    encoded = base64.b64encode(json_str.encode("utf-8")).decode("utf-8")

    return f"vmess://{encoded}"


def save_v2ray_config(config: dict[str, Any], filepath: str) -> None:
    """保存 V2Ray 配置到文件。"""

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
