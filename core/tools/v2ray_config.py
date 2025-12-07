"""V2Ray 配置生成器。V2Ray configuration generator."""

from __future__ import annotations

import json
import uuid
from typing import Any


def generate_v2ray_uuid() -> str:
    """生成 V2Ray UUID。Generate a V2Ray UUID."""
    return str(uuid.uuid4())


def generate_v2ray_server_config(
    port: int = 443,
    uuid: str | None = None,
    ws_path: str = "/ray",
    tls_cert_path: str = "/etc/v2ray/cert.pem",
    tls_key_path: str = "/etc/v2ray/key.pem",
) -> dict[str, Any]:
    """生成 V2Ray 服务器端配置。
    
    Generate V2Ray server configuration with WebSocket + TLS transport.
    
    Args:
        port: V2Ray 监听端口（默认 443，伪装 HTTPS）
        uuid: VMess UUID，如果为 None 则自动生成
        ws_path: WebSocket 路径
        tls_cert_path: TLS 证书路径
        tls_key_path: TLS 私钥路径
    
    Returns:
        V2Ray 配置字典
    """
    if uuid is None:
        uuid = generate_v2ray_uuid()
    
    config = {
        "log": {
            "loglevel": "warning",
            "access": "/var/log/v2ray/access.log",
            "error": "/var/log/v2ray/error.log"
        },
        "inbounds": [
            {
                "port": port,
                "protocol": "vmess",
                "settings": {
                    "clients": [
                        {
                            "id": uuid,
                            "alterId": 0,
                            "security": "auto"
                        }
                    ],
                    "disableInsecureEncryption": True
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "tls",
                    "wsSettings": {
                        "path": ws_path,
                        "headers": {}
                    },
                    "tlsSettings": {
                        "certificates": [
                            {
                                "certificateFile": tls_cert_path,
                                "keyFile": tls_key_path
                            }
                        ],
                        "minVersion": "1.2",
                        "maxVersion": "1.3",
                        "cipherSuites": ""
                    }
                }
            }
        ],
        "outbounds": [
            {
                "protocol": "freedom",
                "settings": {}
            }
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": []
        }
    }
    
    return config


def generate_v2ray_config_json(config: dict[str, Any], indent: int = 2) -> str:
    """将 V2Ray 配置转换为 JSON 字符串。
    
    Convert V2Ray configuration dictionary to JSON string.
    
    Args:
        config: V2Ray 配置字典
        indent: JSON 缩进（默认 2）
    
    Returns:
        JSON 字符串
    """
    return json.dumps(config, indent=indent, ensure_ascii=False)

