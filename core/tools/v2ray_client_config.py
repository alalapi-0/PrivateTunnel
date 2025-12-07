"""V2Ray 客户端配置生成器。V2Ray client configuration generator."""

from __future__ import annotations

import json
import base64
from typing import Any


def generate_v2ray_client_config(
    server_ip: str,
    server_port: int,
    uuid: str,
    ws_path: str = "/ray",
    local_socks_port: int = 10808,
    local_http_port: int = 10809,
) -> dict[str, Any]:
    """生成 V2Ray 客户端配置。
    
    Generate V2Ray client configuration.
    
    Args:
        server_ip: V2Ray 服务器 IP
        server_port: V2Ray 服务器端口
        uuid: VMess UUID
        ws_path: WebSocket 路径
        local_socks_port: 本地 SOCKS 代理端口
        local_http_port: 本地 HTTP 代理端口
    
    Returns:
        V2Ray 客户端配置字典
    """
    config = {
        "log": {
            "loglevel": "warning"
        },
        "inbounds": [
            {
                "port": local_socks_port,
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True
                },
                "tag": "socks-in"
            },
            {
                "port": local_http_port,
                "protocol": "http",
                "settings": {},
                "tag": "http-in"
            }
        ],
        "outbounds": [
            {
                "protocol": "vmess",
                "settings": {
                    "vnext": [
                        {
                            "address": server_ip,
                            "port": server_port,
                            "users": [
                                {
                                    "id": uuid,
                                    "alterId": 0,
                                    "security": "auto"
                                }
                            ]
                        }
                    ]
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "tls",
                    "wsSettings": {
                        "path": ws_path
                    },
                    "tlsSettings": {
                        "allowInsecure": True,
                        "serverName": server_ip
                    }
                },
                "tag": "proxy"
            },
            {
                "protocol": "freedom",
                "settings": {},
                "tag": "direct"
            }
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["socks-in", "http-in"],
                    "outboundTag": "proxy"
                }
            ]
        }
    }
    
    return config


def generate_vmess_url(
    server_ip: str,
    server_port: int,
    uuid: str,
    ws_path: str = "/ray",
    remark: str = "PrivateTunnel-V2Ray",
) -> str:
    """生成 VMess URL。
    
    Generate VMess URL for quick import.
    
    Args:
        server_ip: 服务器 IP
        server_port: 服务器端口
        uuid: VMess UUID
        ws_path: WebSocket 路径
        remark: 备注名称
    
    Returns:
        VMess URL 字符串（vmess://...）
    """
    vmess_json = {
        "v": "2",
        "ps": remark,
        "add": server_ip,
        "port": str(server_port),
        "id": uuid,
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": "",
        "path": ws_path,
        "tls": "tls",
        "sni": server_ip
    }
    
    json_str = json.dumps(vmess_json, separators=(',', ':'))
    encoded = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
    
    return f"vmess://{encoded}"


def save_v2ray_config(config: dict[str, Any], filepath: str) -> None:
    """保存 V2Ray 配置到文件。
    
    Save V2Ray configuration to file.
    
    Args:
        config: V2Ray 配置字典
        filepath: 文件路径
    """
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)


