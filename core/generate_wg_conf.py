#!/usr/bin/env python3
"""
这是占位实现：从 JSON 配置生成 WireGuard 配置文件的脚本骨架。
请在后续迭代中补充真实逻辑，并在生产环境执行前进行手工审核。
"""

import argparse
import json
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "占位脚本：读取符合 core/config-schema.json 的 JSON 配置并输出 wg.conf\n"
            "⚠️ 注意：本脚本不会进行 schema 校验，也不会写入系统目录。"
        )
    )
    parser.add_argument("input", type=Path, help="输入 JSON 配置路径")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("./wg0.conf"),
        help="输出 WireGuard 配置文件路径 (默认: ./wg0.conf)",
    )
    return parser.parse_args()


def load_config(path: Path) -> dict:
    """读取 JSON 配置文件。实际部署中建议增加 schema 校验。"""
    with path.open("r", encoding="utf-8") as fp:
        return json.load(fp)


def render_interface(server: dict) -> str:
    """根据服务器配置生成 [Interface] 段落。"""
    lines = ["[Interface]"]
    lines.append(f"Address = {server.get('address', '10.7.0.1/24')}")
    lines.append(f"ListenPort = {server.get('listenPort', 51820)}")
    lines.append(f"PrivateKey = <请手动填入服务器私钥，路径: {server.get('privateKeyPath', 'N/A')}>")
    dns = server.get("dns")
    if dns:
        lines.append("DNS = " + ", ".join(dns))
    for cmd in server.get("postUp", []):
        lines.append(f"PostUp = {cmd}")
    for cmd in server.get("postDown", []):
        lines.append(f"PostDown = {cmd}")
    return "\n".join(lines)


def render_peer(client: dict, server: dict) -> str:
    """根据客户端配置生成 [Peer] 段落。"""
    lines = ["[Peer]"]
    lines.append(f"# Name = {client.get('name', 'unknown')}")
    lines.append(f"PublicKey = {client.get('publicKey', '<待填写>')}")
    preshared = client.get("presharedKeyPath")
    if preshared:
        lines.append(
            "PresharedKey = <请手动填入或使用 `cat {}`>".format(preshared)
        )
    allowed_ips = client.get("allowedIPs", [])
    if allowed_ips:
        lines.append("AllowedIPs = " + ", ".join(allowed_ips))
    else:
        lines.append("AllowedIPs = 0.0.0.0/0")
    keepalive = client.get("persistentKeepalive")
    if keepalive is not None:
        lines.append(f"PersistentKeepalive = {keepalive}")
    lines.append(
        "Endpoint = {}".format(server.get("endpoint", "example.com:51820"))
    )
    return "\n".join(lines)


def render_config(config: dict) -> str:
    """组装完整的 WireGuard 配置内容。"""
    server = config.get("server", {})
    clients = config.get("clients", [])
    sections = [render_interface(server)]
    for client in clients:
        sections.append(render_peer(client, server))
    return "\n\n".join(sections)


def main() -> None:
    args = parse_args()
    config = load_config(args.input)
    output = render_config(config)
    args.output.write_text(output + "\n", encoding="utf-8")
    print(
        f"[信息] 已生成占位 WireGuard 配置: {args.output}。请手工审核并填写敏感信息后再部署。"
    )


if __name__ == "__main__":
    main()
