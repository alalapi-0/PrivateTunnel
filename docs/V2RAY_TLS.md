# V2Ray WebSocket + TLS 伪装（R4）

本轮重构将「基于域名的 V2Ray WebSocket + TLS 伪装」提升为默认推荐路径。部署流程会尝试启用 V2Ray，如果条件不满足（例如缺少域名或证书生成失败），则自动回退到纯 WireGuard。本文档概述当前支持的模式、前置条件与客户端配置位置。

## 支持的模式

- **V2Ray VMess + WebSocket + TLS**：使用指定域名作为 SNI/Host，默认路径为 `/ws`，端口默认 443，可通过环境变量调整。
- **证书来源**：当前实现使用自签名证书占位，未来可在 `TLSCertManager` 中扩展为 ACME/Let’s Encrypt。

## 前置条件

- 需要一个已经解析到服务器公网 IP 的域名（作为 TLS SNI/Host）。
- 默认会生成自签名证书，浏览器可能不信任，但对 V2Ray 客户端协议可正常工作。
- 如果未提供域名，部署流程会提示输入；用户留空时自动回退到纯 WireGuard。

## 部署流程概览

1. **证书管理**：`TLSCertManager.ensure_cert_for_domain` 会在远端证书目录（默认 `/etc/privatetunnel/certs`）下检查/生成 `<domain>.crt` 与 `<domain>.key`。日志会记录证书复用或生成的结果。
2. **V2Ray 安装与配置**：`V2RayManager.ensure_installed` 负责检测/安装 v2ray 二进制；`generate_server_config` 生成绑定域名的 WebSocket+TLS 配置并下发到远端配置目录（默认 `/etc/v2ray/config.json`）。
3. **服务重启与健康检查**：部署会调用 systemd 重启 V2Ray 并进行健康检查，失败时回退到纯 WireGuard。
4. **客户端产物**：成功时在 `artifacts/` 下生成 `v2ray_client.json` 和 `v2ray_vmess.txt`，可导入 V2RayN/V2RayNG/Clash 等客户端。

## 客户端配置路径与导入

- `artifacts/v2ray_client.json`：完整客户端配置，可直接被大多数 V2Ray 客户端导入。
- `artifacts/v2ray_vmess.txt`：VMess 导入链接文本，便于复制粘贴。
- 在主菜单选择“查看 / 重新生成 V2Ray 配置”可再次生成客户端配置，或查看域名/端口/证书路径等元数据。

## 域前置字段（front_domain）

- R5 在客户端配置层面预留了域前置字段：当 `front_domain` 提供时，生成的 V2Ray 客户端配置会使用 `front_domain` 作为 Host/SNI，而在元数据中保留真实的 `domain`（回源域名）。
- 当前版本仅完成配置表达和占位，未对 CDN/前置链路做实际改动，后续版本将扩展 `DomainFrontingManager` 完成具体交付。

## 手动验证步骤

1. 运行 `python main.py`，按照提示输入解析到服务器的域名完成部署。
2. SSH 登录服务器，检查 `/etc/v2ray/config.json` 与 `/etc/privatetunnel/certs/<domain>.crt` 是否存在且时间更新。
3. 在本地打开 `artifacts/v2ray_client.json` 或 `artifacts/v2ray_vmess.txt`，导入到 V2RayN/V2RayNG。
4. 连接后验证流量是否通过 WebSocket+TLS，若失败可查看服务器 `journalctl -u v2ray` 或部署日志排查。
