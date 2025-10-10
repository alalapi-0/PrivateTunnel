# PrivateTunnel

PrivateTunnel 是一个面向个人/小团队使用的私有 VPN/隧道一键连接项目。核心目标是“自用稳定”：提供可靠的 WireGuard 服务器脚本、跨平台客户端以及灵活的分流与健康检查机制。本仓库为 monorepo 脚手架，便于后续自动化开发与持续迭代，暂不考虑公开发行或应用商店上架。

## 仓库结构

```
.
├── README.md
├── server/
│   ├── provision/
│   │   ├── env.example
│   │   ├── templates/
│   │   │   ├── client.conf.template
│   │   │   └── wg0.conf.template
│   │   ├── wg-add-peer.sh
│   │   ├── wg-install.sh
│   │   ├── wg-list-peers.sh
│   │   ├── wg-qrcode.sh
│   │   ├── wg-revoke-peer.sh
│   │   └── wg-uninstall.sh
│   └── split/
│       └── README.md
├── core/
│   ├── config-schema.json
│   ├── examples/
│   │   ├── minimal.json
│   │   └── whitelist.json
│   ├── qr/
│   │   ├── README.md
│   │   └── gen_qr.sh
│   └── tools/
│       ├── generate_wg_conf.py
│       ├── render_from_env.py
│       └── validate_config.py
├── apps/
│   ├── ios/
│   │   ├── PrivateTunnelApp/
│   │   ├── PacketTunnelProvider/
│   │   └── README.md
│   ├── mac/
│   │   └── README.md
│   └── windows/
│       └── README.md
├── docs/
│   ├── ARCHITECTURE.md
│   ├── DEV-SETUP.md
│   ├── IOS-APP.md
│   └── SERVER-OPERATIONS.md
└── .github/
    └── ISSUE_TEMPLATE.md
```

## 服务器快速开始

服务器侧的一键部署、运维与故障排查指南请参见 [SERVER-OPERATIONS.md](docs/SERVER-OPERATIONS.md)。核心流程概览：

1. `sudo bash server/provision/wg-install.sh --dry-run` 先预览即将执行的操作；
2. `sudo bash server/provision/wg-install.sh --port 51820 --ifname wg0 --wan-if eth0` 真正完成安装并启动服务；
3. 使用 `sudo bash server/provision/wg-add-peer.sh --name iphone --qrcode` 生成客户端配置并在 WireGuard App 中扫码导入。

更多参数说明、升级/回滚方案和安全建议均在文档中详细记录。

## 开发路线图（前 10 轮迭代概览）

1. ✅ Round 1：搭建 monorepo 脚手架与占位脚本。
2. ✅ Round 2：设计 WireGuard 客户端配置与生成工具（详见 [CONFIG.md](docs/CONFIG.md)）。
3. ✅ Round 3：实现服务器侧自动化脚本与配置二维码生成。
4. ✅ Round 4：构建 iOS 容器 App，支持扫码/文件导入配置（详见 [IOS-APP.md](docs/IOS-APP.md)）。
5. ☐ Round 5：集成 iOS PacketTunnel 扩展，建立基础的连接/断开流程。
6. ☐ Round 6：开发 macOS 桌面壳应用，集成自动更新配置。
7. ☐ Round 7：开发 Windows 客户端壳应用（调用 WireGuard 官方驱动）。
8. ☐ Round 8：引入分流策略配置与灰度发布机制。
9. ☐ Round 9：搭建状态监控与健康检查服务，提供仪表板。
10. ☐ Round 10：完善 CI/CD、自动化测试与安全审计。

## 开发前需要确认的事项

为确保后续开发顺利推进，请准备并确认以下信息：

- VPS 信息：服务器 IP/域名、操作系统版本、是否具备 IPv6。
- WireGuard 需求：预期接入客户端数量、对带宽/流量的要求。
- Apple 开发者账户：是否持有付费 Apple Developer Program（发布 iOS/macOS 客户端需要）。
- 目标出口 IP 地理位置：希望的节点所在地（国家/地区/城市）。
- 平台需求：是否需要 Android/路由器等扩展平台支持。
- 安全策略：是否启用多因子身份验证、日志保留政策等。

## 贡献指南

本项目定位为私人自用，但仍欢迎对架构/脚本提出建议或 PR。在提交前请先通过 Issue 讨论需求与设计。针对脚本和配置的修改，请附上手工验证步骤或实验说明。

## License

建议使用 [MIT License](https://opensource.org/licenses/MIT) 授权，鼓励自由使用与二次定制。
