# PrivateTunnel

PrivateTunnel 是一个面向个人/小团队使用的私有 VPN/隧道一键连接项目。核心目标是“自用稳定”：提供可靠的 WireGuard 服务器脚本、跨平台客户端以及灵活的分流与健康检查机制。本仓库为 monorepo 脚手架，便于后续自动化开发与持续迭代，暂不考虑公开发行或应用商店上架。

## 仓库结构

```
.
├── README.md
├── server/
│   └── provision/
│       ├── install.sh
│       └── templates/
│           └── wg0.conf.template
├── core/
│   ├── config-schema.json
│   └── generate_wg_conf.py
├── apps/
│   ├── ios/
│   │   └── README.md
│   ├── mac/
│   │   └── README.md
│   └── windows/
│       └── README.md
├── docs/
│   ├── ARCHITECTURE.md
│   └── DEV-SETUP.md
└── .github/
    └── ISSUE_TEMPLATE.md
```

## 开发路线图（前 10 轮迭代概览）

1. ✅ 搭建 monorepo 脚手架与占位脚本（当前）
2. 设计 WireGuard 服务器配置生成逻辑与配置管理工具
3. 实现服务器自动化部署脚本（支持多节点与健康检查）
4. 构建 iOS PacketTunnel Extension 原型，支持基本连接/断开
5. 开发 macOS 桌面壳应用，集成自动更新配置
6. 开发 Windows 客户端壳应用（调用 WireGuard 官方驱动）
7. 引入分流策略配置（基于域名/IP 规则）与灰度发布机制
8. 搭建状态监控与健康检查服务，提供仪表板
9. 对接 CI/CD（Lint/Test/Build），完善文档与自动化测试
10. 安全审计、性能调优以及高可用部署策略

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
