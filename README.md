# PrivateTunnel

[![CI](https://img.shields.io/github/actions/workflow/status/your-org/PrivateTunnel/ci.yml?branch=main&label=CI)](./.github/workflows/ci.yml)
![Platform](https://img.shields.io/badge/platform-iOS%2016%2B-blue)
![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Build](https://img.shields.io/badge/build-1-blue)
[![License](https://img.shields.io/badge/license-MIT-green)](https://opensource.org/licenses/MIT)

PrivateTunnel 是一个面向个人/小团队自建的私有 VPN/隧道解决方案，聚焦“自用稳定”。仓库覆盖 WireGuard 服务器脚本、iOS 容器 App + Packet Tunnel 扩展、分流与健康检查工具，以及 CI/打包流程。项目不会在中国区 App Store 发布，也不提供公共节点，请确保合法合规使用。

## 架构速览

```
┌──────────────────────────┐      ┌──────────────────────────┐
│ WireGuard Server         │      │ iOS Container App        │
│  • wg-install.sh         │      │  • 配置导入/二维码扫描     │
│  • 分流：resolve_domains │◀────▶│  • 健康检查 & Watchdog    │
│  • 健康：security/audit  │      └────────┬─────────────────┘
└──────────────┬───────────┘               │
               │                           │ App Group / IPC
               ▼                           ▼
        ┌──────────────┐           ┌────────────────────────┐
        │ Toy Gateway  │           │ PacketTunnel Extension │
        │  (仅开发用)  │           │  • WireGuard 客户端核心  │
        └──────────────┘           │  • 分流策略 & 心跳       │
                                    └────────────────────────┘
```

## 三步快速开始

1. **部署服务器（Round 2/3）**：按照 [docs/SERVER-OPERATIONS.md](docs/SERVER-OPERATIONS.md) 与 [docs/CONFIG.md](docs/CONFIG.md) 准备 VPS，运行 `server/provision/wg-install.sh`，生成客户端配置。
2. **构建 iOS 客户端（Round 4/5/6）**：阅读 [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) 与 [docs/BUILD_IOS.md](docs/BUILD_IOS.md)，在本地使用 Xcode 构建容器 App 与 PacketTunnel 扩展。
3. **启用健康检查与分流（Round 7/8）**：根据 [docs/HEALTH-AUTO-RECONNECT.md](docs/HEALTH-AUTO-RECONNECT.md) 与 [docs/SPLIT-IPSET.md](docs/SPLIT-IPSET.md) 配置心跳、自动重连及域名白名单。

## 文档索引

- 入门与流程
  - [GETTING_STARTED.md](docs/GETTING_STARTED.md)：从零到真机调试
  - [BUILD_IOS.md](docs/BUILD_IOS.md)：Xcode 构建与常见错误
  - [CODE_SIGNING.md](docs/CODE_SIGNING.md)：证书、描述文件与权限
  - [DISTRIBUTION_TESTFLIGHT.md](docs/DISTRIBUTION_TESTFLIGHT.md)：TestFlight 上传流程
  - [DISTRIBUTION_ADHOC.md](docs/DISTRIBUTION_ADHOC.md)：Ad-Hoc 分发步骤
- 运维与安全
  - [SERVER-OPERATIONS.md](docs/SERVER-OPERATIONS.md)：服务器部署/运维
  - [SECURITY-HARDENING.md](docs/SECURITY-HARDENING.md)：加固建议
  - [LOGGING.md](docs/LOGGING.md)：日志收集与留存策略
  - [HEALTH-AUTO-RECONNECT.md](docs/HEALTH-AUTO-RECONNECT.md)：健康检查与重连
  - [SPLIT-IPSET.md](docs/SPLIT-IPSET.md)：域名分流实现
- 自动化与工具
  - [CI.md](docs/CI.md)：GitHub Actions 工作流
  - [BADGES.md](docs/BADGES.md)：徽标来源及更新方法
  - [CHANGELOG.md](docs/CHANGELOG.md)：版本发布记录模板
  - [ROADMAP.md](docs/ROADMAP.md)：阶段规划
  - [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)：常见问题排查
  - [TOY-TUN-END2END.md](docs/TOY-TUN-END2END.md)：Toy 通道说明（仅开发）
  - [VULTR_AUTOMATION.md](docs/VULTR_AUTOMATION.md)：Vultr API 自动化创建节点

更多设计细节请参考 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) 与 [docs/IOS-PACKET-TUNNEL.md](docs/IOS-PACKET-TUNNEL.md)。

## CI 与自动化

- `.github/workflows/ci.yml`：在 push / PR 时执行脚本语法检查与 iOS 编译验证；
- `.github/workflows/nightly.yml`：夜间运行文档链接检查与分流脚本干跑，并上传解析结果；
- `scripts/ios_build.sh` / `scripts/ios_export.sh`：一键生成 Archive 与 `.ipa`；
- `scripts/check_links.py`：本地或 CI 检查 Markdown 链接；
- `Makefile`：提供 `make build`、`make export-adhoc`、`make lint`、`make docs` 等便捷命令。

## 责任声明与隐私

PrivateTunnel 仅定位为个人/内部使用工具，不提供公共服务，也不承诺在中国区或其他受限地区的 App Store 上架。请确保遵循所在地法律法规，避免将 Toy 通道用于生产环境。隐私与数据处理政策请参阅 [docs/PRIVACY.md](docs/PRIVACY.md)。

## 贡献与反馈

欢迎就脚本、分流策略、客户端体验提出建议或 Pull Request。在提交变更时，请附上测试说明与影响评估。遇到问题可先参考 [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)，必要时再开启 Issue。
