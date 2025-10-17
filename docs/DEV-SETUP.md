# 本地开发环境搭建指南（占位说明）

> 这是占位实现：本指南概述 PrivateTunnel 开发所需的工具链，细节请在实际操作前手工确认。

## 1. 通用要求

- Git 与 Git LFS（用于管理配置与证书占位文件）。
- Python 3.11+（运行 core 脚本）。
- Node.js (可选，未来前端/桌面应用可能使用 Electron)。

## 2. 服务器侧（Ubuntu 22.04 LTS 建议）

1. 准备一台具备公网 IP 的 VPS，确保开放 UDP 443 端口（若该端口被占用，可改用 51820 或其他值并同步更新配置）。
2. 手工执行以下命令安装 WireGuard：
   ```bash
   sudo apt update
   sudo apt install wireguard wireguard-tools
   ```
3. 克隆仓库并阅读 `server/provision/install.sh`，先运行 `./install.sh plan` 熟悉步骤。
4. 使用 `core/generate_wg_conf.py` 生成占位 `wg0.conf`，手动审核后复制至 `/etc/wireguard/`。

## 3. iOS 开发环境

1. macOS 13+，安装 [Xcode](https://developer.apple.com/xcode/)，确保 Command Line Tools 可用。
2. 需要付费 Apple Developer Program 账号以签署 PacketTunnel Extension。
3. 在 `apps/ios` 中将逐步补充工程，可先创建空白 App + Network Extension，绑定合适的 Team。
4. 安装 WireGuard iOS 客户端用于参考与调试。

## 4. macOS 客户端开发

- 依赖 Xcode 与 Swift/SwiftUI。后续计划提供简单的状态栏应用，调用 `wireguard-go` 或 `wg-quick`。
- 建议安装 [WireGuard for macOS](https://www.wireguard.com/install/) 以便对比行为。

## 5. Windows 客户端开发

- Windows 11 开发机，安装 Visual Studio 2022 (含 C#/.NET 桌面开发工作负载)。
- 需引用官方 WireGuard Windows 驱动/服务，可通过 PowerShell 手工验证。

## 6. 测试与分流验证

- 推荐使用多平台 WireGuard 客户端进行互通测试。
- 对分流策略进行逐条验证，可借助 `traceroute`、`curl --interface` 等命令。
- 后续将提供自动化测试脚本，目前需手工记录验证结果。
