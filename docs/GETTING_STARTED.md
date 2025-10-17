# PrivateTunnel 快速上手指南

本指南面向首次接触 PrivateTunnel 的开发者或自建用户，帮助你从一台全新的服务器开始，一直到 iPhone 真机成功建立 WireGuard 隧道。本项目仅面向个人/小团队自用，请确保遵循所在地法律法规。

## 前置条件

- 一台可 SSH 的 Linux 服务器（推荐 Ubuntu 22.04 LTS），具备公网 IPv4/IPv6；
- 服务器具备 root 权限，或可以 `sudo`；
- 一台运行 iOS 16 及以上版本的真机，已安装 WireGuard 官方 App；
- 一台 macOS 设备用于构建 iOS 应用（Xcode 14 及以上）。

## 步骤一：克隆仓库并了解目录结构

```bash
mkdir -p ~/code && cd ~/code
git clone https://github.com/your-org/PrivateTunnel.git
cd PrivateTunnel
```

建议先阅读 [docs/ARCHITECTURE.md](ARCHITECTURE.md) 了解整体组件：服务器端 WireGuard + 分流脚本、iOS 容器 App 与 Packet Tunnel 扩展、健康检查与日志体系等。

## 步骤二：准备服务器与 WireGuard

1. 登录服务器，切换到仓库根目录；
2. 先进行干跑检查：
   ```bash
   sudo WAN_IF=eth0 bash server/provision/wg-install.sh --dry-run
   ```
   根据实际网卡名称调整 `WAN_IF`。干跑会打印即将执行的操作，确认无误后继续。
3. 执行安装：
   ```bash
   sudo WAN_IF=eth0 bash server/provision/wg-install.sh --port 443 --ifname wg0
   ```
4. 添加第一个客户端（例如 iPhone）：
   ```bash
   sudo bash server/provision/wg-add-peer.sh --name iphone --qrcode
   ```
   终端会打印二维码，使用 WireGuard App 扫描并保存配置。
5. 若计划使用域名分流，参考 [docs/SPLIT-IPSET.md](SPLIT-IPSET.md) 准备 `domains.yaml` 和定时任务。初次部署建议保持全局路由，确认稳定后再开启白名单模式。

## 步骤三：配置 iOS 开发环境

1. 在 macOS 上安装最新稳定版 Xcode（14 或更高），并登录 Apple ID；
2. 打开仓库中的 iOS 工程（位于 `apps/ios/PrivateTunnelApp`）；
3. 阅读 [docs/IOS-APP.md](IOS-APP.md) 与 [docs/IOS-PACKET-TUNNEL.md](IOS-PACKET-TUNNEL.md)，了解容器 App 与扩展的职责；
4. 根据 [docs/CODE_SIGNING.md](CODE_SIGNING.md) 配置团队、证书、App Group，确保容器与扩展共享同一 `App Group`。若暂时只做无签名编译，可在 Xcode 的 `Signing & Capabilities` 中禁用自动签名。

## 步骤四：真机调试与连接

1. 在 Xcode 中选择真机，使用 `Run` 构建容器 App；
2. 首次启动 App 时，授予相机权限以便扫描二维码；
3. 通过“扫码导入”或“文件导入”读取服务器生成的配置文件；
4. 切换到系统设置 → VPN → PrivateTunnel，点击连接；
5. 若成功建立隧道，终端日志与应用 UI 会显示绿色状态。可访问 `https://ifconfig.co` 等站点确认出口 IP 已变更。

## 调优建议

- **固定出口与时区**：服务器与客户端尽量保持统一时区，避免因时间漂移导致密钥刷新失败。
- **心跳间隔**：在 `core/examples/` 中提供了全局路由与白名单示例，可根据需求调整 `persistent_keepalive`。
- **灰度启用白名单**：先在小范围设备启用域名分流，确认 `server/split/resolve_domains.py` 输出的 IP 集合无误后，再推广到所有客户端。

## 后续步骤

- 构建自动化：阅读 [docs/CI.md](CI.md) 了解 GitHub Actions 的编译与脚本检查。
- 分发方案：根据需要选择 [TestFlight](DISTRIBUTION_TESTFLIGHT.md) 或 [Ad-Hoc](DISTRIBUTION_ADHOC.md)。
- 故障排查：遇到连接或性能问题时，参阅 [docs/TROUBLESHOOTING.md](TROUBLESHOOTING.md)。

祝使用愉快，保持自建服务的最小暴露面，合理规划访问策略。
