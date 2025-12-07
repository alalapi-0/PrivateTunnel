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

## 新功能快速体验

### 多节点管理

1. **启用多节点模式**：
   ```bash
   export PT_MULTI_NODE=true
   ```

2. **创建多个节点**：
   - 重复执行"创建 Vultr 实例"步骤
   - 系统会自动管理所有节点

3. **管理节点**：
   - 使用菜单选项 `6) 多节点管理`
   - 查看、设置默认节点、更新状态

### 健康检查

使用菜单选项 `7) 节点健康检查` 查看所有节点状态：

- 自动检查延迟、丢包率、连接性
- 显示节点健康状态
- 自动触发故障转移（如果启用）

### 智能选路

启用智能选路：

```bash
export PT_SMART_ROUTING=true
export PT_ROUTING_STRATEGY=balanced
```

使用菜单选项 `8) 智能节点选择` 手动选择最优节点。

### 连接质量监控

启用监控：

```bash
export PT_ENABLE_MONITORING=true
export PT_MONITOR_INTERVAL=30
```

使用菜单选项 `9) 连接质量报告` 查看监控数据。

### ChatGPT 专用优化

启用 ChatGPT 模式：

```bash
export PT_CHATGPT_MODE=true
```

使用菜单选项 `11) ChatGPT 连接测试` 测试连接。

## 调优建议

- **固定出口与时区**：服务器与客户端尽量保持统一时区，避免因时间漂移导致密钥刷新失败。
- **心跳间隔**：在 `core/examples/` 中提供了全局路由与白名单示例，可根据需求调整 `persistent_keepalive`。
- **灰度启用白名单**：先在小范围设备启用域名分流，确认 `server/split/resolve_domains.py` 输出的 IP 集合无误后，再推广到所有客户端。
- **多节点配置**：建议至少创建 2-3 个节点以实现高可用，并启用智能选路和健康检查。
- **监控与自适应**：启用连接监控和自适应参数调整，系统会自动优化连接参数。

## 后续步骤

- **功能探索**：阅读 [功能说明](FEATURES.md) 了解所有新功能
- **使用指南**：查看 [用户使用指南](USER_GUIDE.md) 获取详细使用说明
- **环境变量**：参考 [环境变量说明](ENVIRONMENT_VARIABLES.md) 配置高级功能
- **构建自动化**：阅读 [CI.md](CI.md) 了解 GitHub Actions 的编译与脚本检查
- **分发方案**：根据需要选择 [TestFlight](DISTRIBUTION_TESTFLIGHT.md) 或 [Ad-Hoc](DISTRIBUTION_ADHOC.md)
- **故障排查**：遇到连接或性能问题时，参阅 [故障排查手册](TROUBLESHOOTING.md)

## 推荐配置

### 基础使用（单节点）

```bash
export VULTR_API_KEY="your-api-key"
export VULTR_SSHKEY_NAME="my-ssh-key"
```

### 高可用配置（多节点）

```bash
export VULTR_API_KEY="your-api-key"
export VULTR_SSHKEY_NAME="my-ssh-key"
export PT_MULTI_NODE=true
export PT_SMART_ROUTING=true
export PT_ROUTING_STRATEGY=balanced
export PT_ENABLE_MONITORING=true
```

### ChatGPT 专用配置

```bash
export VULTR_API_KEY="your-api-key"
export VULTR_SSHKEY_NAME="my-ssh-key"
export PT_MULTI_NODE=true
export PT_CHATGPT_MODE=true
export PT_SMART_ROUTING=true
export PT_ROUTING_STRATEGY=latency_first
export PT_ENABLE_MONITORING=true
```

祝使用愉快，保持自建服务的最小暴露面，合理规划访问策略。
