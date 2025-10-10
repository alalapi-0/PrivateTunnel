# iOS Packet Tunnel Extension (Round 5)

本指南介绍如何在本仓库中构建与调试 iOS Packet Tunnel Extension（Network Extension）。Round 5 目标是打通“容器 App ↔ PacketTunnelProvider 扩展”的通信链路，并使用 Swift Mock Engine 验证生命周期流程。暂未集成真实的 WireGuard 数据面，Round 5B/6 将替换为官方 userspace 引擎。

## 目录结构

```
apps/ios/
 ├── PrivateTunnelApp/                # SwiftUI 容器壳应用
 │   ├── ContentView.swift            # 导入/选择配置 + Connect/Disconnect UI
 │   ├── TunnelManager.swift          # 与 NETunnelProviderManager 交互
 │   └── PrivateTunnelApp.entitlements
 └── PacketTunnelProvider/            # Packet Tunnel Extension
     ├── PacketTunnelProvider.swift   # 扩展入口，应用 NE 设置并启动 Mock Engine
     ├── WGConfig.swift/.Parser.swift # JSON → WGConfig + 最小化 wg conf
     ├── WGEngineMock.swift           # 模拟 WireGuard Engine（仅日志）
     ├── Logger.swift
     ├── Info.plist                   # NSExtension 声明
     └── PacketTunnelProvider.entitlements
```

## 签名与 Bundle Identifier

1. 在 Xcode 中打开 `apps/ios/PrivateTunnelApp/PrivateTunnelApp.xcodeproj`（或将文件夹直接拖入 Workspace）。
2. 为 **容器 App** 与 **Packet Tunnel Extension** 分别设置唯一的 Bundle Identifier，例如：
   - 容器：`com.example.PrivateTunnel`
   - 扩展：`com.example.PrivateTunnel.PacketTunnelProvider`
3. 两个 Target 都需要启用同一 **App Group**（示例：`group.com.example.privatetunnel`）与统一的 **Keychain Access Group**，以便共享配置；本轮默认通过 `providerConfiguration` 传参，App Group 仅作预留。
4. 开发者账号需具备 Network Extension 权限。若首次启用 `packet-tunnel-provider` 能力，请在 Apple Developer 后台申请并等待审核。

## 构建与运行

1. 连接已加入 Apple Developer Program 的真实 iOS 设备，并在 Xcode 中选择容器 App 作为运行 Target。
2. 首次安装时，App 将请求“VPN 配置”授权；允许后系统会在“设置 → VPN”中添加 `PrivateTunnel` 条目。
3. 在容器 App 内导入 Round 3 生成的 JSON 配置（扫码或文件导入），保存后在列表中选择该配置。
4. 点击 **Connect**：
   - 容器通过 `TunnelManager` 保存配置到 `NETunnelProviderManager`；
   - `PacketTunnelProvider.startTunnel` 被调用，解析 JSON 并应用 `NEPacketTunnelNetworkSettings`；
   - Mock Engine 启动，日志会每 5 秒打印一次健康检查；
   - 系统状态栏出现 VPN 图标，`NEVPNStatus == .connected`。
5. 点击 **Disconnect**：扩展停止 Mock Engine，系统回到断开状态。

> 💡 Mock Engine 不进行实际加解密与转发，网络流量仍会走系统默认路由。该实现仅用于验证配置与状态机是否正常。

## 日志与调试

- 使用 Xcode 的 **Console** 或 macOS 的 `Console.app` 过滤 `PacketTunnelProvider`、`MockEngine` 关键字查看日志。
- `Logger.swift` 基于 `os_log`，所有关键信息都使用 `info` 等级打印，可在 Release 版本中统一收敛。
- `TunnelManager` 的错误会通过 SwiftUI Alert 呈现，方便排查签名或配置问题。

## Kill Switch 占位

`PacketTunnelProvider` 中暴露 `enableKillSwitch` 字段但默认关闭。Round 5 仅记录 TODO，未对系统路由施加额外限制。未来计划：

1. 在断开前设置严格的 `includedRoutes`/`excludedRoutes` 或使用系统级 On-Demand 规则阻止直连；
2. 结合真实 WireGuard 引擎的连接状态，动态打开/关闭 Kill Switch。

## 常见错误

| 现象 | 可能原因 | 排查建议 |
| --- | --- | --- |
| 容器 App 点击 Connect 后立即弹窗“保存配置失败” | Bundle Identifier/Team ID 不匹配导致 `saveToPreferences` 失败 | 确认 App 与扩展的签名证书一致，重新生成 Provisioning Profile |
| 系统未弹出 VPN 权限授权 | 未在扩展 target 中启用 `packet-tunnel-provider` 能力 | 打开 Target → Signing & Capabilities，勾选 Network Extension |
| `startTunnel` 返回 “缺少配置数据” | `providerConfiguration` 未写入 JSON | 确认容器调用 `TunnelManager.save` 成功且 `pt_config_json` 字段存在 |
| `setTunnelNetworkSettings` 报错 | JSON 中的地址或 DNS 非法 | 使用 `core/tools/validate_config.py` 校验配置或在 UI 内重新导入 |

## 后续计划

- Round 5B/6：替换 `WGEngineMock` 为真实 WireGuard userspace 引擎（参考 `wireguard-apple`），完善握手与数据转发。
- Round 7+：扩展 `handleAppMessage` 与健康检查机制，为桌面/移动端提供统一状态面板。
- Round 8：实现路由白名单/域名分流策略，移除当前的“全量路由占位”逻辑。

