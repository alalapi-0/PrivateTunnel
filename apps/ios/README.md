# iOS 客户端骨架（占位说明）

> 这是占位实现：此目录将用于存放 iOS 主应用与 PacketTunnel Extension 工程。

## 计划内容

- Swift/SwiftUI 主应用：负责账号管理、隧道开关、策略展示。
- Network Extension (PacketTunnel)：处理 WireGuard 或自定义协议隧道。
- Shared Containers：用于存储配置与凭证。

## TODO

- 创建 Xcode 工程并配置 Bundle Identifier。
- 引入 WireGuardKit 或自行封装协议栈。
- 接入配置同步逻辑（与 core 生成的配置对接）。
