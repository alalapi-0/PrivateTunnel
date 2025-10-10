# Roadmap

本文件追踪 PrivateTunnel 的阶段性目标。前 10 轮迭代已基本完成，后续方向可根据实际需求调整。

## 已完成迭代

1. ✅ Round 1：搭建 monorepo 脚手架与占位脚本。
2. ✅ Round 2：设计 WireGuard 客户端配置与生成工具。
3. ✅ Round 3：实现服务器侧自动化脚本与配置二维码生成。
4. ✅ Round 4：构建 iOS 容器 App，支持扫码/文件导入。
5. ✅ Round 5：集成 PacketTunnel 扩展，建立基础连接流程。
6. ✅ Round 6：toy UDP/TUN 通道用于端到端联调（仅开发用途）。
7. ✅ Round 7：iOS 健康检查、自动重连与软 Kill Switch。
8. ✅ Round 8：域名分流（服务器 ipset/nftables + iOS 白名单模式）。
9. ✅ Round 9：安全审计与日志体系。
10. ✅ Round 10：完善文档、CI、打包与分发流程。

## 下一步规划建议

- **A. 接入 WireGuard 官方 iOS 引擎**：
  - 将现有自定义实现迁移至 `wireguard-apple` 提供的高性能数据面；
  - 需要评估 NEPacketTunnelProvider 与 WireGuard Go 的整合方案；
  - 引入后可显著降低维护成本，并获得成熟的密钥轮换与压缩策略。

- **B. 多节点与智能选路**：
  - 支持在客户端选择不同出口节点；
  - 引入延迟/带宽探测，自动选择最优节点；
  - 与现有分流策略结合，实现更细粒度的路由。

- **C. 桌面壳完善**：
  - 扩展 macOS、Windows 客户端的 UI 与自动更新；
  - 建立统一的配置同步机制（例如 iCloud Drive/自建 API）；
  - 结合桌面平台的通知与登录体验，提供更一致的跨平台支持。

欢迎根据团队需求选择其中一项或多项，并在实施前评估开发成本与安全影响。
