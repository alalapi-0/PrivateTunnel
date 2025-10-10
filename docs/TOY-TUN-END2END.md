# Toy UDP/TUN 通道端到端联调指南

> ⚠️ **重要警告**：本指南涉及的 toy 通道完全没有加密与鉴权，仅允许单人开发者在受控环境下短时调试。请务必：
>
> - 在云防火墙中限制 UDP 端口，仅允许你的出口 IP 访问；
> - 联调结束后立刻执行 `teardown_tun.sh` 并停止 `toy_tun_gateway.py`；
> - 不要在生产或多人共享环境使用本方案。

## 目录

1. [前置条件](#前置条件)
2. [服务器端准备](#服务器端准备)
3. [iOS 客户端配置](#ios-客户端配置)
4. [联调步骤](#联调步骤)
5. [验证方法](#验证方法)
6. [常见问题排查](#常见问题排查)
7. [清理与注意事项](#清理与注意事项)

## 前置条件

- 一台可 SSH 的 Linux VPS（推荐 Ubuntu 22.04+），具备公网 IPv4；
- Python 3.9+ 与基础工具链（`ip`, `iptables`, `sysctl`）；
- 从仓库拉取 `PrivateTunnel` 代码；
- 一台 iOS 真机，已安装容器 App 并具备开发者证书。

## 服务器端准备

1. 登录 VPS，进入仓库目录：
   ```bash
   cd ~/PrivateTunnel/server/toy-gateway
   cp .env.example .env    # 根据实际网络调整端口/接口/子网
   vim .env                # 设置 WAN_IF、TOY_TUN_ADDR 等
   ```
2. 创建 TUN 设备并配置 NAT：
   ```bash
   sudo bash setup_tun.sh
   ```
   脚本会：
   - 创建 `toy0`（或 `.env` 中指定的名称）并分配 `10.66.0.1/24`；
   - 将 MTU 设置为 1380；
   - 打开 `net.ipv4.ip_forward`；
   - 在 `POSTROUTING` 表添加 `MASQUERADE` 规则。
3. 启动 UDP ↔︎ TUN 桥接守护进程：
   ```bash
   python3 toy_tun_gateway.py --verbose
   ```
   默认监听 `0.0.0.0:35000`，可通过 `--listen` 调整。

## iOS 客户端配置

- 在容器 App 的配置 JSON 中新增字段：
  ```jsonc
  {
    "engine": "toy",
    "routing": {
      "mode": "global",
      "allowed_ips": ["0.0.0.0/0"]
    },
    "endpoint": {
      "host": "<你的VPS IP>",
      "port": 35000,
      "public_key": "placeholder"
    },
    "client": {
      "address": "10.66.0.2/32",
      "dns": ["1.1.1.1"],
      "mtu": 1380
    }
  }
  ```
- 通过容器 App 发送 `pt_config_json` 给 Packet Tunnel 扩展，`routing.mode` 必须为 `global`。

## 联调步骤

1. 确认 VPS 端 `toy_tun_gateway.py` 正在运行，并在终端保持窗口以观察日志。
2. 将真机连接到 Wi-Fi，打开容器 App，选择 `engine=toy` 的配置后点击 **Connect**。
3. 等待系统状态栏出现 VPN 图标，同时在 VPS 终端应看到 `Ping/Pong` 或 `UDP -> TUN` 日志。
4. 在 iOS 端使用 Safari 访问 `http://1.1.1.1/` 或通过 Termius 等工具执行 `ping 1.1.1.1`，观察数据包统计是否递增。
5. 若需要查看 toy 引擎统计信息，可在容器 App 发送 app message，扩展会返回：
   ```json
   {
     "status": 3,
     "engine": "toy",
     "toy_stats": {
       "packets_sent": 42,
       "packets_received": 40,
       "bytes_sent": 32768,
       "bytes_received": 30124,
       "last_activity": "2023-09-01T12:34:56.123Z",
       "heartbeats_missed": 0
     }
   }
   ```

## 验证方法

- **基本连通性**：真机上执行 `ping 1.1.1.1`（若 ICMP 被屏蔽，可访问 `http://example.com`）。
- **VPS 观察**：`toy_tun_gateway.py --verbose` 会打印 `UDP -> TUN` 与 `TUN -> UDP` 的字节数。
- **抓包**：
  ```bash
  sudo tcpdump -ni toy0
  sudo tcpdump -ni $WAN_IF host 1.1.1.1
  ```
- **MTU 调优**：若访问网站卡顿，可将 `.env` 与 iOS 配置中的 MTU 同时调低到 1280。

## 常见问题排查

| 现象 | 可能原因 | 排查步骤 |
| ---- | -------- | -------- |
| VPS 没有日志输出 | UDP 流量被云防火墙阻断 | 将监听端口改为 443/853，并在安全组放行 |
| 心跳反复重连 | 移动网络 NAT 激进 | 缩短 `--listen` 端口超时时间或换用稳定网络 |
| iOS 无法出网 | NAT 未生效 / 路由错误 | 检查 `iptables -t nat -S POSTROUTING`，确认 `MASQUERADE` 条目存在 |
| 大文件下载失败 | MTU 过大 | 将 MTU 下调到 1280 后重启 tunnel |

## 清理与注意事项

1. 在 iOS 端点击 **Disconnect**，等待扩展停止心跳。
2. 回到 VPS 终端，终止 `toy_tun_gateway.py`（Ctrl+C）。
3. 执行：
   ```bash
   sudo bash teardown_tun.sh
   ```
4. 如需恢复默认的 `net.ipv4.ip_forward` 值，可运行：
   ```bash
   sudo sysctl -w net.ipv4.ip_forward=0
   ```
5. 删除 `.env` 中保存的临时密钥或 IP 白名单设置。

> ⚠️ 再次提醒：toy 通道仅用于验证数据通道通畅。正式上线时请启用 WireGuard 或其它安全协议。
