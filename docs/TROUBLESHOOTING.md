# 故障排查手册

PrivateTunnel 包含服务器、iOS 客户端、分流脚本等多个组件。本手册列举常见问题及处理建议，帮助快速定位故障来源。

## 连接失败或掉线

| 现象 | 检查项 | 解决方案 |
| --- | --- | --- |
| 无法建立连接，WireGuard 日志显示 `Handshake did not complete` | 服务器 UDP 端口未开放 | 确认云防火墙/安全组开放 `51820/UDP`，并检查 `wg-quick@wg0` 服务状态。|
| 日志持续出现 `Sending handshake initiation` → `Handshake did not complete after 5 seconds`，客户端显示“已连接”但无流量 | 服务器端未收到握手（端口被运营商/NAT/防火墙屏蔽），或配置公钥/AllowedIPs 不匹配 | 1. 在服务器执行 `sudo journalctl -u wg-quick@wg0 -f`，观察是否有对应客户端的 `Handshake for peer ...`；2. 若日志无响应，确认出口 IP 202.182.116.76 的 `51820/UDP` 未被拦截，可尝试临时改用 `443/UDP`；3. 若服务器有日志但握手失败，重新导出服务器端配置，确保客户端公钥与 `AllowedIPs` 与服务器一致。|
| 连接后立即断开，日志出现 `Invalid keepalive` | MTU 不匹配 | 在客户端配置中将 `MTU=1380`，或参考服务器端日志调整。|
| 长时间无流量后断线 | Keepalive 太长 | 在 `core/examples/` 中调整 `persistent_keepalive`（建议 25s）。|
| 配置导入后仍显示“未受信任的开发者” | 未正确签名 | 按 [CODE_SIGNING.md](CODE_SIGNING.md) 重新配置团队与证书。|

## DNS 与网络访问问题

- **域名解析失败**：
  - 检查 `server/split/resolve_domains.py` 的输出，确认 `state/resolved.json` 中目标域名已解析；
  - 在客户端临时切换到全局路由，排除 DNS 劫持问题；
  - 确认服务器上的 `systemd-resolved` 或自建 DNS 是否正常工作。

- **DoH/DoT 导致慢速**：
  - 若启用 DoH，请确保端口 443/853 未被拦截；
  - 可在 iOS 客户端上暂时改用纯 IP DNS（例如 `1.1.1.1`）观察差异。

## 分流命中异常

| 现象 | 原因 | 解决 |
| --- | --- | --- |
| 某些域名未走隧道 | `domains.yaml` 未覆盖 | 使用 `python3 server/split/resolve_domains.py --domain example.com` 手动检查解析结果。|
| 误将出口流量直连 | `ipset` 未加载成功 | 查看 `server/split/ipset_apply.sh` 日志，确认定时任务是否执行。|
| TLS 握手失败 | 系统时间漂移 | 保持服务器与客户端时钟同步（NTP），并在 VPN 内启用 NTP 源。|

## Toy 通道相关

Toy UDP/TUN 模块仅供开发调试，缺乏加密与鉴权：

- 确保仅在受控网络中短时间开启 `toy_tun_gateway.py`；
- 若发现 `PONG timeout`，检查客户端与服务器的心跳间隔、网络丢包率；
- 在云服务商安全组中仅允许来源于调试设备的 IP。

## 日志与诊断

- iOS 端可在 Xcode → `Devices and Simulators` 查看实时日志，或使用 `Console.app`；
- 服务器端使用 `journalctl -u wg-quick@wg0 -f` 观察 WireGuard 状态；
- `server/security/audit.sh --json` 可用于检查服务器安全基线；
- Nightly Workflow 上传的 `server/split/state/resolved.json` 有助于回溯域名解析变化。

## 进一步协助

若排查仍未解决，可：

1. 收集容器 App 与扩展的日志（注意脱敏）；
2. 记录最近一次成功连接的时间点与变更；
3. 在仓库提交 Issue 或 PR，并附上上述信息。
