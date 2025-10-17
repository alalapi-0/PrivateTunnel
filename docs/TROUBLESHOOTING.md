# 故障排查手册

PrivateTunnel 包含服务器、iOS 客户端、分流脚本等多个组件。本手册列举常见问题及处理建议，帮助快速定位故障来源。

## 连接失败或掉线

| 现象 | 检查项 | 解决方案 |
| --- | --- | --- |
| 无法建立连接，WireGuard 日志显示 `Handshake did not complete` | 服务器 UDP 端口未开放 | 确认云防火墙/安全组开放 `443/UDP`（如自定义为 51820 或其它端口，请相应调整），并检查 `wg-quick@wg0` 服务状态。|

| 日志持续出现 `Sending handshake initiation` → `Handshake did not complete after 5 seconds`，客户端显示“已连接”但无流量 | 服务器端未收到握手（端口被运营商/NAT/防火墙屏蔽），或配置公钥/AllowedIPs 不匹配 | 1. 在服务器执行 `sudo journalctl -u wg-quick@wg0 -f`，观察是否有对应客户端的 `Handshake for peer ...`；2. 若日志无响应，确认出口 IP 202.182.116.76 的 `443/UDP` 未被拦截，可改用 `PRIVATETUNNEL_WG_PORT=51820`（或 `PT_WG_PORT`）后重新运行 Windows 一键/脚本流程生成监听 51820/UDP 的配置；3. 若服务器有日志但握手失败，重新导出服务器端配置，确保客户端公钥与 `AllowedIPs` 与服务器一致；4. 在 Windows 客户端上用 `Get-NetFirewallRule -DisplayGroup "WireGuard"` 或直接关闭第三方安全软件确认本地出口未被拦截；5. 在服务器上执行 `sudo wg show wg0 latest-handshakes` 核对时间戳，若长时间为 `0`，说明握手包未到达，可在路由器/运营商侧申请放通或改用端口转发。|

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

## Vultr “Reinstall SSH Keys” 自动化失败

触发 Vultr 的 **Reinstall SSH Keys** API 时，必须显式告知 Vultr 需要注入的 SSH Key ID。脚本会按以下顺序尝试收集 ID：

1. 读取 `artifacts/instance.json` 中的 `ssh_key_ids` 或 `ssh_key_id`，这是创建实例时写入的原始数据。
2. 若缺少 ID，则根据实例记录的 `ssh_key_name` 在账号内查询公钥列表，依赖 `VULTR_API_KEY` 重新拉取并匹配名称。

只要以上两个信息都缺失，API 就无法确定要注入哪把钥匙，脚本会直接报错并停止自动化流程。

排查建议：

- 确认运行 `main.py` 或 `scripts/windows_oneclick.py` 时已导出 `VULTR_API_KEY`，否则无法调用 `list_ssh_keys` 读取账户内的公钥列表。脚本检测不到 `ssh_key_ids` 时会二次获取并更新 `artifacts/instance.json`，便于后续重试。【F:main.py†L594-L642】

- 若希望在执行重装前确认 Vultr 账户里有哪些 SSH 公钥，可直接使用同一 API 读取。例如：

  ```bash
  VULTR_API_KEY=... python - <<'PY'
  import json, os
  from core.tools.vultr_manager import list_ssh_keys

  keys = list_ssh_keys(os.environ["VULTR_API_KEY"])
  print(json.dumps(keys, indent=2, ensure_ascii=False))
  PY
  ```

  输出会包含 `id`、`name` 等字段，可在重装前手动确认或写入 `artifacts/instance.json`。该函数与自动化流程使用的是同一实现，因此无须等待脚本失败后再采集一次。【F:core/tools/vultr_manager.py†L73-L96】


- 检查 `artifacts/instance.json` 是否仍在本地，且包含 `ssh_key_ids`/`ssh_key_name` 字段；若文件被删除，可在 Vultr 控制台查到原始公钥的 ID，再写回到文件后重试。【F:main.py†L594-L656】
- 如果曾重命名或删除 Vultr 控制台里的 SSH Key，请恢复原名称或在 `artifacts/instance.json` 中手动更新 `ssh_key_ids`，否则名称匹配会失败。

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
