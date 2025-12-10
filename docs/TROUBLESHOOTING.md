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

## 多节点相关问题

### 节点无法切换

| 现象 | 检查项 | 解决方案 |
| --- | --- | --- |
| 多节点模式下无法切换到备用节点 | 节点健康状态 | 使用菜单选项 `7) 节点健康检查` 查看所有节点状态，确认备用节点健康 |
| 智能选路未生效 | 环境变量配置 | 确认 `PT_SMART_ROUTING=true` 和 `PT_ROUTING_STRATEGY` 设置正确 |
| 节点状态显示异常 | 节点配置文件 | 检查 `artifacts/multi-node.json` 文件是否存在且格式正确 |

### 故障转移失败

1. **检查节点健康状态**：
   - 运行菜单选项 `7) 节点健康检查`
   - 确认至少有一个备用节点处于健康状态

2. **检查节点配置**：
   - 确认节点优先级和权重设置合理
   - 使用菜单选项 `6) 多节点管理` 查看节点配置

3. **查看日志**：
   - 检查 `artifacts/deploy-*.log` 中的故障转移日志
   - 确认故障转移逻辑是否正常执行

## 智能选路问题

### 选路策略不生效

| 现象 | 原因 | 解决 |
| --- | --- | --- |
| 延迟优先策略仍选择高延迟节点 | 节点健康状态影响 | 检查节点健康状态，不健康的节点会被排除 |
| 权重优先策略未按预期分配流量 | 权重配置不合理 | 调整节点权重，确保差异足够明显 |
| 平衡模式选择结果不符合预期 | 权重和优先级配置冲突 | 重新评估节点配置，确保权重和优先级设置合理 |

### 选路性能问题

- **选路耗时过长**：减少节点数量或增加健康检查缓存时间
- **选路结果不稳定**：启用连接监控，使用历史数据辅助选路

## 连接监控问题

### 监控数据不准确

| 现象 | 原因 | 解决 |
| --- | --- | --- |
| 延迟数据异常高 | 监控间隔过短 | 增加 `PT_MONITOR_INTERVAL` 值（建议 30-60 秒） |
| 丢包率始终为 0 | 监控未正确启用 | 确认 `PT_ENABLE_MONITORING=true` 已设置 |
| 历史数据丢失 | 数据文件损坏 | 检查 `artifacts/monitor/` 目录，必要时重新启用监控 |

### 监控影响性能

- **系统负载过高**：增加监控间隔，减少监控频率
- **网络带宽占用**：调整监控检查的详细程度

## 自适应参数问题

### 参数调整不生效

| 现象 | 原因 | 解决 |
| --- | --- | --- |
| Keepalive 未自动调整 | 自适应功能未启用 | 确认 `PT_ENABLE_ADAPTIVE=true` 和 `PT_ENABLE_MONITORING=true` 都已设置 |
| MTU 调整后连接失败 | MTU 值过小 | 查看参数调整建议，手动设置合理的 MTU 值 |
| 参数频繁变化 | 网络不稳定 | 检查网络连接质量，必要时禁用自适应功能 |

### 查看调整建议

- 使用菜单选项 `10) 参数调整建议` 查看当前参数和建议参数
- 根据建议手动调整参数，观察效果

## ChatGPT 相关问题

### ChatGPT 无法访问

| 现象 | 检查项 | 解决方案 |
| --- | --- | --- |
| ChatGPT 网站无法打开 | 域名解析失败 | 运行菜单选项 `11) ChatGPT 连接测试`，检查域名解析结果 |
| OpenAI API 连接超时 | 节点延迟过高 | 启用智能选路，使用延迟优先策略选择节点 |
| 连接不稳定 | 参数未优化 | 启用 ChatGPT 模式：`PT_CHATGPT_MODE=true`，系统会自动优化参数 |

### ChatGPT 连接测试失败

1. **检查域名解析**：
   - 运行 ChatGPT 连接测试
   - 查看域名解析结果，确认 IP 地址正确

2. **检查节点选择**：
   - 确认使用延迟较低的节点
   - 启用智能选路，使用延迟优先策略

3. **检查分流配置**：
   - 确认 ChatGPT 专用分流配置已生成
   - 检查客户端配置中的 AllowedIPs 设置

## V2Ray 相关问题

### V2Ray 连接失败

| 现象 | 检查项 | 解决方案 |
| --- | --- | --- |
| V2Ray 客户端无法连接 | 端口未开放 | 确认防火墙开放 V2Ray 端口（默认 443） |
| 连接后立即断开 | UUID 不匹配 | 检查 `PT_V2RAY_UUID` 配置，确保客户端和服务器 UUID 一致 |
| 流量伪装未生效 | V2Ray 未正确部署 | 检查服务器 V2Ray 服务状态，确认配置正确 |

### V2Ray 性能问题

- **延迟增加过多**：V2Ray 会增加一定延迟（通常 < 50ms），这是正常现象
- **带宽占用高**：V2Ray 会增加约 5-10% 的带宽开销，这是流量伪装的代价
- **连接不稳定**：检查 V2Ray 日志，确认配置正确

## 日志与诊断

- iOS 端可在 Xcode → `Devices and Simulators` 查看实时日志，或使用 `Console.app`；
- 服务器端使用 `journalctl -u wg-quick@wg0 -f` 观察 WireGuard 状态；
- `server/security/audit.sh --json` 可用于检查服务器安全基线；
- Nightly Workflow 上传的 `server/split/state/resolved.json` 有助于回溯域名解析变化；
- 多节点模式下，检查 `artifacts/multi-node.json` 查看节点配置和状态；
- 连接监控数据保存在 `artifacts/monitor/` 目录，可用于分析连接质量趋势。

## 环境变量配置检查

### 常见配置错误

| 错误 | 现象 | 解决 |
| --- | --- | --- |
| `PT_MULTI_NODE=true` 但未创建多个节点 | 多节点功能无法使用 | 创建至少 2 个节点，或禁用多节点模式 |
| `PT_SMART_ROUTING=true` 但 `PT_MULTI_NODE=false` | 智能选路不生效 | 启用多节点模式：`PT_MULTI_NODE=true` |
| `PT_ENABLE_ADAPTIVE=true` 但 `PT_ENABLE_MONITORING=false` | 自适应功能不工作 | 同时启用监控：`PT_ENABLE_MONITORING=true` |
| `PT_CHATGPT_MODE=true` 但节点延迟高 | ChatGPT 访问慢 | 启用智能选路，使用延迟优先策略 |

### 配置验证

运行以下命令验证环境变量：

```bash
# Windows PowerShell
Get-ChildItem Env: | Where-Object { $_.Name -like "PT_*" -or $_.Name -like "VULTR_*" }

# Linux/macOS
env | grep -E "PT_|VULTR_"
```

## 进一步协助

若排查仍未解决，可：

1. 收集容器 App 与扩展的日志（注意脱敏）；
2. 记录最近一次成功连接的时间点与变更；
3. 收集环境变量配置（注意脱敏敏感信息）；
4. 收集节点配置和健康检查结果；
5. 在仓库提交 Issue 或 PR，并附上上述信息。

## 代理相关问题

### 无法通过代理访问外网

| 现象 | 检查项 | 解决方案 |
| --- | --- | --- |
| 设置了 `ALL_PROXY` 但程序仍无法访问外网 | 代理服务未运行 | 1. 检查代理软件（Clash、V2RayN 等）是否正在运行；2. 检查代理端口是否正确（Clash 默认 7890，V2RayN 默认 10809）；3. 使用 `scripts/setup_proxy.ps1` 或 `scripts/setup_proxy.sh` 自动检测代理 |
| 代理连接超时 | 代理地址或端口错误 | 1. 确认代理地址为 `127.0.0.1` 或 `localhost`；2. 确认端口号正确；3. 检查代理软件是否允许本地连接 |
| 部分请求失败 | 代理协议不匹配 | 1. 确认代理协议正确（HTTP 代理使用 `http://`，SOCKS5 使用 `socks5://`）；2. 注意 `urllib` 不支持 SOCKS 代理，如果使用 `urllib` 请使用 HTTP 代理 |
| 环境变量设置后不生效 | 环境变量作用域问题 | 1. Windows: 确保在同一个 PowerShell 会话中设置和运行；2. Linux/macOS: 确保在同一个 Shell 会话中设置和运行；3. 或使用 `setup_proxy.ps1`/`setup_proxy.sh` 脚本自动配置 |

### 代理检测失败

如果自动检测代理功能无法检测到本地代理服务：

1. **检查代理服务是否运行**：

   - Windows: 查看任务管理器，确认 Clash/V2RayN 进程存在

   - Linux/macOS: 使用 `ps aux | grep clash` 或类似命令检查

2. **检查代理端口**：

   - 使用 `netstat -an | grep 7890`（Linux/macOS）或 `netstat -an | findstr 7890`（Windows）检查端口是否监听

   - 确认端口号与代理软件配置一致

3. **手动指定端口**：

   ```python
   from core.proxy_utils import detect_local_proxy

   # 检测自定义端口
   detected = detect_local_proxy(custom_ports=[8080, 8888])
   ```

### 代理配置验证

使用以下代码验证代理配置是否正确：

```python
from core.proxy_utils import get_proxy_config, log_proxy_status

# 查看当前代理配置
config = get_proxy_config()
print(f"代理配置: {config}")

# 查看代理状态
log_proxy_status()
```

### 常见错误

- **`Connection refused`**: 代理服务未运行或端口错误
- **`Timeout`**: 代理服务器响应慢或网络问题
- **`Proxy authentication required`**: 代理需要认证（当前版本不支持，需要手动配置带认证的代理 URL）

## 相关文档

- [功能说明](FEATURES.md) - 了解所有功能特性
- [用户使用指南](USER_GUIDE.md) - 查看详细使用说明
- [环境变量说明](ENVIRONMENT_VARIABLES.md) - 配置环境变量
- [快速开始指南](GETTING_STARTED.md) - 快速上手
