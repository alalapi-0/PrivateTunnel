# 可观测性与诊断说明（R2）

## 日志系统
- Python 运行时日志统一写入 `artifacts/logs/privatetunnel.log`，同时在终端输出。
- 日志格式包含时间、级别、模块和消息，便于交叉排查。
- 等级含义：
  - **INFO**：常规状态与流程提示。
  - **WARNING**：异常苗头或可能的配置问题（如无握手、服务未运行）。
  - **ERROR**：明确的错误或命令执行失败。

## 一键诊断菜单
- 在 `python main.py` 的主菜单中选择 `12) 诊断当前连接状态`。
- 执行步骤：
  1. 检查 `wg-quick@wg0` 服务状态。
  2. 读取 `wg show wg0 latest-handshakes`，标记近期握手与超时握手。
  3. 通过 `curl -4 -s ifconfig.me` 获取出口 IP。
  4. 使用 `socket.getaddrinfo` 解析 `github.com`，记录耗时与结果。
- 终端会给出彩色摘要，同时所有细节写入 `artifacts/logs/privatetunnel.log`。

### 诊断输出示例
```
🩺 诊断当前连接状态
→ 检查 WireGuard 服务状态…
✅ WireGuard 服务正在运行
→ 检查最近握手…
✅ abc123… 最近握手时间：2024-06-01 12:00:00（0 分钟内）
→ 检测出口 IP…
当前出口 IP：203.0.113.10
→ 测试 DNS 解析…
✅ DNS 解析成功：github.com → 140.82.112.3（45.2 ms）

诊断总结：
- 服务状态：active
- 握手：abc123… 正常
- 出口 IP：203.0.113.10
- DNS：正常
```

## 常见问题与日志排查
- **服务未启动**：日志中出现 `WireGuard 服务未在运行`，建议 `systemctl restart wg-quick@wg0` 或重新部署。
- **无握手**：日志包含 `暂无握手记录` 或 `超 10 分钟`，可能是客户端未启动、端口被封或配置错误。
- **DNS 解析失败**：日志显示 `DNS 解析失败`，可尝试更换 DNS、检查本地网络或代理。
- **出口 IP 未变化**：诊断输出的出口 IP 与预期不符，可能未走隧道或路由未生效，需检查 WireGuard 服务与防火墙。

## 建议的冒烟测试
1. 运行 `python main.py`，确认菜单出现 `诊断当前连接状态` 选项并可执行。
2. 执行诊断，检查终端与 `artifacts/logs/privatetunnel.log` 是否同时记录步骤与结果。
3. 启动连接监控后观察日志是否定期记录延迟/丢包；触发异常时日志是否包含 WARNING/ERROR。
4. 重新跑一次部署流程，确认新的日志文件生成且旧功能（如配置下载）不受影响。

## R3：面向大陆的低成本连通性补丁
- **端口选择**：默认优先尝试 `443`，如本机检测到被占用则在 `20000–45000` 间随机挑选可用端口并写日志（尝试/最终值）。客户端与服务端配置统一使用选出的端口。
- **DNS 策略**：默认 DNS 顺序为 `223.5.5.5, 114.114.114.114, 1.1.1.1, 8.8.8.8`，用户设置 `PT_DNS` 时优先生效。生成配置时会在日志中打印实际使用列表。
- **Keepalive / MTU**：Keepalive 默认在 20 秒基础上加入随机扰动（约 15–30s，用户显式指定时关闭随机）；MTU 采用“用户 > 探测 > 默认 1420”优先级，决策来源会写入日志。
- **连接监控自恢复**：监控采集失败会按指数退避重试，连续多次健康检查失败（默认 3 次）会触发一次 WireGuard 重启（带 5 分钟节流），重启前后均记录日志并追加一次健康检测。

### 日志查阅指引
- 端口选择：在 `privatetunnel.log` 搜索 `WireGuard port` 或 `fallback` 关键字。
- DNS/Keepalive/MTU：部署阶段会记录 `客户端 DNS`、`Keepalive`、`MTU` 等行，随机扰动的基准和偏移会以 `Keepalive chosen with jitter` 的 extra 字段出现。
- 监控重试：连接采集失败会输出 `Connection metrics failed` WARNING，自动重启时会出现 `Attempting WireGuard restart for node`、`WireGuard restart triggered/failed` 等日志，事后验证记录为 `Post-recovery health check`。
