# One-Click Connect（GitHub Actions）

本指南介绍如何通过仓库内的 `One-Click Connect` GitHub Actions 工作流，一键在 Vultr 上基于现有快照创建 WireGuard 服务器、生成首个客户端二维码，并将二维码与配置文件作为 Artifacts 回传。整个过程可重复、可追踪，适合临时开设或快速更新节点。

## 前置要求

1. **Vultr 账号与快照**：提前使用 `server/provision/wg-install.sh` 或其他手段在 Vultr 创建好基于 Ubuntu 22.04 的快照，并记录其 `SNAPSHOT_ID`。
2. **API Access Control**：确保触发工作流的 IP（GitHub Actions 出网 IP 列表）已被 Vultr [Access Control](https://www.vultr.com/docs/access-control/) 放行，否则 API 调用会被拒绝。
3. **GitHub Secrets**：在仓库 Settings → Secrets → Actions 中设置以下条目：
   - `VULTR_API_KEY`：Vultr Personal Access Token（已开启 API 权限并放行 IP）。
   - `SSH_PRIVATE_KEY` / `SSH_PUBLIC_KEY`：一对没有 passphrase 的 OpenSSH 密钥，用于登录新实例。
   - `SNAPSHOT_ID`：默认使用的快照 ID，可在运行工作流时覆盖。
4. **快照网络**：以 Ubuntu 22.04 系列镜像/快照为前提（iptables-nft），若快照已额外启用了 UFW/Firewalld，请确认 22/tcp 与 WireGuard UDP 端口未被阻断。

## 操作步骤

1. **触发工作流**：进入 GitHub → Actions → `One-Click Connect` → `Run workflow`，填写参数：
   - `region`（默认 `nrt`）
   - `plan`（默认 `vc2-1c-1gb`）
   - `snapshot_id`（可留空使用 Secrets）
   - `client_name`（默认 `iphone`）
   - `client_addr`（默认 `10.6.0.2/32`）
   - `wg_port`（默认 `51820`）
2. **等待自动化执行**：工作流会顺序执行以下任务：
   - 使用提供的 SSH 公钥在 Vultr 中创建/更新 `privatetunnel-oneclick` SSH Key，并在实例创建时引用。
   - 读取 `server/cloudinit/user-data.sh`，注入参数并作为 `user_data` 随实例启动。
   - 创建实例并轮询状态直至 `status=active` 且获取 IPv4。
   - 通过 `scripts/wait_for_ssh.sh` 监测 SSH 可达性。
   - 等待 `/root/<client>.png` 与 `/root/<client>.conf` 生成并下载。
   - 将二维码 PNG 与配置文件以 Artifacts 上传，并在 Job Summary 中展示 IP、端口、`wg show` 与 `ss -lun` 结果。
3. **下载客户端配置**：在工作流详情页的 `Artifacts` 区块点击下载 ZIP，内含 `${client_name}.png` 与 `${client_name}.conf`。二维码可直接在 iOS 客户端扫描导入。
4. **确认连通性**：Summary 中包含 `wg show wg0` 与 `ss -lun | grep :<port>`，可快速验证端口监听与对端条目；若需要进一步验证，可远程执行 `curl https://ifconfig.me` 检查外网出口。

## 常见问题与排查

| 症状 | 排查建议 |
| --- | --- |
| `Snapshot ID required` | 确认 `SNAPSHOT_ID` Secret 是否配置，或在手动触发时填写 `snapshot_id`。 |
| API 返回 403 / Access denied | 检查 Vultr Access Control 是否放行 GitHub Actions 出网 IP；必要时暂时关闭限制。 |
| `Timed out waiting for WireGuard client artifacts` | 登录实例查看 `/var/log/cloud-init-output.log` 与 `/root/user-data.log`（脚本输出），确认包安装、WireGuard 服务是否成功；必要时执行 `bash /var/lib/cloud/scripts/per-instance/user-data.sh` 复现。 |
| `wg show` 中无 peer | 检查 `CLIENT_ADDR` 是否格式正确，或在实例内执行 `wg set wg0 peer <pubkey> allowed-ips <cidr>` 手动补齐。 |
| 端口未监听 | 查看 `ss -lun | grep :<port>`、`iptables -t nat -S POSTROUTING`，确认脚本已写入 NAT 规则；若快照启用了 UFW，执行 `ufw allow <port>/udp`。 |
| 扫码后无法联网 | 确认客户端 DNS、AllowedIPs、Endpoint 是否正确；脚本默认使用 `WAN_IF` 的 IPv4，若实例位于内网 NAT，请手动编辑 `/root/<client>.conf` 的 `Endpoint`。 |

## 复用与清理

- **重复执行**：脚本具备幂等性，多次运行同一实例不会重复生成密钥或堆叠 iptables 规则。再次触发工作流会创建新的实例并生成新的客户端文件。
- **实例清理**：如需销毁实例，可登录 Vultr 控制台或调用 `DELETE /v2/instances/{id}`。工作流 Summary 中包含 `Instance ID`，方便定位。
- **本地调试**：可使用 `scripts/vultr_create_from_snapshot.sh` 在本地（需设置 `VULTR_API_KEY`、`SNAPSHOT_ID`）快速验证 API 调用逻辑。

## 安全提示

- 不要在仓库或日志中输出任何 Secrets 值。
- 建议将 Vultr API Token 限制为只允许必要的实例与 SSH Key 操作，并启用 2FA。
- 下载的客户端配置包含私钥，请妥善保存；若泄露，请重新生成客户端并撤销旧密钥。

执行完整流程后，即可通过下载的二维码在 iOS 客户端导入 WireGuard 配置，实现真正的一键开箱体验。
