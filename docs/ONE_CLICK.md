# One-Click Connect

1. 在仓库 **Settings → Secrets → Actions** 配置：
   - `VULTR_API_KEY`、`SSH_PRIVATE_KEY`、`SSH_PUBLIC_KEY`、`SNAPSHOT_ID`
2. **Access Control**：在 Vultr API 页面放行你调用源 IP。
3. 进入 **Actions → One-Click Connect → Run workflow**，按需填：
   - `region`(默认 nrt)、`plan`(默认 vc2-1c-1gb)、`client_name`、`client_addr`、`wg_port`
4. 运行结束后在 Artifacts 下载：
   - `<client_name>.png`（二维码）与 `<client_name>.conf`
5. iPhone 打开 WireGuard → 从二维码创建 → 扫码 → 连接。
6. 排障：
   - `wg show` 无握手 → 核对 NAT 规则与端口 51820/udp
   - 不能调 API → 检查 API Key 与 Access Control
