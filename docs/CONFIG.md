# PrivateTunnel 客户端配置指南

本文档说明如何使用 `core/config-schema.json`、校验工具与生成脚本，从统一的
JSON 配置生成 WireGuard 客户端配置文件，并进一步导出二维码。流程既适用于单机
手工维护，也方便后续集成 CI/CD 渠道。

## 字段总览

配置文件结构如下：

```jsonc
{
  "version": "1",
  "profile_name": "iphone",
  "endpoint": { /* 服务端信息 */ },
  "client": { /* 本端密钥与网络参数 */ },
  "routing": { /* 分流策略 */ },
  "notes": "optional"
}
```

各字段说明：

- `version`：当前仅支持字符串 `"1"`。未来版本将通过 schema 控制升级节奏。
- `profile_name`：用于生成 `profile_name.conf`、二维码文件等。仅允许字母、数字、
  `.`、`_`、`-`，长度不超过 64。
- `endpoint`：描述服务器连接端点。
  - `host`：服务器的公网 IP 或域名。
  - `port`：WireGuard 监听的 UDP 端口。
  - `public_key`：服务器 WireGuard 公钥（Base64）。
  - `ipv6`：是否启用 IPv6 隧道，v1 仅为占位，暂不改变输出。
- `client`：客户端私钥及本地网络设置。
  - `private_key`：WireGuard 私钥。务必限制文件权限并妥善备份。
  - `address`：隧道内分配给客户端的 IP (CIDR)。
  - `dns`：至少一个 DNS 地址或域名，按 WireGuard `DNS =` 语法写入。
  - `mtu`：可选；不填则保持默认。
  - `keepalive`：`PersistentKeepalive` 间隔秒数，未提供时默认 25；如需关闭可显式
    设为 0。
- `routing`：分流策略。
  - `mode`：`global` 表示全局代理，`whitelist` 表示按域名白名单。
  - `allowed_ips`：仅在 `mode = global` 时填写，为 WireGuard `AllowedIPs` 列表。
  - `whitelist_domains`：仅在 `mode = whitelist` 时填写，为待代理域名；v1 仍输出
    全局 `AllowedIPs`，待 Round 8 的服务器脚本同步 IP 集合。
- `notes`：可选备注，工具不会消费该字段。

Schema 中禁止未列出的额外字段。所有校验规则（如 Base64、端口范围、CIDR 格式）
都在 `config-schema.json` 中声明，可提前发现拼写或格式问题。

## 从 JSON 到二维码的三步

以下以 `core/examples/minimal.json` 为例：

1. **校验 JSON**
   ```bash
   python3 core/tools/validate_config.py \
       --schema core/config-schema.json \
       --in core/examples/minimal.json --pretty
   ```
   成功时脚本会打印“Validation succeeded …”并展示脱敏后的 JSON。

2. **生成 WireGuard 配置**
   ```bash
   python3 core/tools/generate_wg_conf.py \
       --schema core/config-schema.json \
       --in core/examples/minimal.json \
       --out /tmp/iphone.conf --force
   ```
   输出的 `iphone.conf` 包含 `[Interface]` 与 `[Peer]` 两个段落，可直接导入客户端。

3. **渲染二维码**
   ```bash
   bash core/qr/gen_qr.sh /tmp/iphone.conf
   ```
   终端会显示 ANSI QR 码，可用 WireGuard iOS/macOS/Android App 扫描导入。
   如果需要 PNG 文件，追加 `--png`，脚本会生成 `/tmp/iphone.png`。

## whitelist 模式说明

`routing.mode = "whitelist"` 时，需配合服务器端的域名解析与 ipset 同步能力
（计划在 Round 8 实现）。在此之前生成的客户端配置会在文件首行输出警告，并暂时
继续写入全局 `AllowedIPs`。部署时请确保服务器端已做好域名白名单到 IP 的映射，
否则流量仍会全量走隧道。

## 安全与最佳实践

- **私钥管理**：`client.private_key` 仅用于生成配置，务必限制文件权限 (`chmod
  600`) 并在可信环境运行脚本。避免将完整私钥粘贴到聊天工具或 Issue。
- **多环境渲染**：如需在 CI/CD 中渲染密钥，可使用
  `core/tools/render_from_env.py` 将 `${VAR}` 占位符替换为环境变量。
- **备份策略**：保留经校验的 JSON 配置，可在需要时重新生成客户端配置或二维码。
- **审计**：生成的 `.conf` 与二维码默认不记录日志，请在分发时记录设备对应的
  `profile_name` 以便后续吊销或更新。

## 故障排查

- **Schema 校验失败**：错误信息会提示具体字段路径（例如
  `routing->allowed_ips`），按提示修正拼写或格式。
- **地址冲突**：`client.address` 应保证与现有客户端不重复，必要时在 JSON 中调整。
- **DNS 格式错误**：校验器支持 IPv4、IPv6 以及域名格式。如果需要 DoH/DoT，请在
  WireGuard App 中手动配置。
- **端口或域名无法解析**：确认 `endpoint.host` 与 `port` 在客户端可达，必要时
  更新防火墙与端口转发。
- **二维码扫描失败**：确保配置文件行尾为 `\n` 且内容完整；PNG 模式可在电脑上
  预览确认。

完成以上流程即可在多平台客户端间复用统一的 JSON 配置，实现安全、可审计的
WireGuard 配置分发。
