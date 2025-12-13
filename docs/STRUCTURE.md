# Repository Structure Overview

本文件概述当前代码树的主要目录与职责划分，并标注 legacy 与配置集中化的落点。

## 目录速览

- `main.py` — Windows 端一键部署与菜单式操作的主入口，串联 VPS 创建、SSH 校验、WireGuard 部署与客户端配置导出。
- `core/` — 核心逻辑与可复用组件。
  - `core/config/` — **新建配置中心**，集中默认端口、DNS、MTU、Keepalive、子网等常量，并预留环境 Profile 结构。
  - `core/port_config.py` — WireGuard 端口解析工具，现从配置中心读取默认端口。
  - `core/tools/` — 部署与运维辅助工具（如参数自适应、连接监控、健康检查、智能路由等）。
  - 其他子目录（如 `qr/`, `examples/`）提供示例与辅助资源。
- `scripts/` — 独立脚本入口（如 Windows 一键部署、Vultr 创建、节点健康监控等），便于在非交互环境或 CI 中调用。
- `legacy/` — 历史遗留实现（如早期服务器安装脚本、旧客户端代码），已标注为非主线，仅供参考。
- `artifacts/` — 生成的客户端/服务器配置与中间产物缓存目录。
- `docs/` — 项目文档与运行说明。
- `portable_bundle/` — 便携打包资源与旧版客户端/服务器支持文件。
- `tests/` — 测试用例与覆盖检查。

## Endpoint 模型（R5）

- 新增 `core/network/endpoints.py` 定义统一的出口描述结构 `Endpoint`，字段包含 `real_ip`、`port`、`domain`、`front_domain`、`transport`、`ws_path`。
- `artifacts/server.json` 现以 `endpoints` 数组记录出口信息，例如：

```json
{
  "real_ip": "203.0.113.10",
  "endpoints": [
    {"real_ip": "203.0.113.10", "port": 443, "transport": "wireguard", "domain": null, "front_domain": null},
    {"real_ip": "203.0.113.10", "port": 443, "transport": "v2ray_ws_tls", "domain": "example.com", "front_domain": "cdn.example.com", "ws_path": "/ws"}
  ],
  "meta": {"provider": "vultr", "created_at": "...", "updated_at": "..."}
}
```

- 客户端配置生成、诊断输出等均通过 `Endpoint` 抽象获取地址与域名信息，为后续多出口或域前置扩展铺路。

## 入口与核心模块

- **客户端入口：** `main.py` 提供 Windows 友好的交互式菜单，整合 Vultr 创建、SSH 探活、WireGuard 部署与配置下载。
- **端口解析：** `core/port_config.py` 负责解析 WireGuard 监听端口，优先读取环境变量，默认值由配置中心提供。
- **主要工具：** `core/tools/` 下的子模块涵盖参数自适应（`adaptive_params.py`）、连接监控与健康检查（`connection_monitor.py`, `node_health_checker.py` 等）以及智能选路（`smart_routing.py`）。

## 配置模块

- 统一默认值位于 `core/config/defaults.py`：
  - `DEFAULT_WG_PORT`, `DEFAULT_DNS_LIST/DEFAULT_DNS_STRING`
  - `DEFAULT_CLIENT_MTU`, `DEFAULT_KEEPALIVE_SECONDS`
  - `DEFAULT_SUBNET_CIDR`, `DEFAULT_SERVER_ADDRESS`
  - `DEFAULT_IPHONE_ADDRESS`, `DEFAULT_DESKTOP_ADDRESS`, `DEFAULT_ALLOWED_IPS`
  - V2Ray/TLS 默认：`DEFAULT_V2RAY_ENABLED`, `DEFAULT_V2RAY_PORT`, `DEFAULT_V2RAY_WS_PATH`, `DEFAULT_TLS_USE_SELF_SIGNED`, `DEFAULT_TLS_CERT_DIR`
- 未来的环境配置可在 `core/config/env_profiles.py` 中扩展。当前仅提供 `DEFAULT_PROFILE`，与现有默认行为一致。

## V2Ray 伪装默认化（R4）

- 部署流程默认尝试开启基于域名的 V2Ray WebSocket+TLS 伪装，如未提供域名或证书失败，则自动回退到纯 WireGuard。
- 新增 `core/tools/v2ray_manager.py` 与 `core/tools/tls_cert_manager.py`，负责远端安装、证书生成与服务重启/健康检查。
- 生成的客户端配置（含 VMess 链接）保存在 `artifacts/`，便于导入 V2RayN/V2RayNG 等客户端。

## 针对中国大陆环境的低成本优化（R3）

- **端口策略**：`core/port_config.py` 默认优先使用 `443`，如被占用则在 `20000–45000` 间挑选可用端口并记录日志，确保服务端与客户端配置一致。
- **DNS 默认**：`core/config/defaults.py` 中的 `DEFAULT_DNS_LIST` 采用“国内优先 + 海外备选”的顺序，`main.py` 生成配置时会使用该列表并允许 `PT_DNS` 覆盖。
- **Keepalive/MTU 决策**：`core/tools/network_params.py` 负责生成带随机扰动的 Keepalive（可被用户指定覆盖）和“用户 > 探测 > 默认 1420”优先级的 MTU，决策细节通过统一日志输出。
- **连接监控自恢复**：`core/tools/connection_monitor.py` 增加采集重试与节流的 WireGuard 重启自恢复流程，避免短时异常导致监控退出。

## Legacy 标注

- `legacy/server/provision/wg-install.sh` 已在文件头标记为 LEGACY，现行 Windows 部署流程不再直接调用，仅供手工运维排障参考。
- `portable_bundle/legacy/` 与 `legacy/` 下其他子目录同属历史保留内容，不参与主线部署。

## Scripts 说明

- `scripts/windows_oneclick.py` — Windows 一键部署脚本；可直接运行，也可通过 `python main.py` 菜单触发同等流程。
- `scripts/vultr_provision.py` — 命令行环境创建/重装 Vultr 实例的辅助工具，复用主流程的云端准备逻辑。
- `scripts/node_health_monitor.py` — 定时或 CI 环境下的节点健康巡检脚本，兼容 `main.py` 生成的节点配置。

## 结构检查方法

- 运行 `python main.py` 进入交互式菜单，按提示创建实例并部署 WireGuard，验证日志与生成的客户端配置是否与既有行为一致。
- 在需要的场景下执行上述脚本或调用 `core` 模块，检查输出与默认值是否匹配预期。
