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
- 未来的环境配置可在 `core/config/env_profiles.py` 中扩展。当前仅提供 `DEFAULT_PROFILE`，与现有默认行为一致。

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
