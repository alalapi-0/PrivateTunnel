> **当前仓库为 Windows 本地自用版**：目标是一键创建 Vultr VPS、部署 WireGuard 并生成手机可扫的二维码。  
> 非 Windows / 非本地一键流程的代码与 CI 已移除或归档至 `legacy/`。  
> 详见：`PROJECT_PRUNE_REPORT.md` 与 `PROJECT_HEALTH_REPORT.md`。

# PrivateTunnel

## 项目综述与多轮 Prompt 演进

PrivateTunnel 起初是覆盖 iOS、macOS、服务器脚本与 CI 的一体化仓库。经过多轮 prompt 迭代后，我们将精力集中在“Windows 本地一键接入”的实用场景：

1. **Prompt Round 1~2**：整理历史资产，把 iOS、macOS、CI 等模块迁移到 `legacy/`，并在 `PROJECT_PRUNE_REPORT.md` 中记录裁剪理由。
2. **Prompt Round 3~4**：构建 Windows 友好的自动化脚本，统一日志、错误提示与远程执行逻辑，确保零基础用户能跟随提示一步步部署。
3. **Prompt Round 5 之后**：补全 GUI、二维码生成器、健康检查、网络诊断等辅助功能，并将常用脚本打包到 `portable_bundle/`，方便离线携带。

当前仓库即是上述演进的整合成果：一份可在本地 Windows 机器上完成 Vultr 实例创建、WireGuard 安装与客户端配置生成的脚本集合。

## 环境准备 Checklist

| 类型 | 必要内容 | 说明 |
| --- | --- | --- |
| 操作系统 | Windows 10/11，或支持 Python 3.8+ 的 macOS / Linux | Windows 是主力场景，其他平台仍可运行 CLI。 |
| Python | Python ≥ 3.8，并确保 `python3`、`pip` 指向该版本 | 建议使用官方安装包或 Microsoft Store 版本。 |
| 依赖库 | `requests`、`paramiko`、`qrcode[pil]`、`PySimpleGUI`、`rich` 等 | `pip install -r requirements.txt` 一次性装齐。 |
| 外部工具 | Git、OpenSSH、WireGuard for Windows（可选自动安装） | `main.py` 会尝试帮你安装缺失的 WireGuard。 |
| 云端账号 | Vultr 账户 + API Key + 预先上传的 SSH 公钥 | API Key 用于创建实例，公钥保证免密登录。 |
| 其他 | 稳定的网络、可写入的工作目录 | 自动脚本会生成 `artifacts/` 与日志。 |

> 提示：如果你在公司或校园网络内，请确认对外 443/22 端口未被阻断，以免部署阶段失败。

## 技术栈一览

- **语言与运行时**：Python 3.8+、Shell（服务器侧 `wg-install.sh`）、批处理脚本（Windows 安装器）。
- **网络与安全库**：Paramiko（SSH）、Requests（Vultr API）、WireGuard 官方工具。
- **界面与辅助**：PySimpleGUI（图形界面）、qrcode（二维码生成）、Rich/Colorama（彩色日志）。
- **自动化生态**：GitHub Actions（`One-Click Connect` 工作流）、Makefile、便携式 `portable_bundle/`。

## 零基础全流程操作指南

以下步骤覆盖从环境初始化到生成客户端二维码的完整旅程，可按顺序执行：

1. **克隆仓库**
   ```bash
   git clone https://github.com/your-org/PrivateTunnel.git
   cd PrivateTunnel
   ```
2. **安装依赖**（Windows 可在 PowerShell 中运行）
   ```bash
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```
3. **准备密钥与 API 配置**
   - 在 Vultr 控制台创建 SSH Key 并下载私钥，私钥路径可通过 `PT_SSH_PRIVATE_KEY` 覆盖。
   - 创建 API Key，设置环境变量：
     ```powershell
     setx VULTR_API_KEY "<你的 API Key>"
     setx VULTR_SSHKEY_NAME "<控制台里的 SSH Key 名称>"
     ```
4. **可选：先熟悉 GUI 配置生成器**
   - 运行 `python core/tools/generate_wg_conf_gui.py`，按界面提示选择 schema、配置与输出路径。
   - 该工具底层调用 `generate_wg_conf.py`，适合提前校验 JSON 配置是否符合 Schema。
5. **启动主菜单脚本**
   ```powershell
   python main.py
   ```
   首次运行会提示创建 `artifacts/` 目录并生成部署日志文件，所有输出都会保存到 `artifacts/deploy-*.log`。
6. **菜单结构与功能详解**
   - `1) 创建 Vultr 实例`：调用 `scripts/windows_oneclick.py` 流程，收集区域、套餐、快照、标签等参数，自动注入 SSH Key。
   - `2) 查看/销毁现有实例`：列出 Vultr 当前实例，支持确认后销毁；也可以查询历史记录文件 `artifacts/instance.json`。
   - `3) 准备本机接入 VPS 网络`：执行核心自动化部署，完成服务器 WireGuard 安装、客户端配置生成及二维码导出。
   - `4) 下载客户端配置/二维码`：在无需重新部署的情况下重新导出 `desktop.conf`、`iphone.conf` 与 `iphone.png`。
   - `5) 网络诊断`：综合使用 `ping`、端口连通、SSH 测试等手段确认实例状态。
   - `6) 多节点管理`：管理多个 VPS 节点，实现负载均衡和故障转移。
   - `7) 节点健康检查`：检查所有节点的健康状态，包括延迟、丢包、连接性等指标。
   - `8) 智能节点选择`：根据延迟、权重、优先级等因素自动选择最优节点。
   - `9) 连接质量报告`：查看连接质量监控报告和历史数据。
   - `10) 参数调整建议`：查看自适应参数调整建议。
   - `11) ChatGPT 连接测试`：测试 ChatGPT/OpenAI 连接并查看优化建议。
   - `Q) 退出`：结束脚本并释放 SSH 连接。
7. **自动部署阶段细节**
   - `main.py` 会根据 `core/port_config.py` 自动选择监听端口，若环境变量指定则优先使用。
   - `core/ssh_utils.py` 会统一处理 Paramiko 与系统 `ssh` 回退逻辑，确保远程执行稳定。
   - 部署脚本会上传至服务器 `/root/server/provision`，执行 `wg-install.sh` 完成 WireGuard 安装、IP 转发、NAT、防火墙、密钥生成。
   - 完成后自动下载客户端配置，并调用 `qrcode` 生成 PNG 二维码。
8. **安装 WireGuard for Windows（如未安装）**
   - 主脚本会尝试通过 PowerShell 下载官方安装包。
   - 也可手动访问 <https://www.wireguard.com/install/> 安装。
9. **导入配置并测试连接**
   - 在 Windows 客户端导入 `artifacts/desktop.conf`；在 iOS 客户端扫描 `artifacts/iphone.png`。
   - 连接成功后，可在服务器执行 `wg show` 查看 peer 状态。
10. **日常运维建议**
    - 使用 `scripts/project_doctor.py --platform windows` 检查依赖是否齐全。
    - 定期运行 `docs/HEALTH-AUTO-RECONNECT.md` 中的健康检查步骤，确保线路可用。

## 常用命令速查

```bash
# 启动主菜单
python main.py

# 生成 WireGuard 配置（命令行版）
python core/tools/generate_wg_conf.py --schema core/config-schema.json --in core/examples/minimal.json --out artifacts/sample.conf --force

# 校验配置文件
python core/tools/validate_config.py --schema core/config-schema.json --in artifacts/sample.conf.json --pretty

# 生成项目概览
python core/project_overview.py --output docs/PROJECT_OVERVIEW.md
```

## 🖥️ GUI 快速生成 WireGuard 配置

1. 在终端执行 `python3 core/tools/generate_wg_conf_gui.py` 启动界面工具。
2. 依次点击 **Schema 文件**、**配置 JSON**、**输出文件** 三个“浏览”按钮完成路径选择（默认 Schema 会自动指向 `core/config-schema.json`）。
3. 如需覆盖既有配置文件，可勾选“允许覆盖已存在的文件”。
4. 点击 **生成 WireGuard 配置**，界面下方的日志区会展示执行结果，并在成功后提示输出文件的位置。

该界面封装了命令行脚本 `core/tools/generate_wg_conf.py` 的校验与渲染流程，无需手动记忆参数即可生成 `.conf` 文件。

## 🚀 One-Click Connect (GitHub Actions)
- 配置仓库 Secrets：`VULTR_API_KEY` / `SSH_PRIVATE_KEY` / `SSH_PUBLIC_KEY` / `SNAPSHOT_ID`
- 打开 **Actions → One-Click Connect → Run workflow**
- 运行完成后下载二维码 PNG，手机 WireGuard 扫码即连  
详见：`docs/ONE_CLICK.md`

## 📸 快照使用注意事项

- **不要** 在制作快照前把私钥、`authorized_keys` 等敏感文件打包进镜像，避免泄露或后续冲突；
- 首次从快照启动后请重新生成 SSH host keys（可启用仓库内的 firstboot/初始化脚本）；
- 使用 `scripts/windows_oneclick.py` 创建实例时，务必选择或创建 Vultr SSH Key，脚本会在云端注入 `/root/.ssh/authorized_keys` 并在启动后再做免密校验；
- 如遇 `Permission denied (publickey)`，脚本会提示 **控制台执行 3 行命令**，按指引粘贴后即可重新验证；
- 若仍失败，可选择 **Reinstall SSH Keys**（会擦除磁盘数据），脚本会进行二次确认并等待实例重装完成；
- 所有创建信息会写入 `artifacts/instance.json`（含 `sshkey_ids`、`user_data_used` 等字段），方便排查和追踪。

## 🛡 Step 3: 准备本机接入 VPS 网络（全自动）

- 在主菜单选择 **3) 准备本机接入 VPS 网络** 后，脚本会读取 `artifacts/instance.json` 获取服务器 IP，并依据环境变量或默认值提示当前 WireGuard 端口、客户端 IP、AllowedIPs、DNS、MTU 等配置；
- 脚本会自动清理旧指纹、探测 SSH 端口、校验免密登录，然后在云端一次性执行部署脚本：安装 WireGuard 与依赖、开启 IP 转发与 NAT、放行防火墙、生成服务端密钥并启动 `wg-quick@wg0`；
- 同步生成 `desktop`（Windows）与 `iphone`（iOS）两个客户端的密钥与配置，登记到服务器并通过 `wg-quick save` 重载，远端 `wg show` 校验将展示两个 peer；
- 本地会自动下载 `artifacts/desktop.conf` 与 `artifacts/iphone.conf`，并基于后者生成 `artifacts/iphone.png` 二维码，便于手机扫码导入；
- 所有默认值均可通过 `PT_DESKTOP_IP`、`PT_IPHONE_IP`、`PT_ALLOWED_IPS`、`PT_DNS`、`PT_CLIENT_MTU`、`PT_SSH_PRIVATE_KEY` 等环境变量覆盖，提示中会直接显示当前默认值，确保用户可一路回车完成部署。

## 新功能说明

### 多节点管理

PrivateTunnel 现在支持管理多个 VPS 节点，实现负载均衡和故障转移：

- **启用多节点模式**：设置环境变量 `PT_MULTI_NODE=true`
- **创建多个节点**：重复执行"创建 Vultr 实例"步骤，系统会自动管理所有节点
- **节点管理**：使用菜单选项 `6) 多节点管理` 查看和管理节点
- **智能选路**：系统会根据延迟、权重、优先级自动选择最佳节点

### 健康检查与故障转移

系统会自动监控节点健康状态，并在节点故障时自动切换：

- **健康检查**：使用菜单选项 `7) 节点健康检查` 查看所有节点状态
- **自动故障转移**：当当前节点不健康时，系统会自动切换到备用节点
- **连接监控**：设置 `PT_ENABLE_MONITORING=true` 启用连接质量监控

### 智能选路

系统提供多种选路策略，自动选择最优节点：

- **延迟优先**：选择延迟最低的节点（适合实时应用）
- **权重优先**：选择权重最高的节点（适合负载均衡）
- **平衡模式**：综合考虑多个因素（推荐）
- **使用方式**：设置 `PT_SMART_ROUTING=true` 和 `PT_ROUTING_STRATEGY=balanced`

### 连接质量监控

持续监控连接质量，记录性能指标：

- **启用监控**：设置 `PT_ENABLE_MONITORING=true`
- **查看报告**：使用菜单选项 `9) 连接质量报告` 查看历史数据
- **监控间隔**：通过 `PT_MONITOR_INTERVAL=30` 设置检查间隔（秒）

### 自适应参数调整

系统会根据连接质量自动优化参数：

- **启用自适应**：设置 `PT_ENABLE_ADAPTIVE=true`
- **参数建议**：使用菜单选项 `10) 参数调整建议` 查看优化建议
- **自动调整**：系统会自动调整 Keepalive 和 MTU 参数

### ChatGPT 专用优化

针对 ChatGPT/OpenAI 的特殊优化：

- **ChatGPT 模式**：设置 `PT_CHATGPT_MODE=true` 启用专用优化
- **连接测试**：使用菜单选项 `11) ChatGPT 连接测试` 测试连接
- **参数优化**：系统会自动优化参数以确保 ChatGPT 访问稳定

### V2Ray 流量伪装

使用 V2Ray 伪装 WireGuard 流量，避免被 DPI 检测：

- **启用 V2Ray**：设置 `PT_ENABLE_V2RAY=true`
- **配置端口**：通过 `PT_V2RAY_PORT=443` 设置 V2Ray 端口（默认 443）
- **UUID 配置**：通过 `PT_V2RAY_UUID` 设置 UUID，或让系统自动生成

## 环境变量速查

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `PT_MULTI_NODE` | 启用多节点模式 | `false` |
| `PT_NODE_PRIORITY` | 节点优先级（数字越小优先级越高） | `1` |
| `PT_NODE_WEIGHT` | 节点权重（用于负载均衡） | `100` |
| `PT_SMART_ROUTING` | 启用智能选路 | `false` |
| `PT_ROUTING_STRATEGY` | 选路策略（latency_first/weight_first/balanced/hybrid） | `balanced` |
| `PT_ENABLE_MONITORING` | 启用连接监控 | `false` |
| `PT_MONITOR_INTERVAL` | 监控检查间隔（秒） | `30` |
| `PT_ENABLE_ADAPTIVE` | 启用自适应参数调整 | `false` |
| `PT_CHATGPT_MODE` | 启用 ChatGPT 专用模式 | `false` |
| `PT_ENABLE_V2RAY` | 启用 V2Ray 流量伪装 | `false` |
| `PT_V2RAY_PORT` | V2Ray 监听端口 | `443` |
| `PT_V2RAY_UUID` | V2Ray UUID（自动生成） | 自动生成 |
| `PT_KEEPALIVE` | WireGuard Keepalive（秒） | `25` |
| `PT_CLIENT_MTU` | 客户端 MTU | `1280` |
| `PT_WG_PORT` | WireGuard 监听端口 | `51820` 或 `443` |

## 🔐 如何确保 SSH 公钥自动注入及排错

- 在创建 Vultr VPS 前于控制台配置 SSH Key，并将其名称写入环境变量 `VULTR_SSHKEY_NAME`，脚本会自动调用 `GET /v2/ssh-keys` 匹配并提取对应 ID；
- 使用快照创建实例时，会自动生成 cloud-init，将公钥写入 `/root/.ssh/authorized_keys` 并重启 SSH 服务，确保首启动即可免密登录；
- 每次创建或部署阶段，脚本都会执行 `ssh-keygen -R <ip>` 清理旧指纹，随后分两阶段检测：先探测 22 端口，再循环运行 `ssh -i ~/.ssh/id_ed25519 -o BatchMode=yes -o StrictHostKeyChecking=accept-new root@<ip> true` 直至免密成功；
- 若仍无法免密连接，终端会提示：
  ```
  ⚠️ 免密连接失败，请在 Vultr 控制台使用 View Console 登录，并执行：
    cat /root/.ssh/authorized_keys
    chmod 700 /root/.ssh; chmod 600 /root/.ssh/authorized_keys
    systemctl restart ssh
  然后重新运行部署。
  ```
- 完成上述排错后重新运行脚本，即可再次检测并继续后续 WireGuard 部署。

[![CI](https://img.shields.io/github/actions/workflow/status/your-org/PrivateTunnel/ci.yml?branch=main&label=CI)](./.github/workflows/ci.yml)
![Platform](https://img.shields.io/badge/platform-iOS%2016%2B-blue)
![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Build](https://img.shields.io/badge/build-1-blue)
[![License](https://img.shields.io/badge/license-MIT-green)](https://opensource.org/licenses/MIT)

PrivateTunnel 是一个面向个人/小团队自建的私有 VPN/隧道解决方案，聚焦“自用稳定”。仓库覆盖 WireGuard 服务器脚本、iOS 容器 App + Packet Tunnel 扩展、分流与健康检查工具，以及 CI/打包流程。项目不会在中国区 App Store 发布，也不提供公共节点，请确保合法合规使用。

> ⚠️ **Python 版本要求**：本仓库的脚本全部基于 Python 3.8+。若在 VS Code 中看到 “Python 版本 2.7 不支持 f 字符串” 之类的提示，通常说明编辑器选中的解释器仍是 2.x。请通过 `Ctrl+Shift+P → Python: Select Interpreter` 选择本机的 `python3`，或直接使用 `python3 main.py`、`python3 core/...` 的方式运行脚本。

## 架构速览

```
┌──────────────────────────┐      ┌──────────────────────────┐
│ WireGuard Server         │      │ iOS Container App        │
│  • wg-install.sh         │      │  • 配置导入/二维码扫描     │
│  • 分流：resolve_domains │◀────▶│  • 健康检查 & Watchdog    │
│  • 健康：security/audit  │      └────────┬─────────────────┘
└──────────────┬───────────┘               │
               │                           │ App Group / IPC
               ▼                           ▼
        ┌──────────────┐           ┌────────────────────────┐
        │ Toy Gateway  │           │ PacketTunnel Extension │
        │  (仅开发用)  │           │  • WireGuard 客户端核心  │
        └──────────────┘           │  • 分流策略 & 心跳       │
                                    └────────────────────────┘
```

## 三步快速开始

- **One-Click Connect（GitHub Actions）**：若需快速拉起新的 WireGuard 节点，可直接使用 [docs/ONE_CLICK.md](docs/ONE_CLICK.md) 中的工作流，一键创建 Vultr 实例并生成客户端二维码。
1. **部署服务器（Round 2/3）**：按照 [docs/SERVER-OPERATIONS.md](docs/SERVER-OPERATIONS.md) 与 [docs/CONFIG.md](docs/CONFIG.md) 准备 VPS，运行 `server/provision/wg-install.sh`，生成客户端配置。
2. **构建 iOS 客户端（Round 4/5/6）**：阅读 [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) 与 [docs/BUILD_IOS.md](docs/BUILD_IOS.md)，在本地使用 Xcode 构建容器 App 与 PacketTunnel 扩展。
3. **启用健康检查与分流（Round 7/8）**：根据 [docs/HEALTH-AUTO-RECONNECT.md](docs/HEALTH-AUTO-RECONNECT.md) 与 [docs/SPLIT-IPSET.md](docs/SPLIT-IPSET.md) 配置心跳、自动重连及域名白名单。

## 文档索引

- 入门与流程
  - [GETTING_STARTED.md](docs/GETTING_STARTED.md)：从零到真机调试
  - [USER_GUIDE.md](docs/USER_GUIDE.md)：用户使用指南（新功能详解）
  - [FEATURES.md](docs/FEATURES.md)：功能说明文档（所有新功能）
  - [ENVIRONMENT_VARIABLES.md](docs/ENVIRONMENT_VARIABLES.md)：环境变量说明
  - [BUILD_IOS.md](docs/BUILD_IOS.md)：Xcode 构建与常见错误
  - [CODE_SIGNING.md](docs/CODE_SIGNING.md)：证书、描述文件与权限
  - [DISTRIBUTION_TESTFLIGHT.md](docs/DISTRIBUTION_TESTFLIGHT.md)：TestFlight 上传流程
  - [DISTRIBUTION_ADHOC.md](docs/DISTRIBUTION_ADHOC.md)：Ad-Hoc 分发步骤
- 运维与安全
  - [SERVER-OPERATIONS.md](docs/SERVER-OPERATIONS.md)：服务器部署/运维
  - [SECURITY-HARDENING.md](docs/SECURITY-HARDENING.md)：加固建议
  - [LOGGING.md](docs/LOGGING.md)：日志收集与留存策略
  - [HEALTH-AUTO-RECONNECT.md](docs/HEALTH-AUTO-RECONNECT.md)：健康检查与重连
  - [SPLIT-IPSET.md](docs/SPLIT-IPSET.md)：域名分流实现
- 自动化与工具
  - [CI.md](docs/CI.md)：GitHub Actions 工作流
  - [BADGES.md](docs/BADGES.md)：徽标来源及更新方法
  - [CHANGELOG.md](docs/CHANGELOG.md)：版本发布记录模板
  - [ROADMAP.md](docs/ROADMAP.md)：阶段规划
  - [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)：常见问题排查（包含新功能问题）
  - [TOY-TUN-END2END.md](docs/TOY-TUN-END2END.md)：Toy 通道说明（仅开发）
  - [VULTR_AUTOMATION.md](docs/VULTR_AUTOMATION.md)：Vultr API 自动化创建节点

更多设计细节请参考 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) 与 [docs/IOS-PACKET-TUNNEL.md](docs/IOS-PACKET-TUNNEL.md)。

## CI 与自动化

- `.github/workflows/ci.yml`：在 push / PR 时执行脚本语法检查与 iOS 编译验证；
- `.github/workflows/nightly.yml`：夜间运行文档链接检查与分流脚本干跑，并上传解析结果；
- `scripts/ios_build.sh` / `scripts/ios_export.sh`：一键生成 Archive 与 `.ipa`；
- `scripts/check_links.py`：本地或 CI 检查 Markdown 链接；
- `Makefile`：提供 `make build`、`make export-adhoc`、`make lint`、`make docs` 等便捷命令。

## 责任声明与隐私

PrivateTunnel 仅定位为个人/内部使用工具，不提供公共服务，也不承诺在中国区或其他受限地区的 App Store 上架。请确保遵循所在地法律法规，避免将 Toy 通道用于生产环境。隐私与数据处理政策请参阅 [docs/PRIVACY.md](docs/PRIVACY.md)。

## 贡献与反馈

欢迎就脚本、分流策略、客户端体验提出建议或 Pull Request。在提交变更时，请附上测试说明与影响评估。遇到问题可先参考 [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)，必要时再开启 Issue。
