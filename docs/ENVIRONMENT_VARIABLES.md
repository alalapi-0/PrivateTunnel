# 环境变量说明

本文档详细说明 PrivateTunnel 支持的所有环境变量及其用途。

## 目录

- [必需变量](#必需变量)
- [Vultr 相关](#vultr-相关)
- [多节点管理](#多节点管理)
- [智能选路](#智能选路)
- [连接监控](#连接监控)
- [自适应参数](#自适应参数)
- [ChatGPT 优化](#chatgpt-优化)
- [V2Ray 配置](#v2ray-配置)
- [WireGuard 配置](#wireguard-配置)
- [客户端配置](#客户端配置)
- [代理配置](#代理配置)
- [其他配置](#其他配置)

## 必需变量

### VULTR_API_KEY

**说明**：Vultr API Key，用于创建和管理 VPS 实例

**类型**：字符串

**必需**：是

**示例**：

```bash
export VULTR_API_KEY="your-api-key-here"
```

**获取方式**：在 Vultr 控制台的 API 设置中创建

### VULTR_SSHKEY_NAME

**说明**：Vultr 中已上传的 SSH 公钥名称

**类型**：字符串

**必需**：是（如果使用 SSH 公钥认证）

**示例**：

```bash
export VULTR_SSHKEY_NAME="my-ssh-key"
```

**注意**：确保该 SSH 公钥已上传到 Vultr 控制台

## Vultr 相关

### VULTR_REGION

**说明**：Vultr 区域代码，用于创建实例时指定区域

**类型**：字符串

**默认值**：`nrt`（东京）

**示例**：

```bash
export VULTR_REGION="nrt"  # 东京
export VULTR_REGION="sjc"  # 圣何塞
export VULTR_REGION="ams"  # 阿姆斯特丹
```

**可用区域**：参考 Vultr API 文档

### VULTR_PLAN

**说明**：Vultr 套餐代码，用于创建实例时指定配置

**类型**：字符串

**默认值**：`vc2-4c-8gb`

**示例**：

```bash
export VULTR_PLAN="vc2-4c-8gb"  # 4核8GB
export VULTR_PLAN="vc2-2c-4gb"  # 2核4GB
```

### VULTR_SNAPSHOT_ID

**说明**：Vultr 快照 ID，用于从快照创建实例

**类型**：字符串

**默认值**：无

**示例**：

```bash
export VULTR_SNAPSHOT_ID="abc123def456"
```

## 多节点管理

### PT_MULTI_NODE

**说明**：启用多节点管理模式

**类型**：布尔值（true/false/1/0/yes/no）

**默认值**：`false`

**示例**：

```bash
export PT_MULTI_NODE=true
```

**功能**：启用后可以管理多个 VPS 节点，实现负载均衡和故障转移

### PT_NODE_PRIORITY

**说明**：节点优先级，数字越小优先级越高

**类型**：整数

**默认值**：`1`

**示例**：

```bash
export PT_NODE_PRIORITY=1  # 最高优先级
export PT_NODE_PRIORITY=2  # 次高优先级
```

**用途**：用于智能选路和故障转移时的节点选择

### PT_NODE_WEIGHT

**说明**：节点权重，用于负载均衡

**类型**：整数

**默认值**：`100`

**示例**：

```bash
export PT_NODE_WEIGHT=100  # 标准权重
export PT_NODE_WEIGHT=200  # 高权重（更多流量）
```

**用途**：在负载均衡场景中，权重高的节点会分配更多流量

## 智能选路

### PT_SMART_ROUTING

**说明**：启用智能选路功能

**类型**：布尔值

**默认值**：`false`

**示例**：

```bash
export PT_SMART_ROUTING=true
```

**功能**：根据延迟、权重、优先级等因素自动选择最优节点

### PT_ROUTING_STRATEGY

**说明**：选路策略

**类型**：字符串

**默认值**：`balanced`

**可选值**：

- `latency_first`：延迟优先，选择延迟最低的节点
- `weight_first`：权重优先，选择权重最高的节点
- `priority_first`：优先级优先，选择优先级最高的节点
- `balanced`：平衡模式，综合考虑多个因素（推荐）
- `hybrid`：混合模式，智能混合策略

**示例**：

```bash
export PT_ROUTING_STRATEGY=balanced
export PT_ROUTING_STRATEGY=latency_first
```

## 连接监控

### PT_ENABLE_MONITORING

**说明**：启用连接质量监控

**类型**：布尔值

**默认值**：`false`

**示例**：

```bash
export PT_ENABLE_MONITORING=true
```

**功能**：持续监控连接质量，记录性能指标，生成质量报告

### PT_MONITOR_INTERVAL

**说明**：监控检查间隔（秒）

**类型**：整数

**默认值**：`30`

**示例**：

```bash
export PT_MONITOR_INTERVAL=30  # 每30秒检查一次
export PT_MONITOR_INTERVAL=60  # 每分钟检查一次
```

**注意**：间隔太短会增加系统负载，建议 30-60 秒

## 自适应参数

### PT_ENABLE_ADAPTIVE

**说明**：启用自适应参数调整

**类型**：布尔值

**默认值**：`false`

**示例**：

```bash
export PT_ENABLE_ADAPTIVE=true
```

**前置条件**：需要同时启用 `PT_ENABLE_MONITORING=true`

**功能**：根据连接质量自动优化 WireGuard 参数（Keepalive、MTU）

## ChatGPT 优化

### PT_CHATGPT_MODE

**说明**：启用 ChatGPT 专用优化模式

**类型**：布尔值

**默认值**：`false`

**示例**：

```bash
export PT_CHATGPT_MODE=true
```

**功能**：

- 自动解析 ChatGPT/OpenAI 相关域名
- 优化连接参数
- 生成专用分流配置
- 优先选择延迟低的节点

## V2Ray 配置

### PT_ENABLE_V2RAY

**说明**：启用 V2Ray 流量伪装

**类型**：布尔值

**默认值**：`false`

**示例**：

```bash
export PT_ENABLE_V2RAY=true
```

**功能**：使用 V2Ray 伪装 WireGuard 流量，避免被 DPI 检测

### PT_V2RAY_PORT

**说明**：V2Ray 监听端口

**类型**：整数

**默认值**：`443`

**示例**：

```bash
export PT_V2RAY_PORT=443
export PT_V2RAY_PORT=8443
```

**注意**：确保防火墙开放该端口

### PT_V2RAY_UUID

**说明**：V2Ray UUID

**类型**：字符串（UUID 格式）

**默认值**：自动生成

**示例**：

```bash
export PT_V2RAY_UUID="12345678-1234-1234-1234-123456789abc"
```

**注意**：如果不设置，系统会自动生成一个 UUID

## WireGuard 配置

### PT_WG_PORT

**说明**：WireGuard 监听端口

**类型**：整数

**默认值**：`51820` 或 `443`（如果启用 V2Ray）

**示例**：

```bash
export PT_WG_PORT=51820
export PT_WG_PORT=443
```

**注意**：也可以使用 `PRIVATETUNNEL_WG_PORT` 或 `WG_PORT`

### PT_KEEPALIVE

**说明**：WireGuard Keepalive 间隔（秒）

**类型**：整数

**默认值**：`25`

**示例**：

```bash
export PT_KEEPALIVE=25
export PT_KEEPALIVE=30
```

**说明**：Keepalive 用于保持连接活跃，防止 NAT 超时

## 客户端配置

### PT_DESKTOP_IP

**说明**：桌面客户端 IP 地址

**类型**：IP 地址（CIDR 格式）

**默认值**：自动分配

**示例**：

```bash
export PT_DESKTOP_IP="10.0.0.2/32"
```

### PT_IPHONE_IP

**说明**：iOS 客户端 IP 地址

**类型**：IP 地址（CIDR 格式）

**默认值**：自动分配

**示例**：

```bash
export PT_IPHONE_IP="10.0.0.3/32"
```

### PT_ALLOWED_IPS

**说明**：允许的 IP 地址范围

**类型**：IP 地址范围（逗号分隔）

**默认值**：`0.0.0.0/0`（全局路由）

**示例**：

```bash
export PT_ALLOWED_IPS="0.0.0.0/0"  # 全局路由
export PT_ALLOWED_IPS="10.0.0.0/8"  # 仅内网
```

### PT_DNS

**说明**：DNS 服务器地址

**类型**：IP 地址（逗号分隔）

**默认值**：`1.1.1.1,8.8.8.8`

**示例**：

```bash
export PT_DNS="1.1.1.1,8.8.8.8"
export PT_DNS="223.5.5.5,114.114.114.114"
```

### PT_CLIENT_MTU

**说明**：客户端 MTU 值

**类型**：整数

**默认值**：`1280`

**示例**：

```bash
export PT_CLIENT_MTU=1280
export PT_CLIENT_MTU=1420
```

**说明**：MTU 值影响数据包大小，较小的 MTU 可以减少分片和丢包

## 代理配置

### ALL_PROXY

**说明**：全局代理设置，同时应用于 HTTP 和 HTTPS 请求

**类型**：字符串（URL格式）

**默认值**：无

**示例**：

```powershell
# Windows PowerShell
$env:ALL_PROXY = "http://127.0.0.1:7890"
```

```bash
# Linux/macOS
export ALL_PROXY="http://127.0.0.1:7890"
```

**支持的协议**：

- `http://` - HTTP 代理
- `https://` - HTTPS 代理
- `socks5://` - SOCKS5 代理
- `socks4://` - SOCKS4 代理

**优先级**：最高（如果设置了 `ALL_PROXY`，会忽略 `HTTP_PROXY` 和 `HTTPS_PROXY`）

**用途**：当你的网络环境无法直接访问外网（如在国内访问 GitHub、Vultr API 等）时，可以通过设置此环境变量使程序通过代理访问。

### HTTP_PROXY

**说明**：HTTP 请求的代理设置

**类型**：字符串（URL格式）

**默认值**：无

**示例**：

```bash
export HTTP_PROXY="http://127.0.0.1:7890"
```

**注意**：如果同时设置了 `ALL_PROXY`，`HTTP_PROXY` 会被忽略

### HTTPS_PROXY

**说明**：HTTPS 请求的代理设置

**类型**：字符串（URL格式）

**默认值**：无

**示例**：

```bash
export HTTPS_PROXY="http://127.0.0.1:7890"
```

**注意**：如果同时设置了 `ALL_PROXY`，`HTTPS_PROXY` 会被忽略

### 自动检测本地代理

程序支持自动检测本地代理服务（如 Clash、V2RayN 等），可以通过以下方式使用：

```python
from core.proxy_utils import auto_configure_proxy

# 自动检测并配置代理（不设置环境变量）
proxy_url = auto_configure_proxy()

# 自动检测并设置环境变量
proxy_url = auto_configure_proxy(set_environment=True)
```

**常见代理端口**：

- Clash for Windows: `7890` (HTTP), `7891` (SOCKS5)
- V2RayN: `10809` (HTTP), `10808` (SOCKS5)
- Shadowsocks: `1080` (SOCKS5)

## 其他配置

### PT_SSH_PRIVATE_KEY

**说明**：SSH 私钥文件路径

**类型**：文件路径

**默认值**：`~/.ssh/id_ed25519` 或 `~/.ssh/id_rsa`

**示例**：

```bash
export PT_SSH_PRIVATE_KEY="/path/to/private/key"
```

### SSH_PROXY

**说明**：SSH 代理服务器地址

**类型**：字符串（host:port 格式）

**默认值**：无

**示例**：

```bash
export SSH_PROXY="proxy.example.com:1080"
```

**用途**：通过代理服务器建立 SSH 连接

## 环境变量设置方法

### Windows PowerShell

```powershell
# 临时设置（当前会话）
$env:VULTR_API_KEY = "your-api-key"
$env:PT_MULTI_NODE = "true"

# 永久设置（用户级别）
[System.Environment]::SetEnvironmentVariable("VULTR_API_KEY", "your-api-key", "User")
```

### Linux/macOS

```bash
# 临时设置（当前会话）
export VULTR_API_KEY="your-api-key"
export PT_MULTI_NODE="true"

# 永久设置（添加到 ~/.bashrc 或 ~/.zshrc）
echo 'export VULTR_API_KEY="your-api-key"' >> ~/.bashrc
echo 'export PT_MULTI_NODE="true"' >> ~/.bashrc
source ~/.bashrc
```

### .env 文件（推荐）

创建 `.env` 文件：

```bash
VULTR_API_KEY=your-api-key
VULTR_SSHKEY_NAME=my-ssh-key
PT_MULTI_NODE=true
PT_SMART_ROUTING=true
PT_ROUTING_STRATEGY=balanced
```

然后使用工具加载（如 `python-dotenv`）：

```python
from dotenv import load_dotenv
load_dotenv()
```

## 配置示例

### 基础单节点配置

```bash
export VULTR_API_KEY="your-api-key"
export VULTR_SSHKEY_NAME="my-ssh-key"
export VULTR_REGION="nrt"
export VULTR_PLAN="vc2-4c-8gb"
```

### 多节点高可用配置

```bash
export VULTR_API_KEY="your-api-key"
export VULTR_SSHKEY_NAME="my-ssh-key"
export PT_MULTI_NODE=true
export PT_SMART_ROUTING=true
export PT_ROUTING_STRATEGY=balanced
export PT_ENABLE_MONITORING=true
export PT_ENABLE_ADAPTIVE=true
```

### ChatGPT 专用配置

```bash
export VULTR_API_KEY="your-api-key"
export VULTR_SSHKEY_NAME="my-ssh-key"
export PT_MULTI_NODE=true
export PT_CHATGPT_MODE=true
export PT_SMART_ROUTING=true
export PT_ROUTING_STRATEGY=latency_first
export PT_ENABLE_MONITORING=true
```

### V2Ray 伪装配置

```bash
export VULTR_API_KEY="your-api-key"
export VULTR_SSHKEY_NAME="my-ssh-key"
export PT_ENABLE_V2RAY=true
export PT_V2RAY_PORT=443
export PT_ENABLE_MONITORING=true
```

## 注意事项

1. **安全性**：不要在代码或公共仓库中硬编码 API Key 和私钥
2. **优先级**：环境变量优先级高于配置文件中的默认值
3. **类型转换**：布尔值变量接受 `true`/`false`/`1`/`0`/`yes`/`no`
4. **验证**：设置后运行 `python main.py` 验证配置是否正确
5. **文档更新**：新增环境变量时请更新本文档

## 相关文档

- [功能说明](FEATURES.md)
- [用户使用指南](USER_GUIDE.md)
- [快速开始指南](GETTING_STARTED.md)




