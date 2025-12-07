# PrivateTunnel 用户使用指南

本指南面向普通用户，提供详细的使用步骤和示例。

## 目录

- [快速开始](#快速开始)
- [基础使用](#基础使用)
- [多节点管理](#多节点管理)
- [高级功能](#高级功能)
- [常见场景](#常见场景)
- [故障排查](#故障排查)

## 快速开始

### 1. 环境准备

确保您的系统满足以下要求：

- Windows 10/11 或 macOS/Linux
- Python 3.8 或更高版本
- Vultr 账户和 API Key
- SSH 公钥已上传到 Vultr

### 2. 安装依赖

```bash
# 克隆仓库
git clone https://github.com/your-org/PrivateTunnel.git
cd PrivateTunnel

# 安装依赖
pip install -r requirements.txt
```

### 3. 配置环境变量

```bash
# Windows PowerShell
$env:VULTR_API_KEY = "your-api-key"
$env:VULTR_SSHKEY_NAME = "your-ssh-key-name"

# Linux/macOS
export VULTR_API_KEY="your-api-key"
export VULTR_SSHKEY_NAME="your-ssh-key-name"
```

### 4. 启动主程序

```bash
python main.py
```

## 基础使用

### 创建第一个节点

1. 在主菜单选择 `2) 创建 VPS（Vultr）`
2. 按照提示选择区域、套餐、操作系统
3. 等待实例创建完成
4. 系统会自动保存节点信息到 `artifacts/instance.json`

### 部署 WireGuard

1. 在主菜单选择 `3) 准备本机接入 VPS 网络`
2. 系统会自动：
   - 连接到服务器
   - 安装 WireGuard
   - 生成客户端配置
   - 创建二维码
3. 配置文件保存在 `artifacts/` 目录

### 连接客户端

**Windows 客户端**：

1. 安装 WireGuard for Windows
2. 导入 `artifacts/desktop.conf`
3. 点击连接

**iOS 客户端**：

1. 安装 WireGuard App
2. 扫描 `artifacts/iphone.png` 二维码
3. 在系统设置中启用 VPN

## 多节点管理

### 启用多节点模式

```bash
# Windows PowerShell
$env:PT_MULTI_NODE = "true"

# Linux/macOS
export PT_MULTI_NODE=true
```

### 创建多个节点

1. 重复执行"创建 VPS"步骤
2. 系统会自动为每个节点分配唯一 ID
3. 所有节点信息保存在 `artifacts/multi-node.json`

### 管理节点

使用菜单选项 `6) 多节点管理`：

- **查看节点列表**：显示所有节点及其状态
- **设置默认节点**：选择默认使用的节点
- **更新节点状态**：手动更新节点状态
- **删除节点**：移除不需要的节点

### 节点配置示例

```bash
# 设置节点优先级（数字越小优先级越高）
export PT_NODE_PRIORITY=1

# 设置节点权重（用于负载均衡）
export PT_NODE_WEIGHT=100
```

## 高级功能

### 健康检查

使用菜单选项 `7) 节点健康检查`：

- 自动检查所有节点的健康状态
- 显示延迟、丢包率、连接性等指标
- 自动触发故障转移（如果启用）

### 智能选路

启用智能选路：

```bash
export PT_SMART_ROUTING=true
export PT_ROUTING_STRATEGY=balanced
```

选路策略说明：

- `latency_first`：延迟优先，适合实时应用
- `weight_first`：权重优先，适合负载均衡
- `balanced`：平衡模式，综合考虑多个因素（推荐）
- `hybrid`：混合模式，智能混合策略

### 连接质量监控

启用监控：

```bash
export PT_ENABLE_MONITORING=true
export PT_MONITOR_INTERVAL=30  # 检查间隔（秒）
```

查看报告：

- 使用菜单选项 `9) 连接质量报告`
- 查看当前会话统计和历史数据
- 分析性能趋势

### 自适应参数调整

启用自适应调整：

```bash
export PT_ENABLE_MONITORING=true
export PT_ENABLE_ADAPTIVE=true
```

查看建议：

- 使用菜单选项 `10) 参数调整建议`
- 查看当前参数和建议参数
- 了解调整原因

### ChatGPT 专用优化

启用 ChatGPT 模式：

```bash
export PT_CHATGPT_MODE=true
```

测试连接：

- 使用菜单选项 `11) ChatGPT 连接测试`
- 查看连接状态和优化建议
- 系统会自动优化参数

### V2Ray 流量伪装

启用 V2Ray：

```bash
export PT_ENABLE_V2RAY=true
export PT_V2RAY_PORT=443  # 可选，默认 443
```

注意事项：

- V2Ray 会增加一定的延迟和带宽开销
- 适合在需要规避检测的场景使用
- 确保防火墙开放 V2Ray 端口

## 常见场景

### 场景 1：单节点基础使用

**目标**：快速搭建一个可用的 VPN 节点

**步骤**：

1. 创建 VPS 实例
2. 部署 WireGuard
3. 导入配置并连接

**环境变量**：无需额外配置

### 场景 2：多节点高可用

**目标**：实现多节点负载均衡和故障转移

**步骤**：

1. 启用多节点模式：`PT_MULTI_NODE=true`
2. 创建 2-3 个节点
3. 启用智能选路：`PT_SMART_ROUTING=true`
4. 启用健康检查（自动）
5. 配置节点优先级和权重

**环境变量**：

```bash
export PT_MULTI_NODE=true
export PT_SMART_ROUTING=true
export PT_ROUTING_STRATEGY=balanced
export PT_NODE_PRIORITY=1
export PT_NODE_WEIGHT=100
```

### 场景 3：ChatGPT 专用优化

**目标**：优化 ChatGPT/OpenAI 访问

**步骤**：

1. 启用 ChatGPT 模式：`PT_CHATGPT_MODE=true`
2. 启用多节点和智能选路
3. 使用延迟优先策略
4. 测试连接并查看优化建议

**环境变量**：

```bash
export PT_MULTI_NODE=true
export PT_CHATGPT_MODE=true
export PT_SMART_ROUTING=true
export PT_ROUTING_STRATEGY=latency_first
export PT_ENABLE_MONITORING=true
```

### 场景 4：规避 DPI 检测

**目标**：使用 V2Ray 伪装流量

**步骤**：

1. 启用 V2Ray：`PT_ENABLE_V2RAY=true`
2. 配置端口（默认 443）
3. 部署并测试连接

**环境变量**：

```bash
export PT_ENABLE_V2RAY=true
export PT_V2RAY_PORT=443
export PT_ENABLE_MONITORING=true
```

### 场景 5：高性能实时应用

**目标**：低延迟、高稳定性

**步骤**：

1. 启用多节点和智能选路
2. 使用延迟优先策略
3. 启用监控和自适应调整
4. 优化 Keepalive 和 MTU

**环境变量**：

```bash
export PT_MULTI_NODE=true
export PT_SMART_ROUTING=true
export PT_ROUTING_STRATEGY=latency_first
export PT_ENABLE_MONITORING=true
export PT_ENABLE_ADAPTIVE=true
export PT_KEEPALIVE=25
export PT_CLIENT_MTU=1280
```

## 故障排查

### 常见问题

1. **无法连接**

   - 检查防火墙是否开放端口
   - 确认服务器 WireGuard 服务是否运行
   - 查看服务器日志：`journalctl -u wg-quick@wg0 -f`

2. **连接不稳定**

   - 启用监控查看连接质量
   - 启用自适应参数调整
   - 检查网络延迟和丢包率

3. **多节点切换失败**

   - 检查节点健康状态
   - 确认节点配置正确
   - 查看故障转移日志

4. **ChatGPT 无法访问**

   - 运行 ChatGPT 连接测试
   - 检查域名解析是否正确
   - 确认分流配置生效

### 获取帮助

- 查看 [故障排查手册](TROUBLESHOOTING.md)
- 查看 [功能说明文档](FEATURES.md)
- 查看 [环境变量说明](ENVIRONMENT_VARIABLES.md)

## 最佳实践

1. **定期健康检查**：定期运行健康检查，确保节点状态正常
2. **监控连接质量**：启用监控功能，及时发现和解决问题
3. **备份配置**：定期备份 `artifacts/` 目录中的配置文件
4. **更新节点信息**：节点状态变化时及时更新
5. **合理配置参数**：根据实际网络环境调整参数

## 相关文档

- [功能说明](FEATURES.md)
- [环境变量说明](ENVIRONMENT_VARIABLES.md)
- [快速开始指南](GETTING_STARTED.md)
- [故障排查手册](TROUBLESHOOTING.md)


