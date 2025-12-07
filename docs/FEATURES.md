# PrivateTunnel 功能说明

本文档详细说明 PrivateTunnel 的所有功能特性。

## 目录

- [多节点管理](#多节点管理)
- [健康检查与故障转移](#健康检查与故障转移)
- [智能选路](#智能选路)
- [连接质量监控](#连接质量监控)
- [自适应参数调整](#自适应参数调整)
- [ChatGPT 专用优化](#chatgpt-专用优化)
- [V2Ray 流量伪装](#v2ray-流量伪装)

## 多节点管理

### 功能概述

多节点管理允许您管理多个 VPS 节点，实现负载均衡、故障转移和智能选路。

### 启用方式

设置环境变量：

```bash
export PT_MULTI_NODE=true
```

### 使用方法

1. **创建多个节点**

   - 重复执行"创建 Vultr 实例"步骤
   - 系统会自动为每个节点分配唯一 ID
   - 节点信息保存在 `artifacts/multi-node.json`

2. **管理节点**

   - 使用菜单选项 `6) 多节点管理`
   - 可以查看、设置默认节点、更新状态、删除节点

3. **节点配置**

   - `PT_NODE_PRIORITY`：设置节点优先级（数字越小优先级越高）
   - `PT_NODE_WEIGHT`：设置节点权重（用于负载均衡）

### 节点状态

- `active`：节点正常，可以连接
- `inactive`：节点未激活
- `failing`：节点故障
- `unknown`：状态未知
- `maintenance`：维护中

## 健康检查与故障转移

### 功能概述

系统会自动监控节点健康状态，检测延迟、丢包、连接性等指标，并在节点故障时自动切换到备用节点。

### 启用方式

健康检查在部署时自动启用，也可以手动执行：

- 使用菜单选项 `7) 节点健康检查`

### 检查指标

- **延迟**：ICMP ping、TCP 连接、HTTPS 请求的延迟
- **丢包率**：基于健康检查失败率计算
- **连接性**：ICMP、TCP、HTTPS、DNS、WireGuard 端口可达性

### 故障转移

当检测到当前节点不健康时：

1. 系统会自动查找备用节点
2. 选择最佳备用节点（基于优先级、权重、延迟）
3. 自动切换到备用节点
4. 更新默认节点配置

## 智能选路

### 功能概述

智能选路根据多个因素自动选择最优节点，包括延迟、权重、优先级、健康状态等。

### 启用方式

设置环境变量：

```bash
export PT_SMART_ROUTING=true
export PT_ROUTING_STRATEGY=balanced
```

### 选路策略

1. **延迟优先（latency_first）**

   - 优先选择延迟最低的节点
   - 适合实时应用、游戏、视频通话

2. **权重优先（weight_first）**

   - 优先选择权重最高的节点
   - 适合负载均衡场景

3. **优先级优先（priority_first）**

   - 优先选择优先级最高的节点
   - 适合有明确主备关系的场景

4. **平衡模式（balanced）**

   - 综合考虑延迟、权重、优先级、健康状态
   - 推荐用于大多数场景

5. **混合模式（hybrid）**

   - 智能混合多种因素
   - 适合复杂场景

### 使用方法

- **自动选路**：在部署时自动使用智能选路
- **手动选路**：使用菜单选项 `8) 智能节点选择`

## 连接质量监控

### 功能概述

持续监控连接质量，记录性能指标，生成质量报告。

### 启用方式

设置环境变量：

```bash
export PT_ENABLE_MONITORING=true
export PT_MONITOR_INTERVAL=30  # 检查间隔（秒）
```

### 监控指标

- **延迟**：实时延迟（毫秒）
- **丢包率**：数据包丢失率（0-1）
- **带宽**：连接带宽（Mbps，可选）
- **抖动**：延迟抖动（毫秒）
- **重连次数**：连接重连次数
- **流量统计**：发送/接收字节数、包数

### 查看报告

使用菜单选项 `9) 连接质量报告` 查看：

- 当前会话统计
- 历史会话记录
- 质量评分
- 性能趋势

## 自适应参数调整

### 功能概述

根据连接质量自动优化 WireGuard 参数（Keepalive、MTU），提升连接稳定性。

### 启用方式

设置环境变量：

```bash
export PT_ENABLE_MONITORING=true
export PT_ENABLE_ADAPTIVE=true
```

### 调整策略

1. **Keepalive 调整**

   - 重连频繁 → 降低 Keepalive（更快检测断线）
   - 丢包率高 → 降低 Keepalive
   - 延迟高但稳定 → 适当提高 Keepalive（减少开销）
   - 连接稳定 → 适当提高 Keepalive

2. **MTU 调整**

   - 丢包率高 → 降低 MTU（减少分片）
   - 延迟高 → 降低 MTU（减少重传）
   - 连接稳定 → 适当提高 MTU（提高效率）

### 查看建议

使用菜单选项 `10) 参数调整建议` 查看：

- 当前参数
- 建议参数
- 调整原因
- 调整历史

## ChatGPT 专用优化

### 功能概述

针对 ChatGPT/OpenAI 的特殊优化，确保访问稳定性和速度。

### 启用方式

设置环境变量：

```bash
export PT_CHATGPT_MODE=true
```

### 优化内容

1. **域名解析**

   - 自动解析所有 ChatGPT/OpenAI 相关域名
   - 定期更新 IP 地址列表

2. **连接测试**

   - 测试 OpenAI API 连接性
   - 测试 ChatGPT Web 连接性
   - 测量延迟和响应时间

3. **参数优化**

   - 针对 ChatGPT 优化 Keepalive 和 MTU
   - 优先选择延迟低的节点

4. **分流配置**

   - 生成 ChatGPT 专用分流配置
   - 仅 ChatGPT 流量走 VPN

### 使用方法

1. **部署时启用**

   - 设置 `PT_CHATGPT_MODE=true`
   - 系统会自动优化参数

2. **连接测试**

   - 使用菜单选项 `11) ChatGPT 连接测试`
   - 查看连接状态和优化建议

## V2Ray 流量伪装

### 功能概述

使用 V2Ray 伪装 WireGuard 流量，避免被 DPI（深度包检测）识别和屏蔽。

### 启用方式

设置环境变量：

```bash
export PT_ENABLE_V2RAY=true
export PT_V2RAY_PORT=443  # 可选，默认 443
export PT_V2RAY_UUID=<uuid>  # 可选，自动生成
```

### 工作原理

1. **流量路径**

   ```
   客户端 → V2Ray 客户端 → V2Ray 服务器 → WireGuard 服务器 → 互联网
   ```

2. **伪装效果**

   - WireGuard 流量被封装在 V2Ray 的 WebSocket/TLS 流中
   - 从外部看像是正常的 HTTPS 流量
   - 可以绕过 DPI 检测

3. **性能影响**

   - 会增加一定的延迟（通常 < 50ms）
   - 带宽开销增加约 5-10%
   - 适合在需要规避检测的场景使用

### 配置说明

- **端口**：默认使用 443，可以自定义
- **UUID**：自动生成，也可以手动指定
- **传输协议**：使用 WebSocket + TLS
- **服务器配置**：自动部署到 VPS

### 注意事项

- V2Ray 需要额外的系统资源
- 确保防火墙开放 V2Ray 端口
- 建议在稳定连接后再启用 V2Ray

## 功能组合使用

### 推荐配置

**高性能场景**（低延迟、高稳定性）：

```bash
export PT_MULTI_NODE=true
export PT_SMART_ROUTING=true
export PT_ROUTING_STRATEGY=latency_first
export PT_ENABLE_MONITORING=true
export PT_ENABLE_ADAPTIVE=true
```

**负载均衡场景**（多节点、高可用）：

```bash
export PT_MULTI_NODE=true
export PT_SMART_ROUTING=true
export PT_ROUTING_STRATEGY=weight_first
export PT_ENABLE_MONITORING=true
```

**ChatGPT 专用场景**：

```bash
export PT_MULTI_NODE=true
export PT_CHATGPT_MODE=true
export PT_SMART_ROUTING=true
export PT_ROUTING_STRATEGY=latency_first
export PT_ENABLE_MONITORING=true
```

**规避检测场景**：

```bash
export PT_ENABLE_V2RAY=true
export PT_V2RAY_PORT=443
export PT_ENABLE_MONITORING=true
```

## 相关文档

- [用户使用指南](USER_GUIDE.md)
- [环境变量说明](ENVIRONMENT_VARIABLES.md)
- [快速开始指南](GETTING_STARTED.md)
- [故障排查手册](TROUBLESHOOTING.md)


