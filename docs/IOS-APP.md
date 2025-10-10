# PrivateTunnel iOS 容器 App 使用说明

> 本文对应工具链 Roadmap Round 4，提供 SwiftUI 容器 App 以导入并保存客户端配置。Round 5 将在此基础上增加 Packet Tunnel 扩展。

## 1. 环境准备
- macOS 14+，安装 Xcode 15 或更新版本。
- iOS 16+ 真机设备，用于调试摄像头扫码与 Keychain 持久化。
- Round 3 生成的 JSON 配置文件或二维码（可在 `docs/CLIENT-CONFIG.md` 中找到示例）。

## 2. 获取代码
```bash
# clone 仓库后进入工程目录
cd PrivateTunnel
```

SwiftUI App 位于 `apps/ios/PrivateTunnelApp/`，使用 Swift Package Manager 管理依赖（仅系统框架）。

## 3. 在 Xcode 中运行
1. 打开 Xcode，选择 **File → Open...**，指向仓库根目录。
2. 在项目导航中选择 `PrivateTunnelApp` 目标。
3. 在 Signing & Capabilities 页面设置有效的开发者 Team，确保 Bundle Identifier 唯一。
4. 连接真机，点击 **Run**。首次运行会弹出相机权限请求，请选择允许。

## 4. 导入配置
App 主界面包含标题「Private Tunnel Configurator」、已保存配置列表以及两个导入按钮。

### 4.1 扫码导入
1. 点击「📷 扫码导入 JSON」。
2. 将 Round 3 生成的二维码置于取景框内。
3. 扫描成功后，App 会解析二维码中的 JSON 字符串并展示配置详情。

> ![扫码示意图占位](images/ios-round4-scan-placeholder.png)

### 4.2 文件导入
1. 点击「📂 从文件导入」。
2. 在 Files App 中选择 `.json` 配置文件。
3. App 将读取文件内容并解析为 `TunnelConfig` 对象。

## 5. 校验与保存
- `TunnelConfig` 模型实现了基本的字段校验：版本号、Profile 名称、端口范围、IPv4 CIDR、DNS 列表等。
- 解析或校验失败时会弹出提示，说明问题原因。
- 校验通过后，点击「保存配置」，配置会以 JSON 形式写入 Keychain，并在 UserDefaults 中记录索引。
- 列表支持左滑删除，同时提供刷新按钮以重新拉取 Keychain 数据。

## 6. 本地存储策略
- 私钥等敏感字段通过 `KeychainHelper` 使用 `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` 访问级别保存。
- 仅保存必要字段，不会上传至服务器，也不会写入沙盒之外的目录。
- App Documents 目录暂不写入任何文件；导出功能将在 Round 6 之后补充。

## 7. 调试技巧
- 使用 Xcode 的 **View Debugging → Capture View Hierarchy** 检查扫描界面布局。
- 如需模拟 JSON 解析失败，可手动修改二维码内容或导入不合法的文件，验证 Alert 展示。
- 通过 **Settings → Developer → Logging** 可确认 App 未进行网络访问。

## 8. 后续规划
Round 5 将在 `apps/ios/PacketTunnelProvider/` 中创建 `PacketTunnelProvider` 扩展，复用当前保存的配置并连接 WireGuard 隧道。请保持配置索引结构不变，以便扩展读取。
