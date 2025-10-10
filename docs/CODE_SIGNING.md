# 签名与权限配置指南

PrivateTunnel 由容器 App 和 PacketTunnel 扩展组成，两者必须共享统一的签名配置和 App Group。本指南总结证书、描述文件以及常见 Network Extension 权限的配置步骤。

## 证书类型

| 场景 | 证书 | 说明 |
| --- | --- | --- |
| 本地调试 | iOS Development | 需要付费 Apple Developer Program 账户，支持真机调试和 Ad-Hoc 安装。|
| TestFlight / App Store | iOS Distribution | 仅用于上传 TestFlight 或正式发布。|
| Ad-Hoc 内部分发 | iOS Distribution | 与 Development 证书不同，导出时需搭配 Ad-Hoc 描述文件。|

证书建议通过 Xcode → Settings → Accounts 登录后自动管理，或在 Apple Developer 网站使用 `.certSigningRequest` 手动生成。

## App ID 与 Bundle Identifier

- 容器 App 默认 Bundle ID：`com.privatetunnel.app`
- PacketTunnel 扩展：`com.privatetunnel.PacketTunnelProvider`

请在 Apple Developer 后台分别创建两个 App ID，并确保都启用了 **Network Extensions** 能力。

## Provisioning Profile

两个 target 需要各自的描述文件，但必须绑定到同一团队、并包含 Network Extension 权限：

- Development 环境：创建 `iOS App Development` 类型的 Profile，分别命名为 `PrivateTunnelApp Dev`、`PacketTunnelProvider Dev` 等；
- Ad-Hoc：使用 `Ad Hoc` 类型，需勾选允许的设备 UDID；
- App Store / TestFlight：使用 `App Store Connect`（即 `App Store`）类型的 Profile。

在 Xcode 中分别为容器与扩展选择对应的 Profile，或保持自动签名以简化管理。

## App Group 与 Keychain Access Groups

容器与扩展需要共享配置存储与密钥：

1. 在 Apple Developer → Identifiers 中为两个 App ID 添加同一个 **App Group**（例如 `group.com.privatetunnel.shared`）；
2. 在 Xcode 的两个 target 中启用 `App Groups`，并勾选上述同名条目；
3. 若需要共享 Keychain，可启用 `Keychain Sharing` 并填写统一的 Access Group（通常自动生成）。

## Network Extension 权限

PacketTunnel 扩展使用 `com.apple.developer.networking.networkextension` entitlement，类型为 `packet-tunnel`。该权限通常随 App ID 启用 Network Extensions 自动获得。

- 开发阶段在真机上调试即可，无需额外申请；
- 若计划发布至 App Store，需要在 App Store Connect 中填写描述，确保定位于“远程访问/隐私保护”等合规场景，避免含糊或违规描述；
- 中国大陆地区 App Store 对 VPN 应用有额外限制，请勿承诺可上架该区域。

## ExportOptions 配置

仓库提供 `apps/ios/PrivateTunnelApp/ExportOptions_adhoc.plist` 与 `ExportOptions_appstore.plist` 模板。在导出前请替换以下字段：

- `teamID`：贵团队的 Team ID，例如 `ABCDE12345`；
- `provisioningProfiles`：容器与扩展各自的描述文件名称；
- 如需自动签名，可删除 `signingStyle` 和 `provisioningProfiles`，改为 `signingStyle = automatic`。

## 常见签名错误

| 错误 | 原因 | 解决 |
| --- | --- | --- |
| `No signing certificate "iOS Development" found` | 本机钥匙串缺少证书 | 在 Xcode Accounts 页面点击 `Download Manual Profiles` 或重新生成证书。|
| `Provisioning profile doesn't include signing certificate` | Profile 与证书不匹配 | 重新在 Developer 网站选择正确证书后下载。|
| `Missing required entitlement: com.apple.developer.networking.networkextension` | Profile 未启用 Network Extension | 更新 App ID 功能并重新生成 Profile。|
| `Your account already has a certificate for this machine` | CSR 重复 | 删除旧证书或撤销后再创建新的 Development/Distribution 证书。|

配置完成后，建议运行 `make build` 确认 Archive 能成功生成，再根据分发目标执行导出脚本。
