# Ad-Hoc 分发指南

Ad-Hoc 分发适用于小规模内部测试或固定设备部署。该模式需要提前收集所有设备的 UDID，并通过描述文件限制可安装的设备数量（最多 100 台/年）。

## 准备工作

1. 有效的 iOS Distribution 证书；
2. 需安装的设备 UDID（可通过 Finder、Xcode、Apple Configurator 或第三方工具获取）；
3. Apple Developer Program 账户，具备创建 Ad-Hoc 描述文件的权限；
4. 已完成 `make build`，生成最新的 `.xcarchive`。

## 收集设备 UDID

- 使用 macOS Finder 连接设备，在“序列号”栏点击即可切换显示 UDID；
- 在 Xcode → `Window → Devices and Simulators` 中选中设备，右键复制 Identifier；
- 对无法直接连接的用户，可提供 Apple Configurator 或 iMazing 导出的 `devices.mobileconfig`。

## 创建 Ad-Hoc 描述文件

1. 登录 Apple Developer 网站 → `Certificates, Identifiers & Profiles`；
2. 在 `Profiles` 中点击 `+`，选择 `Ad Hoc`；
3. 选择容器 App 的 App ID（`com.privatetunnel.app`），随后选择 Distribution 证书；
4. 勾选所有需要安装的设备；
5. 为 PacketTunnel 扩展重复上述流程（或在 Xcode 中启用自动签名）；
6. 下载生成的 `.mobileprovision` 文件，并在开发机器上双击安装。

## 导出 .ipa

1. 确保 `apps/ios/PrivateTunnelApp/ExportOptions_adhoc.plist` 中的 `teamID` 与 `provisioningProfiles` 已填写；
2. 运行导出脚本：
   ```bash
   make export-adhoc
   ```
   或者直接执行 `./scripts/ios_export.sh --method adhoc --export-options apps/ios/PrivateTunnelApp/ExportOptions_adhoc.plist`；
3. 导出成功后，会在 `build/export/` 下生成 `.ipa` 文件。

## 分发与安装

- **Apple Configurator 2**：连接目标设备，选择 `Add → Apps`，导入 `.ipa`；
- **iMazing/TestFlight 替代**：通过 iMazing 的“管理应用”功能安装；
- **自建下载页面**：将 `.ipa` 和 `manifest.plist` 部署到 HTTPS 服务端，提供 `itms-services://?action=download-manifest&url=https://.../manifest.plist` 的链接（需企业开发者证书时谨慎使用）。

## 维护与续期

- Ad-Hoc 描述文件有效期为一年，过期后必须重新生成并重新安装；
- 新增设备时，需要重新生成描述文件并重新导出 `.ipa`；
- 建议通过版本号与构建号区分每次导出，便于回溯。

如需更稳定的分发体验或更大规模测试，建议改用 [TestFlight](DISTRIBUTION_TESTFLIGHT.md)。
