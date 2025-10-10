# TestFlight 分发指南

本文档说明如何通过 Xcode Organizer 或 Transporter 将 PrivateTunnel 提交到 TestFlight。请确保仅限内部测试或受邀用户使用，遵循隐私与合规要求。

## 准备工作

1. Apple Developer Program 付费账户；
2. 完整的应用元数据（名称、描述、隐私政策链接，推荐使用仓库内的 [docs/PRIVACY.md](PRIVACY.md)）；
3. 有效的 Distribution 证书与 `App Store` 描述文件；
4. 构建自检通过：`make build` 生成 `.xcarchive`，并使用 `make export-appstore` 导出 `.ipa`。

## 使用 Xcode Organizer 上传

1. 打开 Xcode → `Window → Organizer`；
2. 选择 `Archives` 选项卡，找到最新生成的 `PrivateTunnel` Archive；
3. 点击 `Distribute App` → 选择 `App Store Connect`；
4. 在分发选项中选择 `Upload`；
5. 在“App Store Distribution Options”中勾选 `Upload your app's symbols`，取消 `Include bitcode`（仓库模板已将 `compileBitcode=false`）；
6. 核对 Bundle Identifier、版本号、构建号与签名团队是否正确；
7. 点击 `Upload`，等待传输完成。

上传成功后，可在 App Store Connect → `My Apps` → `PrivateTunnel` 中查看 Processing 状态。处理完成通常需要 10-30 分钟。

## 使用 Transporter 上传（可选）

1. 从 Mac App Store 安装 Apple 官方 `Transporter`；
2. 登录 Apple ID；
3. 将导出的 `.ipa` 拖入 Transporter；
4. 点击 `Deliver`，等待上传完成。

## TestFlight 配置

1. 在 App Store Connect → `My Apps` → `PrivateTunnel` → `TestFlight` 中，选择刚处理完成的构建；
2. 填写测试信息，包括：
   - `What to Test`：描述本轮测试的重点；
   - 联系方式与隐私政策 URL；
3. 启用 `Internal Testing`（内部测试），选择团队成员；
4. 如需扩展至外部测试，需要提交给 App Review，注意 VPN 类应用的描述要强调远程访问/隐私保护用途，不得涉及翻越网络限制。

## 提审前检查清单

- 隧道说明：避免在 App 描述中出现“翻墙”“代理公共网络”等敏感词；
- 隐私：确认应用不会记录用户的访问内容，必要时在 App Store Connect 中补充 `Privacy Practices`；
- 账号体系：PrivateTunnel 定位为自用工具，推荐在元数据中说明“需要自建服务器配置，非公共服务”；
- 内容加密：确保服务器端使用 WireGuard 正式密钥，避免 toy 通道用于生产；
- 地域限制：若不计划在中国区上架，请在 `Pricing and Availability` 中取消该区域。

处理完成后，可将 TestFlight 链接分享给内部用户或通过邮件邀请。务必定期更新构建并维护描述文件有效期。
