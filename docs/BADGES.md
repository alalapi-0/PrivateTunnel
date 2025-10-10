# README 徽标说明

README 顶部的状态徽标由 [Shields.io](https://shields.io/) 提供，便于快速了解仓库状态。以下为当前使用的徽标及更新方法：

| 徽标 | 含义 | 更新方式 |
| --- | --- | --- |
| `https://img.shields.io/github/actions/workflow/status/<repo>/ci.yml?branch=main&label=CI` | CI 状态 | 自动根据 GitHub Actions 更新。|
| `https://img.shields.io/badge/platform-iOS%2016%2B-blue` | 支持平台 | 如需调整最低系统版本，更新 URL 中的文字即可。|
| `https://img.shields.io/badge/version-1.0.0-blue` | 应用版本 | 使用 `scripts/bump_version.sh --version <x.y.z> --build <n>` 自动更新。|
| `https://img.shields.io/badge/build-1-blue` | 构建号 | 同上脚本会同步更新构建号。|
| `https://img.shields.io/badge/license-MIT-green` | 授权协议 | 若修改 License，请更新 README 中的链接。|

更新版本号步骤：

1. 在 macOS 上执行 `./scripts/bump_version.sh --version 1.1.0 --build 5`；
2. 脚本会同步修改 `apps/ios/*/Info.plist` 和 README 的版本徽标；
3. 提交变更并在 PR 中说明版本号更新。

如需新增徽标，可参考 Shields.io 文档，并在 README 与此文件中保持同步说明。
