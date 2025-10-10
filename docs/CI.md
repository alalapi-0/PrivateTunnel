# CI 工作流说明

PrivateTunnel 使用 GitHub Actions 在每次提交和夜间任务中执行自动化检查，确保脚本、服务器工具与 iOS 工程保持可编译状态。

## 主 CI：`.github/workflows/ci.yml`

触发条件：

- 推送到 `main` 分支；
- 针对 `main` 的 Pull Request；
- 手动触发 `workflow_dispatch`。

工作流包含两个作业：

1. **lint-and-scripts（Ubuntu）**
   - 运行 Bash 语法检查（`bash -n`）与可选的 ShellCheck 分析；
   - 使用 `python -m compileall` 对仓库内 Python 脚本进行语法检查；
   - 干跑 `server/provision/wg-install.sh --dry-run`，验证安装脚本仍然可执行；
   - 调用 `server/split/resolve_domains.py --help`，确保分流脚本参数未变；
   - 执行 `server/security/audit.sh --json`，若返回非零会发出 warning 但不中断 CI；
   - 若发生失败，步骤会提示参考 [docs/BUILD_IOS.md](BUILD_IOS.md) 与 [docs/TROUBLESHOOTING.md](TROUBLESHOOTING.md)。

2. **ios-build-check（macOS）**
   - 使用默认的 Xcode 版本构建容器 App 与 PacketTunnel 扩展；
   - 构建命令禁用了签名（`CODE_SIGNING_ALLOWED=NO`），仅验证代码能编译；
   - 生成的 `xcodebuild` 日志会作为 artifact 上传，可在 PR 页面下载；
   - 若构建失败，日志中会标注常见的签名或依赖问题，可对照 [BUILD_IOS.md](BUILD_IOS.md) 排查。

所有作业均成功时，PR 会显示 `✔️ CI` 状态。

## 夜间任务：`.github/workflows/nightly.yml`

触发条件：

- 每日 UTC 03:00；
- 手动 `workflow_dispatch`。

主要步骤：

- `scripts/check_links.py`：扫描 README 与 docs/ 目录的相对链接，若发现断链则任务失败；
- `python3 server/split/resolve_domains.py`：对分流域名进行解析。解析失败不会导致任务失败，但会发出 warning；
- 将 `server/split/state/resolved.json` 上传为 artifact，方便排查当日解析结果。

## 使用建议

- 在 PR 中，点击 `Details` 可查看每个作业的执行日志；
- 若遇到 DerivedData 污染导致无法编译，可在本地执行 `rm -rf ~/Library/Developer/Xcode/DerivedData`，或在 CI 中禁用缓存（当前默认未启用缓存以避免污染）；
- 变更涉及脚本或服务器配置时，请在 PR 描述中附上手工验证步骤，以配合 CI 报告。
