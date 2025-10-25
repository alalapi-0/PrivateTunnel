# PrivateTunnel Portable Bundle

这个目录是 **PrivateTunnel 一键部署工具** 的“可移植打包版”。你可以将整个
`portable_bundle/` 文件夹拷贝到任意 Python 项目中（例如 `vendor/` 或
`tools/` 目录），无需依赖 Git 子模块即可复用桌面助手的全部功能。

## 目录结构速览

```
portable_bundle/
├── __init__.py          # 允许 `import portable_bundle`
├── __main__.py          # 支持 `python -m portable_bundle`
├── main.py              # 桌面助手交互式 CLI
├── core/                # SSH / WireGuard / Vultr 逻辑与配置工具
├── scripts/             # 自动化脚本（Windows 一键流程等）
├── legacy/              # 归档的历史资料与补充脚本
├── requirements.txt     # 所需的第三方依赖
└── run_vpn.bat          # Windows 下的便捷启动脚本
```

所有可导入的模块都以 `portable_bundle` 作为包名前缀，例如
`portable_bundle.core.ssh_utils`。

## 快速开始

1. 将 `portable_bundle/` 复制到目标项目。
2. 在目标项目中执行
   ```bash
   pip install -r portable_bundle/requirements.txt
   ```
3. 使用模块入口启动桌面助手：
   ```bash
   python -m portable_bundle
   ```
   Windows 用户也可以运行 `run_vpn.bat`，该脚本会自动安装依赖并执行
   上述命令。

## 在其他代码中复用

所有工具函数都位于 `portable_bundle.core` 及其子模块中，可直接导入：

```python
from portable_bundle.core.port_config import resolve_listen_port
from portable_bundle.core.ssh_utils import smart_ssh

port, source = resolve_listen_port()
print(f"Listening on {port} (configured via {source})")

result = smart_ssh("example.com", ["echo", "ok"], key_path="~/.ssh/id_ed25519")
print(result.stdout)
```

若需要运行自动化脚本，可通过 `python -m portable_bundle.scripts.windows_oneclick`
的方式触发；脚本内部使用相对导入，因此无需修改 `PYTHONPATH`。

## 注意事项

- Python 版本需 ≥ 3.8，推荐 3.11 及以上。
- 某些步骤涉及网络或云厂商 API 调用，请确保目标环境具备相应权限。
- `legacy/` 目录包含归档脚本和文档，默认不会在运行时被加载，但保留在包中
  以便参考。

## 常用文件

- `requirements.txt`：列出运行 CLI 所需的最小依赖。
- `core/project_overview.py`：生成项目功能总览的工具。
- `core/tools/wireguard_installer.py`：远程安装 WireGuard 的核心逻辑。
- `scripts/windows_oneclick.py`：Windows 用户的全流程自动化脚本。

如需更多背景知识，可在原仓库的 `docs/` 目录中查看完整文档。

