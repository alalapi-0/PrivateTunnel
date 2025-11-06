"""PrivateTunnel 桌面助手的便携式打包版本。

功能概览：
1. 集成 Windows 优先的一键自动化工作流，便于嵌入其他项目。
2. `portable_bundle.core` 提供可复用的 SSH、WireGuard、Vultr 辅助工具。
3. `portable_bundle.main` 暴露交互式 CLI 入口，保持与主仓库一致的体验。

Portable build of the PrivateTunnel desktop helper.

This package bundles the Windows-first automation workflow together with all
supporting modules so it can be vendored into other projects as-is.  The
modules under :mod:`portable_bundle.core` expose the reusable SSH, WireGuard
and Vultr helpers while :mod:`portable_bundle.main` provides the interactive
CLI entry point.
"""

from __future__ import annotations

from .main import main

__all__ = ["main"]

