"""Portable build of the PrivateTunnel desktop helper.

This package bundles the Windows-first automation workflow together with all
supporting modules so it can be vendored into other projects as-is.  The
modules under :mod:`portable_bundle.core` expose the reusable SSH, WireGuard
and Vultr helpers while :mod:`portable_bundle.main` provides the interactive
CLI entry point.
"""

from __future__ import annotations

from .main import main

__all__ = ["main"]

