#!/usr/bin/env python3
"""运行测试脚本。Test runner script."""

from __future__ import annotations

import sys
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    """主函数。Main function."""
    import argparse

    parser = argparse.ArgumentParser(description="运行测试")
    parser.add_argument(
        "--unit",
        action="store_true",
        help="只运行单元测试",
    )
    parser.add_argument(
        "--integration",
        action="store_true",
        help="只运行集成测试",
    )
    parser.add_argument(
        "--coverage",
        action="store_true",
        help="生成覆盖率报告",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="详细输出",
    )

    args = parser.parse_args()

    # 构建 pytest 命令
    cmd = [sys.executable, "-m", "pytest"]

    if args.unit:
        cmd.append("tests/test_*.py")
        cmd.append("-k")
        cmd.append("not TestIntegration")
    elif args.integration:
        cmd.append("tests/test_integration.py")
    else:
        cmd.append("tests/")

    if args.coverage:
        cmd.extend(["--cov=core", "--cov-report=html", "--cov-report=term"])

    if args.verbose:
        cmd.append("-v")
    else:
        cmd.append("-q")

    # 运行测试
    result = subprocess.run(cmd, cwd=ROOT)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())







