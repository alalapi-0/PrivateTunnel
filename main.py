from __future__ import annotations

import os
import subprocess
import sys


def run_doctor() -> None:
    code = subprocess.call([sys.executable, "scripts/project_doctor.py"])
    if code == 0:
        print("\n✅ 体检通过。详见 PROJECT_HEALTH_REPORT.md")
    else:
        print("\n⚠️ 体检发现问题，请按报告修复后再继续。")


def run_prune() -> None:
    code = subprocess.call([sys.executable, "scripts/prune_non_windows_only.py"])
    if code == 0:
        print("\n🧹 精简完成。请查看 PROJECT_PRUNE_REPORT.md")
    else:
        print("\n⚠️ 精简脚本返回异常，请查看输出。")


def main() -> None:
    while True:
        print("\n=== PrivateTunnel (Windows Only) ===")
        print("1) 运行体检")
        print("2) 执行项目精简（移除/归档非 Windows 代码与 CI）")
        print("q) 退出")
        choice = input("请选择: ").strip().lower()
        if choice == "1":
            run_doctor()
        elif choice == "2":
            run_prune()
        elif choice == "q":
            break
        else:
            print("无效选项，请重试。")


if __name__ == "__main__":
    main()
