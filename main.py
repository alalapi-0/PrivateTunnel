from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def create_vps() -> None:
    from core.tools.vultr_manager import (  # pylint: disable=import-outside-toplevel
        VultrError,
        create_instance,
        wait_instance_active,
    )

    api_key = os.environ.get("VULTR_API_KEY", "")
    if not api_key:
        print("❌ 未检测到环境变量 VULTR_API_KEY。请先设置后重试。")
        return

    region = input("region [nrt]: ").strip() or "nrt"
    plan = input("plan [vc2-1c-1gb]: ").strip() or "vc2-1c-1gb"
    snapshot_id = input("snapshot_id (可留空): ").strip() or None

    try:
        print("→ 创建实例中...")
        inst = create_instance(api_key, region=region, plan=plan, snapshot_id=snapshot_id)
        iid = inst["id"]
        print(f"实例已创建，id={iid}，等待 active ...")
        ready = wait_instance_active(api_key, iid, timeout=600, interval=10)
        ip = ready["ip"]
        print(f"✅ 实例就绪：id={iid}  ip={ip}")

        Path("artifacts").mkdir(exist_ok=True)
        Path("artifacts/instance.json").write_text(
            json.dumps(
                {
                    "id": iid,
                    "ip": ip,
                    "region": region,
                    "plan": plan,
                    "snapshot_id": snapshot_id or "",
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        print("已写入 artifacts/instance.json")
    except VultrError as e:
        print(f"❌ 失败：{e}")
        print(
            "排查建议：\n- 检查 VULTR_API_KEY 是否正确且 Access Control 放行当前公网 IP\n"
            "- 检查 region/plan/snapshot_id 是否可用\n- 查看 Vultr 控制台是否有配额/余额限制"
        )


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
        print("2) 创建 VPS（Vultr）")
        print("3) 执行项目精简（移除/归档非 Windows 代码与 CI）")
        print("q) 退出")
        choice = input("请选择: ").strip().lower()
        if choice == "1":
            run_doctor()
        elif choice == "2":
            create_vps()
        elif choice == "3":
            run_prune()
        elif choice == "q":
            break
        else:
            print("无效选项，请重试。")


if __name__ == "__main__":
    main()
