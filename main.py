from __future__ import annotations

import json
import os
import subprocess
import sys
from getpass import getpass
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


def deploy_wireguard() -> None:
    from core.tools.wireguard_installer import (  # pylint: disable=import-outside-toplevel
        WireGuardProvisionError,
        provision,
    )

    inst_path = Path("artifacts/instance.json")
    if not inst_path.exists():
        print("❌ 未找到 artifacts/instance.json，请先创建 VPS。")
        return

    try:
        instance = json.loads(inst_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"❌ 解析实例信息失败：{exc}")
        return

    ip = instance.get("ip")
    if not ip:
        print("❌ 实例信息缺少 IP 字段，请重新创建或检查 artifacts/instance.json。")
        return

    print(f"发现实例 {ip}")
    method = input("选择认证方式: [Enter=私钥] / p=密码: ").strip().lower()

    artifacts_dir = Path("artifacts")
    artifacts_dir.mkdir(exist_ok=True)

    provision_result: dict | None = None
    fallback_to_password = False

    if method != "p":
        default_key = Path.home() / ".ssh" / "id_rsa"
        key_input = input(f"私钥路径 [{default_key}]: ").strip()
        key_path = Path(key_input or str(default_key)).expanduser()
        if not key_path.exists():
            print(f"⚠️ 私钥文件不存在：{key_path}")
            fallback_to_password = True
        else:
            try:
                provision_result = provision(ip, username="root", pkey_path=str(key_path))
            except WireGuardProvisionError as exc:
                print(f"❌ 使用私钥部署失败：{exc}")
                fallback_to_password = True
            except Exception as exc:  # pragma: no cover - defensive
                print(f"❌ 未预期错误：{exc}")
                return

    if provision_result is None and (method == "p" or fallback_to_password):
        password = getpass("root 密码: ")
        if not password:
            print("❌ 未输入密码，已取消部署。")
            return
        try:
            provision_result = provision(
                ip,
                username="root",
                password=password,
            )
        except WireGuardProvisionError as exc:
            print(f"❌ 使用密码部署失败：{exc}")
            print("排查建议：\n- 检查密码是否正确\n- 确认实例防火墙放行 22 端口\n- 尝试使用私钥重新部署")
            return
        except Exception as exc:  # pragma: no cover - defensive
            print(f"❌ 未预期错误：{exc}")
            return

    if provision_result is None:
        print("❌ 部署已取消。")
        return

    server_path = artifacts_dir / "server.json"
    result_payload = {
        "server_pub": provision_result.get("server_pub", ""),
        "port": provision_result.get("port", 51820),
        "ip": ip,
    }
    server_path.write_text(
        json.dumps(result_payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print("✅ WireGuard 已启动，端口 51820")
    print(f"server_pub: {result_payload['server_pub']}")
    print(f"已写入 {server_path}")


def main() -> None:
    while True:
        print("\n=== PrivateTunnel (Windows Only) ===")
        print("1) 运行体检")
        print("2) 创建 VPS（Vultr）")
        print("3) 部署 WireGuard（到已创建 VPS）")
        print("4) 执行项目精简（移除/归档非 Windows 代码与 CI）")
        print("q) 退出")
        choice = input("请选择: ").strip().lower()
        if choice == "1":
            run_doctor()
        elif choice == "2":
            create_vps()
        elif choice == "3":
            deploy_wireguard()
        elif choice == "4":
            run_prune()
        elif choice == "q":
            break
        else:
            print("无效选项，请重试。")


if __name__ == "__main__":
    main()
