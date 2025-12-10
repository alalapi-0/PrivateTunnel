#!/bin/bash
# 代理自动配置脚本（Linux/macOS）
# 自动检测本地代理服务并配置环境变量

echo "🔍 正在检测本地代理服务..."

# 检查 Python
if ! command -v python3 &> /dev/null; then
    echo "❌ 未找到 Python3，请先安装 Python 3.8+"
    exit 1
fi

# 获取脚本目录和项目根目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# 运行 Python 脚本检测代理
python3 << EOF
import sys
from pathlib import Path
sys.path.insert(0, str(Path("$PROJECT_ROOT").resolve()))

from core.proxy_utils import detect_local_proxy

# 检测代理
detected = detect_local_proxy()
if detected:
    proxy_url = detected['proxy_url']
    service = detected.get('service', 'unknown')
    print(f'✓ 检测到 {service} 代理: {proxy_url}')
    
    # 询问是否设置环境变量
    import os
    current = os.environ.get('ALL_PROXY', '')
    if current:
        print(f'当前已设置: ALL_PROXY={current}')
        response = input('是否覆盖现有配置？[y/N]: ')
        if response.lower() not in ('y', 'yes'):
            print('已取消')
            sys.exit(0)
    
    # 设置环境变量（仅当前会话）
    os.environ['ALL_PROXY'] = proxy_url
    print(f'✓ 已设置环境变量: ALL_PROXY={proxy_url}')
    print('注意：此设置仅对当前 Shell 会话有效')
    print('如需永久设置，请运行:')
    print(f'  export ALL_PROXY="{proxy_url}"')
    print('  或添加到 ~/.bashrc 或 ~/.zshrc')
else:
    print('❌ 未检测到本地代理服务')
    print('请确保已启动 Clash、V2RayN 或其他代理软件')
    sys.exit(1)
EOF

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ 代理配置完成！"
    echo "现在可以运行: python3 main.py"
else
    echo ""
    echo "❌ 代理配置失败"
    exit 1
fi



