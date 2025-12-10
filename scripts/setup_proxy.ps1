#!/usr/bin/env pwsh
# 代理自动配置脚本（Windows PowerShell）
# 自动检测本地代理服务并配置环境变量

Write-Host "🔍 正在检测本地代理服务..." -ForegroundColor Cyan

# 导入代理工具模块（需要先设置 Python 路径）
$pythonPath = Get-Command python -ErrorAction SilentlyContinue

if (-not $pythonPath) {
    Write-Host "❌ 未找到 Python，请先安装 Python 3.8+" -ForegroundColor Red
    exit 1
}

# 运行 Python 脚本检测代理
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
$pythonScript = @"
import sys
from pathlib import Path
sys.path.insert(0, str(Path('$projectRoot').resolve()))

from core.proxy_utils import auto_configure_proxy, detect_local_proxy

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
    print('注意：此设置仅对当前 PowerShell 会话有效')
    print('如需永久设置，请运行:')
    print(f'  [System.Environment]::SetEnvironmentVariable("ALL_PROXY", "{proxy_url}", "User")')
else:
    print('❌ 未检测到本地代理服务')
    print('请确保已启动 Clash、V2RayN 或其他代理软件')
    sys.exit(1)
"@

$output = python -c $pythonScript 2>&1
Write-Host $output

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n✅ 代理配置完成！" -ForegroundColor Green
    Write-Host "现在可以运行: python main.py" -ForegroundColor Yellow
} else {
    Write-Host "`n❌ 代理配置失败" -ForegroundColor Red
    exit 1
}



