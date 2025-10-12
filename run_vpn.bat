@echo off
title PrivateTunnel One-Click (Round 1: Windows Only)
python --version || (echo 请先安装 Python 3.8+ 并添加到 PATH && pause && exit /b)
if exist venv\Scripts\activate.bat (call venv\Scripts\activate.bat)
pip install -r requirements.txt
python main.py
pause
