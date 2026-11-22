@echo off
chcp 65001 >nul
title self-audit
cd /d "%~dp0"
python launcher.py
if errorlevel 1 pause
