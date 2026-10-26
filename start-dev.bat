@echo off
chcp 65001 >nul
title Portboard
cd /d "%~dp0"

where node >nul 2>nul
if errorlevel 1 (
  echo [Portboard] 未找到 Node.js。请安装 Node 18+ 并加入 PATH 后重试。
  pause
  exit /b 1
)

rem 等服务起来再开浏览器，避免首屏 404
start "" /min cmd /c "timeout /t 2 >nul & start http://127.0.0.1:8788"

node server.mjs
echo.
echo [Portboard] 已退出。
pause
