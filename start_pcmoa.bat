@echo off
chcp 65001 >nul
rem PCmoa 서버를 켜고 대시보드를 연다 (이미 켜져 있으면 대시보드만 연다)
setlocal
set "ROOT=%~dp0"
set "URL=http://127.0.0.1:8000"
set "PY=python"
if exist "%ROOT%.venv\Scripts\python.exe" set "PY=%ROOT%.venv\Scripts\python.exe"

curl.exe -s -o nul --max-time 2 "%URL%/api/signup-enabled" && goto open

echo PCmoa 서버를 켜는 중...
start "PCmoa 서버 (이 창을 닫으면 서버가 꺼집니다)" /min /d "%ROOT%server" "%PY%" app.py

for /l %%i in (1,1,30) do (
  curl.exe -s -o nul --max-time 1 "%URL%/api/signup-enabled" && goto open
  timeout /t 1 /nobreak >nul
)
echo 서버가 30초 안에 켜지지 않았습니다. 작업 표시줄의 "PCmoa 서버" 창에서 오류를 확인하세요.
pause
exit /b 1

:open
start "" "%URL%"
exit /b 0
