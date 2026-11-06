@echo off
chcp 65001 >nul
rem 바탕화면에 PCmoa 바로가기를 만든다. "make_shortcut.bat auto" 로 실행하면 PC를 켤 때 자동으로 서버도 켠다
setlocal
set "ROOT=%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$s=New-Object -ComObject WScript.Shell;" ^
  "$root=$env:ROOT.TrimEnd('\');" ^
  "$mk={param($path) $l=$s.CreateShortcut($path); $l.TargetPath=Join-Path $root 'start_pcmoa.bat'; $l.WorkingDirectory=$root; $l.IconLocation=(Join-Path $root 'server\static\pcmoa.ico'); $l.WindowStyle=7; $l.Description='PCmoa 서버를 켜고 대시보드 열기'; $l.Save()};" ^
  "& $mk (Join-Path ([Environment]::GetFolderPath('Desktop')) 'PCmoa.lnk');" ^
  "Write-Output '바탕화면에 PCmoa 바로가기를 만들었습니다.';" ^
  "if('%~1' -eq 'auto'){ & $mk (Join-Path ([Environment]::GetFolderPath('Startup')) 'PCmoa.lnk'); Write-Output 'PC를 켤 때 자동으로 서버를 켜도록 등록했습니다 (시작 프로그램 폴더).' }"
pause
