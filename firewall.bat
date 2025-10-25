@echo off
setlocal

:: Detectar si se está ejecutando con privilegios de administrador
NET SESSION >nul 2>&1
if %errorLevel% == 0 (
    goto :isAdmin
) else (
    echo Ejecutando el script como administrador...
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B
)

:isAdmin

cd /D "%~dp0"
start "" FirewallPython.py

