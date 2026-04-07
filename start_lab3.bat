@echo off
setlocal

set "ROOT_DIR=%~dp0"
set "BUILD_DIR=%ROOT_DIR%build"
set "CONFIG=Debug"
set "SERVER_SCRIPT=%ROOT_DIR%server\server.py"
set "CLIENT_SCRIPT=%ROOT_DIR%server\client.py"

if /i not "%~1"=="" (
    if /i "%~1"=="Debug" (
        set "CONFIG=Debug"
    ) else if /i "%~1"=="Release" (
        set "CONFIG=Release"
    ) else (
        echo [!] Invalid configuration: %~1
        echo [!] Usage: start_lab3.bat [Debug^|Release]
        exit /b 1
    )
)

set "HOST_EXE=%BUILD_DIR%\%CONFIG%\lab3_host.exe"

if not exist "%HOST_EXE%" (
    echo [!] Host executable not found: %HOST_EXE%
    echo [!] Run rebuild.bat first.
    exit /b 1
)

echo [*] Launching server, host, and client in separate windows...
echo [*] Using build configuration: %CONFIG%

start "Lab3 Server" powershell -NoExit -Command "Set-Location '%ROOT_DIR%'; python '%SERVER_SCRIPT%'"
timeout /t 1 /nobreak >nul

start "Lab3 Host" powershell -NoExit -Command "Set-Location '%BUILD_DIR%\%CONFIG%'; .\lab3_host.exe"
timeout /t 1 /nobreak >nul

start "Lab3 Client" powershell -NoExit -Command "Set-Location '%ROOT_DIR%'; python '%CLIENT_SCRIPT%'"

echo [*] Started all components.
exit /b 0
