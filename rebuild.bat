@echo off
setlocal

set "ROOT_DIR=%~dp0"
set "BUILD_DIR=%ROOT_DIR%build"

if exist "%BUILD_DIR%" (
    echo [*] Removing existing build directory...
    rmdir /s /q "%BUILD_DIR%"
    if exist "%BUILD_DIR%" (
        echo [!] Could not remove the build directory because some files are in use.
        choice /c YN /m "Do you want to close Visual Studio and retry"
        if errorlevel 2 (
            echo [!] Please close Visual Studio or any process using files under build\ and run this script again.
            exit /b 1
        )

        echo [*] Attempting to close Visual Studio...
        taskkill /im devenv.exe /f >nul 2>nul
        timeout /t 2 /nobreak >nul

        rmdir /s /q "%BUILD_DIR%"
        if exist "%BUILD_DIR%" (
            echo [!] Still could not remove the build directory.
            echo [!] Please close any process using files under build\ and run this script again.
            exit /b 1
        )
    )
)

echo [*] Creating build directory...
mkdir "%BUILD_DIR%"
if errorlevel 1 (
    echo [!] Failed to create the build directory.
    exit /b 1
)

pushd "%BUILD_DIR%"
if errorlevel 1 (
    echo [!] Failed to enter the build directory.
    exit /b 1
)

echo [*] Running CMake configure...
cmake ..
if errorlevel 1 goto :build_fail
echo [*] CMake configure completed.

echo [*] Building Debug...
cmake --build . --config Debug
if errorlevel 1 goto :build_fail
echo [*] Debug build completed.

echo [*] Building Release...
cmake --build . --config Release
if errorlevel 1 goto :build_fail
echo [*] Release build completed.

set "SOLUTION_FILE="
for %%F in (*.sln) do (
    set "SOLUTION_FILE=%%F"
    goto :open_solution
)

echo [!] No solution file was generated.
goto :build_fail

:open_solution
echo [*] Opening solution: %SOLUTION_FILE%
start "" "%SOLUTION_FILE%"
popd
echo [*] Done.
exit /b 0

:build_fail
popd
echo [!] Build helper failed during configure or one of the build steps.
exit /b 1
