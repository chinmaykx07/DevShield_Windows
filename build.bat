@echo off
setlocal EnableDelayedExpansion

:: ============================================================
:: DevShield — Local Build Script
:: build.bat
::
:: Usage:
::   build.bat           → release build (x64, no console, stripped)
::   build.bat dev       → dev build (console visible, debug symbols)
::   build.bat arm64     → ARM64 cross-compile
::   build.bat clean     → remove dist\ directory
::   build.bat run       → build + immediately launch devshield.exe
:: ============================================================

set VERSION=0.1.0-dev
set OUT_DIR=dist
set EXE_NAME=devshield.exe
set MODULE=github.com/chinmaykx07/DevShield_Windows

:: ── Parse argument ───────────────────────────────────────────
set BUILD_MODE=%1
if "%BUILD_MODE%"=="" set BUILD_MODE=release

:: ── Clean ────────────────────────────────────────────────────
if /i "%BUILD_MODE%"=="clean" (
    echo [DevShield] Cleaning dist\...
    if exist %OUT_DIR%\ rmdir /s /q %OUT_DIR%
    echo [DevShield] Clean complete.
    exit /b 0
)

:: ── Pre-flight: Check Go ─────────────────────────────────────
where go >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Go not found in PATH.
    echo         Install from: https://go.dev/dl/
    exit /b 1
)
for /f "tokens=3" %%v in ('go version') do set GO_VER=%%v
echo [DevShield] Go: %GO_VER%

:: ── Pre-flight: Check GCC (required for CGO) ─────────────────
where gcc >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] GCC not found in PATH. CGO requires GCC.
    echo         Install TDM-GCC from: https://jmeubank.github.io/tdm-gcc/
    echo         Then re-open this terminal so PATH updates take effect.
    exit /b 1
)
for /f "tokens=3" %%v in ('gcc --version 2^>^&1 ^| findstr "gcc"') do (
    set GCC_VER=%%v
    goto :gccfound
)
:gccfound
echo [DevShield] GCC: %GCC_VER%

:: ── Pre-flight: Check icon ────────────────────────────────────
if not exist assets\devshield.ico (
    echo [WARNING] assets\devshield.ico not found.
    echo           The build WILL FAIL without this file.
    echo           See assets\icon.go for creation instructions.
    echo           Using placeholder if it exists...
    if not exist assets\placeholder.ico (
        echo [ERROR] No .ico file found in assets\. Cannot build.
        exit /b 1
    )
    copy /y assets\placeholder.ico assets\devshield.ico >nul
    echo [DevShield] Copied placeholder.ico → devshield.ico for this build.
)

:: ── Create output directory ───────────────────────────────────
if not exist %OUT_DIR%\ mkdir %OUT_DIR%

:: ── Set environment ───────────────────────────────────────────
set CGO_ENABLED=1
set GOOS=windows

:: ── Build flags ───────────────────────────────────────────────
if /i "%BUILD_MODE%"=="dev" (
    :: Dev build: console visible so fmt.Println/log output is readable
    set GOARCH=amd64
    set LDFLAGS=-X main.dsVersion=%VERSION%-dev
    echo [DevShield] Mode: DEV ^(console visible, debug symbols kept^)
) else if /i "%BUILD_MODE%"=="arm64" (
    set GOARCH=arm64
    set LDFLAGS=-H=windowsgui -s -w -X main.dsVersion=%VERSION%
    set EXE_NAME=devshield-arm64.exe
    echo [DevShield] Mode: ARM64 release
) else (
    :: Release build: no console window, stripped symbols
    set GOARCH=amd64
    set LDFLAGS=-H=windowsgui -s -w -X main.dsVersion=%VERSION%
    echo [DevShield] Mode: RELEASE ^(x64, no console, stripped^)
)

:: ── Compile ───────────────────────────────────────────────────
echo [DevShield] Building %OUT_DIR%\%EXE_NAME% ...
echo.

go build ^
    -ldflags "%LDFLAGS%" ^
    -o %OUT_DIR%\%EXE_NAME% ^
    .

if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] Build failed. See errors above.
    exit /b 1
)

:: ── Post-build: size + checksum ───────────────────────────────
echo.
for %%F in (%OUT_DIR%\%EXE_NAME%) do set SIZE_BYTES=%%~zF
set /a SIZE_KB=%SIZE_BYTES% / 1024
echo [DevShield] Build complete: %OUT_DIR%\%EXE_NAME% ^(%SIZE_KB% KB^)

powershell -NoProfile -Command ^
    "(Get-FileHash '%OUT_DIR%\%EXE_NAME%' -Algorithm SHA256).Hash" > %OUT_DIR%\checksums.txt 2>nul
if %ERRORLEVEL% equ 0 (
    set /p HASH=<%OUT_DIR%\checksums.txt
    echo [DevShield] SHA256: !HASH!
)

:: ── Run immediately if requested ─────────────────────────────
if /i "%BUILD_MODE%"=="run" (
    echo.
    echo [DevShield] Launching...
    start "" %OUT_DIR%\%EXE_NAME%
    exit /b 0
)

echo.
echo [DevShield] To run:    dist\devshield.exe
echo [DevShield] To clean:  build.bat clean
echo [DevShield] To launch: build.bat run

endlocal
