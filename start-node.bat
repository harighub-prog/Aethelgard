@echo off
setlocal enabledelayedexpansion
title Project Aethelgard - Swarm Node Launcher

echo ==============================================================================
echo                 PROJECT AETHELGARD - AUTONOMOUS MESH NODE
echo ==============================================================================
echo.

:: 1. Check for Java installation
where java >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [!] Java is not detected on your computer.
    goto :INSTALL_JAVA
)

:: Check Java Version (must be >= 21)
set "JAVA_VER="
for /f "tokens=3" %%g in ('java -version 2^>^&1 ^| findstr /i "version"') do (
    set "RAW_VER=%%~g"
    for /f "delims=.-" %%v in ("!RAW_VER!") do set "JAVA_VER=%%v"
)

if not defined JAVA_VER (
    echo [!] Could not determine Java version. Proceeding anyway...
    goto :LOCATE_JAR
)

if !JAVA_VER! lss 21 (
    echo [!] Found Java version !JAVA_VER!, but Project Aethelgard requires Java 21 LTS or newer.
    goto :INSTALL_JAVA
)

echo [OK] Java 21+ detected (Major Version: !JAVA_VER!).
goto :LOCATE_JAR

:INSTALL_JAVA
echo.
echo ==============================================================================
echo                  AUTOMATIC SETUP REQUIRED: JAVA 21 LTS
echo ==============================================================================
echo Project Aethelgard requires Java 21 LTS to run with quantum-safe cryptography
echo and virtual threads.
echo.
set /p "INSTALL_CHOICE=Would you like to automatically download and install Java 21 now? (Y/N): "
if /i not "!INSTALL_CHOICE!"=="Y" (
    echo.
    echo Installation cancelled. Please install Java 21 manually from:
    echo https://adoptium.net/temurin/releases/?version=21
    echo.
    pause
    exit /b 1
)

echo.
echo [*] Installing Eclipse Adoptium Temurin OpenJDK 21 via Windows Package Manager...
where winget >nul 2>&1
if %ERRORLEVEL% equ 0 (
    winget install EclipseAdoptium.Temurin.21.JRE --accept-source-agreements --accept-package-agreements
    if %ERRORLEVEL% equ 0 (
        echo [OK] Java 21 successfully installed!
        echo Please close this window and double-click start-node.bat again to refresh environment.
        pause
        exit /b 0
    )
)

echo [!] Automated installation via winget was not completed.
echo Opening the official Java 21 download page in your browser...
start https://adoptium.net/temurin/releases/?version=21
echo.
echo Please complete the installer, then run start-node.bat again.
pause
exit /b 1

:LOCATE_JAR
echo.
:: Search for aethelgard.jar in current directory or target/
set "JAR_PATH="
if exist "%~dp0aethelgard.jar" set "JAR_PATH=%~dp0aethelgard.jar"
if not defined JAR_PATH if exist "%~dp0target\aethelgard.jar" set "JAR_PATH=%~dp0target\aethelgard.jar"

if not defined JAR_PATH (
    echo [ERROR] Could not find 'aethelgard.jar'.
    echo Please ensure aethelgard.jar is in this folder or in the target\ folder.
    pause
    exit /b 1
)

:: 2. Interactive node configuration
echo ------------------------------------------------------------------------------
echo                        NODE CONFIGURATION
echo ------------------------------------------------------------------------------
set "PORT=8001"
set /p "INPUT_PORT=Enter port to listen on [Default: 8001]: "
if defined INPUT_PORT set "PORT=%INPUT_PORT%"

set "CONNECT_ARG="
set /p "INPUT_PEER=Connect to an existing peer IP:port (e.g. 192.168.1.50:8001, or Enter for standalone): "
if defined INPUT_PEER set "CONNECT_ARG=--connect=%INPUT_PEER%"

echo.
echo [*] Starting Aethelgard Node on port %PORT%...
if defined CONNECT_ARG echo [*] Connecting to peer: %INPUT_PEER%
echo.

:: 3. Execute with preview features enabled
java --enable-preview -jar "%JAR_PATH%" --port=%PORT% %CONNECT_ARG%

if %ERRORLEVEL% neq 0 (
    echo.
    echo [!] Node process exited with code %ERRORLEVEL%.
    pause
)
