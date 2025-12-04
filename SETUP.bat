@echo off
REM DNS Tunnel Detection Service - Windows Setup Launcher

echo ========================================
echo DNS Tunnel Detection Service
echo Interactive Installation Wizard
echo ========================================
echo.

REM Check Python installation
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo.
    echo Please install Python 3.11 or higher from:
    echo https://www.python.org/downloads/
    echo.
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

echo Python found:
python --version
echo.

REM Check Python version
python -c "import sys; exit(0 if sys.version_info >= (3, 11) else 1)" 2>nul
if %errorLevel% neq 0 (
    echo ERROR: Python 3.11 or higher is required
    echo.
    echo Current version:
    python --version
    echo.
    echo Please upgrade Python from:
    echo https://www.python.org/downloads/
    pause
    exit /b 1
)

echo Starting installer...
echo.
python install.py

if %errorLevel% equ 0 (
    echo.
    echo ========================================
    echo Installation Complete!
    echo ========================================
    echo.
    echo To install as a Windows Service:
    echo   1. Open Command Prompt as Administrator
    echo   2. Run: install_service_windows.bat
    echo.
    echo To start manually:
    echo   python service\dns_tunnel_service.py
    echo.
) else (
    echo.
    echo Installation failed. Check the error messages above.
    echo.
)

pause
