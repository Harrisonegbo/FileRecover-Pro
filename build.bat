@echo off
REM ============================================================
REM  Retrievo – Build standalone Windows executable
REM  Run this on a Windows machine with Python 3.10+ installed
REM ============================================================
setlocal
cd /d "%~dp0"

echo.
echo  [Retrievo] Building Windows executable...
echo.

if not exist "venv\" (
    echo Creating virtual environment...
    python -m venv venv
)

call venv\Scripts\activate.bat

echo Installing dependencies...
pip install -q --upgrade pip
pip install -q -r requirements.txt
pip install -q pyinstaller

echo.
echo Running PyInstaller (this may take a few minutes)...
pyinstaller --noconfirm retrievo.spec

if errorlevel 1 (
    echo.
    echo BUILD FAILED
    pause
    exit /b 1
)

echo.
echo ============================================================
echo  Build complete!
echo  Executable: dist\Retrievo\Retrievo.exe
echo  Portable folder: dist\Retrievo\
echo ============================================================
echo.
echo You can zip the dist\Retrievo folder and distribute it.
echo Users can run Retrievo.exe without installing Python.
echo.
pause
