@echo off
setlocal enabledelayedexpansion

REM ============================================================================
REM Windows Runner Script for Lab 2: AES-128 (CTR Mode)
REM ============================================================================

where python >nul 2>nul
if %ERRORLEVEL% equ 0 (
    python "%~dp0run.py" %*
    exit /b %ERRORLEVEL%
)

where py >nul 2>nul
if %ERRORLEVEL% equ 0 (
    py -3 "%~dp0run.py" %*
    exit /b %ERRORLEVEL%
)

echo [INFO] Python not found in PATH. Using native Windows CMake fallback...

if "%1"=="" goto help
if "%1"=="build" goto build
if "%1"=="test" goto test
if "%1"=="kat" goto kat
if "%1"=="demo" goto demo
goto help

:build
if not exist "%~dp0build" mkdir "%~dp0build"
cd /d "%~dp0build"
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
cd /d "%~dp0"
echo [SUCCESS] Build finished.
exit /b 0

:test
cd /d "%~dp0build"
ctest -C Release --output-on-failure
cd /d "%~dp0"
exit /b %ERRORLEVEL%

:kat
if exist "%~dp0build\bin\Release\aestool.exe" (
    "%~dp0build\bin\Release\aestool.exe" --kat "%~dp0vectors\vectors.json"
) else if exist "%~dp0build\bin\aestool.exe" (
    "%~dp0build\bin\aestool.exe" --kat "%~dp0vectors\vectors.json"
) else (
    echo [ERROR] aestool.exe not found. Please run 'run.bat build' first.
    exit /b 1
)
exit /b %ERRORLEVEL%

:demo
echo Running demo...
if not exist "%~dp0build\bin\Release\aestool.exe" (
    if not exist "%~dp0build\bin\aestool.exe" (
        echo [ERROR] aestool.exe not found. Run 'run.bat build' first.
        exit /b 1
    )
)
REM Set tool path
if exist "%~dp0build\bin\Release\aestool.exe" (
    set "TOOL=%~dp0build\bin\Release\aestool.exe"
) else (
    set "TOOL=%~dp0build\bin\aestool.exe"
)
if not exist "%~dp0demo_workspace" mkdir "%~dp0demo_workspace"
"%TOOL%" keygen --out "%~dp0demo_workspace\key.bin"
"%TOOL%" ivgen --out "%~dp0demo_workspace\iv.bin"
echo Plaintext test message for Windows > "%~dp0demo_workspace\msg.txt"
"%TOOL%" encrypt --mode ctr --key "%~dp0demo_workspace\key.bin" --iv "%~dp0demo_workspace\iv.bin" --in "%~dp0demo_workspace\msg.txt" --out "%~dp0demo_workspace\ct.bin"
"%TOOL%" decrypt --mode ctr --key "%~dp0demo_workspace\key.bin" --iv "%~dp0demo_workspace\iv.bin" --in "%~dp0demo_workspace\ct.bin" --out "%~dp0demo_workspace\dec.txt"
fc "%~dp0demo_workspace\msg.txt" "%~dp0demo_workspace\dec.txt"
exit /b %ERRORLEVEL%

:help
echo Usage: run.bat [build ^| test ^| kat ^| demo]
echo Or install Python to access the full interactive suite and benchmarks.
exit /b 0
