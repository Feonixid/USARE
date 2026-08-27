@echo off
setlocal

:: Find the directory where this script is located
set "BASE_DIR=%~dp0"
set "VENV_PYTHON=%BASE_DIR%.venv\Scripts\python.exe"

:: Check if the global `usare` command is available in PATH
where usare >nul 2>nul
if %ERRORLEVEL% equ 0 (
    usare %*
) else if exist "%VENV_PYTHON%" (
    :: Fallback to local virtual environment
    "%VENV_PYTHON%" "%BASE_DIR%usare.py" %*
) else (
    :: Fallback to system python
    python "%BASE_DIR%usare.py" %*
)

endlocal
