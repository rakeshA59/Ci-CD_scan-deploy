@echo off
REM Usage:  run.bat <path-to-python-repo> [extra args, e.g. --continue-on-fail]
REM Example: run.bat sample_apps\customer_api --continue-on-fail
if "%~1"=="" (
  echo Usage: run.bat ^<repo-path^> [--continue-on-fail] [--skip tests,container] [--no-llm]
  exit /b 2
)
if not exist .venv\Scripts\python.exe (
  echo Creating virtualenv .venv ...
  python -m venv .venv || exit /b 1
  .venv\Scripts\python.exe -m pip install --upgrade pip
  .venv\Scripts\python.exe -m pip install -r requirements.txt
)
set PYTHONIOENCODING=utf-8
.venv\Scripts\python.exe -m cip.cli run %*
