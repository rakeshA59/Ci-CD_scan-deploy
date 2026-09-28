@echo off
REM Starts the CIP web UI at http://127.0.0.1:8765 and opens your browser.
if not exist .venv\Scripts\python.exe (
  echo Creating virtualenv .venv ...
  python -m venv .venv || exit /b 1
  .venv\Scripts\python.exe -m pip install -r requirements.txt
)
set PYTHONIOENCODING=utf-8
.venv\Scripts\python.exe -m cip.server %*
