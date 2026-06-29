@echo off
REM Launch the PII Guardian cell-encryption web UI.
REM Double-click this file, then open http://127.0.0.1:5000 in your browser.
cd /d "%~dp0"
echo Starting PII Guardian UI...
echo Open http://127.0.0.1:5000  (close this window to stop the server)
python ui.py
echo.
echo Server stopped.
pause
