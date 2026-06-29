@echo off
REM Watchdog launcher for PII Guardian (Streamlit) — keeps it running and restarts
REM it if it ever exits. Started automatically by the "PII Guardian Streamlit"
REM scheduled task at logon. Logs to service.log in this folder.
cd /d "%~dp0"
set PY="C:\Users\ex_prateeka\AppData\Local\Python\pythoncore-3.14-64\python.exe"
:loop
echo [%date% %time%] starting streamlit >> service.log
%PY% -m streamlit run streamlit_app.py >> service.log 2>&1
echo [%date% %time%] streamlit exited (code %errorlevel%), restarting in 5s >> service.log
timeout /t 5 /nobreak >nul
goto loop
