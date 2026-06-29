@echo off
REM Launch the PII Guardian Streamlit app.
REM Double-click this file; your browser opens at http://localhost:8501
cd /d "%~dp0"
echo Starting PII Guardian (Streamlit) ...
echo Open http://localhost:8501   (close this window to stop)
python -m streamlit run streamlit_app.py
echo.
echo App stopped.
pause
