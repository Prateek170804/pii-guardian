' Launches the PII Guardian watchdog with no visible window.
' Used by the "PII Guardian Streamlit" scheduled task.
CreateObject("WScript.Shell").Run "cmd /c """ & _
  Replace(WScript.ScriptFullName, "run_hidden.vbs", "run_service.bat") & """", 0, False
