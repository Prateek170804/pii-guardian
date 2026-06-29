# Deploying the PII Guardian Streamlit app (self-hosted)

The app processes files **wherever it runs**, so self-host it to keep sensitive data
and the generated keys inside your control. It never connects to Snowflake or any
external service.

## 1. One-time setup
```bash
cd pii-guardian
python -m venv .venv && .venv\Scripts\activate      # Windows (use source .venv/bin/activate on macOS/Linux)
pip install -r requirements.txt
```

## 2a. Local (single user)
```bash
python -m streamlit run streamlit_app.py
```
Then open http://localhost:8501  (or double-click `start_streamlit.bat`).
Uses `.streamlit/config.toml` — bound to `127.0.0.1`, so only this machine can reach it.

## 2b. Internal server / VM (team access)
Two changes from the local setup, **both required**:

1. **Turn on the password** so it isn't open on your network. Either:
   - set an env var: `set PII_GUARDIAN_PASSWORD=your-strong-secret` (Windows) /
     `export PII_GUARDIAN_PASSWORD=...` (macOS/Linux), **or**
   - copy `.streamlit/secrets.toml.example` → `.streamlit/secrets.toml` and set `password`.
2. **Bind to the network**: in `.streamlit/config.toml` set `address = "0.0.0.0"`.

```bash
python -m streamlit run streamlit_app.py
```
Colleagues reach it at `http://<server-ip>:8501`.

### Harden it
- **Firewall**: allow port 8501 only from your internal subnet/VPN.
- **HTTPS**: put it behind a reverse proxy (nginx/Caddy/IIS) terminating TLS, e.g.
  proxy `https://pii.internal` → `http://127.0.0.1:8501`. Don't expose plain HTTP off-box.
- **Keep it running**: run inside `tmux`/`screen` (Linux) or as a Windows service
  (e.g. NSSM wrapping `python -m streamlit run streamlit_app.py`) so it survives logout.
- **secrets.toml** holds the gate password — do not commit it to version control.

## 3. Notes
- `streamlit` as a bare command may not be on PATH; use `python -m streamlit run ...`.
- Supported file types: `.csv`, `.xlsx`. Others are rejected with a clear message.
- The Flask UI (`ui.py`) and CLI (`protect.py`) remain available and use the same core.
- Do **not** deploy to Streamlit Community Cloud with real PII — that uploads files to a
  public third-party service. Use self-hosting (this guide) or Streamlit-in-Snowflake.
