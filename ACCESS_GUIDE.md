# PII Guardian — Access Guide

A connection-free tool that finds sensitive columns in a CSV/XLSX and **encrypts
just those cells** (reversibly), so you can share or store the file with PII protected.
This page explains **how to use it**, **how it's set up**, and **the security trade-offs**.

---

## 1. How to access

| | |
|---|---|
| **URL** | _ask the app owner (internal address, changes per VPN session)_ |
| **Password** | _set locally in `.streamlit/secrets.toml` or the `PII_GUARDIAN_PASSWORD` env var — not stored in this repo_ |
| **Network** | EXL corporate network / VPN (the URL is an internal address) |

1. Make sure you're on the EXL network (office LAN or VPN).
2. Open the URL in a browser.
3. Enter the password.

> If the page doesn't load, the host firewall may not be open yet — see section 5.

---

## 2. How to use it

### Encrypt
1. **Encrypt** tab → upload a `.csv` or `.xlsx` file.
2. Review the detected columns. Sensitive ones are flagged with a category
   (e.g. `DIRECT_IDENTIFIER`, `GOV_ID`, `CONTACT`), a sensitivity tier, the
   regulations they fall under (GLBA / HIPAA / PCI / CCPA), and a confidence score.
   - **High-confidence columns are pre-checked.** Borderline ones are shown but
     left unchecked — tick the ones you want.
   - Tick **"show all columns"** to add a column the detector didn't flag.
3. Click **Encrypt selected**.
4. Download **three files**:
   - `*.protected.csv/xlsx` — your file with the chosen cells encrypted.
   - `pii.key` — **the key. Without it the data cannot be decrypted. Keep it safe.**
   - `*.manifest.json` — an audit record (metadata only, no raw values).

### Decrypt
1. **Decrypt** tab → upload the protected file **and its matching `pii.key`**.
2. Download the decrypted file.

> Each encryption generates a **fresh key**. A protected file can only be decrypted
> with the key produced in that same run. Keep file + key paired.

---

## 3. What it detects (and why categories matter)

Detection combines **column-name patterns** + **value patterns** (SSN, email,
card-with-Luhn, etc.) into a confidence score. Each flagged column is tagged on three
axes so the result is audit evidence, not just a flag:

- **Category** — what it is: `GOV_ID`, `FINANCIAL`, `HEALTH` (PHI), `DIRECT_IDENTIFIER`
  (a person's name), `CONTACT` (email/phone/address), `QUASI_IDENTIFIER` (DOB, gender,
  city, VIN — re-identification risk).
- **Sensitivity** — RESTRICTED / CONFIDENTIAL / INTERNAL.
- **Regulations** — GLBA, HIPAA, PCI (payment cards), CCPA.

Low-confidence columns are **never auto-selected** — they go to you for review.
Supported file types: **`.csv` and `.xlsx`** only (others are rejected with a message).

---

## 4. Why it's set up this way (design decisions)

| Decision | Why |
|---|---|
| **Connection-free** — only reads/writes files, never connects to Snowflake or any system | Keeps credentials out of the tool and gives a clean audit story. A human applies any downstream change. |
| **Self-hosted** on an internal machine (not Streamlit Cloud) | A public cloud would mean uploading the very PII we're protecting to a third party. Self-hosting keeps data on EXL infrastructure. |
| **Same engine across CLI / Flask / Streamlit** | One tested detection+crypto core (`pii_guardian/cellcrypto.py`); every front-end behaves identically. |
| **Reversible AES (Fernet) per-file key** | You can decrypt when authorized; the key is the single control point. |
| **High-confidence auto-select, low-confidence to review** | Avoids over-encrypting business keys (policy numbers, counts) while not silently missing real PII. |
| **Auto-start via the Windows Startup folder + watchdog** | Survives reboots/logoff and self-heals if it crashes — without needing admin or a Windows service. |

---

## 5. Security posture — read this

This deployment is **internal team access over plain HTTP**. Be aware:

- **Who can reach it:** anyone on the EXL network who can route to `10.16.29.77`
  **and** has the password. The URL alone is not enough — the password is the gate.
- **Not on the public internet:** `10.16.29.77` is a private address. Do **not**
  port-forward it or use the machine's public IP.
- **⚠️ Plain HTTP (no TLS):** the password and uploaded file data travel
  **unencrypted** on the network and could be captured by someone sniffing traffic.
- **⚠️ Single shared password:** there is **no per-user login and no audit** of who
  accessed what.

**Required one-time step for team access** — the host firewall must allow port 8501.
On the host, in an **Administrator** terminal:
```
netsh advfirewall firewall add rule name="PII Guardian Streamlit 8501" dir=in action=allow protocol=TCP localport=8501 profile=domain,private
```
Until this is run, only the host machine can open the URL.

**Recommended hardening for production PII use (needs IT/admin):**
1. **HTTPS** — put it behind a reverse proxy (nginx / Caddy / IIS) terminating TLS,
   so traffic is encrypted. `run_service.bat` is ready to sit behind a proxy on
   `127.0.0.1:8501`.
2. **Restrict access** — limit the firewall rule to specific teammate IPs
   (`remoteip=...`) instead of the whole network, and/or add per-user SSO.
3. Share the URL + password only with people who need it, over a secure channel.

---

## 6. Operating / managing it (on the host)

- **Logs:** `C:\dev\pii-guardian\service.log`
- **Change the password:** edit `.streamlit\secrets.toml`, then end `python.exe` in
  Task Manager — the watchdog relaunches it within ~5s with the new password.
- **Restart the app:** end `python.exe` (streamlit); the watchdog restarts it.
- **Stop completely / disable auto-start:** delete
  `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\PIIGuardian.vbs`,
  then end the `python.exe` and `cmd.exe` (watchdog) processes.
- **Make it localhost-only again:** set `address = "127.0.0.1"` in
  `.streamlit\config.toml`, then restart.

---

*This is operational guidance, not legal advice. Regulation mappings are indicative;
confirm obligations and the network/security posture with your compliance and IT teams.*
