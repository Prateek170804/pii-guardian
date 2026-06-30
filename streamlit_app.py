#!/usr/bin/env python3
"""streamlit_app.py — Streamlit UI for cell-level encryption / decryption.

Reuses pii_guardian.cellcrypto (the same detection + crypto core as protect.py and
ui.py), so classification, categories, regulations and guards are identical.

Run locally:   streamlit run streamlit_app.py

IMPORTANT — data sovereignty: files are processed wherever this app runs. Run it on
your own machine or an internal host so sensitive data and the generated keys stay in
your control. Hosting on a public service (e.g. Streamlit Community Cloud) uploads the
files you are trying to protect to that third party — not recommended for real PII.
"""
import datetime as dt
import html
import json
import os
import tempfile

import streamlit as st
from cryptography.fernet import Fernet, InvalidToken

from pii_guardian.cellcrypto import (
    MARKER, make_classifier, build_plan, encrypt_file, decrypt_file,
)

APP_DIR = os.path.dirname(os.path.abspath(__file__))

st.set_page_config(page_title="PII Guardian -- Cell Encryption", layout="wide")


@st.cache_resource
def get_classifier():
    return make_classifier(os.path.join(APP_DIR, "config"))


def workdir() -> str:
    if "work" not in st.session_state:
        st.session_state.work = tempfile.mkdtemp(prefix="pii_st_")
    return st.session_state.work


def _conf_bar(v: float) -> str:
    """Render confidence as a colored progress bar: green high, amber medium, red low."""
    color = "#21c45d" if v >= 0.80 else "#f59e0b" if v >= 0.50 else "#ef4444"
    pct = max(0, min(100, int(round(v * 100))))
    return (
        "<div style='display:flex;align-items:center;gap:8px;'>"
        "<div style='flex:1;min-width:90px;background:#2b2f3a;border-radius:6px;height:14px;overflow:hidden;'>"
        f"<div style='width:{pct}%;background:{color};height:100%;border-radius:6px;'></div></div>"
        f"<span style='min-width:34px;text-align:right;'>{v:.2f}</span></div>"
    )


CLF = get_classifier()

st.title("PII Guardian -- Cell Encryption")
st.caption("Reuses the project's PII detection (cde_dictionary + value detectors). "
           "Connection-free: files are processed where this app runs.")
st.warning("Run this locally or on an internal host. Uploading sensitive files to a "
           "public deployment defeats the purpose — keep data and keys in your control.")

tab_enc, tab_dec = st.tabs(["Encrypt", "Decrypt"])

# ---------------------------------------------------------------------------
# ENCRYPT
# ---------------------------------------------------------------------------
with tab_enc:
    up = st.file_uploader("Upload a CSV or XLSX file", type=["csv", "xlsx"], key="enc_up")

    if up is not None:
        fid = (up.name, up.size)
        if st.session_state.get("fid") != fid:
            d = workdir()
            src = os.path.join(d, up.name)
            with open(src, "wb") as f:
                f.write(up.getbuffer())
            try:
                st.session_state.plan = build_plan(src, CLF)
            except Exception as ex:
                st.error(f"Could not read file: {ex}")
                st.stop()
            st.session_state.fid = fid
            st.session_state.src = src
            st.session_state.base = up.name
            st.session_state.pop("result", None)

        plan = st.session_state.plan
        multi = len({p["scope"] for p in plan}) > 1
        flagged = sum(1 for p in plan if p["plan"] != "skip")
        rec = sum(1 for p in plan if p["recommend"])

        st.markdown(f"**{up.name}** · {len(plan)} columns · "
                    f":green[{flagged} flagged] · {rec} recommended (pre-checked)")
        noisy = [p for p in plan if p["plan"] != "skip" and not p["name_strength"]
                 and p["value_detector"] in ("phone", "zip")]
        if noisy:
            st.info(f"{len(noisy)} column(s) matched only a loose numeric pattern "
                    "(phone/ZIP-like digits) -- verify before including.")

        show_all = st.checkbox("show all columns (incl. not-flagged)", value=False)
        rows = [p for p in plan if show_all or p["plan"] != "skip"]

        if not rows:
            st.success("No sensitive columns detected.")
        else:
            def _row_label(p):
                return f"{p['scope']} · {p['name']}" if multi else p["name"]

            # Color-coded table rendered as HTML: st.data_editor draws on a canvas
            # whose ProgressColumn has no per-value color option, so the bars are
            # built here instead. Selection lives in the multiselect below.
            head = ["column"] + (["sheet"] if multi else []) + [
                "category", "sensitivity", "regulations", "confidence", "decision", "evidence"]
            thead = "".join(f"<th>{h}</th>" for h in head)
            body = []
            for p in rows:
                ev = ((f"name:{p['name_strength']}" if p["name_strength"] else "")
                      + (f" value:{p['value_detector']}({p['value_ratio']})"
                         if p["value_detector"] else "")).strip()
                text_cells = [p["name"]] + ([p["scope"]] if multi else []) + [
                    p["category"] or "—", p["sensitivity"] or "",
                    ", ".join(p["regulations"])]
                tds = "".join(f"<td>{html.escape(str(c))}</td>" for c in text_cells)
                tds += f"<td>{_conf_bar(float(p['confidence']))}</td>"
                tds += f"<td>{html.escape(p['plan'])}</td><td>{html.escape(ev)}</td>"
                body.append(f"<tr>{tds}</tr>")
            st.markdown(
                "<style>.pgtbl{width:100%;border-collapse:collapse;font-size:0.9rem;}"
                ".pgtbl th,.pgtbl td{padding:6px 10px;border-bottom:1px solid #2b2f3a;"
                "text-align:left;vertical-align:middle;}"
                ".pgtbl th{color:#9aa0aa;font-weight:600;}</style>"
                f"<table class='pgtbl'><thead><tr>{thead}</tr></thead>"
                f"<tbody>{''.join(body)}</tbody></table>",
                unsafe_allow_html=True,
            )

            label_key = {_row_label(p): (p["scope"], p["name"]) for p in rows}
            default_sel = [_row_label(p) for p in rows if p["recommend"]]
            chosen = st.multiselect(
                "Columns to encrypt (recommended are pre-selected)",
                options=list(label_key.keys()), default=default_sel,
                key=f"enc_sel::{st.session_state.base}",
            )
            sel = {label_key[c] for c in chosen}

            if st.button(f"Encrypt selected ({len(sel)})", type="primary", disabled=not sel):
                d = workdir()
                root, ext = os.path.splitext(st.session_state.base)
                out = os.path.join(d, f"{root}.protected{ext}")
                key = Fernet.generate_key()
                entries = encrypt_file(st.session_state.src, out, Fernet(key), sel, plan)
                manifest = {
                    "generated": dt.datetime.now().isoformat(timespec="seconds"),
                    "source_file": st.session_state.base,
                    "key_file": "pii.key",
                    "algorithm": "Fernet (AES-128-CBC + HMAC-SHA256)",
                    "marker": MARKER,
                    "note": "Metadata only. No raw sensitive values are stored here.",
                    "encrypted_columns": entries,
                }
                with open(out, "rb") as f:
                    protected_bytes = f.read()
                st.session_state.result = {
                    "protected": protected_bytes,
                    "protected_name": f"{root}.protected{ext}",
                    "key": key,
                    "manifest": json.dumps(manifest, indent=2),
                    "manifest_name": f"{root}.protected.manifest.json",
                    "cells": sum(e["encrypted_cells"] for e in entries),
                    "columns": len(entries),
                }

            r = st.session_state.get("result")
            if r:
                st.success(f"Encrypted **{r['cells']}** cells across **{r['columns']}** column(s).")
                c1, c2, c3 = st.columns(3)
                c1.download_button("Download Protected file", r["protected"],
                                   file_name=r["protected_name"], use_container_width=True)
                c2.download_button("Download Key (pii.key)", r["key"],
                                   file_name="pii.key", use_container_width=True)
                c3.download_button("Download Manifest", r["manifest"],
                                   file_name=r["manifest_name"], use_container_width=True)
                st.error("Keep the key file safe and separate — without it the data "
                         "cannot be decrypted; anyone with it can decrypt.")

# ---------------------------------------------------------------------------
# DECRYPT
# ---------------------------------------------------------------------------
with tab_dec:
    st.write("Upload the protected file and its matching key.")
    pf = st.file_uploader("Protected file (.csv / .xlsx)", type=["csv", "xlsx"], key="dec_file")
    kf = st.file_uploader("Key file (pii.key)", key="dec_key")

    if st.button("Decrypt", type="primary", disabled=not (pf and kf)):
        d = workdir()
        src = os.path.join(d, pf.name)
        with open(src, "wb") as f:
            f.write(pf.getbuffer())
        try:
            fernet = Fernet(kf.getvalue().strip())
        except Exception:
            st.error("Invalid key file.")
            st.stop()
        root, ext = os.path.splitext(pf.name)
        if root.endswith(".protected"):
            root = root[: -len(".protected")]
        out = os.path.join(d, f"{root}.decrypted{ext}")
        try:
            n = decrypt_file(src, out, fernet)
        except InvalidToken:
            st.error("Key does not match this file (decryption failed).")
            st.stop()
        except Exception as ex:
            st.error(f"Decryption failed: {ex}")
            st.stop()
        with open(out, "rb") as f:
            data = f.read()
        st.success(f"Decrypted **{n}** cells.")
        st.download_button("Download Decrypted file", data, file_name=f"{root}.decrypted{ext}")
        st.caption("Decrypted output is real cleartext — handle and delete it carefully.")
