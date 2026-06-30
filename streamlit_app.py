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
        "<div style='flex:1;min-width:60px;background:#2b2f3a;border-radius:6px;height:14px;overflow:hidden;'>"
        f"<div style='width:{pct}%;background:{color};height:100%;border-radius:6px;'></div></div>"
        f"<span style='min-width:34px;text-align:right;font-size:0.8rem;'>{v:.2f}</span></div>"
    )


def _cell(text) -> str:
    """Small-font table cell."""
    return f"<span style='font-size:0.8rem;'>{html.escape(str(text))}</span>"


CLF = get_classifier()

st.title("PII Guardian -- Cell Encryption")

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
            # Inline checkboxes AND a color-coded confidence bar. st.data_editor
            # draws cells on a canvas whose ProgressColumn can't be colored per
            # value, so rows are laid out manually with st.checkbox + an HTML bar.
            base = st.session_state.base
            spec = [0.7, 1.8] + ([1.2] if multi else []) + [1.3, 1.1, 1.4, 1.8, 1.0, 1.6]
            heads = ["", "column"] + (["sheet"] if multi else []) + [
                "category", "sensitivity", "regulations", "confidence", "decision", "evidence"]
            hcols = st.columns(spec)
            for hc, h in zip(hcols, heads):
                hc.markdown(
                    f"<span style='font-size:0.75rem;font-weight:700;color:#9aa0aa;'>{h}</span>"
                    if h else "", unsafe_allow_html=True)

            sel = set()
            for p in rows:
                ev = ((f"name:{p['name_strength']}" if p["name_strength"] else "")
                      + (f" value:{p['value_detector']}({p['value_ratio']})"
                         if p["value_detector"] else "")).strip()
                c = st.columns(spec)
                if c[0].checkbox("select", value=p["recommend"],
                                 key=f"enc::{base}::{p['scope']}::{p['name']}",
                                 label_visibility="collapsed"):
                    sel.add((p["scope"], p["name"]))
                i = 1
                c[i].markdown(_cell(p["name"]), unsafe_allow_html=True); i += 1
                if multi:
                    c[i].markdown(_cell(p["scope"]), unsafe_allow_html=True); i += 1
                c[i].markdown(_cell(p["category"] or "—"), unsafe_allow_html=True); i += 1
                c[i].markdown(_cell(p["sensitivity"] or ""), unsafe_allow_html=True); i += 1
                c[i].markdown(_cell(", ".join(p["regulations"])), unsafe_allow_html=True); i += 1
                c[i].markdown(_conf_bar(float(p["confidence"])), unsafe_allow_html=True); i += 1
                c[i].markdown(_cell(p["plan"]), unsafe_allow_html=True); i += 1
                c[i].markdown(_cell(ev), unsafe_allow_html=True)

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
