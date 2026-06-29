#!/usr/bin/env python3
"""ui.py — local web UI for cell-level encryption / decryption.

Connection-free: binds to 127.0.0.1 only; uploaded files are processed on this
machine and never sent anywhere. Reuses pii_guardian.cellcrypto (the same detection
+ crypto core as protect.py), so behavior matches the CLI exactly.

Run:
    python ui.py
then open http://127.0.0.1:5000 (opens automatically).

Flow:
    Encrypt: upload CSV/XLSX -> review detection plan (recommended columns pre-checked,
             loose numeric matches flagged but unchecked) -> encrypt selected ->
             download protected file + key + manifest.
    Decrypt: upload protected file + key -> download decrypted file.
"""
import datetime as dt
import json
import os
import secrets
import tempfile
import threading
import webbrowser

from flask import Flask, request, jsonify, send_file, abort
from cryptography.fernet import Fernet, InvalidToken

from pii_guardian.cellcrypto import (
    MARKER, make_classifier, build_plan, file_kind,
    encrypt_file, decrypt_file,
)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(APP_DIR, "config")
WORK = tempfile.mkdtemp(prefix="pii_ui_")        # transient working dir (this machine only)
SESSIONS: dict[str, dict] = {}                    # token -> file paths / plan

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # 200 MB
_CLF = make_classifier(CONFIG_DIR)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _safe_ext(filename: str) -> str:
    ext = os.path.splitext(filename or "")[1].lower()
    if ext not in (".csv", ".xlsx"):
        abort(400, "Only .csv and .xlsx files are supported.")
    return ext


def _new_token() -> str:
    return secrets.token_hex(8)


def _session_dir(token: str) -> str:
    d = os.path.join(WORK, token)
    os.makedirs(d, exist_ok=True)
    return d


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------
@app.get("/")
def index():
    return PAGE


@app.post("/plan")
def plan():
    f = request.files.get("file")
    if not f or not f.filename:
        abort(400, "No file uploaded.")
    ext = _safe_ext(f.filename)
    token = _new_token()
    d = _session_dir(token)
    base = os.path.basename(f.filename)
    src = os.path.join(d, base)
    f.save(src)
    try:
        plan = build_plan(src, _CLF)
    except Exception as ex:                      # malformed file, etc.
        abort(400, f"Could not read file: {ex}")
    SESSIONS[token] = {"src": src, "base": base, "ext": ext, "plan": plan}
    multi = len({p["scope"] for p in plan}) > 1
    return jsonify({
        "token": token, "filename": base, "ext": ext, "multi_sheet": multi,
        "total_columns": len(plan),
        "recommended": sum(1 for p in plan if p["recommend"]),
        "flagged": sum(1 for p in plan if p["plan"] != "skip"),
        "plan": plan,
    })


@app.post("/encrypt")
def encrypt():
    data = request.get_json(force=True)
    token = data.get("token")
    sess = SESSIONS.get(token)
    if not sess:
        abort(400, "Session expired — please re-analyze the file.")
    selected = {(c["scope"], c["name"]) for c in data.get("selected", [])}
    if not selected:
        abort(400, "No columns selected.")
    d = _session_dir(token)
    root, ext = os.path.splitext(sess["base"])
    out_path = os.path.join(d, f"{root}.protected{ext}")
    key_path = os.path.join(d, "pii.key")
    manifest_path = os.path.join(d, f"{root}.protected.manifest.json")

    key = Fernet.generate_key()
    with open(key_path, "wb") as kf:
        kf.write(key)
    fernet = Fernet(key)
    entries = encrypt_file(sess["src"], out_path, fernet, selected, sess["plan"])

    with open(manifest_path, "w", encoding="utf-8") as mf:
        json.dump({
            "generated": dt.datetime.now().isoformat(timespec="seconds"),
            "source_file": sess["base"],
            "key_file": "pii.key",
            "algorithm": "Fernet (AES-128-CBC + HMAC-SHA256)",
            "marker": MARKER,
            "note": "Metadata only. No raw sensitive values are stored here.",
            "encrypted_columns": entries,
        }, mf, indent=2)

    sess.update({"protected": out_path, "key": key_path, "manifest": manifest_path,
                 "out_root": root, "out_ext": ext})
    total = sum(e["encrypted_cells"] for e in entries)
    return jsonify({
        "token": token,
        "columns": len(entries),
        "cells": total,
        "entries": entries,
        "downloads": {
            "protected": f"/download/{token}/protected",
            "key": f"/download/{token}/key",
            "manifest": f"/download/{token}/manifest",
        },
    })


@app.post("/decrypt")
def decrypt():
    f = request.files.get("file")
    kf = request.files.get("key")
    if not f or not f.filename:
        abort(400, "No protected file uploaded.")
    if not kf or not kf.filename:
        abort(400, "No key file uploaded.")
    ext = _safe_ext(f.filename)
    token = _new_token()
    d = _session_dir(token)
    base = os.path.basename(f.filename)
    src = os.path.join(d, base)
    key_path = os.path.join(d, "pii.key")
    f.save(src)
    kf.save(key_path)
    try:
        fernet = Fernet(open(key_path, "rb").read().strip())
    except Exception:
        abort(400, "Invalid key file.")
    root, e = os.path.splitext(base)
    if root.endswith(".protected"):
        root = root[: -len(".protected")]
    out_path = os.path.join(d, f"{root}.decrypted{e}")
    try:
        n = decrypt_file(src, out_path, fernet)
    except InvalidToken:
        abort(400, "Key does not match this file (decryption failed).")
    except Exception as ex:
        abort(400, f"Decryption failed: {ex}")
    SESSIONS[token] = {"decrypted": out_path}
    return jsonify({"token": token, "cells": n,
                    "download": f"/download/{token}/decrypted"})


_DOWNLOAD_NAMES = {
    "protected": lambda s: f"{s['out_root']}.protected{s['out_ext']}",
    "key": lambda s: "pii.key",
    "manifest": lambda s: f"{s['out_root']}.protected.manifest.json",
    "decrypted": lambda s: os.path.basename(s["decrypted"]),
}


@app.get("/download/<token>/<which>")
def download(token, which):
    sess = SESSIONS.get(token)
    if not sess or which not in sess or which not in _DOWNLOAD_NAMES:
        abort(404)
    return send_file(sess[which], as_attachment=True,
                     download_name=_DOWNLOAD_NAMES[which](sess))


# ---------------------------------------------------------------------------
# page (single-file vanilla JS)
# ---------------------------------------------------------------------------
PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PII Guardian — Cell Encryption</title>
<style>
:root{--bg:#0f1221;--card:#191d33;--line:#2b3052;--ink:#e7e9f3;--mut:#9aa0c0;
--accent:#6c7bff;--accent2:#4cd1a0;--warn:#ffb454;--danger:#ff6b81;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 system-ui,Segoe UI,Roboto,Arial,sans-serif}
.wrap{max-width:1040px;margin:0 auto;padding:28px 20px 80px}
h1{font-size:22px;margin:0 0 2px}.sub{color:var(--mut);font-size:13px;margin-bottom:22px}
.tabs{display:flex;gap:8px;margin-bottom:18px}
.tab{padding:9px 16px;border-radius:10px;background:var(--card);border:1px solid var(--line);
cursor:pointer;color:var(--mut);font-weight:600}
.tab.on{color:#fff;border-color:var(--accent);background:linear-gradient(180deg,#262c4d,#191d33)}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px;margin-bottom:16px}
.card h2{font-size:15px;margin:0 0 12px}
.drop{border:1.5px dashed var(--line);border-radius:12px;padding:26px;text-align:center;color:var(--mut);
cursor:pointer;transition:.15s}.drop:hover{border-color:var(--accent);color:var(--ink)}
.drop.has{border-style:solid;border-color:var(--accent2);color:var(--ink)}
button{font:inherit;font-weight:600;border:0;border-radius:10px;padding:10px 16px;cursor:pointer}
.btn{background:var(--accent);color:#fff}.btn:disabled{opacity:.45;cursor:not-allowed}
.btn2{background:#262c4d;color:var(--ink);border:1px solid var(--line)}
.btn-g{background:var(--accent2);color:#06281d}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.spacer{flex:1}.mut{color:var(--mut)}.small{font-size:12.5px}
input[type=search]{background:#10132a;border:1px solid var(--line);color:var(--ink);
border-radius:9px;padding:8px 11px;min-width:220px}
table{width:100%;border-collapse:collapse;margin-top:10px;font-size:13.5px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:middle}
th{color:var(--mut);font-weight:600;position:sticky;top:0;background:var(--card)}
.tbl-wrap{max-height:430px;overflow:auto;border:1px solid var(--line);border-radius:10px}
tr.skip{opacity:.55}td.col{font-family:ui-monospace,Consolas,monospace}
.badge{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11.5px;font-weight:700}
.b-auto{background:#1d3b30;color:var(--accent2)}.b-rev{background:#3a3320;color:var(--warn)}
.b-skip{background:#2b3052;color:var(--mut)}
.rbadge{display:inline-block;background:#23284a;color:#aeb6e6;border:1px solid var(--line);border-radius:5px;padding:1px 6px;font-size:10.5px;margin:1px;white-space:nowrap}
.warn{color:var(--warn);font-size:12px}.ok{color:var(--accent2)}
.bar{height:6px;border-radius:6px;background:#2b3052;overflow:hidden;width:64px;display:inline-block;vertical-align:middle}
.bar>i{display:block;height:100%;background:var(--accent)}
.note{background:#101633;border:1px solid var(--line);border-left:3px solid var(--accent);
border-radius:8px;padding:10px 12px;color:var(--mut);font-size:13px;margin-top:10px}
.note.warn{border-left-color:var(--warn)}
.dl{display:flex;gap:10px;flex-wrap:wrap;margin-top:8px}
.dl a{text-decoration:none}
.kbd{font-family:ui-monospace,Consolas,monospace;background:#10132a;padding:1px 6px;border-radius:5px;border:1px solid var(--line)}
.hide{display:none}.err{color:var(--danger);font-size:13px;margin-top:8px}
input[type=checkbox]{width:16px;height:16px;accent-color:var(--accent)}
</style></head><body><div class="wrap">
<h1>🔐 PII Guardian — Cell Encryption</h1>
<div class="sub">Connection-free. Files are processed on this machine and never uploaded anywhere. Reuses the project's PII detection (<span class="kbd">cde_dictionary.yaml</span> + value detectors).</div>

<div class="tabs">
  <div class="tab on" data-t="enc">Encrypt</div>
  <div class="tab" data-t="dec">Decrypt</div>
</div>

<!-- ENCRYPT -->
<div id="enc">
  <div class="card">
    <h2>1 · Choose a file</h2>
    <div class="drop" id="encDrop">Drop a <b>.csv</b> or <b>.xlsx</b> here, or click to browse</div>
    <input id="encFile" type="file" accept=".csv,.xlsx" class="hide">
    <div class="row" style="margin-top:12px">
      <button class="btn" id="analyzeBtn" disabled>Analyze for sensitive data</button>
      <span id="encName" class="mut small"></span>
    </div>
    <div id="encErr" class="err"></div>
  </div>

  <div class="card hide" id="planCard">
    <h2>2 · Review &amp; choose columns to encrypt</h2>
    <div id="planSummary" class="small mut"></div>
    <div class="note warn" id="warnNote" style="display:none"></div>
    <div class="row" style="margin:12px 0">
      <input type="search" id="filter" placeholder="filter columns…">
      <button class="btn2 small" id="selRec">Select recommended</button>
      <button class="btn2 small" id="selFlag">Select all flagged</button>
      <button class="btn2 small" id="selNone">Clear</button>
      <label class="row small mut" style="gap:6px"><input type="checkbox" id="showAll">show all columns</label>
      <span class="spacer"></span>
    </div>
    <div class="tbl-wrap"><table id="planTbl">
      <thead><tr><th style="width:34px"></th><th>column</th><th class="sheetcol">sheet</th>
      <th>category</th><th>regulations</th><th>confidence</th><th>evidence</th><th>note</th></tr></thead>
      <tbody></tbody></table></div>
    <div class="row" style="margin-top:14px">
      <button class="btn" id="encryptBtn">Encrypt selected (<span id="selCount">0</span>)</button>
      <span class="mut small">A fresh key is generated for this file. You'll download it next — keep it safe.</span>
    </div>
  </div>

  <div class="card hide" id="resultCard">
    <h2>3 · Done</h2>
    <div id="resultText" class="ok"></div>
    <div class="dl" id="dlLinks"></div>
    <div class="note warn">⚠ The <b>key file</b> is the only way to decrypt this data. Store it somewhere safe and separate from the protected file — if it's lost, the data is unrecoverable. Anyone with the key can decrypt.</div>
  </div>
</div>

<!-- DECRYPT -->
<div id="dec" class="hide">
  <div class="card">
    <h2>Decrypt a protected file</h2>
    <div class="row" style="gap:18px;flex-wrap:wrap">
      <div style="flex:1;min-width:240px">
        <div class="small mut" style="margin-bottom:6px">Protected file (.csv / .xlsx)</div>
        <div class="drop" id="decDrop">Drop or click to browse</div>
        <input id="decFile" type="file" accept=".csv,.xlsx" class="hide">
      </div>
      <div style="flex:1;min-width:240px">
        <div class="small mut" style="margin-bottom:6px">Key file (pii.key)</div>
        <div class="drop" id="keyDrop">Drop or click to browse</div>
        <input id="keyFile" type="file" class="hide">
      </div>
    </div>
    <div class="row" style="margin-top:14px">
      <button class="btn" id="decryptBtn" disabled>Decrypt</button>
      <span id="decName" class="mut small"></span>
    </div>
    <div id="decErr" class="err"></div>
    <div class="note">Decryption restores real cleartext to the output file. Handle and delete it carefully after use.</div>
  </div>
  <div class="card hide" id="decResult">
    <div id="decResultText" class="ok"></div>
    <div class="dl" id="decDl"></div>
  </div>
</div>

<script>
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
let STATE={plan:[],token:null,multi:false,selected:new Set()};
const keyOf=p=>p.scope+"||"+p.name;

// tabs
$$(".tab").forEach(t=>t.onclick=()=>{$$(".tab").forEach(x=>x.classList.remove("on"));
 t.classList.add("on");const v=t.dataset.t;$("#enc").classList.toggle("hide",v!=="enc");
 $("#dec").classList.toggle("hide",v!=="dec");});

// generic drop+pick wiring
function wireDrop(drop,input,onset){
 drop.onclick=()=>input.click();
 input.onchange=()=>{if(input.files[0]){drop.classList.add("has");drop.textContent="📄 "+input.files[0].name;onset&&onset();}};
 ["dragover","dragenter"].forEach(e=>drop.addEventListener(e,ev=>{ev.preventDefault();drop.style.borderColor="var(--accent)";}));
 ["dragleave","drop"].forEach(e=>drop.addEventListener(e,ev=>{ev.preventDefault();drop.style.borderColor="";}));
 drop.addEventListener("drop",ev=>{ev.preventDefault();input.files=ev.dataTransfer.files;input.onchange();});
}
wireDrop($("#encDrop"),$("#encFile"),()=>{$("#analyzeBtn").disabled=false;
 $("#encName").textContent="";$("#planCard").classList.add("hide");$("#resultCard").classList.add("hide");});
wireDrop($("#decDrop"),$("#decFile"),checkDec);
wireDrop($("#keyDrop"),$("#keyFile"),checkDec);

// ---- analyze ----
$("#analyzeBtn").onclick=async()=>{
 const f=$("#encFile").files[0]; if(!f)return;
 $("#encErr").textContent="";$("#analyzeBtn").disabled=true;$("#analyzeBtn").textContent="Analyzing…";
 const fd=new FormData();fd.append("file",f);
 try{
  const r=await fetch("/plan",{method:"POST",body:fd});
  if(!r.ok)throw new Error(await r.text());
  const j=await r.json();
  STATE.plan=j.plan;STATE.token=j.token;STATE.multi=j.multi_sheet;
  STATE.selected=new Set(j.plan.filter(p=>p.recommend).map(keyOf));
  $("#planSummary").innerHTML=`<b>${j.filename}</b> · ${j.total_columns} columns · `+
   `<span class="ok">${j.flagged} flagged</span> · ${j.recommended} recommended (pre-checked)`;
  $$(".sheetcol").forEach(e=>e.style.display=j.multi_sheet?"":"none");
  const noisy=j.plan.filter(p=>p.plan!=="skip"&&!p.name_strength&&["phone","zip"].includes(p.value_detector));
  const wn=$("#warnNote");
  if(noisy.length){wn.style.display="";wn.innerHTML=`⚠ ${noisy.length} column(s) matched only a loose numeric pattern `+
   `(any 10 digits "looks like" a phone; any 5 digits "looks like" a ZIP). These are often just IDs/counts — `+
   `they're <b>left unchecked</b>. Verify before including.`;}
  else wn.style.display="none";
  renderPlan();
  $("#planCard").classList.remove("hide");
 }catch(e){$("#encErr").textContent=e.message;}
 $("#analyzeBtn").disabled=false;$("#analyzeBtn").textContent="Analyze for sensitive data";
};

function renderPlan(){
 const showAll=$("#showAll").checked, q=$("#filter").value.toLowerCase();
 const tb=$("#planTbl tbody");tb.innerHTML="";
 const rows=STATE.plan
   .filter(p=>showAll||p.plan!=="skip")
   .filter(p=>!q||p.name.toLowerCase().includes(q))
   .sort((a,b)=>(b.recommend-a.recommend)||(b.confidence-a.confidence)||a.name.localeCompare(b.name));
 for(const p of rows){
  const tr=document.createElement("tr");if(p.plan==="skip")tr.className="skip";
  const noisy=p.plan!=="skip"&&!p.name_strength&&["phone","zip"].includes(p.value_detector);
  const ev=[];if(p.name_strength)ev.push(`name:<b>${p.name_strength}</b>`);
  if(p.value_detector)ev.push(`value:${p.value_detector} (${p.value_ratio})`);
  const badge=p.plan==="auto"?'<span class="badge b-auto">auto</span>':
   p.plan==="review"?'<span class="badge b-rev">review</span>':'<span class="badge b-skip">—</span>';
  const note=noisy?'<span class="warn">loose numeric match — verify</span>':
   (p.name_strength==="strong"?'<span class="ok">strong name</span>':'');
  const regs=(p.regulations||[]).map(r=>`<span class="rbadge">${r}</span>`).join(" ")||'<span class="mut">—</span>';
  const sens=p.sensitivity?` <span class="small mut">${p.sensitivity}</span>`:'';
  tr.innerHTML=`<td><input type="checkbox" data-k="${p.scope}||${p.name}" ${STATE.selected.has(keyOf(p))?"checked":""}></td>
   <td class="col">${p.name||'<span class="mut">(blank)</span>'}</td>
   <td class="sheetcol mut small" style="${STATE.multi?'':'display:none'}">${p.scope}</td>
   <td>${p.category?p.category+' '+badge+sens:'<span class="mut">—</span>'}</td>
   <td>${regs}</td>
   <td><span class="bar"><i style="width:${Math.round(p.confidence*100)}%"></i></span> <span class="small mut">${p.confidence.toFixed(2)}</span></td>
   <td class="small mut">${ev.join(", ")}</td><td>${note}</td>`;
  tb.appendChild(tr);
 }
 tb.querySelectorAll("input[type=checkbox]").forEach(c=>c.onchange=()=>{
   if(c.checked)STATE.selected.add(c.dataset.k);else STATE.selected.delete(c.dataset.k);updateCount();});
 updateCount();
}
function updateCount(){$("#selCount").textContent=STATE.selected.size;}
$("#filter").oninput=renderPlan;$("#showAll").onchange=renderPlan;
$("#selRec").onclick=()=>setAll(p=>p.recommend);
$("#selFlag").onclick=()=>setAll(p=>p.plan!=="skip");
$("#selNone").onclick=()=>setAll(()=>false);
function setAll(pred){STATE.selected=new Set(STATE.plan.filter(pred).map(keyOf));renderPlan();}

// ---- encrypt ----
$("#encryptBtn").onclick=async()=>{
 const sel=[...STATE.selected].map(k=>{const i=k.indexOf("||");return{scope:k.slice(0,i),name:k.slice(i+2)};});
 if(!sel.length){$("#encErr").textContent="Select at least one column.";return;}
 $("#encErr").textContent="";$("#encryptBtn").disabled=true;$("#encryptBtn").textContent="Encrypting…";
 try{
  const r=await fetch("/encrypt",{method:"POST",headers:{"Content-Type":"application/json"},
   body:JSON.stringify({token:STATE.token,selected:sel})});
  if(!r.ok)throw new Error(await r.text());
  const j=await r.json();
  $("#resultText").innerHTML=`Encrypted <b>${j.cells}</b> cells across <b>${j.columns}</b> column(s).`;
  $("#dlLinks").innerHTML=
   `<a href="${j.downloads.protected}"><button class="btn-g">⬇ Protected file</button></a>`+
   `<a href="${j.downloads.key}"><button class="btn">⬇ Key file (pii.key)</button></a>`+
   `<a href="${j.downloads.manifest}"><button class="btn2">⬇ Manifest</button></a>`;
  $("#resultCard").classList.remove("hide");
  $("#resultCard").scrollIntoView({behavior:"smooth"});
 }catch(e){$("#encErr").textContent=e.message;}
 $("#encryptBtn").disabled=false;$("#encryptBtn").innerHTML='Encrypt selected (<span id="selCount">'+sel.length+'</span>)';
};

// ---- decrypt ----
function checkDec(){$("#decryptBtn").disabled=!($("#decFile").files[0]&&$("#keyFile").files[0]);}
$("#decryptBtn").onclick=async()=>{
 $("#decErr").textContent="";$("#decryptBtn").disabled=true;$("#decryptBtn").textContent="Decrypting…";
 const fd=new FormData();fd.append("file",$("#decFile").files[0]);fd.append("key",$("#keyFile").files[0]);
 try{
  const r=await fetch("/decrypt",{method:"POST",body:fd});
  if(!r.ok)throw new Error(await r.text());
  const j=await r.json();
  $("#decResultText").innerHTML=`Decrypted <b>${j.cells}</b> cells.`;
  $("#decDl").innerHTML=`<a href="${j.download}"><button class="btn-g">⬇ Decrypted file</button></a>`;
  $("#decResult").classList.remove("hide");
 }catch(e){$("#decErr").textContent=e.message;}
 $("#decryptBtn").disabled=false;$("#decryptBtn").textContent="Decrypt";checkDec();
};
</script></div></body></html>"""


def main():
    host, port = "127.0.0.1", 5000
    url = f"http://{host}:{port}"
    print(f"PII Guardian UI running at {url}")
    print(f"Working dir (transient): {WORK}")
    print("Connection-free: bound to localhost; files are not sent anywhere. Ctrl+C to stop.")
    threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    app.run(host=host, port=port, debug=False, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
