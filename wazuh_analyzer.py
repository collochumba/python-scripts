"""
wazuh_analyzer.py
─────────────────────────────────────────────────────────────────────────────
Wazuh / SIEM JSON Log Analyzer  —  SOC Tool 
─────────────────────────────────────────────────────────────────────────────
"""

import json
import ipaddress
import re
from pathlib import Path

import pandas as pd
import streamlit as st

# ─────────────────────────────────────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Wazuh SIEM Analyzer",
    page_icon="🛡️",
    layout="wide",
)

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

CRED_DUMP_TOOLS = {
    "mimikatz", "procdump", "wce", "pwdump", "lazagne",
    "gsecdump", "fgdump", "quarks-pwdump", "lsass",
}

SUSPICIOUS_PROCESSES = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe",
    "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe",
    "rundll32.exe", "certutil.exe", "bitsadmin.exe", "nc.exe",
    "ncat.exe", "psexec.exe", "psexesvc.exe",
}

PERSISTENCE_SERVICES = {
    "psexesvc", "remcos", "njrat", "quasar", "darkcomet",
}

SUSPICIOUS_PATH_KEYWORDS = [
    "\\temp\\", "\\tmp\\", "\\downloads\\",
    "\\appdata\\roaming\\", "\\appdata\\local\\temp\\",
    "\\public\\", "\\recycle",
]

PRIVILEGED_ACCOUNT_PATTERNS = [
    r"^administrator$", r"^admin$", r"^svc_",
    r"^service_", r"_admin$", r"^system$", r"^root$",
]

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

# Each entry: threat-keyword → (tactic, technique_id, technique_name)
MITRE_MAP: dict[str, tuple[str, str, str]] = {
    "Credential Dumping Tool":      ("Credential Access",    "T1003", "OS Credential Dumping"),
    "Suspicious Process":           ("Execution",            "T1059", "Command & Scripting Interpreter"),
    "Suspicious Parent Process":    ("Execution",            "T1059", "Command & Scripting Interpreter"),
    "Persistence Service":          ("Persistence",          "T1543", "Create or Modify System Process"),
    "New Service Installed":        ("Persistence",          "T1543.003", "Windows Service"),
    "Service ImagePath":            ("Persistence",          "T1543.003", "Windows Service"),
    "Execution from Unusual Path":  ("Defense Evasion",      "T1036", "Masquerading"),
    "Privileged Account":           ("Privilege Escalation", "T1078", "Valid Accounts"),
    "External Source IP":           ("Exfiltration",         "T1041", "Exfiltration Over C2 Channel"),
    "External Destination IP":      ("Exfiltration",         "T1041", "Exfiltration Over C2 Channel"),
    "Agent on Public IP":           ("Discovery",            "T1016", "System Network Configuration Discovery"),
    "Encoded / Obfuscated Command": ("Defense Evasion",      "T1027", "Obfuscated Files or Information"),
    "Download Cradle":              ("Command & Control",    "T1105", "Ingress Tool Transfer"),
    "Suspicious DNS Query":         ("Command & Control",    "T1071", "Application Layer Protocol"),
    "Data Staging":                 ("Exfiltration",         "T1074", "Data Staged"),
    "Lateral Movement":             ("Lateral Movement",     "T1021", "Remote Services"),
}

SEV_COLOR = {"High": "#FF4B4B", "Medium": "#FFA500", "Low": "#21C354"}

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def safe_get(d: dict, *keys, default=None):
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, {})
    return d if d != {} else default


def is_public_ip(ip_str: str) -> bool:
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return not any(ip in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


def is_privileged_account(username: str) -> bool:
    if not username:
        return False
    return any(re.search(p, username.strip(), re.IGNORECASE) for p in PRIVILEGED_ACCOUNT_PATTERNS)


def basename(path_str: str) -> str:
    if not path_str:
        return ""
    return Path(path_str.replace("\\", "/")).name.lower()


def path_lower(path_str: str) -> str:
    return (path_str or "").lower()


def mitre_lookup(threat_label: str) -> tuple[str, str, str] | None:
    """Return (tactic, tid, tname) for the first matching MITRE entry."""
    for keyword, entry in MITRE_MAP.items():
        if keyword.lower() in threat_label.lower():
            return entry
    return None


# ─────────────────────────────────────────────────────────────────────────────
# PARSING
# ─────────────────────────────────────────────────────────────────────────────

def parse_record(raw: dict) -> dict:
    """Flatten a Wazuh alert record into a simple dict."""
    src      = raw.get("_source", raw)
    agent    = src.get("agent", {})
    rule     = src.get("rule", {})
    win_data = safe_get(src, "data", "win", default={})
    sys_d    = win_data.get("system", {})
    evt_d    = win_data.get("eventdata", {})

    return {
        # Store the original raw record so we can display it as JSON later
        "_raw":          raw,
        "timestamp":     src.get("timestamp") or "",
        "host":          agent.get("name") or "",
        "agent_ip":      agent.get("ip") or "",
        "user":          (evt_d.get("subjectUserName") or evt_d.get("user") or ""),
        "event_id":      sys_d.get("eventID") or "",
        "rule_level":    int(rule.get("level", 0)),
        "rule_desc":     rule.get("description") or "",
        "new_process":   (evt_d.get("newProcessName") or evt_d.get("image")
                          or evt_d.get("targetFilename") or ""),
        "parent_process":(evt_d.get("parentProcessName") or evt_d.get("parentImage") or ""),
        "image_path":    evt_d.get("imagePath") or "",
        "hashes":        evt_d.get("hashes") or "",
        "source_ip":     (evt_d.get("sourceIp") or evt_d.get("clientIp") or ""),
        "dest_ip":       evt_d.get("destinationIp") or "",
        "dest_port":     evt_d.get("destinationPort") or "",
        "service_name":  evt_d.get("serviceName") or "",
        "command_line":  evt_d.get("commandLine") or "",
        "query_name":    evt_d.get("queryName") or "",
        "details":       (evt_d.get("details") or evt_d.get("message") or ""),
    }


@st.cache_data(show_spinner=False)
def load_and_parse(file_bytes: bytes) -> pd.DataFrame:
    """Parse JSON bytes → DataFrame, cached per upload."""
    data = json.loads(file_bytes)
    if isinstance(data, dict):
        data = [data]
    df = pd.DataFrame([parse_record(r) for r in data])
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    return df


# ─────────────────────────────────────────────────────────────────────────────
# THREAT DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def _detect_row(row: pd.Series) -> pd.Series:
    """
    Detect threats for a single row.
    Returns: threats (str), severity (str), flagged (bool),
             mitre_list (list of dicts), mitre_ids (str — for display/filter).
    """
    threats: list[str] = []

    proc_name      = basename(row["new_process"])
    parent_name    = basename(row["parent_process"])
    img_name       = basename(row["image_path"])
    new_proc_lower = path_lower(row["new_process"])
    img_path_lower = path_lower(row["image_path"])
    cmd_lower      = (row["command_line"] or "").lower()
    svc_lower      = (row["service_name"] or "").lower()
    source_ip      = (row["source_ip"] or "").strip()
    dest_ip        = (row["dest_ip"] or "").strip()
    agent_ip       = (row["agent_ip"] or "").strip()
    event_id       = str(row["event_id"])

    # 1 — Credential dumping
    for tool in CRED_DUMP_TOOLS:
        if tool in proc_name or tool in img_name or tool in cmd_lower:
            threats.append(f"Credential Dumping Tool ({tool})")

    # 2 — Suspicious processes
    if proc_name in SUSPICIOUS_PROCESSES:
        threats.append(f"Suspicious Process ({proc_name})")
    if parent_name in SUSPICIOUS_PROCESSES:
        threats.append(f"Suspicious Parent Process ({parent_name})")

    # 3 — Persistence (FP fix: ImagePath only on service-install events)
    if svc_lower in PERSISTENCE_SERVICES:
        threats.append(f"Persistence Service ({row['service_name']})")
    if row["image_path"] and event_id in ("7045", "4697"):
        threats.append("Service ImagePath (Persistence)")
        threats.append("New Service Installed")

    # 4 — Unusual execution path
    for kw in SUSPICIOUS_PATH_KEYWORDS:
        if kw in new_proc_lower or kw in img_path_lower:
            threats.append(f"Execution from Unusual Path ({kw.strip(chr(92))})")
            break

    # 5 — Privileged account
    if is_privileged_account(row["user"]):
        threats.append(f"Privileged Account ({row['user']})")

    # 6 — External IPs
    for ip_val, label in [(source_ip, "External Source IP"),
                          (dest_ip,   "External Destination IP"),
                          (agent_ip,  "Agent on Public IP")]:
        if is_public_ip(ip_val):
            threats.append(f"{label} ({ip_val})")

    # 7 — Obfuscation
    if any(k in cmd_lower for k in ("-enc ", "-encodedcommand", "base64", "frombase64")):
        threats.append("Encoded / Obfuscated Command")

    # 8 — Download cradles
    if any(k in cmd_lower for k in ("downloadfile", "downloadstring", "webclient",
                                     "invoke-webrequest", "curl", "wget")):
        threats.append("Download Cradle Detected")

    # 9 — Suspicious DNS
    q = (row["query_name"] or "").lower()
    if q and any(w in q for w in ("evil", "malware", "c2", "attacker", "payload")):
        threats.append(f"Suspicious DNS Query ({row['query_name']})")

    # 10 — Data staging / exfil
    all_text = f"{new_proc_lower} {cmd_lower} {path_lower(row['details'])}"
    if any(k in all_text for k in (".zip", "compress", "archive", "7z", "rar")):
        threats.append("Data Staging (Compression Tool)")
    if any(k in cmd_lower for k in ("put ", "upload", "ftp", "sftp", "scp ",
                                     "copy-item", "robocopy")):
        threats.append("Data Staging (Possible Upload/Transfer)")
    if any(k in (row["details"] or "").lower() for k in ("smb connect", "\\\\", "net use")):
        threats.append("Lateral Movement (SMB/Network Share)")

    # — Severity scoring
    score = len(threats)
    sev   = "High" if score > 2 else ("Medium" if score > 0 else "Low")
    if row["rule_level"] >= 12:
        sev = "High"
    elif row["rule_level"] >= 7 and sev == "Low":
        sev = "Medium"

    # — MITRE mapping: build a clean list of unique technique dicts
    #   FIX: store as a list (not a pipe-joined string) to avoid word-splitting
    mitre_list: list[dict] = []
    seen_tids: set[str] = set()
    for t in threats:
        entry = mitre_lookup(t)
        if entry:
            tactic, tid, tname = entry
            if tid not in seen_tids:
                mitre_list.append({
                    "id":     tid,
                    "name":   tname,
                    "tactic": tactic,
                    "label":  f"{tid} – {tname}",
                })
                seen_tids.add(tid)

    # Human-readable string for display column (one per line, not pipe-joined)
    mitre_display = "\n".join(m["label"] for m in mitre_list) if mitre_list else "—"

    return pd.Series({
        "threats":      ", ".join(threats) if threats else "—",
        "severity":     sev,
        "flagged":      bool(threats),
        "mitre_list":   mitre_list,          # list[dict] — used for drill-down
        "mitre_ids":    mitre_display,        # str — shown in table
    })


@st.cache_data(show_spinner=False)
def detect_threats(df: pd.DataFrame) -> pd.DataFrame:
    results = df.apply(_detect_row, axis=1)
    return pd.concat([df, results], axis=1)


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK CORRELATION
# ─────────────────────────────────────────────────────────────────────────────

def build_correlation(df: pd.DataFrame) -> pd.DataFrame:
    flagged = df[df["flagged"] & df["user"].replace("", pd.NA).notna()]
    if flagged.empty:
        return pd.DataFrame()
    grp = (
        flagged.groupby("user")
        .agg(
            hosts_seen=("host", lambda x: ", ".join(sorted(x.dropna().unique()))),
            host_count=("host", "nunique"),
            event_count=("host", "count"),
            severity_max=("severity", lambda x: (
                "High" if "High" in x.values
                else ("Medium" if "Medium" in x.values else "Low")
            )),
        )
        .reset_index()
        .sort_values("host_count", ascending=False)
    )
    return grp[grp["host_count"] > 1]


# ─────────────────────────────────────────────────────────────────────────────
# DISPLAY HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def colorize_severity(val: str) -> str:
    return f"background-color:{SEV_COLOR.get(val,'#eee')};color:white;font-weight:600"


def metric_card(label: str, value, color: str = "#1f77b4"):
    st.markdown(
        f"""<div style="background:{color}18;border-left:4px solid {color};
            padding:12px 16px;border-radius:6px">
            <div style="font-size:0.72rem;color:#999;text-transform:uppercase;
                letter-spacing:1px;margin-bottom:2px">{label}</div>
            <div style="font-size:1.9rem;font-weight:800;color:{color}">{value}</div>
        </div>""",
        unsafe_allow_html=True,
    )


def _search_df(df: pd.DataFrame, query: str) -> pd.DataFrame:
    if not query.strip():
        return df
    q = query.strip().lower()
    mask = df.apply(
        lambda col: col.astype(str).str.lower().str.contains(q, na=False)
        if col.dtype == object else pd.Series(False, index=col.index),
        axis=0,
    ).any(axis=1)
    return df[mask]


def row_to_json_dict(row: pd.Series) -> dict:
    """
    Build a clean, analyst-friendly JSON dict from a DataFrame row.
    Includes all fields plus the analysis results (threats, severity, MITRE).
    """
    ts = row["timestamp"]
    return {
        "alert": {
            "timestamp":  ts.isoformat() if pd.notna(ts) else None,
            "host":       row["host"],
            "agent_ip":   row["agent_ip"],
        },
        "identity": {
            "user":       row["user"],
            "event_id":   row["event_id"],
            "rule_level": int(row["rule_level"]),
            "rule_desc":  row["rule_desc"],
        },
        "process": {
            "new_process":    row["new_process"]    or None,
            "parent_process": row["parent_process"] or None,
            "command_line":   row["command_line"]   or None,
            "image_path":     row["image_path"]     or None,
            "hashes":         row["hashes"]         or None,
        },
        "network": {
            "source_ip":  row["source_ip"]  or None,
            "dest_ip":    row["dest_ip"]    or None,
            "dest_port":  row["dest_port"]  or None,
            "query_name": row["query_name"] or None,
        },
        "service": {
            "service_name": row["service_name"] or None,
            "details":      row["details"]      or None,
        },
        "analysis": {
            "severity":   row["severity"],
            "flagged":    bool(row["flagged"]),
            "threats":    [t.strip() for t in row["threats"].split(", ")]
                          if row["threats"] != "—" else [],
            "mitre_attack": row["mitre_list"] if isinstance(row["mitre_list"], list) else [],
        },
        "raw_event": row["_raw"],
    }


def render_json_detail(row: pd.Series, idx: int):
    """
    Render a coloured JSON detail block for a single alert row.
    Uses st.expander so it stays collapsed until clicked.
    """
    sev   = row["severity"]
    color = SEV_COLOR.get(sev, "#888")
    label = (
        f"🔍 #{idx} | {sev} | {row['host'] or '?'} | "
        f"{row['user'] or '—'} | {row['event_id'] or '—'} | "
        f"{basename(row['new_process']) or row['details'][:40] or '(no process)'}"
    )

    with st.expander(label, expanded=False):
        detail = row_to_json_dict(row)
        json_str = json.dumps(detail, indent=2, default=str)

        # Styled JSON block
        st.markdown(
            f"""<div style="border-left:4px solid {color};padding:4px 0 4px 12px;
                border-radius:4px;background:#0e1117">
                <pre style="font-size:0.78rem;color:#e8e8e8;
                    white-space:pre-wrap;word-break:break-all;margin:0">{json_str}</pre>
            </div>""",
            unsafe_allow_html=True,
        )

        # Per-event JSON download button
        st.download_button(
            label="⬇️ Download this alert as JSON",
            data=json_str.encode("utf-8"),
            file_name=f"alert_{idx}_{row['host']}_{row['event_id']}.json",
            mime="application/json",
            key=f"dl_json_{idx}",
        )


# ─────────────────────────────────────────────────────────────────────────────
# MITRE TABLE HELPER  (FIX: explode the list column correctly)
# ─────────────────────────────────────────────────────────────────────────────

def build_mitre_table(df: pd.DataFrame) -> pd.DataFrame:
    """
    Explode the mitre_list column (list of dicts) into a flat DataFrame.
    Each row = one unique technique.
    Returns columns: id | name | tactic | count
    """
    flagged = df[df["flagged"]]
    if flagged.empty:
        return pd.DataFrame()

    rows = []
    for ml in flagged["mitre_list"]:
        if isinstance(ml, list):
            for m in ml:
                rows.append(m)

    if not rows:
        return pd.DataFrame()

    exploded = pd.DataFrame(rows)
    counts = (
        exploded.groupby(["id", "name", "tactic"])
        .size()
        .reset_index(name="count")
        .sort_values("count", ascending=False)
    )
    counts["technique"] = counts["id"] + " – " + counts["name"]
    return counts[["technique", "tactic", "count"]]


# ─────────────────────────────────────────────────────────────────────────────
# MAIN APP
# ─────────────────────────────────────────────────────────────────────────────

def main():
    st.markdown(
        """
        <h1 style='margin-bottom:2px'>🛡️ Wazuh SIEM Analyzer
        </h1>
        <p style='color:#888;margin-top:0'>
        SOC-grade detection · MITRE ATT&amp;CK · Correlation · Timeline ·
        <b>Clickable JSON drill-down</b>
        </p><hr style='margin:8px 0 20px 0'>
        """,
        unsafe_allow_html=True,
    )

    uploaded = st.file_uploader(
        "📁 Upload Wazuh JSON export", type=["json"],
        help="Array of Wazuh alert records (_source wrapped or bare).",
    )

    if not uploaded:
        st.info("👆 Upload a Wazuh JSON file to get started.")
        _show_format_help()
        return

    with st.spinner("Parsing logs and running detection engine…"):
        try:
            raw_df = load_and_parse(uploaded.read())
        except Exception as e:
            st.error(f"❌ Failed to parse JSON: {e}")
            return
        df = detect_threats(raw_df)

    if df.empty:
        st.warning("No records found.")
        return

    # ── totals ────────────────────────────────────────────────────────────────
    total     = len(df)
    n_flagged = int(df["flagged"].sum())
    n_high    = int((df["severity"] == "High").sum())
    n_medium  = int((df["severity"] == "Medium").sum())
    n_users   = df["user"].replace("", pd.NA).dropna().nunique()
    n_hosts   = df["host"].replace("", pd.NA).dropna().nunique()

    # ═════════════════════════════════════════════════════════════════════════
    # SECTION 1 — SUMMARY DASHBOARD
    # ═════════════════════════════════════════════════════════════════════════
    st.subheader("📊 Summary Dashboard")

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    with c1: metric_card("Total Alerts",      total,      "#1f77b4")
    with c2: metric_card("Suspicious Events", n_flagged,  "#d62728")
    with c3: metric_card("High Severity",     n_high,     "#FF4B4B")
    with c4: metric_card("Medium Severity",   n_medium,   "#FFA500")
    with c5: metric_card("Unique Users",      n_users,    "#2ca02c")
    with c6: metric_card("Affected Hosts",    n_hosts,    "#9467bd")

    st.markdown("")
    col_hosts, col_mitre = st.columns(2)

    with col_hosts:
        with st.expander("🖥️ Affected Hosts (flagged events)", expanded=True):
            h = df[df["flagged"]]["host"].value_counts().reset_index()
            h.columns = ["Host", "Suspicious Events"]
            st.dataframe(h, use_container_width=True, hide_index=True)

    with col_mitre:
        with st.expander("🗺️ MITRE ATT&CK Techniques Seen", expanded=True):
            mt = build_mitre_table(df)       # ← FIX: uses list column, not string split
            if mt.empty:
                st.info("No MITRE mappings found.")
            else:
                st.dataframe(mt, use_container_width=True, hide_index=True)

    # ═════════════════════════════════════════════════════════════════════════
    # SECTION 2 — ATTACK CORRELATION
    # ═════════════════════════════════════════════════════════════════════════
    st.markdown("---")
    st.subheader("🔗 Attack Correlation — Lateral Movement Indicators")

    corr = build_correlation(df)
    if corr.empty:
        st.success("✅ No cross-host user activity detected.")
    else:
        st.warning(
            f"⚠️ **{len(corr)} user(s)** seen on **multiple hosts** — "
            "possible lateral movement or credential reuse."
        )
        st.dataframe(
            corr.style.applymap(colorize_severity, subset=["severity_max"]),
            use_container_width=True, hide_index=True,
        )

    # ═════════════════════════════════════════════════════════════════════════
    # SECTION 3 — ATTACK TIMELINE
    # ═════════════════════════════════════════════════════════════════════════
    st.markdown("---")
    st.subheader("📅 Attack Timeline")

    timeline_df = (
        df[df["flagged"] & df["timestamp"].notna()]
        .sort_values("timestamp")
        [["timestamp", "host", "user", "event_id", "new_process",
          "severity", "threats", "mitre_ids"]]
        .copy()
    )
    timeline_df["timestamp"] = timeline_df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")

    if timeline_df.empty:
        st.info("No timestamped suspicious events to plot.")
    else:
        ts_counts = (
            df[df["flagged"]].set_index("timestamp")
            .resample("10min")["flagged"].sum()
            .reset_index()
        )
        ts_counts.columns = ["time", "events"]
        ts_counts = ts_counts[ts_counts["events"] > 0]
        if not ts_counts.empty:
            st.markdown("**Suspicious Events Over Time (10-min buckets)**")
            st.bar_chart(ts_counts.set_index("time")["events"])

        st.markdown("**Sorted Event Timeline**")
        st.dataframe(
            timeline_df.style.applymap(colorize_severity, subset=["severity"]),
            use_container_width=True, hide_index=True, height=300,
        )
        first_ts = timeline_df["timestamp"].iloc[0]
        last_ts  = timeline_df["timestamp"].iloc[-1]
        st.caption(f"🕐 First: **{first_ts}**  |  Last: **{last_ts}**")

    # ═════════════════════════════════════════════════════════════════════════
    # SECTION 4 — FILTER & SEARCH
    # ═════════════════════════════════════════════════════════════════════════
    st.markdown("---")
    st.subheader("🔍 Filter & Search")

    search_query = st.text_input(
        "🔎 Search across all fields",
        placeholder="e.g. mimikatz, 192.168.1.5, administrator, powershell…",
    )

    col_a, col_b, col_c = st.columns(3)
    with col_a:
        host_filter = st.multiselect(
            "Filter by Host", options=sorted(df["host"].dropna().unique().tolist()))
    with col_b:
        user_filter = st.multiselect(
            "Filter by User",
            options=sorted(df["user"].replace("", pd.NA).dropna().unique().tolist()))
    with col_c:
        sev_filter = st.multiselect(
            "Filter by Severity", options=["High", "Medium", "Low"],
            default=["High", "Medium", "Low"])

    show_flagged_only = st.checkbox("Show suspicious events only", value=False)

    view = df.copy()
    if host_filter:
        view = view[view["host"].isin(host_filter)]
    if user_filter:
        view = view[view["user"].isin(user_filter)]
    if sev_filter:
        view = view[view["severity"].isin(sev_filter)]
    if show_flagged_only:
        view = view[view["flagged"]]
    view = _search_df(view, search_query)

    st.caption(f"Showing **{len(view):,}** of **{total:,}** records")

    # ═════════════════════════════════════════════════════════════════════════
    # SECTION 5 — FINDINGS TABLE  (summary view)
    # ═════════════════════════════════════════════════════════════════════════
    st.subheader("🚨 Findings Table")

    DISPLAY_COLS = [
        "timestamp", "host", "agent_ip", "user", "event_id",
        "new_process", "parent_process", "image_path", "hashes",
        "source_ip", "dest_ip", "command_line", "service_name",
        "threats", "mitre_ids", "severity",
    ]
    present_cols = [c for c in DISPLAY_COLS if c in view.columns]
    table = view[present_cols].copy()
    table["timestamp"] = table["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S").fillna("")

    styled = (
        table.style
        .applymap(colorize_severity, subset=["severity"])
        .set_properties(**{"font-size": "0.78rem"})
    )
    st.dataframe(styled, use_container_width=True, hide_index=True, height=420)

    # ═════════════════════════════════════════════════════════════════════════
    # SECTION 6 — JSON DETAIL VIEWER  ← NEW
    # Each suspicious alert is expandable and shows full structured JSON.
    # ═════════════════════════════════════════════════════════════════════════
    st.markdown("---")
    st.subheader("🔎 JSON Alert Detail Viewer")
    st.caption(
        "Click any row below to expand the full structured JSON for that alert. "
        "Each alert also has a one-click download button."
    )

    # Limit to flagged events by default; let user show all
    show_all_json = st.checkbox("Include non-suspicious (Low) events in detail view",
                                value=False)

    json_view = view[view["flagged"]] if not show_all_json else view

    if json_view.empty:
        st.info("No events match the current filters.")
    else:
        # Allow user to sort by severity so High events appear first
        sort_order = {"High": 0, "Medium": 1, "Low": 2}
        json_view = json_view.copy()
        json_view["_sort"] = json_view["severity"].map(sort_order)
        json_view = json_view.sort_values(["_sort", "timestamp"]).drop(columns=["_sort"])

        st.caption(f"Showing **{len(json_view)}** alert(s) — click a row to expand.")
        for display_idx, (orig_idx, row) in enumerate(json_view.iterrows(), start=1):
            render_json_detail(row, display_idx)

    # ═════════════════════════════════════════════════════════════════════════
    # SECTION 7 — MITRE DRILL-DOWN  ← NEW
    # Pick a technique → see all matching events in JSON.
    # ═════════════════════════════════════════════════════════════════════════
    st.markdown("---")
    st.subheader("🗺️ MITRE ATT&CK Drill-Down")
    st.caption("Select a technique to view all matching alerts as JSON.")

    mt_full = build_mitre_table(df)
    if mt_full.empty:
        st.info("No MITRE techniques detected.")
    else:
        technique_options = mt_full["technique"].tolist()
        selected_technique = st.selectbox(
            "Select a MITRE technique", options=["— choose —"] + technique_options
        )

        if selected_technique and selected_technique != "— choose —":
            # Extract the technique ID (e.g. "T1078") from the label
            tid_selected = selected_technique.split("–")[0].strip()

            # Filter rows whose mitre_list contains this technique ID
            def has_technique(ml):
                if not isinstance(ml, list):
                    return False
                return any(m.get("id") == tid_selected for m in ml)

            matched = df[df["mitre_list"].apply(has_technique)]

            # Show tactic context
            tactic_row = mt_full[mt_full["technique"] == selected_technique]
            if not tactic_row.empty:
                tactic = tactic_row.iloc[0]["tactic"]
                count  = int(tactic_row.iloc[0]["count"])
                st.info(f"**{selected_technique}** — Tactic: *{tactic}* — **{count} event(s)** matched")

            if matched.empty:
                st.warning("No events found for this technique.")
            else:
                for display_idx, (orig_idx, row) in enumerate(matched.iterrows(), start=1):
                    render_json_detail(row, display_idx)

    # ═════════════════════════════════════════════════════════════════════════
    # SECTION 8 — THREAT ANALYTICS
    # ═════════════════════════════════════════════════════════════════════════
    st.markdown("---")
    st.subheader("📈 Threat Analytics")

    col_l, col_r = st.columns(2)
    with col_l:
        st.markdown("**Severity Distribution**")
        sev_counts = (
            df["severity"].value_counts()
            .reindex(["High", "Medium", "Low"], fill_value=0)
        )
        st.bar_chart(sev_counts)

    with col_r:
        st.markdown("**Top Flagged Users**")
        top_users = (
            df[df["flagged"]]["user"].replace("", pd.NA).dropna()
            .value_counts().head(10).reset_index()
        )
        top_users.columns = ["User", "Events"]
        if top_users.empty:
            st.info("No flagged user activity.")
        else:
            st.bar_chart(top_users.set_index("User"))

    st.markdown("**Top Threat Categories**")
    threat_series = (
        df[df["flagged"]]["threats"]
        .str.split(", ").explode().str.strip()
        .replace("—", pd.NA).dropna()
    )
    if not threat_series.empty:
        clean = threat_series.str.replace(r"\s*\(.*\)", "", regex=True).str.strip()
        top_t = clean.value_counts().head(12).reset_index()
        top_t.columns = ["Threat Category", "Count"]
        st.dataframe(top_t, use_container_width=True, hide_index=True)

    # ═════════════════════════════════════════════════════════════════════════
    # SECTION 9 — IOC PANEL
    # ═════════════════════════════════════════════════════════════════════════
    st.markdown("---")
    st.subheader("🔴 IOC Extraction Panel")

    ioc_col1, ioc_col2 = st.columns(2)

    with ioc_col1:
        st.markdown("**Suspicious External IPs**")
        all_ips = (
            pd.concat([df["source_ip"].rename("ip"), df["dest_ip"].rename("ip")])
            .replace("", pd.NA).dropna().unique()
        )
        public_ips = [ip for ip in all_ips if is_public_ip(ip)]
        if public_ips:
            st.dataframe(pd.DataFrame({"IP": sorted(public_ips)}),
                         use_container_width=True, hide_index=True)
        else:
            st.success("No public IPs found.")

    with ioc_col2:
        st.markdown("**Suspicious Process Names**")
        flagged_procs = (
            df[df["flagged"]]["new_process"].replace("", pd.NA).dropna()
            .apply(basename).value_counts().reset_index()
        )
        flagged_procs.columns = ["Process", "Count"]
        if not flagged_procs.empty:
            st.dataframe(flagged_procs, use_container_width=True, hide_index=True)
        else:
            st.info("No flagged processes.")

    hashes = df["hashes"].replace("", pd.NA).dropna().unique()
    if len(hashes):
        with st.expander(f"🔑 File Hashes Found ({len(hashes)})"):
            st.dataframe(pd.DataFrame({"Hash": hashes}),
                         use_container_width=True, hide_index=True)

    # ═════════════════════════════════════════════════════════════════════════
    # SECTION 10 — EXPORTS
    # ═════════════════════════════════════════════════════════════════════════
    st.markdown("---")

    col_d1, col_d2, col_d3 = st.columns(3)

    with col_d1:
        csv_all = df[present_cols].to_csv(index=False).encode("utf-8")
        st.download_button("⬇️ All findings (CSV)",
                           csv_all, "wazuh_all_findings.csv", "text/csv")

    with col_d2:
        flagged_rows = df[df["flagged"]][present_cols]
        csv_flagged  = flagged_rows.to_csv(index=False).encode("utf-8")
        st.download_button("⬇️ Suspicious only (CSV)",
                           csv_flagged, "wazuh_suspicious.csv", "text/csv")

    with col_d3:
        # Full suspicious events as a JSON array (analyst-friendly format)
        suspicious_json = [
            row_to_json_dict(row)
            for _, row in df[df["flagged"]].iterrows()
        ]
        json_export = json.dumps(suspicious_json, indent=2, default=str).encode("utf-8")
        st.download_button("⬇️ Suspicious only (JSON)",
                           json_export, "wazuh_suspicious.json", "application/json")


# ─────────────────────────────────────────────────────────────────────────────
# FORMAT HELP
# ─────────────────────────────────────────────────────────────────────────────

def _show_format_help():
    with st.expander("ℹ️ Expected JSON format"):
        st.markdown(
            """
**The app accepts a Wazuh alert export in one of two formats:**

**1. Wrapped records** (standard OpenSearch / Wazuh export):
```json
[
  {
    "_source": {
      "agent": { "name": "PC01", "ip": "192.168.1.5" },
      "timestamp": "2025-10-09T08:00:00Z",
      "rule": { "level": 10, "description": "Process created" },
      "data": {
        "win": {
          "system": { "eventID": "4688" },
          "eventdata": {
            "subjectUserName": "john",
            "newProcessName": "C:\\\\Windows\\\\System32\\\\cmd.exe",
            "parentProcessName": "C:\\\\Windows\\\\explorer.exe"
          }
        }
      }
    }
  }
]
```
**2. Array of bare `_source` objects** — also accepted automatically.
            """
        )


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()
