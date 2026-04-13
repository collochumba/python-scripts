"""
wazuh_analyzer.py
─────────────────────────────────────────────────────────────────────────────
Wazuh / SIEM JSON Log Analyzer — Streamlit application
─────────────────────────────────────────────────────────────────────────────
Run:
    pip install streamlit pandas
    streamlit run wazuh_analyzer.py
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
# CONSTANTS — threat intelligence lists
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

SUSPICIOUS_PATH_KEYWORDS = {
    "\\temp\\", "\\tmp\\", "\\downloads\\", "\\appdata\\roaming\\",
    "\\appdata\\local\\temp\\", "\\public\\", "\\recycle",
}

PRIVILEGED_ACCOUNT_PATTERNS = [
    r"^administrator$",
    r"^admin$",
    r"^svc_",
    r"^service_",
    r"_admin$",
    r"^system$",
    r"^root$",
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

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def safe_get(d: dict, *keys, default=None):
    """Safely traverse nested dict keys."""
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, {})
    return d if d != {} else default


def is_public_ip(ip_str: str) -> bool:
    """Return True when ip_str is a routable public IP address."""
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
    username = username.strip().lower()
    return any(re.search(pat, username, re.IGNORECASE) for pat in PRIVILEGED_ACCOUNT_PATTERNS)


def basename(path_str: str) -> str:
    """Extract the executable name from a Windows / Unix path."""
    if not path_str:
        return ""
    return Path(path_str.replace("\\", "/")).name.lower()


def path_lower(path_str: str) -> str:
    return (path_str or "").lower().replace("\\", "\\")


# ─────────────────────────────────────────────────────────────────────────────
# PARSING
# ─────────────────────────────────────────────────────────────────────────────

def parse_record(raw: dict) -> dict:
    """
    Extract all relevant fields from a single Wazuh alert record.
    Returns a flat dictionary ready for a DataFrame row.
    """
    src = raw.get("_source", raw)          # handle both wrapped & bare records

    agent   = src.get("agent", {})
    rule    = src.get("rule", {})
    win_data = safe_get(src, "data", "win", default={})
    sys_d   = win_data.get("system", {})
    evt_d   = win_data.get("eventdata", {})

    # ── core identifiers ──────────────────────────────────────────────────
    host      = agent.get("name") or ""
    agent_ip  = agent.get("ip") or ""
    timestamp = src.get("timestamp") or ""
    event_id  = sys_d.get("eventID") or ""
    rule_level = int(rule.get("level", 0))
    rule_desc  = rule.get("description") or ""

    # ── eventdata fields (vary by event type) ────────────────────────────
    user             = (evt_d.get("subjectUserName")
                        or evt_d.get("user")
                        or "")
    new_process      = (evt_d.get("newProcessName")
                        or evt_d.get("image")
                        or evt_d.get("targetFilename")
                        or "")
    parent_process   = (evt_d.get("parentProcessName")
                        or evt_d.get("parentImage")
                        or "")
    image_path       = evt_d.get("imagePath") or ""
    hashes           = evt_d.get("hashes") or ""
    source_ip        = evt_d.get("sourceIp") or evt_d.get("clientIp") or ""
    dest_ip          = evt_d.get("destinationIp") or ""
    dest_port        = evt_d.get("destinationPort") or ""
    service_name     = evt_d.get("serviceName") or ""
    command_line     = evt_d.get("commandLine") or ""
    query_name       = evt_d.get("queryName") or ""
    details          = evt_d.get("details") or evt_d.get("message") or ""

    return {
        "timestamp":       timestamp,
        "host":            host,
        "agent_ip":        agent_ip,
        "user":            user,
        "event_id":        event_id,
        "rule_level":      rule_level,
        "rule_desc":       rule_desc,
        "new_process":     new_process,
        "parent_process":  parent_process,
        "image_path":      image_path,
        "hashes":          hashes,
        "source_ip":       source_ip,
        "dest_ip":         dest_ip,
        "dest_port":       dest_port,
        "service_name":    service_name,
        "command_line":    command_line,
        "query_name":      query_name,
        "details":         details,
    }


@st.cache_data(show_spinner=False)
def load_and_parse(file_bytes: bytes) -> pd.DataFrame:
    """Parse uploaded JSON bytes → DataFrame. Cached per unique upload."""
    data = json.loads(file_bytes)
    if isinstance(data, dict):
        data = [data]
    rows = [parse_record(r) for r in data]
    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    return df


# ─────────────────────────────────────────────────────────────────────────────
# THREAT DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def detect_threats(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add three columns to the DataFrame:
        threats  – list[str]  individual threat labels
        severity – str        "Low" | "Medium" | "High"
        flagged  – bool
    """
    threats_col  = []
    severity_col = []
    flagged_col  = []

    for _, row in df.iterrows():
        threats = []

        proc_name      = basename(row["new_process"])
        parent_name    = basename(row["parent_process"])
        img_name       = basename(row["image_path"])
        new_proc_lower = path_lower(row["new_process"])
        img_path_lower = path_lower(row["image_path"])
        cmd_lower      = (row["command_line"] or "").lower()
        svc_lower      = (row["service_name"] or "").lower()
        user_lower     = (row["user"] or "").lower()
        source_ip      = (row["source_ip"] or "").strip()
        dest_ip        = (row["dest_ip"] or "").strip()
        agent_ip       = (row["agent_ip"] or "").strip()

        # ── 1. Credential dumping ────────────────────────────────────────
        for tool in CRED_DUMP_TOOLS:
            if tool in proc_name or tool in img_name or tool in cmd_lower:
                threats.append(f"Credential Dumping Tool ({tool})")

        # ── 2. Suspicious processes ──────────────────────────────────────
        if proc_name in SUSPICIOUS_PROCESSES:
            threats.append(f"Suspicious Process ({proc_name})")
        if parent_name in SUSPICIOUS_PROCESSES:
            threats.append(f"Suspicious Parent Process ({parent_name})")

        # ── 3. Persistence mechanisms ────────────────────────────────────
        if svc_lower in PERSISTENCE_SERVICES or svc_lower == "psexesvc":
            threats.append(f"Persistence Service ({row['service_name']})")
        if row["image_path"]:
            threats.append("Service ImagePath Defined (Possible Persistence)")
        if svc_lower and row["event_id"] in ("7045", "4697"):
            threats.append("New Service Installed")

        # ── 4. Execution from unusual paths ──────────────────────────────
        for kw in SUSPICIOUS_PATH_KEYWORDS:
            if kw in new_proc_lower or kw in img_path_lower:
                threats.append(f"Execution from Unusual Path ({kw.strip(chr(92))})")
                break

        # ── 5. Privileged account usage ──────────────────────────────────
        if is_privileged_account(row["user"]):
            threats.append(f"Privileged Account ({row['user']})")

        # ── 6. External / public IPs (possible exfiltration) ─────────────
        for ip_field, label in [
            (source_ip, "External Source IP"),
            (dest_ip,   "External Destination IP"),
            (agent_ip,  "Agent on Public IP"),
        ]:
            if is_public_ip(ip_field):
                threats.append(f"{label} ({ip_field})")

        # ── 7. Obfuscated / encoded commands ────────────────────────────
        if any(kw in cmd_lower for kw in ("-enc ", "-encodedcommand", "base64", "frombase64")):
            threats.append("Encoded / Obfuscated Command")

        # ── 8. Living-off-the-land download cradles ──────────────────────
        if any(kw in cmd_lower for kw in ("downloadfile", "downloadstring", "webclient", "invoke-webrequest", "curl", "wget")):
            threats.append("Download Cradle Detected")

        # ── 9. Suspicious DNS query ───────────────────────────────────────
        q = (row["query_name"] or "").lower()
        if q and any(w in q for w in ("evil", "malware", "c2", "attacker", "payload", "cdn.evil")):
            threats.append(f"Suspicious DNS Query ({row['query_name']})")

        # ── Severity scoring ─────────────────────────────────────────────
        score = len(threats)
        if score == 0:
            sev = "Low"
        elif score <= 2:
            sev = "Medium"
        else:
            sev = "High"

        # Escalate based on Wazuh rule level
        if row["rule_level"] >= 12 and sev != "High":
            sev = "High"
        elif row["rule_level"] >= 7 and sev == "Low":
            sev = "Medium"

        threats_col.append(", ".join(threats) if threats else "—")
        severity_col.append(sev)
        flagged_col.append(bool(threats))

    df = df.copy()
    df["threats"]  = threats_col
    df["severity"] = severity_col
    df["flagged"]  = flagged_col
    return df


# ─────────────────────────────────────────────────────────────────────────────
# DISPLAY HELPERS
# ─────────────────────────────────────────────────────────────────────────────

SEV_COLOR = {
    "High":   "#FF4B4B",
    "Medium": "#FFA500",
    "Low":    "#21C354",
}


def severity_badge(sev: str) -> str:
    color = SEV_COLOR.get(sev, "#888")
    return f'<span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:0.8rem;font-weight:600">{sev}</span>'


def colorize_severity(val):
    return f"background-color:{SEV_COLOR.get(val,'#eee')};color:white;font-weight:600"


def metric_card(label: str, value, color: str = "#1f77b4"):
    st.markdown(
        f"""
        <div style="background:{color}15;border-left:4px solid {color};
                    padding:12px 16px;border-radius:6px;margin-bottom:4px">
            <div style="font-size:0.8rem;color:#888;text-transform:uppercase;letter-spacing:1px">{label}</div>
            <div style="font-size:2rem;font-weight:700;color:{color}">{value}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ─────────────────────────────────────────────────────────────────────────────
# MAIN APP
# ─────────────────────────────────────────────────────────────────────────────

def main():
    # ── Header ───────────────────────────────────────────────────────────
    st.markdown(
        """
        <h1 style='margin-bottom:0'>🛡️ Wazuh SIEM Log Analyzer</h1>
        <p style='color:#888;margin-top:4px'>
        Upload a Wazuh JSON alert export to detect malicious activity across your environment.
        </p>
        <hr style='margin:8px 0 20px 0'>
        """,
        unsafe_allow_html=True,
    )

    # ── File upload ───────────────────────────────────────────────────────
    uploaded = st.file_uploader(
        "📁 Upload Wazuh JSON export",
        type=["json"],
        help="Supports Wazuh alert export format (array of _source objects or raw alerts).",
    )

    if not uploaded:
        st.info("👆 Upload a JSON file to get started.")
        _show_format_help()
        return

    # ── Parse & detect ────────────────────────────────────────────────────
    with st.spinner("Parsing and analyzing logs…"):
        try:
            raw_df = load_and_parse(uploaded.read())
        except (json.JSONDecodeError, Exception) as e:
            st.error(f"❌ Failed to parse JSON: {e}")
            return

        df = detect_threats(raw_df)

    if df.empty:
        st.warning("No records found in the uploaded file.")
        return

    # ── Summary dashboard ─────────────────────────────────────────────────
    st.subheader("📊 Summary Dashboard")

    total       = len(df)
    flagged     = df["flagged"].sum()
    unique_users  = df["user"].replace("", pd.NA).dropna().nunique()
    unique_hosts  = df["host"].replace("", pd.NA).dropna().nunique()
    high_count    = (df["severity"] == "High").sum()
    medium_count  = (df["severity"] == "Medium").sum()

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    with c1: metric_card("Total Alerts",      total,        "#1f77b4")
    with c2: metric_card("Suspicious Events", int(flagged), "#d62728")
    with c3: metric_card("High Severity",     int(high_count),   "#FF4B4B")
    with c4: metric_card("Medium Severity",   int(medium_count), "#FFA500")
    with c5: metric_card("Unique Users",      unique_users,  "#2ca02c")
    with c6: metric_card("Affected Hosts",    unique_hosts,  "#9467bd")

    # Affected hosts list
    with st.expander("🖥️ Affected Hosts", expanded=True):
        hosts = df[df["flagged"]]["host"].value_counts().reset_index()
        hosts.columns = ["Host", "Suspicious Events"]
        if hosts.empty:
            st.write("No flagged hosts.")
        else:
            st.dataframe(hosts, use_container_width=True, hide_index=True)

    st.markdown("---")

    # ── Filters ───────────────────────────────────────────────────────────
    st.subheader("🔍 Filter Findings")

    col_a, col_b, col_c = st.columns(3)

    with col_a:
        all_hosts = sorted(df["host"].dropna().unique().tolist())
        host_filter = st.multiselect("Filter by Host", options=all_hosts, default=[])

    with col_b:
        all_users = sorted(df["user"].replace("", pd.NA).dropna().unique().tolist())
        user_filter = st.multiselect("Filter by User", options=all_users, default=[])

    with col_c:
        sev_filter = st.multiselect(
            "Filter by Severity",
            options=["High", "Medium", "Low"],
            default=["High", "Medium", "Low"],
        )

    show_flagged_only = st.checkbox("Show suspicious events only", value=False)

    # Apply filters
    view = df.copy()
    if host_filter:
        view = view[view["host"].isin(host_filter)]
    if user_filter:
        view = view[view["user"].isin(user_filter)]
    if sev_filter:
        view = view[view["severity"].isin(sev_filter)]
    if show_flagged_only:
        view = view[view["flagged"]]

    st.caption(f"Showing **{len(view):,}** of **{total:,}** records")

    # ── Findings table ────────────────────────────────────────────────────
    st.subheader("🚨 Findings Table")

    DISPLAY_COLS = [
        "timestamp", "host", "agent_ip", "user",
        "event_id", "new_process", "parent_process",
        "image_path", "hashes", "source_ip", "dest_ip",
        "command_line", "service_name", "threats", "severity",
    ]

    # Only show columns that actually have data
    present_cols = [c for c in DISPLAY_COLS if c in view.columns]
    table = view[present_cols].copy()
    table["timestamp"] = table["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S").fillna("")

    styled = (
        table.style
        .applymap(colorize_severity, subset=["severity"])
        .set_properties(**{"font-size": "0.8rem"})
    )

    st.dataframe(styled, use_container_width=True, hide_index=True, height=450)

    # ── Threat breakdown chart ────────────────────────────────────────────
    st.markdown("---")
    st.subheader("📈 Threat Breakdown")

    col_left, col_right = st.columns(2)

    with col_left:
        sev_counts = df["severity"].value_counts().reindex(["High", "Medium", "Low"], fill_value=0)
        sev_df = pd.DataFrame({"Severity": sev_counts.index, "Count": sev_counts.values})
        st.markdown("**Severity Distribution**")
        st.bar_chart(sev_df.set_index("Severity"), color=["#FF4B4B"])

    with col_right:
        st.markdown("**Top Flagged Users**")
        top_users = (
            df[df["flagged"]]["user"]
            .replace("", pd.NA).dropna()
            .value_counts()
            .head(10)
            .reset_index()
        )
        top_users.columns = ["User", "Events"]
        if top_users.empty:
            st.write("No flagged user activity.")
        else:
            st.bar_chart(top_users.set_index("User"))

    # ── Top threat types ──────────────────────────────────────────────────
    st.markdown("**Top Threat Categories Detected**")
    threat_series = (
        df[df["flagged"]]["threats"]
        .str.split(", ")
        .explode()
        .str.strip()
        .replace("—", pd.NA)
        .dropna()
    )
    if not threat_series.empty:
        # Strip detail in parentheses for grouping
        threat_series_clean = threat_series.str.replace(r"\s*\(.*\)", "", regex=True).str.strip()
        top_threats = threat_series_clean.value_counts().head(12).reset_index()
        top_threats.columns = ["Threat Category", "Count"]
        st.dataframe(top_threats, use_container_width=True, hide_index=True)
    else:
        st.info("No suspicious events detected in this dataset.")

    # ── Raw data expander ─────────────────────────────────────────────────
    st.markdown("---")
    with st.expander("🗂️ Raw Parsed Data (all fields)"):
        st.dataframe(view, use_container_width=True, hide_index=True)

    # ── Download ──────────────────────────────────────────────────────────
    st.markdown("---")
    csv_bytes = view[present_cols].to_csv(index=False).encode("utf-8")
    st.download_button(
        label="⬇️ Download findings as CSV",
        data=csv_bytes,
        file_name="wazuh_findings.csv",
        mime="text/csv",
    )


# ─────────────────────────────────────────────────────────────────────────────
# FORMAT HELP
# ─────────────────────────────────────────────────────────────────────────────

def _show_format_help():
    with st.expander("ℹ️ Expected JSON format"):
        st.markdown(
            """
**The app expects a Wazuh alert export in one of two formats:**

**1. Array of wrapped records** (standard Wazuh/OpenSearch export):
```json
[
  {
    "_index": "wazuh-alerts-4.x-2025.10.09",
    "_id": "abc123",
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

**2. Array of bare `_source` objects** (also accepted).
            """
        )


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    main()
