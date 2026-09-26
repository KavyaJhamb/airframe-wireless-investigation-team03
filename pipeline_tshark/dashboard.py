"""
Airframe - step 3: dashboard.

Reads only the masked outputs of detect.py (no raw MACs, SSIDs or EAP identities).

Run:  streamlit run dashboard.py            (reads ./out)
      streamlit run dashboard.py -- --out other_folder
"""
import json
import os
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# full-width charts/tables on both old and new Streamlit versions
_V = tuple(int(x) for x in st.__version__.split(".")[:2])
WIDE = {"width": "stretch"} if _V >= (1, 48) else {"use_container_width": True}

OUT = Path(sys.argv[sys.argv.index("--out") + 1] if "--out" in sys.argv
           else os.environ.get("AIRFRAME_OUT", "out"))

SEV_COLOR = {"critical": "#B42318", "high": "#C4320A", "medium": "#B54708",
             "low": "#3E4784", "info": "#667085"}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]
EVENT_GROUP = {"Auth": "Join", "Assoc req": "Join", "Assoc resp": "Join", "Reassoc req": "Join",
               "Reassoc resp": "Join", "EAP request": "802.1X", "EAP response": "802.1X",
               "EAP success": "802.1X", "EAP failure": "802.1X", "Key M1": "Key handshake",
               "Key M2": "Key handshake", "Key M3": "Key handshake", "Key M4": "Key handshake",
               "Deauth": "Disconnect", "Disassoc": "Disconnect", "Probe req": "Probe"}
EVENT_COLOR = {"Join": "#2E6FD8", "802.1X": "#7A5AF8", "Key handshake": "#0E9384",
               "Disconnect": "#D92D20", "Probe": "#98A2B3"}
OUTCOME_COLOR = {"connected": "#12B76A", "assoc_comeback": "#12B76A", "in_progress": "#98A2B3",
                 "client_left": "#98A2B3", "interrupted_by_loop": "#F79009"}
OUTCOME_FAIL = "#F04438"

st.set_page_config(page_title="Airframe", layout="wide")
st.markdown("""
<style>
  .block-container {padding-top: 2rem; max-width: 1400px;}
  .headline {font-size: 1.35rem; line-height: 1.45; margin: 0.2rem 0 0.2rem 0; max-width: 62rem;}
  .headline b {font-weight: 650;}
  .sev {display:inline-block; padding: 0 .45rem; border-radius: 4px; color: white; font-size: .8rem;}
  .muted {color: #667085; font-size: .9rem;}
</style>""", unsafe_allow_html=True)


@st.cache_data
def load(out: str):
    o = Path(out)
    d = {name: pd.read_csv(o / f"{name}.csv") for name in
         ["findings", "attempts", "events", "channel_minutes", "aps", "clients", "sensors", "roams"]
         if (o / f"{name}.csv").exists() and (o / f"{name}.csv").stat().st_size > 1}
    d["summary"] = json.loads((o / "summary.json").read_text())
    for name, col in [("findings", "start_ts"), ("findings", "end_ts"), ("attempts", "start"),
                      ("attempts", "end"), ("events", "ts"), ("channel_minutes", "t")]:
        if name in d and col in d[name]:
            d[name][col + "_dt"] = pd.to_datetime(d[name][col], unit="s", utc=True)
    if "findings" not in d:
        d["findings"] = pd.DataFrame(columns=["id", "severity", "category", "title", "explanation",
                                              "client", "ap", "ssid", "sensors", "channels", "start_ts",
                                              "end_ts", "count", "parent", "tags", "related",
                                              "start_ts_dt", "end_ts_dt"])
    f = d["findings"]
    for c in ["parent", "tags", "related", "client", "ap", "ssid", "sensors", "channels"]:
        if c in f:
            f[c] = f[c].fillna("")
    return d


if not (OUT / "summary.json").exists():
    st.error(f"No detector output in '{OUT}'. Run extract.py and detect.py first.")
    st.stop()

D = load(str(OUT))
S, F = D["summary"], D["findings"]
events, attempts = D.get("events", pd.DataFrame()), D.get("attempts", pd.DataFrame())
t0 = pd.to_datetime(S["capture_start"], unit="s", utc=True)
dur_min = (S["capture_end"] - S["capture_start"]) / 60


def sev_badge(sev: str) -> str:
    return f'<span class="sev" style="background:{SEV_COLOR.get(sev, "#667085")}">{sev}</span>'


def clock(dt) -> str:
    return "" if pd.isna(dt) else dt.strftime("%H:%M:%S")


# ------------------------------------------------------------------ header: the answer first
st.title("Airframe")
st.markdown(f'<div class="muted">{S["sensors"]} sensors · {S["aps"]} APs · {S["clients"]} clients · '
            f'{dur_min:.0f} min of header-only captures starting {t0:%Y-%m-%d %H:%M} UTC</div>',
            unsafe_allow_html=True)

top = F[(F.parent == "") & F.severity.isin(["critical", "high"])]
if len(top):
    lines = "".join(f'<p class="headline">{sev_badge(r.severity)} <b>{r.title}.</b> '
                    f'<span class="muted">{r.explanation.split(". ")[0]}.</span></p>'
                    for r in top.head(4).itertuples())
    st.markdown(lines, unsafe_allow_html=True)

m = st.columns(5)
m[0].metric("Issues found", int((F.parent == "").sum()) - int((F.severity == "info").sum()))
m[1].metric("Clients affected", F.loc[F.severity != "info", "client"].replace("", pd.NA).nunique())
m[2].metric("Join attempts", S["attempts"])
m[3].metric("Connected", int((attempts.outcome == "connected").sum()) if len(attempts) else 0)
m[4].metric("Normal roams (not flagged)", S.get("roams", 0))

tab_f, tab_t, tab_c, tab_s = st.tabs(["Findings", "Client timeline", "Channels", "Sensors"])

# ------------------------------------------------------------------ findings
with tab_f:
    c1, c2, c3 = st.columns([1, 2, 2])
    sev = c1.multiselect("Severity", SEV_ORDER, default=[s for s in SEV_ORDER if s != "info"])
    cats = c2.multiselect("Category", sorted(F.category.unique()))
    group_children = c3.toggle("Group clients under network-wide findings", value=True)
    view = F[F.severity.isin(sev)]
    if cats:
        view = view[view.category.isin(cats)]
    if group_children:
        kids = F[F.parent != ""].groupby("parent").size()
        view = view[view.parent == ""].copy()
        view["title"] = [t + (f"  (+{kids[i]} clients)" if i in kids else "") for t, i in zip(view.title, view.id)]

    left, right = st.columns([3, 2])
    with left:
        counts = (F[F.parent == ""].groupby(["category", "severity"]).size().reset_index(name="n"))
        fig = px.bar(counts, y="category", x="n", color="severity", orientation="h",
                     color_discrete_map=SEV_COLOR, category_orders={"severity": SEV_ORDER})
        fig.update_layout(height=260, margin=dict(l=0, r=0, t=10, b=0), yaxis_title="",
                          xaxis_title="findings (clients grouped)", legend_title="")
        st.plotly_chart(fig, **WIDE)
        table = view.assign(start=view.start_ts_dt.map(clock), end=view.end_ts_dt.map(clock))
        st.dataframe(table[["id", "severity", "category", "title", "sensors", "count", "start", "end"]],
                     hide_index=True, **WIDE, height=420)
    with right:
        if len(view):
            pick = st.selectbox("Details", view.id + "  " + view.title, index=0)
            r = F[F.id == pick.split()[0]].iloc[0]
            st.markdown(f"{sev_badge(r.severity)} **{r.category}**", unsafe_allow_html=True)
            st.markdown(f"#### {r.title}")
            st.write(r.explanation)
            facts = {"Client": r.client, "AP": r.ap, "Network": r.ssid, "Seen by": r.sensors.replace(";", ", "),
                     "Channels": r.channels, "From": clock(r.start_ts_dt), "To": clock(r.end_ts_dt),
                     "Tags": r.tags}
            st.markdown("\n".join(f"- **{k}:** {v}" for k, v in facts.items() if v))
            children = F[F.parent == r.id]
            if len(children):
                st.markdown(f"**{len(children)} clients in this finding**")
                st.dataframe(children[["id", "client", "ap", "count", "tags"]], hide_index=True,
                             **WIDE, height=220)
            if r.related:
                rel = F[F.id.isin(r.related.split(";"))]
                st.markdown("**Same client, other findings:** " +
                            "; ".join(f"{x.id} {x.category}" for x in rel.itertuples()))
            if r.client:
                if st.button(f"Show {r.client} in the client timeline"):
                    st.session_state["client"] = r.client
                    st.info("Open the Client timeline tab.")

# ------------------------------------------------------------------ client timeline
with tab_t:
    if events.empty:
        st.info("No client events.")
    else:
        flagged = F[(F.client != "") & (F.severity != "info")].groupby("client").category.agg(
            lambda s: ", ".join(sorted(set(s))))
        all_clients = sorted(events.client.unique(), key=lambda c: (c not in flagged.index, c))
        labels = {c: f"{c}  ({flagged[c]})" if c in flagged.index else c for c in all_clients}
        default = st.session_state.get("client", all_clients[0])
        c1, c2 = st.columns([3, 1])
        client = c1.selectbox("Client", all_clients, index=all_clients.index(default)
                              if default in all_clients else 0, format_func=lambda c: labels[c])
        show_probes = c2.toggle("Show probe requests", value=False)

        e = events[events.client == client].copy()
        if not show_probes:
            e = e[e.event != "Probe req"]
        e["group"] = e.event.map(EVENT_GROUP).fillna("Other")
        e = e.assign(lane=e.sensors.str.split(";")).explode("lane")
        lanes = sorted(e.lane.unique())
        fig = px.scatter(e, x="ts_dt", y="lane", color="group", color_discrete_map=EVENT_COLOR,
                         hover_data={"event": True, "detail": True, "ap": True, "channel": True,
                                     "direction": True, "ts_dt": False, "lane": False, "group": False},
                         category_orders={"lane": lanes})
        fig.update_traces(marker=dict(size=11, line=dict(width=0.5, color="white")))
        a = attempts[attempts.client == client] if len(attempts) else pd.DataFrame()
        for r in a.itertuples():
            color = OUTCOME_COLOR.get(r.outcome, OUTCOME_FAIL)
            end = r.end_dt if r.end_dt > r.start_dt else r.start_dt + pd.Timedelta(seconds=2)
            for lane in str(r.sensors).split(";"):
                if lane in lanes:
                    i = lanes.index(lane)
                    fig.add_shape(type="rect", x0=r.start_dt, x1=end, y0=i - 0.35, y1=i + 0.35,
                                  fillcolor=color, opacity=0.18, line_width=0, layer="below")
        fig.update_layout(height=180 + 60 * len(lanes), margin=dict(l=0, r=0, t=10, b=0),
                          yaxis_title="", xaxis_title="time (UTC)", legend_title="")
        st.plotly_chart(fig, **WIDE)
        st.caption("Each lane is one sensor. Shaded bars are join attempts: green = connected, "
                   "red = failed, orange = cut short by a disconnect loop, grey = still in progress.")

        mine = F[F.client == client]
        if len(mine):
            for r in mine.itertuples():
                st.markdown(f"{sev_badge(r.severity)} **{r.title}** — {r.explanation}",
                            unsafe_allow_html=True)
        if len(a):
            st.dataframe(a.assign(start=a.start_dt.map(clock), end=a.end_dt.map(clock))[
                ["attempt_id", "network", "start", "end", "outcome", "eap_req", "eap_resp", "keys",
                 "end_type", "end_reason", "client_heard", "sensors"]],
                hide_index=True, **WIDE)

# ------------------------------------------------------------------ channels
with tab_c:
    cm = D.get("channel_minutes", pd.DataFrame())
    if cm.empty:
        st.info("No channel data.")
    else:
        cm["channel"] = cm.channel.fillna(-1).astype(int).astype(str).replace("-1", "unknown")
        st.caption("One sensor per channel. Retry share excludes beacons and probe responses: probe "
                   "responses are routinely retried when the scanning client has already left the "
                   "channel, which would make every channel look congested.")
        c1, c2 = st.columns(2)
        for col, y, title in [(c1, "retry_share", "Retry share"), (c2, "beacon_loss", "Beacon loss"),
                              (c1, "active_clients", "Active clients"), (c2, "frames_per_s", "Frames per second")]:
            fig = px.line(cm, x="t_dt", y=y, color="channel", title=title)
            if y in ("retry_share", "beacon_loss"):
                fig.update_yaxes(tickformat=".0%")
            fig.update_layout(height=280, margin=dict(l=0, r=0, t=40, b=0), xaxis_title="",
                              yaxis_title="", legend_title="channel")
            col.plotly_chart(fig, **WIDE)
        aps = D.get("aps", pd.DataFrame())
        if len(aps):
            per = aps.dropna(subset=["channel"]).groupby("channel").ap.nunique().reset_index(name="APs")
            per["channel"] = per.channel.astype(int).astype(str)
            over = set(F.loc[F.category == "Co-channel overlap", "channels"].astype(str))
            per["status"] = ["overloaded" if c in over else "ok" for c in per.channel]
            fig = px.bar(per, x="channel", y="APs", color="status", title="APs per channel",
                         color_discrete_map={"overloaded": SEV_COLOR["medium"], "ok": "#98A2B3"})
            fig.update_layout(height=280, margin=dict(l=0, r=0, t=40, b=0), legend_title="")
            st.plotly_chart(fig, **WIDE)

# ------------------------------------------------------------------ sensors
with tab_s:
    sensors = D.get("sensors", pd.DataFrame())
    if len(sensors):
        st.markdown("Each sensor listens on one channel, so no frame is heard twice: sensors are "
                    "correlated through the same client, not the same frame. *One-sided* = share of join "
                    "attempts where the sensor heard only the AP, never the client.")
        show = sensors.drop(columns=["first_ts", "last_ts"], errors="ignore")
        st.dataframe(show, hide_index=True, **WIDE)
    if not events.empty:
        ex = events.assign(sensor=events.sensors.str.split(";")).explode("sensor")
        focus = st.toggle("Only clients with findings", value=True)
        if focus:
            ex = ex[ex.client.isin(F.loc[F.severity != "info", "client"])]
        mat = ex.groupby(["client", "sensor"]).size().unstack(fill_value=0)
        mat = mat.loc[mat.sum(axis=1).sort_values(ascending=False).index[:40]]
        fig = go.Figure(go.Heatmap(z=mat.values, x=mat.columns, y=mat.index, colorscale="Blues",
                                   hovertemplate="%{y} on %{x}: %{z} events<extra></extra>"))
        fig.update_layout(title="Same client, several sensors (events per client and sensor)",
                          height=200 + 16 * len(mat), margin=dict(l=0, r=0, t=40, b=0))
        st.plotly_chart(fig, **WIDE)

st.markdown('<p class="muted">Privacy: MAC addresses and SSIDs are salted hashes, EAP identities are '
            'never extracted, and there is no payload or layer-3 data anywhere in this pipeline.</p>',
            unsafe_allow_html=True)
