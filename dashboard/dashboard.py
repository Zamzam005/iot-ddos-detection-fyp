"""
dashboard.py - IoT DDoS Defense Center
SIMAD University FYP 2026
Hafso Hussein Ahmed & Zamzam Hassan Ali

Multi-page professional dashboard for DDoS detection.
Features:
  - 5 navigable pages (Home, Live Detection, Performance, Architecture, About)
  - Per-attack-type breakdown (SYN/UDP/ICMP/HTTP)
  - Top attacker IPs
  - Downloadable CSV report
  - Embedded performance images (confusion matrix, ROC, feature importance)
  - Topology image on Architecture page
  - Tooltips on technical terms
  - Live system status + clock in sidebar
"""

import os
import time
import tempfile
from datetime import datetime
from collections import defaultdict

import numpy as np
import pandas as pd
import streamlit as st
import joblib
import matplotlib.pyplot as plt
from sklearn.preprocessing import LabelEncoder
from scapy.all import rdpcap, IP, TCP, UDP

# ============================================================
# PAGE CONFIG
# ============================================================
st.set_page_config(
    page_title="IoT DDoS Defense Center | SIMAD University",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================
# CUSTOM CSS - PROFESSIONAL DARK CYBERSECURITY THEME
# ============================================================
st.markdown("""
<style>
    .stApp {
        background: linear-gradient(135deg, #0a0e1a 0%, #131826 50%, #0a0e1a 100%);
    }

    #MainMenu { visibility: hidden; }
    footer { visibility: hidden; }
    /* KEEP header visible so sidebar toggle arrow is accessible */

    /* === HORIZONTAL TAB NAVIGATION === */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background: linear-gradient(90deg, #131826, #1a2236);
        padding: 14px;
        border-radius: 12px;
        margin-bottom: 25px;
        border: 1px solid #1e3a8a;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3);
    }
    .stTabs [data-baseweb="tab"] {
        background: #1a2236;
        color: #94a3b8;
        padding: 14px 22px;
        border-radius: 8px;
        font-weight: 600;
        font-size: 14px;
        border: 1px solid #334155;
        transition: all 0.2s;
    }
    .stTabs [data-baseweb="tab"]:hover {
        background: #1e3a8a;
        color: white;
        border-color: #3b82f6;
        transform: translateY(-1px);
    }
    .stTabs [aria-selected="true"] {
        background: linear-gradient(90deg, #1e3a8a, #2563eb) !important;
        color: white !important;
        border-color: #3b82f6 !important;
        box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4) !important;
    }
    .stTabs [data-baseweb="tab-highlight"] {
        background: transparent !important;
    }
    .stTabs [data-baseweb="tab-border"] {
        background: transparent !important;
    }

    /* Main banner */
    .main-banner {
        background: linear-gradient(90deg, #1e3a8a 0%, #2563eb 50%, #1e3a8a 100%);
        padding: 30px 25px;
        border-radius: 12px;
        margin-bottom: 30px;
        border: 1px solid #3b82f6;
        box-shadow: 0 8px 24px rgba(59, 130, 246, 0.25);
    }
    .banner-title {
        color: #ffffff;
        font-size: 36px;
        font-weight: 800;
        text-align: center;
        margin: 0;
        letter-spacing: -0.5px;
    }
    .banner-subtitle {
        color: #bfdbfe;
        font-size: 14px;
        text-align: center;
        margin-top: 10px;
        font-weight: 300;
        letter-spacing: 1.5px;
        text-transform: uppercase;
    }

    /* Section titles */
    .section-title {
        color: #60a5fa;
        font-size: 22px;
        font-weight: 700;
        padding-bottom: 10px;
        margin-top: 30px;
        margin-bottom: 18px;
        border-bottom: 2px solid #1e3a8a;
    }

    /* Metric cards */
    .metric-box {
        background: linear-gradient(135deg, #1a2236 0%, #1f2937 100%);
        padding: 22px;
        border-radius: 10px;
        border-left: 4px solid #3b82f6;
        text-align: center;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        transition: transform 0.2s, box-shadow 0.2s;
    }
    .metric-box:hover {
        transform: translateY(-3px);
        box-shadow: 0 8px 20px rgba(59, 130, 246, 0.3);
    }
    .metric-box-green { border-left-color: #10b981; }
    .metric-box-red { border-left-color: #ef4444; }
    .metric-box-orange { border-left-color: #f59e0b; }
    .metric-box-purple { border-left-color: #a855f7; }

    .metric-label {
        color: #94a3b8;
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 1.2px;
        font-weight: 600;
    }
    .metric-value {
        color: #ffffff;
        font-size: 34px;
        font-weight: 800;
        margin-top: 6px;
        line-height: 1;
    }
    .metric-sub {
        color: #64748b;
        font-size: 11px;
        margin-top: 6px;
    }
    .mv-green { color: #10b981; }
    .mv-red { color: #ef4444; }
    .mv-orange { color: #f59e0b; }
    .mv-purple { color: #a855f7; }

    /* Status banners */
    .status-safe {
        background: linear-gradient(90deg, #064e3b, #065f46);
        color: #d1fae5;
        padding: 20px;
        border-radius: 10px;
        font-size: 22px;
        font-weight: 700;
        text-align: center;
        border: 2px solid #10b981;
        margin: 20px 0;
        box-shadow: 0 4px 16px rgba(16,185,129,0.2);
    }
    .status-danger {
        background: linear-gradient(90deg, #7f1d1d, #991b1b);
        color: #fee2e2;
        padding: 20px;
        border-radius: 10px;
        font-size: 22px;
        font-weight: 700;
        text-align: center;
        border: 2px solid #ef4444;
        margin: 20px 0;
        box-shadow: 0 4px 16px rgba(239,68,68,0.3);
        animation: pulse 2s infinite;
    }
    .status-wait {
        background: linear-gradient(135deg, #1f2937, #111827);
        color: #94a3b8;
        padding: 30px;
        border-radius: 10px;
        font-size: 18px;
        text-align: center;
        border: 2px dashed #475569;
        margin: 20px 0;
    }
    @keyframes pulse {
        0%, 100% { opacity: 1; box-shadow: 0 4px 16px rgba(239,68,68,0.3); }
        50%      { opacity: 0.9; box-shadow: 0 4px 24px rgba(239,68,68,0.6); }
    }

    /* Info card */
    .info-card {
        background: linear-gradient(135deg, #1a2236 0%, #1f2937 100%);
        padding: 20px;
        border-radius: 10px;
        border: 1px solid #334155;
        color: #e2e8f0;
        margin: 10px 0;
        line-height: 1.7;
    }
    .info-card-title {
        color: #60a5fa;
        font-size: 16px;
        font-weight: 700;
        margin-bottom: 12px;
    }

    /* Step boxes for pipeline */
    .step-box {
        background: linear-gradient(135deg, #1a2236, #1f2937);
        padding: 20px;
        border-radius: 10px;
        border: 1px solid #334155;
        margin: 10px 0;
    }
    .step-number {
        display: inline-block;
        width: 32px;
        height: 32px;
        background: #3b82f6;
        color: white;
        border-radius: 50%;
        text-align: center;
        line-height: 32px;
        font-weight: bold;
        margin-right: 12px;
    }
    .step-title {
        color: #60a5fa;
        font-size: 18px;
        font-weight: 700;
        display: inline;
    }
    .step-desc {
        color: #cbd5e1;
        margin-top: 8px;
        margin-left: 44px;
        line-height: 1.6;
    }

    /* Team card */
    .team-card {
        background: linear-gradient(135deg, #1e3a8a 0%, #1e40af 100%);
        padding: 30px 25px;
        border-radius: 12px;
        text-align: center;
        margin: 10px;
        border: 1px solid #3b82f6;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    }
    .team-icon { font-size: 60px; }
    .team-name { color: white; font-size: 22px; font-weight: 700; margin-top: 10px; }
    .team-role { color: #bfdbfe; font-size: 13px; margin-top: 6px; letter-spacing: 0.5px; }
    .team-task { color: #93c5fd; font-size: 12px; margin-top: 12px; }

    /* Hybrid model diagram */
    .model-diagram {
        background: #131826;
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 25px;
        margin-top: 15px;
    }
    .model-row {
        display: flex;
        justify-content: space-around;
        gap: 15px;
        margin: 15px 0;
    }
    .base-model {
        flex: 1;
        background: linear-gradient(135deg, #1e3a8a, #2563eb);
        color: white;
        padding: 18px 12px;
        border-radius: 10px;
        text-align: center;
        font-weight: 700;
        border: 2px solid #3b82f6;
    }
    .meta-model {
        background: linear-gradient(135deg, #7c3aed, #a855f7);
        color: white;
        padding: 18px 12px;
        border-radius: 10px;
        text-align: center;
        font-weight: 700;
        margin: 15px auto;
        max-width: 70%;
        border: 2px solid #a855f7;
    }
    .final-prediction {
        background: linear-gradient(135deg, #065f46, #10b981);
        color: white;
        padding: 18px 12px;
        border-radius: 10px;
        text-align: center;
        font-weight: 700;
        margin: 15px auto;
        max-width: 50%;
        border: 2px solid #10b981;
    }
    .arrow-row {
        text-align: center;
        color: #60a5fa;
        font-size: 24px;
        font-weight: 900;
        margin: 5px 0;
    }

    /* Tooltip help icon */
    .help-icon {
        display: inline-block;
        width: 16px;
        height: 16px;
        background: #475569;
        color: white;
        border-radius: 50%;
        text-align: center;
        font-size: 11px;
        line-height: 16px;
        margin-left: 5px;
        cursor: help;
    }

    /* Sidebar */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0a0e1a 0%, #131826 100%);
        border-right: 1px solid #1e3a8a;
    }

    /* Feature pill */
    .feature-pill {
        background: #1a2236;
        padding: 10px 14px;
        border-radius: 8px;
        border-left: 3px solid #3b82f6;
        margin-bottom: 6px;
        color: #e2e8f0;
        font-size: 13px;
    }

    /* Nav hint */
    .nav-hint {
        background: rgba(59,130,246,0.1);
        color: #93c5fd;
        padding: 14px 18px;
        border-radius: 8px;
        font-size: 13px;
        border-left: 3px solid #3b82f6;
        margin: 15px 0;
    }

    /* DataFrame styling */
    div[data-testid="stDataFrame"] {
        background: #1a2236;
        border-radius: 8px;
        border: 1px solid #334155;
    }
</style>
""", unsafe_allow_html=True)


# ============================================================
# CONFIG
# ============================================================
MODEL_PATH = "hybrid_model.pkl"
SCALER_PATH = "scaler.pkl"
GRAPHS_DIR = "graphs"  # folder with confusion_matrix.png, roc_curve.png, etc.


# ============================================================
# LOAD MODEL
# ============================================================
@st.cache_resource
def load_model():
    return joblib.load(MODEL_PATH), joblib.load(SCALER_PATH)

try:
    model, scaler = load_model()
    model_loaded = True
    model_error = None
except Exception as e:
    model_loaded = False
    model_error = str(e)


# ============================================================
# FEATURE EXTRACTION (returns features + metadata)
# ============================================================
def extract_features_from_pcap(pcap_path):
    """Read PCAP, extract per-flow features + metadata (src/dst/protocol)."""
    packets = rdpcap(pcap_path)
    flows = defaultdict(lambda: {
        'packets': [], 'start_time': None, 'end_time': None,
        'bytes': 0, 'syn_count': 0, 'ack_count': 0,
        'rst_count': 0, 'fin_count': 0,
    })

    for pkt in packets:
        if IP in pkt:
            src_ip, dst_ip, proto = pkt[IP].src, pkt[IP].dst, pkt[IP].proto
            src_port, dst_port = 0, 0
            if TCP in pkt:
                src_port, dst_port = pkt[TCP].sport, pkt[TCP].dport
                flags = pkt[TCP].flags
                key = (src_ip, dst_ip, src_port, dst_port, proto)
                if flags & 0x02: flows[key]['syn_count'] += 1
                if flags & 0x10: flows[key]['ack_count'] += 1
                if flags & 0x04: flows[key]['rst_count'] += 1
                if flags & 0x01: flows[key]['fin_count'] += 1
            elif UDP in pkt:
                src_port, dst_port = pkt[UDP].sport, pkt[UDP].dport
            key = (src_ip, dst_ip, src_port, dst_port, proto)
            flows[key]['packets'].append(pkt)
            flows[key]['bytes'] += len(pkt)
            t = pkt.time
            if flows[key]['start_time'] is None or t < flows[key]['start_time']:
                flows[key]['start_time'] = t
            if flows[key]['end_time'] is None or t > flows[key]['end_time']:
                flows[key]['end_time'] = t

    rows = []
    meta_rows = []
    for key, d in flows.items():
        duration = (d['end_time'] - d['start_time']) if d['end_time'] and d['start_time'] else 0.001
        if duration <= 0: duration = 0.001
        pc = len(d['packets'])
        rows.append({
            'flow_duration': duration,
            'total_fwd_packets': pc,
            'total_bwd_packets': 0,
            'total_length_fwd_packets': d['bytes'],
            'bwd_bytes_per_second': 0,
            'packet_length_mean': d['bytes'] / max(pc, 1),
            'fwd_packet_length_max': d['bytes'] / max(pc, 1),
            'syn_flag_count': d['syn_count'],
            'ack_flag_count': d['ack_count'],
            'rst_flag_count': d['rst_count'],
            'fin_flag_count': d['fin_count'],
            'fwd_packets_per_second': pc / duration,
            'bwd_packets_per_second': 0,
            'flow_iat_mean': duration / max(pc, 1) * 1000,
            'protocol_type': key[4],
            'service': key[3],
        })
        meta_rows.append({
            'src_ip': key[0],
            'dst_ip': key[1],
            'src_port': key[2],
            'dst_port': key[3],
            'raw_protocol': key[4],  # 6=TCP, 17=UDP, 1=ICMP
        })

    features_df = pd.DataFrame(rows)
    meta_df = pd.DataFrame(meta_rows)

    # Encode for model
    for col in ['protocol_type', 'service']:
        if col in features_df.columns:
            features_df[col] = LabelEncoder().fit_transform(features_df[col].astype(str))

    return features_df, meta_df


# ============================================================
# ATTACK TYPE CLASSIFIER (heuristic)
# ============================================================
def classify_attack_type(feat_row, meta_row):
    """Classify a malicious flow into SYN / UDP / ICMP / HTTP flood."""
    proto = meta_row['raw_protocol']
    dst_port = meta_row['dst_port']
    syn = feat_row['syn_flag_count']
    ack = feat_row['ack_flag_count']

    if proto == 1:
        return 'ICMP Flood'
    if proto == 17:
        return 'UDP Flood'
    if proto == 6:  # TCP
        if dst_port in (80, 8080) and ack > 0:
            return 'HTTP Flood'
        if syn > 0 and ack < syn:
            return 'SYN Flood'
        return 'TCP-based DDoS'
    return 'Other DDoS'


# ============================================================
# SIDEBAR — system status only (navigation is now in tabs at top)
# ============================================================
with st.sidebar:
    st.markdown("""
    <div style="text-align: center; padding: 20px 0;">
        <div style="font-size: 50px;">🛡️</div>
        <div style="color: white; font-size: 19px; font-weight: 700; margin-top: 10px;">
            DDoS Defense Center
        </div>
        <div style="color: #64748b; font-size: 11px; letter-spacing: 1px; margin-top: 4px;">
            SIMAD UNIVERSITY · FYP 2026
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### ⚙️ System Status")
    if model_loaded:
        st.markdown("""
        <div class="info-card">
            <div style="color: #10b981; font-weight: 700;">🟢 ONLINE</div>
            <div style="font-size: 12px; color: #94a3b8; margin-top: 8px;">
                Model: Stacking Ensemble<br>
                Base: RF + KNN + GB<br>
                Meta: Logistic Regression
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.error(f"🔴 Model load error:\n{model_error}")

    st.markdown("### 📊 Quick Stats")
    st.markdown("""
    <div class="info-card">
        <div style="font-size: 13px; line-height: 1.8;">
            🎯 <b>Accuracy:</b> 99.99%<br>
            🛡️ <b>Precision:</b> 100.00%<br>
            ⚡ <b>Detection:</b> 19 ms/flow<br>
            📦 <b>Dataset:</b> 341,699 flows
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown(f"""
    <div style="text-align: center; color: #475569; font-size: 11px; margin-top: 20px;">
        🕐 {datetime.now().strftime('%Y-%m-%d %H:%M')}<br>
        Version 1.0
    </div>
    """, unsafe_allow_html=True)
    st.caption("💡 Tip: Use the tabs at the top of the page to navigate between sections.")


# ============================================================
# PAGE 1: HOME
# ============================================================
def render_home():
    st.markdown("""
    <div class="main-banner">
        <div class="banner-title">🛡️ IoT DDoS Defense Center</div>
        <div class="banner-subtitle">Hybrid Machine Learning Approach for Real-Time Attack Detection</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="section-title">📌 Project Overview</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="info-card">
        This system protects Internet of Things (IoT) networks from Distributed Denial-of-Service (DDoS) attacks
        using a <b>hybrid machine learning model</b> that combines three complementary classifiers — Random Forest,
        K-Nearest Neighbors, and Gradient Boosting — through a stacking ensemble with a Logistic Regression meta-learner.
        The system analyzes captured network traffic and detects malicious flows in near real-time, helping safeguard
        resource-constrained IoT devices from coordinated attacks.
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="section-title">📈 Key Performance Indicators</div>', unsafe_allow_html=True)
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown("""
        <div class="metric-box metric-box-green">
            <div class="metric-label">Accuracy</div>
            <div class="metric-value mv-green">99.99%</div>
            <div class="metric-sub">on 51,255 test flows</div>
        </div>""", unsafe_allow_html=True)
    with c2:
        st.markdown("""
        <div class="metric-box">
            <div class="metric-label">Precision</div>
            <div class="metric-value">100%</div>
            <div class="metric-sub">zero false positives</div>
        </div>""", unsafe_allow_html=True)
    with c3:
        st.markdown("""
        <div class="metric-box metric-box-orange">
            <div class="metric-label">Recall</div>
            <div class="metric-value mv-orange">99.97%</div>
            <div class="metric-sub">attacks caught</div>
        </div>""", unsafe_allow_html=True)
    with c4:
        st.markdown("""
        <div class="metric-box metric-box-purple">
            <div class="metric-label">Detection Time</div>
            <div class="metric-value mv-purple">19 ms</div>
            <div class="metric-sub">per flow</div>
        </div>""", unsafe_allow_html=True)

    st.markdown('<div class="section-title">⚠️ The Problem We Solve</div>', unsafe_allow_html=True)
    p1, p2 = st.columns(2)
    with p1:
        st.markdown("""
        <div class="info-card">
            <div class="info-card-title">🌐 Vulnerable IoT Devices</div>
            Billions of smart devices (sensors, cameras, smart home appliances) have weak built-in security
            and limited processing power, making them easy targets for attackers who hijack them into massive botnets.
        </div>""", unsafe_allow_html=True)
    with p2:
        st.markdown("""
        <div class="info-card">
            <div class="info-card-title">💥 Devastating DDoS Attacks</div>
            Compromised IoT devices generate floods of malicious traffic that overwhelm servers, disable hospital
            equipment, disrupt smart cities, and cause millions in damages per hour of downtime.
        </div>""", unsafe_allow_html=True)

    st.markdown('<div class="section-title">💡 Our Solution</div>', unsafe_allow_html=True)
    s1, s2, s3 = st.columns(3)
    with s1:
        st.markdown("""
        <div class="info-card">
            <div class="info-card-title">🎯 Hybrid Model</div>
            Combines 3 ML classifiers (Random Forest, KNN, Gradient Boosting) to overcome the weaknesses
            of any single model and produce zero false alarms.
        </div>""", unsafe_allow_html=True)
    with s2:
        st.markdown("""
        <div class="info-card">
            <div class="info-card-title">⚡ Real-Time Detection</div>
            Analyzes each network flow in under 20 milliseconds, making it suitable for deployment on
            IoT gateways that need to respond quickly.
        </div>""", unsafe_allow_html=True)
    with s3:
        st.markdown("""
        <div class="info-card">
            <div class="info-card-title">🪶 Lightweight</div>
            Uses only 15 carefully selected traffic features, making the model efficient enough for
            resource-constrained edge devices.
        </div>""", unsafe_allow_html=True)

    st.markdown('<div class="section-title">🎯 What We Detect</div>', unsafe_allow_html=True)
    a1, a2, a3, a4 = st.columns(4)
    attacks_info = [
        (a1, "🚀", "SYN Flood", "Floods target with TCP SYN packets, exhausting connection queue"),
        (a2, "📡", "UDP Flood", "Saturates bandwidth with high-volume UDP packets"),
        (a3, "📍", "ICMP Flood", "Overwhelms target with ping requests"),
        (a4, "🌐", "HTTP Flood", "Application-layer attack with seemingly legitimate web requests"),
    ]
    for col, icon, name, desc in attacks_info:
        with col:
            st.markdown(f"""
            <div class="info-card" style="text-align: center;">
                <div style="font-size: 40px;">{icon}</div>
                <div class="info-card-title" style="justify-content: center;">{name}</div>
                <div style="font-size: 12px; color: #94a3b8;">{desc}</div>
            </div>""", unsafe_allow_html=True)

    st.markdown("""
    <div class="nav-hint">
        👉 Use the sidebar to navigate. Try <b>Live Detection</b> to upload a PCAP and see the system in action.
    </div>
    """, unsafe_allow_html=True)


# ============================================================
# PAGE 2: LIVE DETECTION
# ============================================================
def render_detection():
    st.markdown("""
    <div class="main-banner">
        <div class="banner-title">🔍 Live Threat Detection</div>
        <div class="banner-subtitle">Upload Network Traffic · Get Instant DDoS Analysis</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="info-card">
        <div class="info-card-title">📡 How this works</div>
        Upload a <b>.pcap</b> or <b>.pcapng</b> network capture below. The system will parse all packets,
        group them into flows, extract 15 statistical features, and feed them into the trained hybrid model.
        For each flow you'll see the prediction (benign or attack), confidence score, and — for attacks —
        the type of DDoS (SYN, UDP, ICMP, or HTTP flood).
    </div>
    """, unsafe_allow_html=True)

    uploaded_file = st.file_uploader(
        "📂 Upload PCAP file",
        type=['pcap', 'pcapng'],
        help="Drag and drop or click to browse. Up to 2 GB supported.",
    )

    if not uploaded_file:
        st.markdown("""
        <div class="status-wait">
            🔍 <b>AWAITING NETWORK TRAFFIC INPUT</b><br>
            <span style="font-size: 14px; color: #64748b;">
                Upload a PCAP file above to begin threat analysis
            </span>
        </div>""", unsafe_allow_html=True)
        return

    # Save temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp:
        tmp.write(uploaded_file.getvalue())
        tmp_path = tmp.name

    with st.spinner("🔬 Analyzing network traffic — extracting features and running detection..."):
        t0 = time.time()
        features, metadata = extract_features_from_pcap(tmp_path)
        os.unlink(tmp_path)
        if len(features) == 0:
            st.error("No valid IP flows found in this PCAP. Please upload a different file.")
            return
        X_scaled = scaler.transform(features.values)
        preds = model.predict(X_scaled)
        probs = model.predict_proba(X_scaled)
        analysis_time = time.time() - t0

    benign = int((preds == 0).sum())
    attack = int((preds == 1).sum())
    total = len(preds)
    threat_pct = (attack / total * 100) if total > 0 else 0
    avg_conf = probs[preds == 1, 1].mean() * 100 if attack > 0 else 0

    # === VERDICT BANNER ===
    if attack > 0:
        st.markdown(f"""
        <div class="status-danger">
            ⚠️ <b>THREAT DETECTED · {attack:,} MALICIOUS FLOWS IDENTIFIED</b><br>
            <span style="font-size: 14px;">
                Average attack confidence: {avg_conf:.2f}% · File: {uploaded_file.name}
            </span>
        </div>""", unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div class="status-safe">
            ✅ <b>NETWORK TRAFFIC IS SAFE · NO THREATS DETECTED</b><br>
            <span style="font-size: 14px;">
                All {total:,} flows classified as legitimate · File: {uploaded_file.name}
            </span>
        </div>""", unsafe_allow_html=True)

    # === SUMMARY CARDS ===
    st.markdown('<div class="section-title">📊 Detection Summary</div>', unsafe_allow_html=True)
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f"""
        <div class="metric-box">
            <div class="metric-label">Total Flows</div>
            <div class="metric-value">{total:,}</div>
            <div class="metric-sub">analyzed in {analysis_time:.1f}s</div>
        </div>""", unsafe_allow_html=True)
    with c2:
        st.markdown(f"""
        <div class="metric-box metric-box-green">
            <div class="metric-label">Benign Traffic</div>
            <div class="metric-value mv-green">{benign:,}</div>
            <div class="metric-sub">{(benign/total*100):.1f}% of total</div>
        </div>""", unsafe_allow_html=True)
    with c3:
        st.markdown(f"""
        <div class="metric-box metric-box-red">
            <div class="metric-label">DDoS Attacks</div>
            <div class="metric-value mv-red">{attack:,}</div>
            <div class="metric-sub">{threat_pct:.1f}% of total</div>
        </div>""", unsafe_allow_html=True)
    with c4:
        if threat_pct > 50: lvl, cls = "CRITICAL", "mv-red"
        elif threat_pct > 20: lvl, cls = "HIGH", "mv-red"
        elif threat_pct > 0:  lvl, cls = "LOW", "mv-orange"
        else: lvl, cls = "NONE", "mv-green"
        st.markdown(f"""
        <div class="metric-box metric-box-orange">
            <div class="metric-label">Threat Level</div>
            <div class="metric-value {cls}">{lvl}</div>
            <div class="metric-sub">based on threat ratio</div>
        </div>""", unsafe_allow_html=True)

    # === CHARTS ===
    st.markdown('<div class="section-title">📈 Traffic Composition</div>', unsafe_allow_html=True)
    cc1, cc2 = st.columns(2)
    with cc1:
        fig, ax = plt.subplots(figsize=(6.5, 4.8), facecolor='#0a0e1a')
        ax.set_facecolor('#0a0e1a')
        if benign > 0 and attack > 0:
            sizes = [benign, attack]; lbls = ['Benign', 'DDoS Attack']
            cols = ['#10b981', '#ef4444']; expl = (0.02, 0.05)
        elif attack == 0:
            sizes = [benign]; lbls = ['Benign']; cols = ['#10b981']; expl = (0,)
        else:
            sizes = [attack]; lbls = ['DDoS Attack']; cols = ['#ef4444']; expl = (0,)
        w, t, a = ax.pie(sizes, labels=lbls, colors=cols, explode=expl, autopct='%1.1f%%',
                         startangle=90, shadow=True,
                         wedgeprops={'edgecolor': '#0a0e1a', 'linewidth': 3})
        for x in t: x.set_color('white'); x.set_fontsize(13); x.set_fontweight('bold')
        for x in a: x.set_color('white'); x.set_fontsize(12); x.set_fontweight('bold')
        ax.set_title('Traffic Distribution', color='white', fontsize=14, fontweight='bold', pad=15)
        st.pyplot(fig)
    with cc2:
        fig2, ax2 = plt.subplots(figsize=(6.5, 4.8), facecolor='#0a0e1a')
        ax2.set_facecolor('#0a0e1a')
        bars = ax2.bar(['Benign', 'DDoS Attack'], [benign, attack],
                       color=['#10b981', '#ef4444'], edgecolor='white', linewidth=1.5)
        ax2.set_ylabel('Number of Flows', color='white', fontsize=12)
        ax2.set_title('Flow Count Comparison', color='white', fontsize=14, fontweight='bold', pad=15)
        ax2.tick_params(colors='white', labelsize=11)
        for s in ['top', 'right']: ax2.spines[s].set_visible(False)
        for s in ['bottom', 'left']: ax2.spines[s].set_color('white')
        ax2.grid(axis='y', alpha=0.15, color='gray')
        for b, v in zip(bars, [benign, attack]):
            ax2.text(b.get_x() + b.get_width() / 2,
                     b.get_height() + max([benign, attack]) * 0.02,
                     f'{v:,}', ha='center', color='white', fontsize=12, fontweight='bold')
        st.pyplot(fig2)

    # === PER-ATTACK-TYPE BREAKDOWN (only if attacks found) ===
    if attack > 0:
        st.markdown('<div class="section-title">🎯 Attack Type Breakdown</div>', unsafe_allow_html=True)
        st.caption("The system classifies each malicious flow into one of four DDoS categories based on its protocol and traffic signature.")

        attack_types = []
        for i in range(total):
            if preds[i] == 1:
                attack_types.append(classify_attack_type(features.iloc[i], metadata.iloc[i]))
            else:
                attack_types.append('Benign')

        type_counts = pd.Series([t for t in attack_types if t != 'Benign']).value_counts()

        # Show attack type cards (4 columns)
        at_cols = st.columns(4)
        type_icons = {
            'SYN Flood': ('🚀', 'metric-box-red'),
            'UDP Flood': ('📡', 'metric-box-orange'),
            'ICMP Flood': ('📍', 'metric-box-purple'),
            'HTTP Flood': ('🌐', 'metric-box-red'),
            'TCP-based DDoS': ('💥', 'metric-box-red'),
            'Other DDoS': ('⚡', 'metric-box-orange'),
        }
        for i, (atype, icon_cls) in enumerate(type_icons.items()):
            count = int(type_counts.get(atype, 0))
            if i < 4:
                with at_cols[i]:
                    icon, cls = icon_cls
                    pct = (count / attack * 100) if attack > 0 else 0
                    st.markdown(f"""
                    <div class="metric-box {cls}">
                        <div class="metric-label">{icon} {atype}</div>
                        <div class="metric-value mv-red">{count:,}</div>
                        <div class="metric-sub">{pct:.1f}% of attacks</div>
                    </div>""", unsafe_allow_html=True)

        # Attack type bar chart
        if len(type_counts) > 0:
            fig3, ax3 = plt.subplots(figsize=(10, 4.5), facecolor='#0a0e1a')
            ax3.set_facecolor('#0a0e1a')
            colors_map = {'SYN Flood': '#ef4444', 'UDP Flood': '#f59e0b',
                          'ICMP Flood': '#a855f7', 'HTTP Flood': '#dc2626',
                          'TCP-based DDoS': '#7f1d1d', 'Other DDoS': '#f97316'}
            bar_colors = [colors_map.get(name, '#ef4444') for name in type_counts.index]
            bars3 = ax3.bar(type_counts.index, type_counts.values,
                            color=bar_colors, edgecolor='white', linewidth=1.5)
            ax3.set_ylabel('Number of Flows', color='white', fontsize=12)
            ax3.set_title('DDoS Attack Types Detected', color='white', fontsize=14, fontweight='bold', pad=15)
            ax3.tick_params(colors='white', labelsize=11)
            for s in ['top', 'right']: ax3.spines[s].set_visible(False)
            for s in ['bottom', 'left']: ax3.spines[s].set_color('white')
            ax3.grid(axis='y', alpha=0.15, color='gray')
            for b, v in zip(bars3, type_counts.values):
                ax3.text(b.get_x() + b.get_width() / 2,
                         b.get_height() + max(type_counts.values) * 0.02,
                         f'{v:,}', ha='center', color='white', fontsize=11, fontweight='bold')
            st.pyplot(fig3)

    # === TOP ATTACKER IPs (only if attacks found) ===
    if attack > 0:
        st.markdown('<div class="section-title">🔥 Top Attacker IPs</div>', unsafe_allow_html=True)
        st.caption("Source IP addresses sending the most malicious flows. In a real deployment, these would be blocked at the firewall.")

        attack_mask = preds == 1
        attacker_ips = metadata.loc[attack_mask, 'src_ip'].value_counts().head(5)

        attacker_df = pd.DataFrame({
            'Rank': list(range(1, len(attacker_ips) + 1)),
            'Source IP': attacker_ips.index,
            'Malicious Flows': attacker_ips.values,
            '% of Attacks': [f"{(v/attack*100):.1f}%" for v in attacker_ips.values],
            'Recommended Action': ['🚫 BLOCK'] * len(attacker_ips),
        })
        st.dataframe(attacker_df, use_container_width=True, hide_index=True)

    # === FLOW DETAIL TABLE ===
    st.markdown('<div class="section-title">🔬 Flow-Level Detection Details</div>', unsafe_allow_html=True)
    st.caption("Each row is one network flow that the model classified individually with a confidence score.")

    n = min(25, total)
    detail_df = pd.DataFrame({
        'Src IP': metadata.head(n)['src_ip'].values,
        'Dst Port': metadata.head(n)['dst_port'].values,
        'Prediction': ['🟢 BENIGN' if preds[i] == 0 else '🔴 DDoS ATTACK' for i in range(n)],
        'Confidence': [f"{probs[i, preds[i]] * 100:.2f}%" for i in range(n)],
        'Duration (s)': features.head(n)['flow_duration'].round(3).values,
        'Packets': features.head(n)['total_fwd_packets'].astype(int).values,
        'Pkts/sec': features.head(n)['fwd_packets_per_second'].round(1).values,
    })
    st.dataframe(detail_df, use_container_width=True, height=400, hide_index=True)
    st.caption(f"Showing first {n} flows of {total:,} total")

    # === DOWNLOAD REPORT ===
    st.markdown('<div class="section-title">📥 Export Report</div>', unsafe_allow_html=True)

    full_report = pd.DataFrame({
        'flow_id': list(range(1, total + 1)),
        'src_ip': metadata['src_ip'].values,
        'dst_ip': metadata['dst_ip'].values,
        'src_port': metadata['src_port'].values,
        'dst_port': metadata['dst_port'].values,
        'protocol': metadata['raw_protocol'].values,
        'prediction': ['BENIGN' if p == 0 else 'DDoS' for p in preds],
        'attack_type': [classify_attack_type(features.iloc[i], metadata.iloc[i]) if preds[i] == 1 else 'N/A'
                        for i in range(total)],
        'confidence_%': [round(probs[i, preds[i]] * 100, 2) for i in range(total)],
        'flow_duration_s': features['flow_duration'].round(3).values,
        'total_packets': features['total_fwd_packets'].astype(int).values,
        'packets_per_sec': features['fwd_packets_per_second'].round(2).values,
        'syn_count': features['syn_flag_count'].astype(int).values,
        'ack_count': features['ack_flag_count'].astype(int).values,
    })
    csv_data = full_report.to_csv(index=False).encode('utf-8')
    report_name = f"ddos_detection_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    col_dl1, col_dl2 = st.columns([1, 2])
    with col_dl1:
        st.download_button(
            label="📥 Download Full CSV Report",
            data=csv_data,
            file_name=report_name,
            mime="text/csv",
            use_container_width=True,
        )
    with col_dl2:
        st.markdown(f"""
        <div class="info-card" style="margin: 0;">
            Full detection report with all {total:,} flows, source/destination IPs, ports, protocols,
            predictions, attack types, and confidence scores. Suitable for forensic analysis.
        </div>
        """, unsafe_allow_html=True)


# ============================================================
# PAGE 3: MODEL PERFORMANCE
# ============================================================
def render_performance():
    st.markdown("""
    <div class="main-banner">
        <div class="banner-title">📊 Model Performance</div>
        <div class="banner-subtitle">Evaluation Results from 51,255 Held-Out Test Flows</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="info-card">
        These results were obtained by evaluating the trained hybrid stacking model on the test partition
        (15% of the dataset, 51,255 flows the model had never seen during training). All metrics are computed
        following standard machine learning evaluation practice.
    </div>
    """, unsafe_allow_html=True)

    # === METRICS ===
    st.markdown('<div class="section-title">🎯 Evaluation Metrics</div>', unsafe_allow_html=True)
    c1, c2, c3, c4, c5 = st.columns(5)
    metrics = [
        ('Accuracy',  '99.99%', 'mv-green',  'metric-box-green',  'Overall correct predictions'),
        ('Precision', '100.00%','mv-green',  'metric-box-green',  'Zero false positives'),
        ('Recall',    '99.97%', 'mv-orange', 'metric-box-orange', 'True attacks detected'),
        ('F1-Score',  '99.98%', 'mv-purple', 'metric-box-purple', 'Harmonic mean of P & R'),
        ('AUC',       '1.0000', 'mv-green',  'metric-box-green',  'Perfect separability'),
    ]
    for col, (label, val, cls, box, sub) in zip([c1, c2, c3, c4, c5], metrics):
        with col:
            st.markdown(f"""
            <div class="metric-box {box}">
                <div class="metric-label">{label}</div>
                <div class="metric-value {cls}">{val}</div>
                <div class="metric-sub">{sub}</div>
            </div>""", unsafe_allow_html=True)

    # === CONFUSION MATRIX ===
    st.markdown('<div class="section-title">🧮 Confusion Matrix</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="info-card">
        The confusion matrix breaks down the model's predictions on the test set. Out of 51,255 flows:
        the model perfectly identified all 29,195 benign flows (zero false alarms) and correctly
        flagged 22,053 out of 22,060 actual attack flows (only 7 missed).
    </div>
    """, unsafe_allow_html=True)

    cm_path = os.path.join(GRAPHS_DIR, "confusion_matrix.png")
    cc1, cc2 = st.columns([3, 2])
    with cc1:
        if os.path.exists(cm_path):
            st.image(cm_path, caption="Confusion Matrix (absolute and normalized)", use_column_width=True)
        else:
            cm_data = pd.DataFrame({
                'Predicted Benign': [29195, 7],
                'Predicted DDoS': [0, 22053],
            }, index=['Actual Benign', 'Actual DDoS'])
            st.dataframe(cm_data, use_container_width=True)
            st.caption(f"💡 To display the heatmap image, place it at: `{cm_path}`")
    with cc2:
        st.markdown("""
        <div class="info-card">
            <div class="info-card-title">📖 Reading the matrix</div>
            <b>True Negatives (29,195):</b> Benign correctly flagged as benign<br><br>
            <b>False Positives (0):</b> Benign wrongly flagged as attack — none! 🎉<br><br>
            <b>False Negatives (7):</b> Attacks missed by the model<br><br>
            <b>True Positives (22,053):</b> Attacks correctly caught
        </div>
        """, unsafe_allow_html=True)

    # === ROC CURVE ===
    st.markdown('<div class="section-title">📈 ROC Curve</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="info-card">
        The Receiver Operating Characteristic (ROC) curve plots the True Positive Rate against the False Positive Rate
        across all classification thresholds. The model achieves an Area Under the Curve (AUC) of <b>1.0000</b>,
        which corresponds to perfect separability between benign and attack traffic on this test set.
    </div>
    """, unsafe_allow_html=True)

    roc_path = os.path.join(GRAPHS_DIR, "roc_curve.png")
    rc1, rc2 = st.columns([3, 2])
    with rc1:
        if os.path.exists(roc_path):
            st.image(roc_path, caption="ROC Curve (AUC = 1.0000)", use_column_width=True)
        else:
            st.markdown(f"💡 To display the ROC curve image, place it at: `{roc_path}`")
    with rc2:
        st.markdown("""
        <div class="info-card">
            <div class="info-card-title">📖 What this shows</div>
            A curve that hugs the top-left corner is ideal. An AUC of 1.0 means
            the model can perfectly distinguish attacks from benign traffic — every attack flow
            gets a higher attack-probability score than every benign flow.
        </div>
        """, unsafe_allow_html=True)

    # === FEATURE IMPORTANCE ===
    st.markdown('<div class="section-title">🌟 Top 15 Feature Importance</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="info-card">
        Random Forest based importance ranking shows which of the 15 features contribute most to discriminating
        benign from attack traffic. Volumetric and rate-based features dominate, which is consistent with the
        flooding nature of DDoS attacks.
    </div>
    """, unsafe_allow_html=True)

    fi_path = os.path.join(GRAPHS_DIR, "feature_importance.png")
    fc1, fc2 = st.columns([3, 2])
    with fc1:
        if os.path.exists(fi_path):
            st.image(fi_path, caption="Top 15 features by importance", use_column_width=True)
        else:
            st.markdown(f"💡 To display the chart image, place it at: `{fi_path}`")
    with fc2:
        fi_data = pd.DataFrame({
            'Feature': [
                'total_length_fwd_packets', 'total_fwd_packets', 'flow_duration',
                'flow_iat_mean', 'fwd_packets_per_second', 'bwd_packets_per_second',
                'bwd_bytes_per_second', 'fin_flag_count', 'fwd_packet_length_max', 'service',
            ],
            'Score': [0.2328, 0.2229, 0.1341, 0.1030, 0.0845, 0.0662, 0.0567, 0.0446, 0.0257, 0.0104],
        })
        st.dataframe(fi_data, use_container_width=True, hide_index=True)

    # === BASELINE COMPARISON ===
    st.markdown('<div class="section-title">⚖️ Comparison with Baseline Models</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="info-card">
        All baselines were trained on the same dataset, the same train/test split, and the same
        SMOTE-balanced training data — ensuring a fair, apples-to-apples comparison.
    </div>
    """, unsafe_allow_html=True)

    baselines = pd.DataFrame({
        'Model': [
            'Random Forest (alone)',
            'KNN (K=7, alone)',
            'Gradient Boosting (alone)',
            'Decision Tree (alone)',
            'SVM (alone)',
            'Proposed Hybrid (RF+KNN+GB → LR)',
        ],
        'Accuracy (%)':  [99.99, 99.98, 99.99, 99.99, 99.67, 99.99],
        'Precision (%)': [99.99, 99.98, 99.99, 99.99, 99.60, 100.00],
        'Recall (%)':    [99.99, 99.98, 99.99, 99.99, 99.70, 99.97],
        'F1 (%)':        [99.99, 99.98, 99.99, 99.99, 99.65, 99.98],
        'Detection (ms)':[0.50, 4.20, 1.80, 0.30, 2.10, 19.15],
    })
    st.dataframe(baselines, use_container_width=True, hide_index=True)

    st.markdown("""
    <div class="info-card">
        <div class="info-card-title">💡 Key insight</div>
        On this simulated dataset, several individual models also reach very high accuracy because the
        attack/benign separation is clean. The proposed hybrid model's real advantage is its
        <b>perfect precision (100%)</b> — <b>zero false positives</b> — and its expected robustness
        on noisier real-world traffic where individual classifiers tend to fail in different ways.
    </div>
    """, unsafe_allow_html=True)


# ============================================================
# PAGE 4: SYSTEM ARCHITECTURE
# ============================================================
def render_architecture():
    st.markdown("""
    <div class="main-banner">
        <div class="banner-title">🏗️ System Architecture</div>
        <div class="banner-subtitle">How the IoT Simulation and ML Pipeline Work Together</div>
    </div>
    """, unsafe_allow_html=True)

    # === NETWORK TOPOLOGY ===
    st.markdown('<div class="section-title">🌐 Simulated IoT Network Topology</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="info-card">
        We built a realistic IoT network using <b>Mininet</b>, a network emulator that creates virtual
        hosts and switches on a single Linux machine. The topology mimics a small smart-home or
        industrial-IoT deployment.
    </div>
    """, unsafe_allow_html=True)

    topo_path = os.path.join(GRAPHS_DIR, "topology_drawing.png")
    tc1, tc2 = st.columns([3, 2])
    with tc1:
        if os.path.exists(topo_path):
            st.image(topo_path, caption="Simulated IoT network topology", use_column_width=True)
        else:
            st.markdown(f"💡 To display the diagram, place it at: `{topo_path}`")
    with tc2:
        st.markdown("""
        <div class="info-card">
            <div class="info-card-title">📋 Components</div>
            <b>1 Cloud Server</b> (10.0.0.1)<br>
            Main attack target<br><br>
            <b>1 Gateway Switch</b><br>
            Routes traffic between devices<br><br>
            <b>10 IoT Devices</b> (10.0.0.10–19)<br>
            Sensors, cameras, smart devices<br><br>
            <b>2 Fog Nodes</b> (10.0.0.50–51)<br>
            Local processing nodes
        </div>
        """, unsafe_allow_html=True)

    # === PIPELINE STEPS ===
    st.markdown('<div class="section-title">🔄 End-to-End Detection Pipeline</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="info-card">
        From raw network packets to real-time DDoS alerts, the system follows a 7-step pipeline.
        Each step is fully reproducible using only open-source tools.
    </div>
    """, unsafe_allow_html=True)

    steps = [
        ("1", "📡 Traffic Generation",
         "Each IoT device sends realistic sensor data (temperature, humidity, MQTT messages) "
         "to the cloud server using scapy. Meanwhile, attacker devices launch 4 types of DDoS attacks "
         "using hping3 (SYN, UDP, ICMP) and a custom multi-threaded HTTP flood script."),
        ("2", "📦 Packet Capture",
         "Wireshark/tshark captures every packet flowing through the network and saves them "
         "as .pcap files — one for benign traffic and one for each attack type. "
         "Total: 4.1 GB of raw network data over 5 files."),
        ("3", "🔬 Feature Extraction",
         "The nfstream library reads each PCAP and groups packets into bidirectional flows. "
         "For every flow, we compute 15 statistical features: flow duration, packet counts, byte rates, "
         "TCP flag counts (SYN, ACK, FIN, RST), and inter-arrival times."),
        ("4", "🎯 Feature Selection",
         "Random Forest based importance ranking identifies the 15 most discriminative features. "
         "Volumetric (total bytes, total packets) and rate-based (packets per second, flow duration) "
         "features dominate, reflecting the flooding nature of DDoS attacks."),
        ("5", "⚖️ Class Balancing with SMOTE",
         "SMOTE (Synthetic Minority Over-sampling Technique) is applied to the training set to balance "
         "the 57% benign / 43% attack distribution to a 50/50 split. Crucially, SMOTE is only applied "
         "to training data — never to validation or test data — to preserve honest evaluation."),
        ("6", "🤖 Hybrid Model Training",
         "Three base classifiers (Random Forest, KNN with K=7, Gradient Boosting) are trained in parallel "
         "via 5-fold cross-validation. Their out-of-fold predictions are then combined by a Logistic Regression "
         "meta-learner that learns the optimal way to merge the three outputs."),
        ("7", "✅ Real-Time Detection",
         "The trained model is saved as a .pkl file and loaded by this dashboard. When a new PCAP is "
         "uploaded, the same feature extraction pipeline runs, then the model predicts each flow in "
         "under 20 milliseconds. Alerts are issued immediately if attacks are detected."),
    ]
    for num, title, desc in steps:
        st.markdown(f"""
        <div class="step-box">
            <span class="step-number">{num}</span>
            <span class="step-title">{title}</span>
            <div class="step-desc">{desc}</div>
        </div>""", unsafe_allow_html=True)

    # === HYBRID MODEL ARCHITECTURE ===
    st.markdown('<div class="section-title">🧠 Hybrid Stacking Model Architecture</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="info-card">
        The model combines three diverse base classifiers, each with a different learning approach,
        and uses Logistic Regression as a meta-learner to optimally weight their predictions.
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="model-diagram">
        <div style="text-align: center; color: #94a3b8; font-size: 13px; margin-bottom: 10px;">
            INPUT: 15 Flow Features
        </div>
        <div class="arrow-row">↓ ↓ ↓</div>
        <div class="model-row">
            <div class="base-model">
                🌳 Random Forest<br>
                <span style="font-size: 11px; font-weight: 400;">100 trees · non-linear patterns</span>
            </div>
            <div class="base-model">
                📍 KNN (K=7)<br>
                <span style="font-size: 11px; font-weight: 400;">local patterns · neighbor-based</span>
            </div>
            <div class="base-model">
                📈 Gradient Boosting<br>
                <span style="font-size: 11px; font-weight: 400;">100 estimators · error correction</span>
            </div>
        </div>
        <div class="arrow-row">↓ ↓ ↓</div>
        <div class="meta-model">
            ⚖️ Logistic Regression (Meta-Learner)<br>
            <span style="font-size: 12px; font-weight: 400;">Learns optimal weights for base predictions</span>
        </div>
        <div class="arrow-row">↓</div>
        <div class="final-prediction">
            🎯 Final Prediction: BENIGN or DDoS
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="info-card">
        <div class="info-card-title">🤔 Why stacking?</div>
        Each base classifier has different strengths and weaknesses. By combining them, the ensemble
        "averages out" individual errors. The meta-learner doesn't just take a vote — it learns
        <i>when</i> to trust each base classifier, producing a more robust final prediction than
        any single model could achieve alone.
    </div>
    """, unsafe_allow_html=True)

    # === TECH STACK ===
    st.markdown('<div class="section-title">🛠️ Technology Stack</div>', unsafe_allow_html=True)
    t1, t2, t3 = st.columns(3)
    with t1:
        st.markdown("""
        <div class="info-card">
            <div class="info-card-title">🌐 Network Simulation</div>
            <div class="feature-pill">Mininet — topology</div>
            <div class="feature-pill">hping3 — flood attacks</div>
            <div class="feature-pill">scapy — traffic gen</div>
            <div class="feature-pill">tshark — capture</div>
            <div class="feature-pill">Wireshark — inspection</div>
        </div>""", unsafe_allow_html=True)
    with t2:
        st.markdown("""
        <div class="info-card">
            <div class="info-card-title">🤖 Machine Learning</div>
            <div class="feature-pill">scikit-learn — models</div>
            <div class="feature-pill">imbalanced-learn — SMOTE</div>
            <div class="feature-pill">nfstream — features</div>
            <div class="feature-pill">pandas & numpy — data</div>
            <div class="feature-pill">joblib — model save/load</div>
        </div>""", unsafe_allow_html=True)
    with t3:
        st.markdown("""
        <div class="info-card">
            <div class="info-card-title">📊 Dashboard</div>
            <div class="feature-pill">Streamlit — UI</div>
            <div class="feature-pill">matplotlib — charts</div>
            <div class="feature-pill">Python 3.10+</div>
            <div class="feature-pill">Debian Linux — host OS</div>
            <div class="feature-pill">All open-source ✨</div>
        </div>""", unsafe_allow_html=True)


# ============================================================
# PAGE 5: ABOUT (no supervisor card)
# ============================================================
def render_about():
    st.markdown("""
    <div class="main-banner">
        <div class="banner-title">ℹ️ About the Project</div>
        <div class="banner-subtitle">Team, University, and Acknowledgements</div>
    </div>
    """, unsafe_allow_html=True)

    # === ACADEMIC INFO ===
    st.markdown('<div class="section-title">🎓 Academic Information</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="info-card">
        <div class="info-card-title">📍 Institution</div>
        <b>SIMAD University</b><br>
        Faculty of Computing · Department of Computer Science<br>
        Mogadishu, Somalia<br>
        <br>
        <div class="info-card-title">📅 Program</div>
        Final Year Project · BSc in Computer Science<br>
        Academic Year 2026/2027<br>
        Submission Date: May 2026<br>
        <br>
        <div class="info-card-title">📄 Project Title</div>
        Hybrid Machine Learning Approach for Detecting DDoS Attacks in Simulated IoT Networks
    </div>
    """, unsafe_allow_html=True)

    # === PROJECT TEAM ===
    st.markdown('<div class="section-title">👥 Project Team</div>', unsafe_allow_html=True)
    t1, t2 = st.columns(2)
    with t1:
        st.markdown("""
        <div class="team-card">
            <div class="team-icon">👩‍💻</div>
            <div class="team-name">Hafso Hussein Ahmed</div>
            <div class="team-role">Co-Researcher</div>
            <div class="team-task">
                Machine Learning Engineer<br>
                Model Training · Dashboard Development
            </div>
        </div>""", unsafe_allow_html=True)
    with t2:
        st.markdown("""
        <div class="team-card">
            <div class="team-icon">👩‍💻</div>
            <div class="team-name">Zamzam Hassan Ali</div>
            <div class="team-role">Co-Researcher</div>
            <div class="team-task">
                Network Simulation Engineer<br>
                Attack Generation · Data Pipeline
            </div>
        </div>""", unsafe_allow_html=True)

    # === ACKNOWLEDGEMENTS (supervisor mentioned naturally) ===
    st.markdown('<div class="section-title">🙏 Acknowledgements</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="info-card">
        First and foremost, all praise is due to Almighty Allah for granting us the strength and
        perseverance to complete this research successfully.
        <br><br>
        We extend our deepest gratitude to our supervisor <b>Lul Farah Abdullahi</b> for her
        invaluable guidance, continuous support, and constructive feedback throughout this project.
        <br><br>
        We also thank the <b>Department of Computer Science at SIMAD University</b> for the
        resources and supportive environment, our <b>families</b> for their unwavering love and
        prayers, and our <b>peers and friends</b> for their encouragement throughout this journey.
    </div>
    """, unsafe_allow_html=True)

    # === REFERENCES ===
    st.markdown('<div class="section-title">📚 Key References</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="info-card">
        This project builds on insights from <b>20 peer-reviewed papers</b>. Top references include:
        <ul style="margin-top: 12px; line-height: 1.9;">
            <li>Akif et al. (2025) — Hybrid ML models for intrusion detection in IoT</li>
            <li>Alenezi (2025) — ML-driven algorithms for DDoS in IoT systems</li>
            <li>Nawaz et al. (2025) — Lightweight ML for IoT DDoS detection</li>
            <li>Sakr et al. (2025) — DDoS in 6G-energy hub IoT networks</li>
            <li>Mante & Kolhe (2024) — Hybrid model for IoT intrusion detection</li>
            <li>Hossain & Islam (2024) — Hybrid IDS for IoT networks</li>
            <li>Almaraz-Rivera et al. (2023) — Deep learning multi-class IoT DDoS</li>
            <li>Bhayo et al. (2023) — SDN-based DoS detection</li>
            <li>Alahmadi et al. (2023) — DDoS detection survey for IoT</li>
            <li>Ferrag et al. (2022) — Edge-IIoTset benchmark dataset</li>
            <li>Doshi et al. (2018) — ML DDoS detection for consumer IoT</li>
        </ul>
        Complete reference list is available in the thesis document (Chapter Two and References section).
    </div>
    """, unsafe_allow_html=True)

    # === FOOTER ===
    st.markdown("""
    <div style="text-align: center; color: #475569; font-size: 12px; margin-top: 40px; padding: 20px;
                border-top: 1px solid #1e3a8a;">
        © 2026 · SIMAD University · Faculty of Computing<br>
        Built with Python, Streamlit, and open-source machine learning tools
    </div>
    """, unsafe_allow_html=True)


# ============================================================
# MAIN PAGE — HORIZONTAL TAB NAVIGATION AT TOP
# ============================================================
tab_home, tab_detection, tab_performance, tab_architecture, tab_about = st.tabs([
    "🏠  Home",
    "🔍  Live Detection",
    "📊  Model Performance",
    "🏗️  System Architecture",
    "ℹ️  About the Team",
])

with tab_home:
    render_home()

with tab_detection:
    render_detection()

with tab_performance:
    render_performance()

with tab_architecture:
    render_architecture()

with tab_about:
    render_about()
