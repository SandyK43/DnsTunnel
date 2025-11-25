"""
Interactive DNS Tunneling Detection Demo Dashboard
Built with Streamlit for real-time visualization
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import time
import requests
from typing import List, Dict
import random

# Configuration
API_BASE_URL = "http://api:8000/api/v1"
LOCAL_API_URL = "http://localhost:8000/api/v1"

# Try local first, fallback to container name
try:
    requests.get(f"{LOCAL_API_URL}/health", timeout=1)
    API_URL = LOCAL_API_URL
except:
    API_URL = API_BASE_URL

# Page config
st.set_page_config(
    page_title="DNS Tunnel Detection Demo",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
    }
    .alert-high {
        background-color: #ffebee;
        border-left: 4px solid #f44336;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
        color: #000000;
    }
    .alert-high code {
        background-color: #333333;
        color: #ffffff;
        padding: 0.2rem 0.4rem;
        border-radius: 0.25rem;
        font-family: 'Courier New', monospace;
    }
    .alert-suspicious {
        background-color: #fff3e0;
        border-left: 4px solid #ff9800;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
        color: #000000;
    }
    .alert-suspicious code {
        background-color: #333333;
        color: #ffffff;
        padding: 0.2rem 0.4rem;
        border-radius: 0.25rem;
        font-family: 'Courier New', monospace;
    }
    .alert-normal {
        background-color: #e8f5e9;
        border-left: 4px solid #4caf50;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
        color: #000000;
    }
    .alert-normal code {
        background-color: #333333;
        color: #ffffff;
        padding: 0.2rem 0.4rem;
        border-radius: 0.25rem;
        font-family: 'Courier New', monospace;
    }
    .remediation {
        background-color: #f5f5f5;
        padding: 0.5rem;
        margin-top: 0.5rem;
        border-radius: 0.25rem;
        font-size: 0.9rem;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'attack_history' not in st.session_state:
    st.session_state.attack_history = []
if 'stats' not in st.session_state:
    st.session_state.stats = {
        'total_queries': 0,
        'normal': 0,
        'suspicious': 0,
        'high': 0
    }
if 'auto_refresh' not in st.session_state:
    st.session_state.auto_refresh = False

# Helper functions
def generate_dnscat2_query() -> str:
    """Generate a dnscat2-style DNS query"""
    chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    subdomain = ''.join(random.choices(chars, k=random.randint(20, 40)))
    return f"{subdomain}.dnscat.example.com"

def generate_iodine_query() -> str:
    """Generate an iodine-style DNS query"""
    # Base32-like encoding
    chars = 'abcdefghijklmnopqrstuvwxyz234567'
    subdomain = ''.join(random.choices(chars, k=random.randint(25, 45)))
    return f"{subdomain}.t1.iodine.example.com"

def generate_custom_exfil_query() -> str:
    """Generate a custom data exfiltration query"""
    # Hex-encoded data
    hex_data = ''.join(random.choices('0123456789abcdef', k=random.randint(30, 50)))
    return f"{hex_data}.data.exfil.example.com"

def generate_normal_query() -> str:
    """Generate a normal DNS query"""
    domains = [
        "www.google.com", "api.github.com", "www.amazon.com",
        "mail.example.com", "docs.python.org", "www.wikipedia.org",
        "cdn.jsdelivr.net", "fonts.googleapis.com", "www.reddit.com"
    ]
    return random.choice(domains)

def analyze_query(query: str, client_ip: str = None) -> Dict:
    """Send query to API for analysis"""
    if client_ip is None:
        client_ip = f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}"

    try:
        response = requests.post(
            f"{API_URL}/dns/analyze",
            json={"query": query, "client_ip": client_ip},
            timeout=5
        )
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"API returned {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def get_stats() -> Dict:
    """Get system statistics"""
    try:
        response = requests.get(f"{API_URL}/stats", timeout=5)
        if response.status_code == 200:
            return response.json()
        return {}
    except:
        return {}

def get_recent_alerts(limit: int = 10) -> List[Dict]:
    """Get recent alerts"""
    try:
        response = requests.get(f"{API_URL}/alerts?limit={limit}", timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get('alerts', [])
        return []
    except:
        return []

# Header
st.markdown('<div class="main-header">🔒 DNS Tunneling Detection Demo</div>', unsafe_allow_html=True)
st.markdown("Real-time DNS tunnel detection using Machine Learning")

# Sidebar
with st.sidebar:
    st.header("⚙️ Controls")

    st.subheader("Scenario Simulator")

    scenario = st.selectbox(
        "Select Scenario",
        [
            "🟢 Normal Business Day",
            "🔴 Data Exfiltration Attack",
            "⚠️ Malware C2 Communication",
            "🟡 Insider Threat Activity",
            "🔥 Zero-Day Outbreak"
        ]
    )

    if st.button("▶️ Run Scenario", type="primary", use_container_width=True):
        # Define scenario patterns
        scenarios = {
            "🟢 Normal Business Day": [
                ("normal", 30, "Morning traffic"),
                ("normal", 40, "Peak business hours"),
                ("normal", 20, "Afternoon activity"),
                ("normal", 10, "Evening wind-down")
            ],
            "🔴 Data Exfiltration Attack": [
                ("normal", 20, "Normal baseline"),
                ("mixed_light", 15, "Attack preparation"),
                ("exfil_heavy", 25, "Active exfiltration"),
                ("mixed_light", 10, "Covering tracks"),
                ("normal", 10, "Return to normal")
            ],
            "⚠️ Malware C2 Communication": [
                ("normal", 25, "Pre-infection"),
                ("c2_beacon", 15, "Initial C2 beacon"),
                ("normal", 10, "Dormant period"),
                ("c2_burst", 20, "Command execution"),
                ("normal", 10, "Post-activity")
            ],
            "🟡 Insider Threat Activity": [
                ("normal", 30, "Normal work hours"),
                ("insider_recon", 15, "Reconnaissance"),
                ("insider_exfil", 20, "Data theft"),
                ("normal", 15, "Cleanup")
            ],
            "🔥 Zero-Day Outbreak": [
                ("normal", 25, "Pre-outbreak"),
                ("outbreak_start", 15, "Initial infection"),
                ("outbreak_spread", 30, "Rapid spread"),
                ("mixed_heavy", 20, "Peak activity"),
                ("containment", 10, "Containment efforts")
            ]
        }

        pattern = scenarios[scenario]
        total_queries = sum(count for _, count, _ in pattern)

        with st.spinner(f"Running scenario: {scenario}"):
            progress_bar = st.progress(0)
            status_text = st.empty()
            queries_processed = 0

            for phase_type, phase_count, phase_desc in pattern:
                status_text.text(f"📊 Phase: {phase_desc}")

                for i in range(phase_count):
                    # Generate query based on phase
                    if phase_type == "normal":
                        query = generate_normal_query()
                    elif phase_type == "mixed_light":
                        query = generate_normal_query() if random.random() < 0.7 else generate_dnscat2_query()
                    elif phase_type == "exfil_heavy":
                        query = generate_custom_exfil_query()
                    elif phase_type == "c2_beacon":
                        query = generate_iodine_query() if random.random() < 0.6 else generate_normal_query()
                    elif phase_type == "c2_burst":
                        query = generate_dnscat2_query()
                    elif phase_type == "insider_recon":
                        query = generate_normal_query() if random.random() < 0.5 else generate_custom_exfil_query()
                    elif phase_type == "insider_exfil":
                        query = generate_custom_exfil_query()
                    elif phase_type == "outbreak_start":
                        query = generate_dnscat2_query() if random.random() < 0.4 else generate_normal_query()
                    elif phase_type == "outbreak_spread":
                        query = generate_dnscat2_query() if random.random() < 0.7 else generate_iodine_query()
                    elif phase_type == "mixed_heavy":
                        generators = [generate_dnscat2_query, generate_iodine_query, generate_custom_exfil_query]
                        query = random.choice(generators)()
                    elif phase_type == "containment":
                        query = generate_normal_query() if random.random() < 0.8 else generate_dnscat2_query()
                    else:
                        query = generate_normal_query()

                    # Analyze
                    result = analyze_query(query)

                    if 'error' not in result:
                        st.session_state.attack_history.insert(0, result)

                        # Update stats
                        st.session_state.stats['total_queries'] += 1
                        severity = result.get('severity', 'NORMAL')
                        if severity == 'HIGH':
                            st.session_state.stats['high'] += 1
                        elif severity == 'SUSPICIOUS':
                            st.session_state.stats['suspicious'] += 1
                        else:
                            st.session_state.stats['normal'] += 1

                        # Keep only last 100 entries
                        if len(st.session_state.attack_history) > 100:
                            st.session_state.attack_history = st.session_state.attack_history[:100]

                    queries_processed += 1
                    progress_bar.progress(queries_processed / total_queries)
                    time.sleep(0.05)  # Faster for scenarios

            status_text.empty()
            st.success(f"✅ Scenario complete! Analyzed {total_queries} queries across {len(pattern)} phases.")

    st.divider()

    if st.button("🔄 Refresh Data", use_container_width=True):
        st.rerun()

    if st.button("🗑️ Clear History", use_container_width=True):
        st.session_state.attack_history = []
        st.session_state.stats = {
            'total_queries': 0,
            'normal': 0,
            'suspicious': 0,
            'high': 0
        }
        st.rerun()

    st.divider()

    # Use session state to control expander to prevent duplication
    if 'about_expanded' not in st.session_state:
        st.session_state.about_expanded = False

    about_expanded = st.expander("ℹ️ About Scenarios", expanded=st.session_state.about_expanded)
    with about_expanded:
        st.markdown("""
        **🟢 Normal Business Day**: Typical corporate traffic with no threats

        **🔴 Data Exfiltration Attack**: Attacker slowly exfiltrates data via DNS

        **⚠️ Malware C2 Communication**: Infected machine beaconing to command server

        **🟡 Insider Threat Activity**: Employee stealing data before leaving

        **🔥 Zero-Day Outbreak**: Malware spreading rapidly through network
        """)

# Main content
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        "Total Queries",
        st.session_state.stats['total_queries'],
        delta=None
    )

with col2:
    st.metric(
        "🟢 Normal",
        st.session_state.stats['normal'],
        delta=None
    )

with col3:
    st.metric(
        "🟡 Suspicious",
        st.session_state.stats['suspicious'],
        delta=None
    )

with col4:
    st.metric(
        "🔴 High Risk",
        st.session_state.stats['high'],
        delta=None
    )

st.divider()

# Tabs
tab1, tab2, tab3, tab4 = st.tabs(["📊 Real-Time Results", "📈 Analytics", "🚨 Alert Feed", "ℹ️ About"])

with tab1:
    st.subheader("Recent Detections")

    if st.session_state.attack_history:
        for entry in st.session_state.attack_history[:20]:
            severity = entry.get('severity', 'NORMAL')
            score = entry.get('anomaly_score', 0)
            query = entry.get('query', 'N/A')
            timestamp = entry.get('timestamp', 'N/A')

            if severity == 'HIGH':
                css_class = "alert-high"
                icon = "🔴"
                remediation_html = '<div class="remediation"><strong>🛡️ Recommended Actions:</strong><br>• Immediately isolate client system from network<br>• Investigate client for malware/tunneling tools<br>• Review DNS logs for past 24 hours from this IP<br>• Block domain at firewall/DNS filter<br>• Escalate to security team</div>'
            elif severity == 'SUSPICIOUS':
                css_class = "alert-suspicious"
                icon = "🟡"
                remediation_html = '<div class="remediation"><strong>⚠️ Recommended Actions:</strong><br>• Monitor client system for additional activity<br>• Review query patterns for anomalies<br>• Consider blocking if pattern continues<br>• Add to watchlist for 24-48 hours</div>'
            else:
                css_class = "alert-normal"
                icon = "🟢"
                remediation_html = ''

            # Build the HTML in one go
            html = f'<div class="{css_class}"><strong>{icon} {severity}</strong> | Score: {score:.4f}<br><code>{query}</code><br><small>{timestamp}</small>{remediation_html}</div>'

            st.markdown(html, unsafe_allow_html=True)
    else:
        st.info("👈 Use the sidebar to simulate DNS tunnel attacks and see detection results here!")

with tab2:
    st.subheader("Detection Analytics")

    if st.session_state.attack_history:
        # Convert to DataFrame
        df = pd.DataFrame(st.session_state.attack_history)

        col1, col2 = st.columns(2)

        with col1:
            # Severity distribution pie chart
            severity_counts = df['severity'].value_counts()
            fig_pie = px.pie(
                values=severity_counts.values,
                names=severity_counts.index,
                title="Severity Distribution",
                color=severity_counts.index,
                color_discrete_map={
                    'NORMAL': '#4caf50',
                    'SUSPICIOUS': '#ff9800',
                    'HIGH': '#f44336'
                }
            )
            st.plotly_chart(fig_pie, use_container_width=True)

        with col2:
            # Anomaly score distribution
            fig_hist = px.histogram(
                df,
                x='anomaly_score',
                nbins=30,
                title="Anomaly Score Distribution",
                labels={'anomaly_score': 'Anomaly Score'},
                color_discrete_sequence=['#1f77b4']
            )
            st.plotly_chart(fig_hist, use_container_width=True)

        # Feature analysis
        st.subheader("Feature Analysis")

        if 'features' in df.columns and len(df) > 0:
            features_df = pd.json_normalize(df['features'])

            col1, col2 = st.columns(2)

            with col1:
                # Entropy vs Query Length
                fig_scatter = px.scatter(
                    x=features_df['len_q'],
                    y=features_df['entropy'],
                    color=df['severity'],
                    title="Query Length vs Entropy",
                    labels={'x': 'Query Length', 'y': 'Entropy'},
                    color_discrete_map={
                        'NORMAL': '#4caf50',
                        'SUSPICIOUS': '#ff9800',
                        'HIGH': '#f44336'
                    }
                )
                st.plotly_chart(fig_scatter, use_container_width=True)

            with col2:
                # Feature comparison
                feature_cols = ['len_q', 'entropy', 'num_labels', 'max_label_len']
                available_cols = [col for col in feature_cols if col in features_df.columns]

                if available_cols:
                    fig_box = go.Figure()
                    for col in available_cols:
                        fig_box.add_trace(go.Box(y=features_df[col], name=col))

                    fig_box.update_layout(title="Feature Value Ranges")
                    st.plotly_chart(fig_box, use_container_width=True)
    else:
        st.info("Generate some queries to see analytics!")

with tab3:
    st.subheader("Alert Feed")

    # Get recent alerts from API
    alerts = get_recent_alerts(20)

    if alerts:
        for alert in alerts:
            severity = alert.get('severity', 'NORMAL')
            domain = alert.get('domain', 'N/A')
            score = alert.get('anomaly_score', 0)
            timestamp = alert.get('timestamp', 'N/A')

            if severity == 'HIGH':
                st.error(f"🔴 **HIGH RISK** | Score: {score:.4f} | Domain: `{domain}` | {timestamp}")
            elif severity == 'SUSPICIOUS':
                st.warning(f"🟡 **SUSPICIOUS** | Score: {score:.4f} | Domain: `{domain}` | {timestamp}")
            else:
                st.success(f"🟢 **NORMAL** | Score: {score:.4f} | Domain: `{domain}` | {timestamp}")
    else:
        st.info("No alerts yet. Start generating queries to create alerts!")

with tab4:
    st.subheader("About DNS Tunneling Detection")

    st.markdown("""
    ### 🎯 What is DNS Tunneling?

    DNS tunneling is a technique used to exfiltrate data or establish command-and-control
    channels by encoding data within DNS queries and responses. Attackers abuse DNS because:

    - DNS traffic is rarely blocked
    - It can bypass many security controls
    - It's often unmonitored

    ### 🔍 How This System Works

    Our ML-based detection system analyzes DNS queries in real-time using:

    1. **Feature Extraction**: Extracts characteristics like:
       - Query length and entropy
       - Label structure and patterns
       - Character distribution (digits, special chars)
       - Query frequency patterns

    2. **Anomaly Detection**: Uses Isolation Forest ML algorithm to:
       - Score each query based on learned baseline
       - Identify unusual patterns
       - Classify severity (Normal/Suspicious/High)

    3. **Real-Time Alerting**: Sends alerts through:
       - Slack, Microsoft Teams
       - Email notifications
       - JIRA ticket creation

    ### 🛡️ Common DNS Tunnel Tools Detected

    - **DNSCat2**: Creates an encrypted C2 channel over DNS
    - **Iodine**: Tunnels IPv4 data through DNS servers
    - **Custom Exfiltration**: Base64/hex-encoded data extraction

    ### 📊 Features Analyzed

    - `len_q`: Total query length
    - `entropy`: Shannon entropy (randomness)
    - `num_labels`: Number of DNS labels
    - `max_label_len`: Longest label length
    - `digits_ratio`: Percentage of numeric characters
    - `non_alnum_ratio`: Special character percentage
    - `qps`: Queries per second from same source

    ### 🚀 Try It Yourself

    Use the sidebar to:
    1. Select an attack type
    2. Choose number of queries
    3. Click "Launch Attack"
    4. Watch real-time detection in action!
    """)

    st.divider()

    st.markdown("""
    <div style='text-align: center; color: #888;'>
        <p>Built with Streamlit | Powered by Machine Learning</p>
        <p>🔒 Enterprise DNS Security Solution</p>
    </div>
    """, unsafe_allow_html=True)

# Auto-refresh option
st.sidebar.divider()
st.session_state.auto_refresh = st.sidebar.checkbox(
    "🔄 Auto-refresh (every 5s)",
    value=st.session_state.auto_refresh,
    key="auto_refresh_checkbox"
)
if st.session_state.auto_refresh:
    time.sleep(5)
    st.rerun()
