import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import joblib
import warnings
from pathlib import Path
warnings.filterwarnings('ignore')

ROOT_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT_DIR / 'data'
MODEL_DIR = ROOT_DIR / 'ml_pipeline' / 'models'

# ============================================================
# PAGE CONFIG
# ============================================================
st.set_page_config(
    page_title="IoT Honeypot Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================
# LOAD DATA (cached so it doesn't reload on every interaction)
# ============================================================
@st.cache_data
def load_data():
    auth = pd.read_csv(DATA_DIR / 'auth_final.csv')
    sessions = pd.read_csv(DATA_DIR / 'sessions_with_mitre.csv')
    enriched_ips = pd.read_csv(DATA_DIR / 'enriched_ip_data.csv')
    full = pd.read_csv(DATA_DIR / 'full_enriched_sessions.csv')

    # Fix timestamps
    auth['timestamp'] = pd.to_datetime(auth['timestamp'])
    sessions['starttime'] = pd.to_datetime(sessions['starttime'])
    sessions['endtime'] = pd.to_datetime(sessions['endtime'])
    full['starttime'] = pd.to_datetime(full['starttime'])

    # Fix boolean
    auth['success'] = auth['success'].map(
        {'t': True, 'f': False, True: True, False: False}
    )

    return auth, sessions, enriched_ips, full

@st.cache_resource
def load_model():
    model = joblib.load(MODEL_DIR / 'isolation_forest_model.pkl')
    scaler = joblib.load(MODEL_DIR / 'scaler.pkl')
    return model, scaler

auth_df, sessions_df, enriched_df, full_df = load_data()
iso_model, scaler = load_model()

# ============================================================
# SIDEBAR
# ============================================================
st.sidebar.image(
    "https://img.icons8.com/color/96/000000/honeypot.png",
    width=80
)
st.sidebar.title("IoT Honeypot Dashboard")
st.sidebar.markdown("---")

page = st.sidebar.radio(
    "Navigation",
    [
        "📊 Overview",
        "🌍 Geographic Analysis",
        "🤖 ML Detection Results",
        "🔐 Credential Analysis",
        "⚔️ MITRE ATT&CK",
        "🎯 Live Threat Predictor"
    ]
)

st.sidebar.markdown("---")
st.sidebar.markdown("**Dataset Summary**")
st.sidebar.metric("Total Sessions", f"{len(sessions_df):,}")
st.sidebar.metric("Auth Attempts", f"{len(auth_df):,}")
st.sidebar.metric("Unique Attacker IPs", f"{full_df['ip'].nunique()}")
st.sidebar.metric("Countries", f"{full_df['country'].nunique()}")

date_min = auth_df['timestamp'].min().strftime('%Y-%m-%d')
date_max = auth_df['timestamp'].max().strftime('%Y-%m-%d')
st.sidebar.markdown(f"**Collection period:**")
st.sidebar.markdown(f"{date_min} → {date_max}")

# ============================================================
# PAGE 1: OVERVIEW
# ============================================================
if page == "📊 Overview":
    st.title("🛡️ IoT Honeypot Threat Intelligence Dashboard")
    st.markdown(
        "Real-world attack data captured from a live IoT device "
        "fleet honeypot deployed on AWS EC2. All data reflects "
        "genuine attacker activity."
    )
    st.markdown("---")

    # Key metrics row
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric(
            "Total Login Attempts",
            f"{len(auth_df):,}",
            delta="Real attacker data"
        )
    with col2:
        st.metric(
            "Unique Attacker IPs",
            f"{full_df['ip'].nunique()}",
            delta=f"{full_df['country'].nunique()} countries"
        )
    with col3:
        critical = len(enriched_df[
            enriched_df['abuse_confidence_score'] >= 80
        ])
        st.metric(
            "Critical Threat IPs",
            f"{critical}",
            delta="AbuseIPDB score ≥ 80"
        )
    with col4:
        known = len(enriched_df[enriched_df['total_reports'] > 0])
        pct = known / len(enriched_df) * 100
        st.metric(
            "Known Malicious IPs",
            f"{known}/101",
            delta=f"{pct:.0f}% already reported"
        )
    with col5:
        attacks = len(sessions_df[
            sessions_df['iso_label'] == 'attack'
        ])
        st.metric(
            "ML Flagged Sessions",
            f"{attacks:,}",
            delta="Isolation Forest"
        )

    st.markdown("---")

    # Attacks over time
    st.subheader("Attack Frequency Over Time")
    hourly = auth_df.set_index('timestamp').resample('h').size(
    ).reset_index()
    hourly.columns = ['time', 'attacks']
    fig = px.area(
        hourly, x='time', y='attacks',
        color_discrete_sequence=['#e74c3c'],
        labels={'attacks': 'Login Attempts', 'time': 'Date/Time'}
    )
    fig.update_layout(
        height=300,
        margin=dict(l=0, r=0, t=0, b=0),
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)'
    )
    st.plotly_chart(fig, use_container_width=True)

    # Two columns — countries and threat levels
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Top Attacking Countries")
        country_counts = full_df['country'].value_counts().head(
            10).reset_index()
        country_counts.columns = ['Country', 'Sessions']
        fig = px.bar(
            country_counts, x='Sessions', y='Country',
            orientation='h',
            color='Sessions',
            color_continuous_scale='Reds'
        )
        fig.update_layout(
            height=350,
            margin=dict(l=0, r=0, t=0, b=0),
            yaxis={'categoryorder': 'total ascending'},
            coloraxis_showscale=False
        )
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Threat Level Distribution")
        threat_counts = enriched_df[
            'threat_level'].value_counts().reset_index()
        threat_counts.columns = ['Threat Level', 'Count']
        colors = {
            'Critical': '#c0392b',
            'High': '#e74c3c',
            'Medium': '#f39c12',
            'Low': '#f1c40f',
            'Unknown': '#95a5a6'
        }
        fig = px.pie(
            threat_counts,
            values='Count',
            names='Threat Level',
            color='Threat Level',
            color_discrete_map=colors,
            hole=0.4
        )
        fig.update_layout(
            height=350,
            margin=dict(l=0, r=0, t=0, b=0)
        )
        st.plotly_chart(fig, use_container_width=True)

    # Recent high-threat sessions
    st.subheader("Recent High-Threat Sessions")
    recent = full_df[
        full_df['abuse_confidence_score'] >= 50
    ].sort_values('starttime', ascending=False).head(10)[[
        'starttime', 'ip', 'country',
        'abuse_confidence_score', 'threat_level',
        'iso_label', 'mitre_techniques'
    ]].copy()
    recent.columns = [
        'Time', 'IP', 'Country',
        'Abuse Score', 'Threat Level',
        'ML Label', 'MITRE Techniques'
    ]
    st.dataframe(recent, use_container_width=True)

# ============================================================
# PAGE 2: GEOGRAPHIC ANALYSIS
# ============================================================
elif page == "🌍 Geographic Analysis":
    st.title("🌍 Geographic Attack Analysis")
    st.markdown("---")

    # World map
    st.subheader("Attacker Locations — World Map")
    map_data = enriched_df[
    enriched_df['latitude'].notna() & 
    enriched_df['longitude'].notna()
].copy()

    fig = px.scatter_geo(
        map_data,
        lat='latitude',
        lon='longitude',
        color='threat_level',
        hover_name='ip',
        hover_data={
            'country': True,
            'abuse_confidence_score': True,
            'threat_level': True,
            'latitude': False,
            'longitude': False
        },
        color_discrete_map={
            'Critical': '#c0392b',
            'High': '#e74c3c',
            'Medium': '#f39c12',
            'Low': '#f1c40f',
            'Unknown': '#95a5a6'
        },
        size='abuse_confidence_score',
        size_max=20,
        projection='natural earth',
        title='Attacker IP Locations (sized by abuse confidence score)'
    )
    fig.update_layout(height=500)
    st.plotly_chart(fig, use_container_width=True)

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Sessions by Country")
        country_sessions = full_df[
            full_df['country'] != 'Unknown'
        ]['country'].value_counts().reset_index()
        country_sessions.columns = ['Country', 'Sessions']
        fig = px.bar(
            country_sessions.head(15),
            x='Country', y='Sessions',
            color='Sessions',
            color_continuous_scale='Reds'
        )
        fig.update_layout(
            height=350,
            xaxis_tickangle=-45,
            coloraxis_showscale=False
        )
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Top Attacker ISPs")
        isp_counts = enriched_df[
            enriched_df['isp'] != 'Unknown'
        ]['isp'].value_counts().head(10).reset_index()
        isp_counts.columns = ['ISP', 'Count']
        fig = px.bar(
            isp_counts,
            x='Count', y='ISP',
            orientation='h',
            color='Count',
            color_continuous_scale='Blues'
        )
        fig.update_layout(
            height=350,
            yaxis={'categoryorder': 'total ascending'},
            coloraxis_showscale=False
        )
        st.plotly_chart(fig, use_container_width=True)

    # Full IP reputation table
    st.subheader("Complete IP Reputation Table")
    col_filter1, col_filter2 = st.columns(2)
    with col_filter1:
        threat_filter = st.multiselect(
            "Filter by Threat Level",
            options=enriched_df['threat_level'].unique(),
            default=enriched_df['threat_level'].unique()
        )
    with col_filter2:
        min_score = st.slider(
            "Minimum Abuse Score", 0, 100, 0
        )

    filtered = enriched_df[
        (enriched_df['threat_level'].isin(threat_filter)) &
        (enriched_df['abuse_confidence_score'] >= min_score)
    ][[
        'ip', 'country', 'city', 'isp',
        'abuse_confidence_score', 'total_reports',
        'threat_level', 'is_tor'
    ]].sort_values('abuse_confidence_score', ascending=False)

    st.dataframe(filtered, use_container_width=True)
    st.caption(f"Showing {len(filtered)} of {len(enriched_df)} IPs")

# ============================================================
# PAGE 3: ML DETECTION RESULTS
# ============================================================
elif page == "🤖 ML Detection Results":
    st.title("🤖 ML-Based Intrusion Detection Results")
    st.markdown(
        "Three unsupervised anomaly detection models trained on "
        "real honeypot session behavioral features."
    )
    st.markdown("---")

    # Model comparison
    col1, col2, col3 = st.columns(3)
    models = [
        ('Isolation Forest', 'iso_label'),
        ('One-Class SVM', 'ocsvm_label'),
        ('Autoencoder', 'ae_label')
    ]
    for col, (name, label_col) in zip([col1, col2, col3], models):
        with col:
            if label_col in sessions_df.columns:
                counts = sessions_df[label_col].value_counts()
                attack_count = counts.get('attack', 0)
                normal_count = counts.get('normal', 0)
                total = attack_count + normal_count
                st.metric(
                    name,
                    f"{attack_count:,} attacks",
                    delta=f"{attack_count/total*100:.1f}% of sessions"
                )

    st.markdown("---")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Isolation Forest — Anomaly Score Distribution")
        fig = px.histogram(
            sessions_df,
            x='iso_score',
            nbins=50,
            color_discrete_sequence=['#3498db'],
            labels={'iso_score': 'Anomaly Score',
                    'count': 'Session Count'}
        )
        fig.add_vline(
            x=sessions_df['iso_score'].quantile(0.1),
            line_dash='dash',
            line_color='red',
            annotation_text='Attack threshold'
        )
        fig.update_layout(height=350)
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Detection Label Distribution")
        if 'iso_label' in sessions_df.columns:
            label_counts = sessions_df[
                'iso_label'].value_counts().reset_index()
            label_counts.columns = ['Label', 'Count']
            fig = px.pie(
                label_counts,
                values='Count',
                names='Label',
                color='Label',
                color_discrete_map={
                    'normal': '#2ecc71',
                    'attack': '#e74c3c'
                },
                hole=0.4
            )
            fig.update_layout(height=350)
            st.plotly_chart(fig, use_container_width=True)

    # Feature distributions
    st.subheader("Behavioral Feature Comparison — Normal vs Attack")
    feature = st.selectbox(
        "Select feature to compare",
        ['duration_seconds', 'total_attempts',
         'attempts_per_second', 'unique_usernames',
         'failure_count', 'hour_of_day']
    )

    if 'iso_label' in sessions_df.columns:
        fig = px.box(
            sessions_df[sessions_df[feature] < sessions_df[
                feature].quantile(0.99)],
            x='iso_label', y=feature,
            color='iso_label',
            color_discrete_map={
                'normal': '#2ecc71',
                'attack': '#e74c3c'
            },
            labels={'iso_label': 'ML Label', feature: feature}
        )
        fig.update_layout(height=350)
        st.plotly_chart(fig, use_container_width=True)

    # Most suspicious sessions
    st.subheader("Top 20 Most Suspicious Sessions")
    suspicious = sessions_df.nsmallest(20, 'iso_score')[[
        'starttime', 'ip', 'duration_seconds',
        'total_attempts', 'attempts_per_second',
        'unique_usernames', 'iso_score', 'iso_label'
    ]].copy() if 'starttime' in sessions_df.columns else \
        sessions_df.nsmallest(20, 'iso_score')[[
            'ip', 'duration_seconds', 'total_attempts',
            'attempts_per_second', 'unique_usernames',
            'iso_score', 'iso_label'
        ]].copy()
    st.dataframe(suspicious, use_container_width=True)

# ============================================================
# PAGE 4: CREDENTIAL ANALYSIS
# ============================================================
elif page == "🔐 Credential Analysis":
    st.title("🔐 Attacker Credential Analysis")
    st.markdown(
        "Analysis of 28,794 real login attempts captured "
        "by the Cowrie SSH honeypot."
    )
    st.markdown("---")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Top 15 Usernames Tried")
        top_users = auth_df['username'].value_counts(
        ).head(15).reset_index()
        top_users.columns = ['Username', 'Attempts']
        fig = px.bar(
            top_users,
            x='Attempts', y='Username',
            orientation='h',
            color='Attempts',
            color_continuous_scale='Reds'
        )
        fig.update_layout(
            height=400,
            yaxis={'categoryorder': 'total ascending'},
            coloraxis_showscale=False
        )
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Top 15 Passwords Tried")
        top_passwords = auth_df['password'].value_counts(
        ).head(15).reset_index()
        top_passwords.columns = ['Password', 'Attempts']
        fig = px.bar(
            top_passwords,
            x='Attempts', y='Password',
            orientation='h',
            color='Attempts',
            color_continuous_scale='Blues'
        )
        fig.update_layout(
            height=400,
            yaxis={'categoryorder': 'total ascending'},
            coloraxis_showscale=False
        )
        st.plotly_chart(fig, use_container_width=True)

    # Attack timing
    st.subheader("Attack Frequency by Hour of Day")
    hourly_dist = auth_df.copy()
    hourly_dist['hour'] = auth_df['timestamp'].dt.hour
    hour_counts = hourly_dist['hour'].value_counts(
    ).sort_index().reset_index()
    hour_counts.columns = ['Hour', 'Attacks']
    fig = px.bar(
        hour_counts, x='Hour', y='Attacks',
        color='Attacks',
        color_continuous_scale='Reds',
        labels={'Hour': 'Hour of Day (UTC)',
                'Attacks': 'Login Attempts'}
    )
    fig.update_layout(
        height=300,
        coloraxis_showscale=False,
        xaxis=dict(tickmode='linear', tick0=0, dtick=1)
    )
    st.plotly_chart(fig, use_container_width=True)

    # Daily attack trend
    st.subheader("Daily Attack Volume Trend")
    daily = auth_df.set_index('timestamp').resample(
        'D').size().reset_index()
    daily.columns = ['Date', 'Attacks']
    fig = px.line(
        daily, x='Date', y='Attacks',
        color_discrete_sequence=['#e74c3c'],
        markers=True
    )
    fig.update_layout(height=300)
    st.plotly_chart(fig, use_container_width=True)

    # Credential search
    st.subheader("Search Credentials")
    search = st.text_input(
        "Search for a specific username or password:"
    )
    if search:
        results = auth_df[
            auth_df['username'].str.contains(
                search, case=False, na=False) |
            auth_df['password'].str.contains(
                search, case=False, na=False)
        ][['timestamp', 'username', 'password', 'success']]
        st.dataframe(results, use_container_width=True)
        st.caption(f"Found {len(results)} matching records")

# ============================================================
# PAGE 5: MITRE ATT&CK
# ============================================================
elif page == "⚔️ MITRE ATT&CK":
    st.title("⚔️ MITRE ATT&CK Framework Mapping")
    st.markdown(
        "Observed attacker behaviors mapped to the MITRE ATT&CK "
        "framework — the industry-standard taxonomy for "
        "categorizing cyber attack techniques."
    )
    st.markdown("---")

    mitre_reference = {
        'T1595.001': {
            'name': 'Active Scanning: Scanning IP Blocks',
            'tactic': 'Reconnaissance',
            'color': '#9b59b6',
            'description': (
                'Adversaries scan victim IP blocks to gather '
                'information about open ports and services.'
            )
        },
        'T1110.001': {
            'name': 'Brute Force: Password Guessing',
            'tactic': 'Credential Access',
            'color': '#e74c3c',
            'description': (
                'Adversaries attempt to guess credentials to '
                'gain unauthorized access.'
            )
        },
        'T1110.003': {
            'name': 'Brute Force: Password Spraying',
            'tactic': 'Credential Access',
            'color': '#c0392b',
            'description': (
                'Using a small number of commonly used passwords '
                'against many different accounts.'
            )
        },
        'T1078': {
            'name': 'Valid Accounts',
            'tactic': 'Defense Evasion / Persistence',
            'color': '#f39c12',
            'description': (
                'Adversaries use credentials of existing accounts '
                'to bypass access controls.'
            )
        },
        'T1021.004': {
            'name': 'Remote Services: SSH',
            'tactic': 'Lateral Movement',
            'color': '#3498db',
            'description': (
                'Adversaries use SSH to log into remote machines '
                'using valid credentials.'
            )
        }
    }

    # Technique frequency
    from collections import Counter
    all_techniques = []
    for t in sessions_df['mitre_techniques'].dropna():
        all_techniques.extend(t.split(', '))
    technique_counts = Counter(all_techniques)

    st.subheader("Technique Frequency")
    tech_df = pd.DataFrame([
        {
            'Technique ID': t,
            'Name': mitre_reference.get(t, {}).get('name', t),
            'Tactic': mitre_reference.get(t, {}).get(
                'tactic', 'Unknown'),
            'Sessions': c
        }
        for t, c in technique_counts.most_common()
    ])

    fig = px.bar(
        tech_df,
        x='Technique ID', y='Sessions',
        color='Tactic',
        hover_data=['Name', 'Tactic'],
        color_discrete_sequence=px.colors.qualitative.Set2
    )
    fig.update_layout(height=400)
    st.plotly_chart(fig, use_container_width=True)

    # Technique cards
    st.subheader("Observed Techniques — Detail")
    for technique_id, count in technique_counts.most_common():
        info = mitre_reference.get(technique_id, {})
        with st.expander(
            f"{technique_id} — {info.get('name', 'Unknown')} "
            f"({count:,} sessions)"
        ):
            col1, col2 = st.columns([1, 3])
            with col1:
                st.metric("Sessions", f"{count:,}")
                st.metric(
                    "% of Total",
                    f"{count/len(sessions_df)*100:.1f}%"
                )
            with col2:
                st.markdown(f"**Tactic:** {info.get('tactic', 'N/A')}")
                st.markdown(
                    f"**Description:** "
                    f"{info.get('description', 'N/A')}"
                )
                st.markdown(
                    f"**MITRE ATT&CK Reference:** "
                    f"[{technique_id}]"
                    f"(https://attack.mitre.org/techniques/"
                    f"{technique_id.replace('.', '/')})"
                )

# ============================================================
# PAGE 6: LIVE THREAT PREDICTOR
# ============================================================
elif page == "🎯 Live Threat Predictor":
    st.title("🎯 Live Threat Predictor")
    st.markdown(
        "Enter session characteristics to get a real-time "
        "anomaly prediction from the trained Isolation Forest model."
    )
    st.markdown("---")

    st.info(
        "This predictor uses the Isolation Forest model trained on "
        "28,958 real honeypot sessions. Input a session's behavioral "
        "features to determine if it matches normal or attack patterns."
    )

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Session Features")
        duration = st.number_input(
            "Session Duration (seconds)",
            min_value=0.0, max_value=3600.0,
            value=1.5, step=0.1,
            help="How long did the session last?"
        )
        total_attempts = st.number_input(
            "Total Login Attempts",
            min_value=0, max_value=1000,
            value=1,
            help="How many login attempts were made?"
        )
        unique_usernames = st.number_input(
            "Unique Usernames Tried",
            min_value=0, max_value=500,
            value=1,
            help="How many different usernames were tried?"
        )
        unique_passwords = st.number_input(
            "Unique Passwords Tried",
            min_value=0, max_value=500,
            value=1,
            help="How many different passwords were tried?"
        )

    with col2:
        st.subheader(" ")
        failure_count = st.number_input(
            "Failed Login Attempts",
            min_value=0, max_value=1000,
            value=0,
            help="How many attempts failed?"
        )
        success_rate = st.slider(
            "Login Success Rate",
            min_value=0.0, max_value=1.0,
            value=1.0, step=0.01,
            help="Ratio of successful logins (0 = all failed, "
                 "1 = all succeeded)"
        )
        hour_of_day = st.slider(
            "Hour of Day (UTC)",
            min_value=0, max_value=23,
            value=12,
            help="What hour did the session occur?"
        )

        # Auto-calculate derived features
        attempts_per_second = (
            total_attempts / duration if duration > 0 else 0
        )
        username_password_ratio = (
            unique_usernames / unique_passwords
            if unique_passwords > 0 else 1
        )

        st.metric(
            "Calculated: Attempts/Second",
            f"{attempts_per_second:.3f}"
        )
        st.metric(
            "Calculated: Username/Password Ratio",
            f"{username_password_ratio:.2f}"
        )

    st.markdown("---")
    predict_btn = st.button(
        "🔍 Predict Threat Level",
        type="primary",
        use_container_width=True
    )

    if predict_btn:
        features = np.array([[
            duration,
            total_attempts,
            unique_usernames,
            unique_passwords,
            attempts_per_second,
            success_rate,
            hour_of_day,
            failure_count,
            username_password_ratio
        ]])

        features_scaled = scaler.transform(features)
        prediction = iso_model.predict(features_scaled)[0]
        anomaly_score = iso_model.score_samples(features_scaled)[0]

        st.markdown("---")
        col1, col2, col3 = st.columns(3)

        with col1:
            if prediction == -1:
                st.error("🚨 ANOMALY DETECTED")
                st.markdown("**Classification: ATTACK**")
            else:
                st.success("✅ NORMAL SESSION")
                st.markdown("**Classification: NORMAL**")

        with col2:
            st.metric(
                "Anomaly Score",
                f"{anomaly_score:.4f}",
                delta="Lower = more anomalous"
            )

        with col3:
            threshold = sessions_df['iso_score'].quantile(0.1)
            confidence = min(
                abs(anomaly_score - threshold) /
                abs(threshold) * 100, 100
            )
            st.metric(
                "Model Confidence",
                f"{confidence:.1f}%"
            )

        # Explanation
        st.subheader("Why this prediction?")
        baseline_duration = sessions_df['duration_seconds'].median()
        baseline_attempts = sessions_df['total_attempts'].median()

        explanations = []
        if duration > 30:
            explanations.append(
                f"⚠️ Session duration ({duration:.1f}s) is much "
                f"longer than typical ({baseline_duration:.1f}s)"
            )
        if total_attempts == 0:
            explanations.append(
                "⚠️ No login attempts — typical of "
                "reconnaissance/scanning behavior"
            )
        if attempts_per_second > 2:
            explanations.append(
                f"⚠️ High login speed ({attempts_per_second:.2f}/s) "
                f"— typical of automated botnet activity"
            )
        if unique_usernames > 3:
            explanations.append(
                f"⚠️ Multiple usernames tried ({unique_usernames}) "
                f"— typical of credential spraying"
            )
        if not explanations:
            explanations.append(
                "✅ Session characteristics match normal "
                "honeypot traffic patterns"
            )

        for exp in explanations:
            st.markdown(f"- {exp}")

        # Show how this compares to your real data
        st.subheader("Comparison to Real Dataset")
        comp_col1, comp_col2 = st.columns(2)
        with comp_col1:
            st.markdown("**Your input vs. dataset median:**")
            comparison = pd.DataFrame({
                'Feature': [
                    'Duration (s)', 'Total Attempts',
                    'Unique Usernames', 'Attempts/Second'
                ],
                'Your Input': [
                    duration, total_attempts,
                    unique_usernames, round(attempts_per_second, 3)
                ],
                'Dataset Median': [
                    round(sessions_df[
                        'duration_seconds'].median(), 3),
                    round(sessions_df[
                        'total_attempts'].median(), 3),
                    round(sessions_df[
                        'unique_usernames'].median(), 3),
                    round(sessions_df[
                        'attempts_per_second'].median(), 3)
                ]
            })
            st.dataframe(comparison, use_container_width=True)

        with comp_col2:
            st.markdown("**Try these example inputs:**")
            st.markdown(
                "**Typical bot attack:** duration=1.5s, "
                "attempts=1, usernames=1, speed=0.67/s"
            )
            st.markdown(
                "**Reconnaissance scan:** duration=120s, "
                "attempts=0, usernames=0, speed=0"
            )
            st.markdown(
                "**Aggressive brute force:** duration=60s, "
                "attempts=50, usernames=10, speed=0.83/s"
            )

# ============================================================
# FOOTER
# ============================================================
st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: gray; font-size: 12px;'>"
    "IoT Device Fleet + Intrusion Detection System | "
    "Built with Cowrie Honeypot, Isolation Forest ML, "
    "AbuseIPDB, MITRE ATT&CK | AWS EC2"
    "</div>",
    unsafe_allow_html=True
)