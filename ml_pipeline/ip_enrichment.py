import pandas as pd
import numpy as np
import requests
import geoip2.database
import time
import json
import os
from pathlib import Path
from collections import Counter
from dotenv import load_dotenv
import matplotlib.pyplot as plt
import warnings
warnings.filterwarnings('ignore')

ROOT_DIR = Path(__file__).resolve().parents[1]
load_dotenv(ROOT_DIR / '.env')
DATA_DIR = ROOT_DIR / 'data'
CHART_DIR = ROOT_DIR / 'results' / 'charts'
CHART_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================
# CONFIGURATION — fill these in before running
# ============================================================
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
GEOIP_DB_PATH = DATA_DIR / 'GeoLite2-City.mmdb'

# ============================================================
# STEP 1: LOAD DATA
# ============================================================
print("Loading data...")
sessions_df = pd.read_csv(DATA_DIR / 'sessions_final.csv')
predictions_df = pd.read_csv(DATA_DIR / 'sessions_with_predictions.csv')
auth_df = pd.read_csv(DATA_DIR / 'auth_final.csv')

unique_ips = sessions_df['ip'].dropna().unique()
print(f"Total sessions: {len(sessions_df)}")
print(f"Unique attacker IPs to enrich: {len(unique_ips)}")

# ============================================================
# STEP 2: GEOIP LOOKUP
# ============================================================
print("\nRunning GeoIP lookups...")

def get_geo_info(ip, reader):
    try:
        response = reader.city(ip)
        return {
            'ip': ip,
            'country': response.country.name or 'Unknown',
            'country_code': response.country.iso_code or 'XX',
            'city': response.city.name or 'Unknown',
            'latitude': response.location.latitude,
            'longitude': response.location.longitude
        }
    except Exception:
        return {
            'ip': ip,
            'country': 'Unknown',
            'country_code': 'XX',
            'city': 'Unknown',
            'latitude': None,
            'longitude': None
        }

geo_results = []
try:
    with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
        for ip in unique_ips:
            geo_results.append(get_geo_info(ip, reader))
    print(f"GeoIP complete: {len(geo_results)} IPs looked up")
except FileNotFoundError:
    print(f"GeoLite2-City.mmdb not found — using ip-api.com fallback")
    for ip in unique_ips:
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if r.status_code == 200:
                d = r.json()
                geo_results.append({
                    'ip': ip,
                    'country': d.get('country', 'Unknown'),
                    'country_code': d.get('countryCode', 'XX'),
                    'city': d.get('city', 'Unknown'),
                    'latitude': d.get('lat', None),
                    'longitude': d.get('lon', None)
                })
            time.sleep(1.5)  # ip-api.com rate limit
        except Exception:
            geo_results.append({
                'ip': ip, 'country': 'Unknown',
                'country_code': 'XX', 'city': 'Unknown',
                'latitude': None, 'longitude': None
            })

geo_df = pd.DataFrame(geo_results)

print("\nTop 10 countries attacking you:")
print(geo_df['country'].value_counts().head(10).to_string())

# ============================================================
# STEP 3: ABUSEIPDB LOOKUP
# ============================================================
print(f"\nRunning AbuseIPDB lookups for {len(unique_ips)} IPs...")
print("This will take a few minutes...")

def check_abuseipdb(ip, api_key):
    if not api_key:
        return {
            'ip': ip,
            'abuse_confidence_score': 0,
            'total_reports': 0,
            'num_distinct_users': 0,
            'last_reported_at': None,
            'isp': 'Unknown',
            'usage_type': 'Unknown',
            'domain': 'Unknown',
            'is_tor': False
        }

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": api_key
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    try:
        response = requests.get(
            url, headers=headers,
            params=params, timeout=10
        )
        if response.status_code == 200:
            data = response.json()['data']
            return {
                'ip': ip,
                'abuse_confidence_score': data.get(
                    'abuseConfidenceScore', 0),
                'total_reports': data.get('totalReports', 0),
                'num_distinct_users': data.get(
                    'numDistinctUsers', 0),
                'last_reported_at': data.get(
                    'lastReportedAt', None),
                'isp': data.get('isp', 'Unknown'),
                'usage_type': data.get('usageType', 'Unknown'),
                'domain': data.get('domain', 'Unknown'),
                'is_tor': data.get('isTor', False)
            }
        elif response.status_code == 429:
            print(f"  Rate limited — waiting 60 seconds...")
            time.sleep(60)
            return check_abuseipdb(ip, api_key)
    except Exception as e:
        print(f"  Error checking {ip}: {e}")

    return {
        'ip': ip,
        'abuse_confidence_score': 0,
        'total_reports': 0,
        'num_distinct_users': 0,
        'last_reported_at': None,
        'isp': 'Unknown',
        'usage_type': 'Unknown',
        'domain': 'Unknown',
        'is_tor': False
    }

abuse_results = []
for i, ip in enumerate(unique_ips):
    result = check_abuseipdb(ip, ABUSEIPDB_API_KEY)
    abuse_results.append(result)
    if (i + 1) % 10 == 0:
        print(f"  Checked {i+1}/{len(unique_ips)} IPs...")
    time.sleep(1.2)  # stay within free tier rate limit

abuse_df = pd.DataFrame(abuse_results)

print(f"\nAbuseIPDB complete")
print(f"IPs with any abuse reports: "
      f"{len(abuse_df[abuse_df['total_reports'] > 0])}")
print(f"High confidence malicious (score >= 50): "
      f"{len(abuse_df[abuse_df['abuse_confidence_score'] >= 50])}")
print(f"Critical threat (score >= 80): "
      f"{len(abuse_df[abuse_df['abuse_confidence_score'] >= 80])}")

# ============================================================
# STEP 4: THREAT LEVEL CLASSIFICATION
# ============================================================
def get_threat_level(score):
    if score >= 80:
        return 'Critical'
    elif score >= 50:
        return 'High'
    elif score >= 25:
        return 'Medium'
    elif score > 0:
        return 'Low'
    else:
        return 'Unknown'

abuse_df['threat_level'] = abuse_df[
    'abuse_confidence_score'].apply(get_threat_level)

print(f"\nThreat level breakdown:")
print(abuse_df['threat_level'].value_counts().to_string())

# ============================================================
# STEP 5: MITRE ATT&CK MAPPING
# ============================================================
print("\nApplying MITRE ATT&CK mappings...")

mitre_reference = {
    'T1595.001': {
        'name': 'Active Scanning: Scanning IP Blocks',
        'tactic': 'Reconnaissance'
    },
    'T1110.001': {
        'name': 'Brute Force: Password Guessing',
        'tactic': 'Credential Access'
    },
    'T1110.003': {
        'name': 'Brute Force: Password Spraying',
        'tactic': 'Credential Access'
    },
    'T1078': {
        'name': 'Valid Accounts',
        'tactic': 'Defense Evasion / Persistence'
    },
    'T1021.004': {
        'name': 'Remote Services: SSH',
        'tactic': 'Lateral Movement'
    }
}

def apply_mitre(row):
    techniques = []
    total = row.get('total_attempts', 0)
    usernames = row.get('unique_usernames', 0)
    success = row.get('success_count', 0)

    if total == 0:
        techniques.append('T1595.001')
    if total > 0:
        techniques.append('T1110.001')
    if usernames > 1:
        techniques.append('T1110.003')
    if success > 0:
        techniques.append('T1078')
    techniques.append('T1021.004')

    return ', '.join(techniques)

predictions_df['mitre_techniques'] = predictions_df.apply(
    apply_mitre, axis=1)

# Count technique frequency
all_techniques = []
for t in predictions_df['mitre_techniques']:
    all_techniques.extend(t.split(', '))
technique_counts = Counter(all_techniques)

print("\nMITRE ATT&CK technique frequency:")
for technique, count in technique_counts.most_common():
    info = mitre_reference.get(technique, {})
    name = info.get('name', technique)
    tactic = info.get('tactic', '')
    print(f"  [{tactic}] {technique}: {name} — {count} sessions")

# ============================================================
# STEP 6: MERGE EVERYTHING
# ============================================================
enriched_df = geo_df.merge(abuse_df, on='ip', how='left')
final_df = sessions_df.merge(enriched_df, on='ip', how='left')
final_df = final_df.merge(
    predictions_df[['id', 'iso_label', 'iso_score',
                    'mitre_techniques']],
    on='id', how='left'
)

# ============================================================
# STEP 7: VISUALIZATIONS
# ============================================================
print("\nGenerating visualizations...")

# Plot 1: Top attacking countries
fig, ax = plt.subplots(figsize=(12, 6))
country_counts = geo_df['country'].value_counts().head(15)
bars = ax.barh(country_counts.index[::-1],
               country_counts.values[::-1],
               color='#e74c3c', edgecolor='black', alpha=0.8)
ax.set_xlabel('Number of Sessions', fontsize=12)
ax.set_title('Top 15 Countries Attacking Your Honeypot',
             fontsize=14, fontweight='bold')
for bar, val in zip(bars, country_counts.values[::-1]):
    ax.text(bar.get_width() + 0.3,
            bar.get_y() + bar.get_height()/2,
            str(val), va='center', fontweight='bold')
plt.tight_layout()
plt.savefig(CHART_DIR / 'attacking_countries.png', dpi=150)
plt.show()
print("Saved: attacking_countries.png")

# Plot 2: Threat level distribution
fig, ax = plt.subplots(figsize=(8, 5))
threat_colors = {
    'Critical': '#c0392b',
    'High': '#e74c3c',
    'Medium': '#f39c12',
    'Low': '#f1c40f',
    'Unknown': '#95a5a6'
}
threat_counts = abuse_df['threat_level'].value_counts()
colors = [threat_colors.get(t, '#95a5a6')
          for t in threat_counts.index]
bars = ax.bar(threat_counts.index, threat_counts.values,
              color=colors, edgecolor='black', alpha=0.85)
ax.set_xlabel('Threat Level', fontsize=12)
ax.set_ylabel('Number of IPs', fontsize=12)
ax.set_title('AbuseIPDB Threat Level Distribution',
             fontsize=14, fontweight='bold')
for bar, val in zip(bars, threat_counts.values):
    ax.text(bar.get_x() + bar.get_width()/2,
            bar.get_height() + 0.3,
            str(val), ha='center', fontweight='bold')
plt.tight_layout()
plt.savefig(CHART_DIR / 'threat_levels.png', dpi=150)
plt.show()
print("Saved: threat_levels.png")

# Plot 3: Abuse confidence score distribution
fig, ax = plt.subplots(figsize=(10, 4))
ax.hist(abuse_df['abuse_confidence_score'], bins=20,
        color='#e74c3c', edgecolor='black', alpha=0.7)
ax.axvline(50, color='orange', linestyle='--',
           linewidth=2, label='High threat threshold (50)')
ax.axvline(80, color='red', linestyle='--',
           linewidth=2, label='Critical threshold (80)')
ax.set_xlabel('AbuseIPDB Confidence Score (0-100)', fontsize=12)
ax.set_ylabel('Number of IPs', fontsize=12)
ax.set_title('Attacker IP Reputation Score Distribution',
             fontsize=14, fontweight='bold')
ax.legend()
plt.tight_layout()
plt.savefig(CHART_DIR / 'abuse_scores.png', dpi=150)
plt.show()
print("Saved: abuse_scores.png")

# Plot 4: MITRE ATT&CK technique frequency
fig, ax = plt.subplots(figsize=(12, 5))
technique_labels = []
technique_values = []
for t, c in technique_counts.most_common():
    info = mitre_reference.get(t, {})
    label = f"{t}\n{info.get('name', t)[:25]}"
    technique_labels.append(label)
    technique_values.append(c)

bars = ax.bar(range(len(technique_labels)), technique_values,
              color='#3498db', edgecolor='black', alpha=0.85)
ax.set_xticks(range(len(technique_labels)))
ax.set_xticklabels(technique_labels, fontsize=8)
ax.set_ylabel('Session Count', fontsize=12)
ax.set_title('MITRE ATT&CK Technique Frequency',
             fontsize=14, fontweight='bold')
for bar, val in zip(bars, technique_values):
    ax.text(bar.get_x() + bar.get_width()/2,
            bar.get_height() + 100,
            str(val), ha='center', fontweight='bold')
plt.tight_layout()
plt.savefig(CHART_DIR / 'mitre_techniques.png', dpi=150)
plt.show()
print("Saved: mitre_techniques.png")

# Plot 5: Top 10 ISPs of attackers
fig, ax = plt.subplots(figsize=(12, 5))
isp_counts = abuse_df[
    abuse_df['isp'] != 'Unknown']['isp'].value_counts().head(10)
if len(isp_counts) > 0:
    bars = ax.barh(isp_counts.index[::-1],
                   isp_counts.values[::-1],
                   color='#9b59b6', edgecolor='black', alpha=0.8)
    ax.set_xlabel('Number of IPs', fontsize=12)
    ax.set_title('Top 10 ISPs of Attacking IPs',
                 fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.savefig(CHART_DIR / 'top_isps.png', dpi=150)
    plt.show()
    print("Saved: top_isps.png")

# ============================================================
# STEP 8: SAVE ALL OUTPUT
# ============================================================
enriched_df.to_csv(DATA_DIR / 'enriched_ip_data.csv', index=False)
predictions_df.to_csv(DATA_DIR / 'sessions_with_mitre.csv', index=False)
final_df.to_csv(DATA_DIR / 'full_enriched_sessions.csv', index=False)

# ============================================================
# STEP 9: FINAL SUMMARY
# ============================================================
print("\n" + "="*55)
print("PHASE 6 COMPLETE — KEY FINDINGS")
print("="*55)
print(f"Total unique attacker IPs:        {len(unique_ips)}")
print(f"Countries represented:             "
      f"{geo_df['country'].nunique()}")
print(f"IPs with prior abuse reports:      "
      f"{len(abuse_df[abuse_df['total_reports'] > 0])}")
print(f"High/Critical threat IPs:          "
      f"{len(abuse_df[abuse_df['abuse_confidence_score'] >= 50])}")
print(f"Tor exit nodes detected:           "
      f"{abuse_df['is_tor'].sum()}")
print(f"\nTop attacking country:             "
      f"{geo_df['country'].value_counts().index[0]}")
print(f"Most common threat level:          "
      f"{abuse_df['threat_level'].value_counts().index[0]}")
print(f"\nMITRE techniques observed:        "
      f"{len(technique_counts)} distinct techniques")
print(f"Most frequent technique:           "
      f"{technique_counts.most_common(1)[0][0]} "
      f"({technique_counts.most_common(1)[0][1]} sessions)")

print("\nOutput files saved:")
print("  enriched_ip_data.csv")
print("  sessions_with_mitre.csv")
print("  full_enriched_sessions.csv")
print("  attacking_countries.png")
print("  threat_levels.png")
print("  abuse_scores.png")
print("  mitre_techniques.png")
print("  top_isps.png")