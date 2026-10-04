import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from collections import Counter
import joblib
import warnings
from pathlib import Path
warnings.filterwarnings('ignore')

ROOT_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT_DIR / 'data'
CHART_DIR = ROOT_DIR / 'results' / 'charts'
MODEL_DIR = ROOT_DIR / 'ml_pipeline' / 'models'
CHART_DIR.mkdir(parents=True, exist_ok=True)
MODEL_DIR.mkdir(parents=True, exist_ok=True)

# ============================================================
# STEP 1: LOAD DATA
# ============================================================
print("Loading data...")
auth_df = pd.read_csv(DATA_DIR / 'auth_final.csv')
sessions_df = pd.read_csv(DATA_DIR / 'sessions_final.csv')

print(f"Auth records: {len(auth_df)}")
print(f"Session records: {len(sessions_df)}")

# ============================================================
# STEP 2: EXPLORATORY ANALYSIS
# ============================================================
print("\n=== EXPLORATORY ANALYSIS ===")

# Convert timestamps
auth_df['timestamp'] = pd.to_datetime(auth_df['timestamp'])
sessions_df['starttime'] = pd.to_datetime(sessions_df['starttime'])
sessions_df['endtime'] = pd.to_datetime(sessions_df['endtime'])

# Basic stats
print(f"\nUnique attacker IPs: {sessions_df['ip'].nunique()}")
print(f"Date range: {auth_df['timestamp'].min()} to {auth_df['timestamp'].max()}")
print(f"\nTop 10 usernames tried:")
print(auth_df['username'].value_counts().head(10))
print(f"\nTop 10 passwords tried:")
print(auth_df['password'].value_counts().head(10))
print(f"\nLogin success vs failure:")
print(auth_df['success'].value_counts())

# ============================================================
# STEP 3: FEATURE ENGINEERING
# ============================================================
print("\n=== FEATURE ENGINEERING ===")

# Session duration
sessions_df['duration_seconds'] = (
    sessions_df['endtime'] - sessions_df['starttime']
).dt.total_seconds()

# Replace negative or zero durations
sessions_df['duration_seconds'] = sessions_df['duration_seconds'].clip(lower=0)

# Fix PostgreSQL boolean export (t/f strings → True/False)
auth_df['success'] = auth_df['success'].map({'t': True, 'f': False})

# Aggregate auth attempts per session
attempts_per_session = auth_df.groupby('session').agg(
    total_attempts=('username', 'count'),
    unique_usernames=('username', 'nunique'),
    unique_passwords=('password', 'nunique'),
    success_count=('success', 'sum'),
    failure_count=('success', lambda x: (~x).sum())
).reset_index()

# Merge sessions with auth features
features_df = sessions_df.merge(
    attempts_per_session,
    left_on='id',
    right_on='session',
    how='left'
)

# Fill sessions with no auth attempts
features_df[['total_attempts', 'unique_usernames',
             'unique_passwords', 'success_count',
             'failure_count']] = features_df[[
    'total_attempts', 'unique_usernames',
    'unique_passwords', 'success_count',
    'failure_count']].fillna(0)

# Additional features
features_df['attempts_per_second'] = (
    features_df['total_attempts'] /
    features_df['duration_seconds'].replace(0, 1)
)

features_df['success_rate'] = (
    features_df['success_count'] /
    features_df['total_attempts'].replace(0, 1)
)

features_df['hour_of_day'] = features_df['starttime'].dt.hour
features_df['username_password_ratio'] = (
    features_df['unique_usernames'] /
    features_df['unique_passwords'].replace(0, 1)
)

print(f"Total sessions with features: {len(features_df)}")
print(f"\nFeature summary:")
print(features_df[[
    'duration_seconds', 'total_attempts',
    'attempts_per_second', 'unique_usernames',
    'unique_passwords', 'success_rate'
]].describe())

# ============================================================
# STEP 4: PREPARE DATA FOR ML
# ============================================================
feature_cols = [
    'duration_seconds',
    'total_attempts',
    'unique_usernames',
    'unique_passwords',
    'attempts_per_second',
    'success_rate',
    'hour_of_day',
    'failure_count',
    'username_password_ratio'
]

X = features_df[feature_cols].copy()
X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(0)

# Scale features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

print(f"\nFinal dataset shape: {X_scaled.shape}")

# ============================================================
# STEP 5: MODEL 1 — ISOLATION FOREST
# ============================================================
print("\n=== MODEL 1: ISOLATION FOREST ===")

iso_forest = IsolationForest(
    contamination=0.1,
    random_state=42,
    n_estimators=100
)

iso_predictions = iso_forest.fit_predict(X_scaled)
iso_labels = ['attack' if p == -1 else 'normal' for p in iso_predictions]
iso_counts = Counter(iso_labels)

print(f"Normal sessions: {iso_counts['normal']}")
print(f"Attack sessions: {iso_counts['attack']}")
print(f"Attack detection rate: {iso_counts['attack']/len(iso_labels)*100:.1f}%")

# Anomaly scores
iso_scores = iso_forest.score_samples(X_scaled)
features_df['iso_score'] = iso_scores
features_df['iso_label'] = iso_labels

# ============================================================
# STEP 6: MODEL 2 — ONE-CLASS SVM
# ============================================================
print("\n=== MODEL 2: ONE-CLASS SVM ===")

ocsvm = OneClassSVM(kernel='rbf', nu=0.1, gamma='scale')
ocsvm_predictions = ocsvm.fit_predict(X_scaled)
ocsvm_labels = ['attack' if p == -1 else 'normal' for p in ocsvm_predictions]
ocsvm_counts = Counter(ocsvm_labels)

print(f"Normal sessions: {ocsvm_counts['normal']}")
print(f"Attack sessions: {ocsvm_counts['attack']}")
print(f"Attack detection rate: {ocsvm_counts['attack']/len(ocsvm_labels)*100:.1f}%")

features_df['ocsvm_label'] = ocsvm_labels

# ============================================================
# STEP 7: MODEL 3 — AUTOENCODER
# ============================================================
print("\n=== MODEL 3: AUTOENCODER ===")

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset

    X_tensor = torch.FloatTensor(X_scaled)

    class Autoencoder(nn.Module):
        def __init__(self, input_dim):
            super(Autoencoder, self).__init__()
            self.encoder = nn.Sequential(
                nn.Linear(input_dim, 16),
                nn.ReLU(),
                nn.Linear(16, 8),
                nn.ReLU(),
                nn.Linear(8, 4)
            )
            self.decoder = nn.Sequential(
                nn.Linear(4, 8),
                nn.ReLU(),
                nn.Linear(8, 16),
                nn.ReLU(),
                nn.Linear(16, input_dim)
            )

        def forward(self, x):
            return self.decoder(self.encoder(x))

    dataset = TensorDataset(X_tensor)
    loader = DataLoader(dataset, batch_size=32, shuffle=True)

    ae_model = Autoencoder(input_dim=X_scaled.shape[1])
    optimizer = optim.Adam(ae_model.parameters(), lr=0.001)
    criterion = nn.MSELoss()

    print("Training autoencoder...")
    for epoch in range(50):
        total_loss = 0
        for batch in loader:
            inputs = batch[0]
            outputs = ae_model(inputs)
            loss = criterion(outputs, inputs)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        if (epoch + 1) % 10 == 0:
            print(f"  Epoch {epoch+1}/50, Loss: {total_loss/len(loader):.4f}")

    ae_model.eval()
    with torch.no_grad():
        reconstructed = ae_model(X_tensor)
        reconstruction_errors = torch.mean(
            (X_tensor - reconstructed) ** 2, dim=1
        ).numpy()

    threshold = np.percentile(reconstruction_errors, 90)
    ae_labels = ['attack' if e > threshold else 'normal'
                 for e in reconstruction_errors]
    ae_counts = Counter(ae_labels)

    print(f"Normal sessions: {ae_counts['normal']}")
    print(f"Attack sessions: {ae_counts['attack']}")
    print(f"Attack detection rate: {ae_counts['attack']/len(ae_labels)*100:.1f}%")

    features_df['ae_label'] = ae_labels
    features_df['ae_error'] = reconstruction_errors
    torch_available = True

except ImportError:
    print("PyTorch not available — skipping autoencoder")
    torch_available = False

# ============================================================
# STEP 8: COMPARISON AND VISUALIZATIONS
# ============================================================
print("\n=== MODEL COMPARISON ===")
print(f"{'Model':<25} {'Attacks':<10} {'Normal':<10} {'Attack %':<10}")
print("-" * 55)
print(f"{'Isolation Forest':<25} {iso_counts['attack']:<10} {iso_counts['normal']:<10} {iso_counts['attack']/len(iso_labels)*100:.1f}%")
print(f"{'One-Class SVM':<25} {ocsvm_counts['attack']:<10} {ocsvm_counts['normal']:<10} {ocsvm_counts['attack']/len(ocsvm_labels)*100:.1f}%")
if torch_available:
    print(f"{'Autoencoder':<25} {ae_counts['attack']:<10} {ae_counts['normal']:<10} {ae_counts['attack']/len(ae_labels)*100:.1f}%")

# Plot 1: Attack distribution comparison
fig, axes = plt.subplots(1, 3 if torch_available else 2, figsize=(15, 5))
fig.suptitle('Model Comparison — Attack Detection', fontsize=14)

models = [('Isolation Forest', iso_counts),
          ('One-Class SVM', ocsvm_counts)]
if torch_available:
    models.append(('Autoencoder', ae_counts))

for i, (name, counts) in enumerate(models):
    axes[i].pie(
        [counts['normal'], counts['attack']],
        labels=['Normal', 'Attack'],
        colors=['#2ecc71', '#e74c3c'],
        autopct='%1.1f%%'
    )
    axes[i].set_title(name)

plt.tight_layout()
plt.savefig(CHART_DIR / 'model_comparison.png', dpi=150)
plt.show()
print("Saved: model_comparison.png")

# Plot 2: Top attacked credentials
fig, axes = plt.subplots(1, 2, figsize=(14, 5))

top_users = auth_df['username'].value_counts().head(10)
axes[0].barh(top_users.index, top_users.values, color='#e74c3c')
axes[0].set_title('Top 10 Usernames Tried by Attackers')
axes[0].set_xlabel('Attempt Count')

top_passwords = auth_df['password'].value_counts().head(10)
axes[1].barh(top_passwords.index, top_passwords.values, color='#3498db')
axes[1].set_title('Top 10 Passwords Tried by Attackers')
axes[1].set_xlabel('Attempt Count')

plt.tight_layout()
plt.savefig(CHART_DIR / 'top_credentials.png', dpi=150)
plt.show()
print("Saved: top_credentials.png")

# Plot 3: Attack timing heatmap
fig, ax = plt.subplots(figsize=(12, 4))
hourly_attacks = auth_df.copy()
hourly_attacks['hour'] = auth_df['timestamp'].dt.hour
hourly_attacks['date'] = auth_df['timestamp'].dt.date
heatmap_data = hourly_attacks.groupby(
    ['date', 'hour']).size().unstack(fill_value=0)

sns.heatmap(heatmap_data, cmap='YlOrRd', ax=ax)
ax.set_title('Attack Frequency Heatmap (Date vs Hour of Day)')
ax.set_xlabel('Hour of Day')
ax.set_ylabel('Date')
plt.tight_layout()
plt.savefig(CHART_DIR / 'attack_heatmap.png', dpi=150)
plt.show()
print("Saved: attack_heatmap.png")

# Plot 4: Isolation Forest anomaly scores
fig, ax = plt.subplots(figsize=(10, 4))
ax.hist(iso_scores, bins=50, color='#3498db', edgecolor='black', alpha=0.7)
ax.axvline(np.percentile(iso_scores, 10), color='red',
           linestyle='--', label='Attack threshold')
ax.set_xlabel('Anomaly Score (lower = more anomalous)')
ax.set_ylabel('Session Count')
ax.set_title('Isolation Forest — Anomaly Score Distribution')
ax.legend()
plt.tight_layout()
plt.savefig(CHART_DIR / 'anomaly_scores.png', dpi=150)
plt.show()
print("Saved: anomaly_scores.png")

# ============================================================
# STEP 9: SHOW MOST SUSPICIOUS SESSIONS
# ============================================================
print("\n=== TOP 10 MOST SUSPICIOUS SESSIONS (Isolation Forest) ===")
suspicious = features_df.nsmallest(10, 'iso_score')[
    ['ip', 'duration_seconds', 'total_attempts',
     'attempts_per_second', 'unique_usernames', 'iso_score']
]
print(suspicious.to_string(index=False))

# ============================================================
# STEP 10: SAVE MODEL
# ============================================================
joblib.dump(iso_forest, MODEL_DIR / 'isolation_forest_model.pkl')
joblib.dump(scaler, MODEL_DIR / 'scaler.pkl')
features_df.to_csv(DATA_DIR / 'sessions_with_predictions.csv', index=False)

print("\n=== SAVED FILES ===")
print("isolation_forest_model.pkl — trained model")
print("scaler.pkl — feature scaler")
print("sessions_with_predictions.csv — all sessions with attack labels")
print("model_comparison.png — model comparison chart")
print("top_credentials.png — most tried usernames/passwords")
print("attack_heatmap.png — attack timing patterns")
print("anomaly_scores.png — anomaly score distribution")
print("\nPhase 5 complete.")