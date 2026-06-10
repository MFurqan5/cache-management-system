import matplotlib
matplotlib.use('Agg')
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os
import warnings

warnings.filterwarnings('ignore')
sns.set_theme(style="darkgrid")
plt.rcParams['figure.figsize'] = (10, 6)

# ── Paths ──
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, 'datasets', 'App Malware Datasets')
OUTPUT_DIR = os.path.join(BASE_DIR, 'preprocessing', 'preprocessed_data')
os.makedirs(OUTPUT_DIR, exist_ok=True)

print("=" * 60)
print("APP MALWARE DATASET PREPROCESSING (Drebin-215)")
print("=" * 60)

drebin_path = os.path.join(DATASET_DIR, 'drebin-215-dataset-5560malware-9476-benign.csv')
print(f"\nLoading dataset from: {drebin_path}")

df = pd.read_csv(drebin_path)
print(f"Shape: {df.shape}")
print(f"Columns count: {len(df.columns)}")

target_col = df.columns[-1]
feature_cols = df.columns[:-1].tolist()
print(f"Target column: '{target_col}'")
print(f"Number of features: {len(feature_cols)}")
print(f"\nFirst 10 feature names: {feature_cols[:10]}")
print(f"\nData types:\n{df.dtypes.value_counts()}")

print("\n--- Missing Values ---")
missing_total = df.isnull().sum().sum()
print(f"Total missing values: {missing_total}")

if missing_total > 0:
    missing_cols = df.isnull().sum()
    missing_cols = missing_cols[missing_cols > 0]
    print(f"Columns with missing values:\n{missing_cols}")
    df = df.fillna(0)
    print("Filled missing values with 0.")

print("\n--- Duplicate Rows ---")
dup_count = df.duplicated().sum()
print(f"Duplicate rows found: {dup_count}")
if dup_count > 0:
    df = df.drop_duplicates().reset_index(drop=True)
    print(f"After removing duplicates: {df.shape}")

print("\n--- Data Validation ---")
for col in feature_cols:
    non_numeric = pd.to_numeric(df[col], errors='coerce').isnull() & df[col].notnull()
    if non_numeric.any():
        print(f"  Column '{col}' has {non_numeric.sum()} non-numeric values -> replacing with 0")
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(int)
print("\n--- Target Mapping ---")
print(f"Original class distribution:\n{df[target_col].value_counts()}")

label_map = {'B': 0, 'S': 1}
df['label'] = df[target_col].map(label_map)

unmapped = df['label'].isnull().sum()
if unmapped > 0:
    print(f"WARNING: {unmapped} rows could not be mapped. Dropping them.")
    df = df.dropna(subset=['label']).reset_index(drop=True)

df['label'] = df['label'].astype(int)

print(f"\nBinary class distribution:")
print(f"  0 (Benign/Safe):     {(df['label'] == 0).sum()}")
print(f"  1 (Malware/Threat):  {(df['label'] == 1).sum()}")
print(f"  Total:               {len(df)}")

X = df[feature_cols].values.astype(np.float32)
y = df['label'].values.astype(np.int32)

print(f"\nFeatures array shape: {X.shape}")
print(f"Labels array shape:  {y.shape}")
print(f"Feature value range: [{X.min()}, {X.max()}]")

print("\n--- Generating Visualizations ---")

fig, axes = plt.subplots(1, 2, figsize=(12, 5))
class_counts = pd.Series(y).value_counts().sort_index()
colors = ['#2ecc71', '#e74c3c']
labels_plot = ['Benign (0)', 'Malware (1)']
bars = axes[0].bar(labels_plot, class_counts.values, color=colors, edgecolor='black')
axes[0].set_title('App Malware Class Distribution', fontsize=14, fontweight='bold')
axes[0].set_ylabel('Count')
for bar, val in zip(bars, class_counts.values):
    axes[0].text(bar.get_x() + bar.get_width() / 2, val + 100, str(val),
                 ha='center', fontweight='bold')

axes[1].pie(class_counts.values, labels=['Benign', 'Malware'], autopct='%1.1f%%',
            colors=colors, startangle=90, explode=(0, 0.05))
axes[1].set_title('App Malware Class Proportion', fontsize=14, fontweight='bold')

plt.tight_layout()
chart_path = os.path.join(OUTPUT_DIR, 'app_class_balance.png')
plt.savefig(chart_path, dpi=150, bbox_inches='tight')
plt.close()
print(f"Saved class balance chart: {chart_path}")

fig, ax = plt.subplots(figsize=(14, 8))
malware_mask = y == 1
benign_mask = y == 0
malware_freq = X[malware_mask].mean(axis=0)
benign_freq = X[benign_mask].mean(axis=0)
diff = malware_freq - benign_freq

top_indices = np.argsort(diff)[-20:]
top_features = [feature_cols[i] for i in top_indices]
top_malware = malware_freq[top_indices]
top_benign = benign_freq[top_indices]

x_pos = np.arange(len(top_features))
width = 0.35

ax.barh(x_pos - width/2, top_benign, width, label='Benign', color='#2ecc71', edgecolor='black')
ax.barh(x_pos + width/2, top_malware, width, label='Malware', color='#e74c3c', edgecolor='black')
ax.set_yticks(x_pos)
ax.set_yticklabels(top_features, fontsize=9)
ax.set_xlabel('Frequency (proportion of apps with this feature)')
ax.set_title('Top 20 Features Most Associated with Malware', fontsize=14, fontweight='bold')
ax.legend()
plt.tight_layout()
chart_path2 = os.path.join(OUTPUT_DIR, 'app_top_malware_features.png')
plt.savefig(chart_path2, dpi=150, bbox_inches='tight')
plt.close()
print(f"Saved top malware features chart: {chart_path2}")

print("\n--- Saving Preprocessed Data ---")

np.save(os.path.join(OUTPUT_DIR, 'app_features.npy'), X)
np.save(os.path.join(OUTPUT_DIR, 'app_labels.npy'), y)
pd.Series(feature_cols).to_csv(
    os.path.join(OUTPUT_DIR, 'app_feature_names.csv'), index=False, header=['feature_name']
)

print("Saved: app_features.npy, app_labels.npy, app_feature_names.csv")

print("\n" + "=" * 60)
print("APP MALWARE PREPROCESSING SUMMARY")
print("=" * 60)
print(f"""
DREBIN-215 DATASET:
  - Original:      {df.shape[0]} rows × {len(feature_cols)} features + 1 target
  - Features:      215 binary indicators (permissions, API calls, intents, commands)
  - Output shape:  {X.shape}
  - Target:        Binary (Benign=0, Malware=1)
  - Class balance: {(y==0).sum()} benign, {(y==1).sum()} malware

All preprocessed data saved to: {OUTPUT_DIR}
""")
print("App malware preprocessing COMPLETE!")
