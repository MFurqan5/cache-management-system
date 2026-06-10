import os
import sys
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix
)
import warnings
warnings.filterwarnings('ignore')

# Import shared 25-feature extractor (single source of truth)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from url_features import extract_url_features_batch, FEATURE_NAMES

# ── Paths ──
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'preprocessing', 'preprocessed_data')
MODEL_DIR = os.path.join(BASE_DIR, 'models')
os.makedirs(MODEL_DIR, exist_ok=True)

# ── Load API-Compatible Data (from urlset.csv) ──
print("=" * 60)
print("URL PHISHING MODEL TRAINING (API COMPATIBLE)")
print("=" * 60)

csv_path_mal = os.path.join(BASE_DIR, 'datasets', 'urlset.csv')
csv_path_ben = os.path.join(BASE_DIR, 'datasets', 'benign_domains_dataset.csv')
print(f"Loading raw datasets from:\n - {csv_path_mal}\n - {csv_path_ben}")
df_mal = pd.read_csv(csv_path_mal, encoding='latin-1', on_bad_lines='skip', low_memory=False)
df_ben = pd.read_csv(csv_path_ben, encoding='latin-1', on_bad_lines='skip', low_memory=False)
df = pd.concat([df_mal, df_ben], ignore_index=True)

print("Preprocessing for API conformity...")
df = df.dropna(subset=['label'])
df['label'] = pd.to_numeric(df['label'], errors='coerce').fillna(0).astype(int)
# Binary map aligned with API: 1 = Malicious, 0 = Safe
df['Result_binary'] = df['label'].apply(lambda x: 1 if x == 1 else 0)

# Extract 25 features using the shared module (identical to API)
X = extract_url_features_batch(df['domain'])
y = df['Result_binary'].values

print(f"\nFeatures shape: {X.shape}  ({len(FEATURE_NAMES)} features)")
print(f"Labels shape:   {y.shape}")
print(f"Features aligned with backend: {FEATURE_NAMES}")
print(f"Class distribution: Safe={sum(y==0)}, Malicious={sum(y==1)}")

# ── Train/Test Split (80/20) ──
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"\nTrain set: {X_train.shape[0]} samples")
print(f"Test set:  {X_test.shape[0]} samples")

# ── Define Models ──
models = {
    'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
}

# ── Train & Evaluate All Models ──
results = []

for name, model in models.items():
    print(f"\n{'-' * 40}")
    print(f"Training: {name}")
    print(f"{'-' * 40}")

    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    results.append({
        'Model': name,
        'Accuracy': acc,
        'Precision': prec,
        'Recall': rec,
        'F1 Score': f1,
        'model_obj': model
    })

    print(f"Accuracy:  {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1 Score:  {f1:.4f}")
    print(f"\nClassification Report:\n{classification_report(y_test, y_pred, target_names=['Malicious', 'Safe'])}")
    print(f"Confusion Matrix:\n{confusion_matrix(y_test, y_pred)}")

# Skipping hyperparameter tuning to save time.
# Best model is just our Random Forest.
best = results[0]

# ── Final Comparison (Base vs Tuned) ──
print("FINAL MODEL COMPARISON")
print("=" * 60)

results_df = pd.DataFrame(results).drop(columns=['model_obj'])
results_df = results_df.sort_values('F1 Score', ascending=False).reset_index(drop=True)
print(results_df.to_string(index=False))

# ── Best Model ──
best = max(results, key=lambda x: x['F1 Score'])
print(f"\nBest Model: {best['Model']} (F1 Score: {best['F1 Score']:.4f})")

# ── Save Best Model and Export to Backend ──
pkl_path = os.path.join(MODEL_DIR, 'url_model.pkl')
joblib.dump(best['model_obj'], pkl_path)
print(f"Model saved to ML output: {pkl_path}")

backend_path = os.path.join(os.path.dirname(BASE_DIR), 'backend', 'models', 'url_model.pkl')
os.makedirs(os.path.dirname(backend_path), exist_ok=True)
joblib.dump(best['model_obj'], backend_path)
print(f"API-Compatible model deployed to: {backend_path}")

print("\nURL model training COMPLETE!")

