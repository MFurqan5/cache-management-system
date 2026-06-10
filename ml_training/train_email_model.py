import os
import numpy as np
import pandas as pd
import joblib
from scipy import sparse
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix
)
import warnings
warnings.filterwarnings('ignore')

# ── Paths ──
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'preprocessing', 'preprocessed_data')
MODEL_DIR = os.path.join(BASE_DIR, 'models')
os.makedirs(MODEL_DIR, exist_ok=True)

# ── Load Preprocessed Data ──
print("=" * 60)
print("EMAIL PHISHING MODEL TRAINING")
print("=" * 60)

X = sparse.load_npz(os.path.join(DATA_DIR, 'email_tfidf_features.npz'))
y = np.load(os.path.join(DATA_DIR, 'email_labels.npy'))

print(f"Features shape: {X.shape}")
print(f"Labels shape:   {y.shape}")
print(f"Class distribution: Ham={sum(y==0)}, Spam={sum(y==1)}")

# ── Train/Test Split (80/20) ──
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"\nTrain set: {X_train.shape[0]} samples")
print(f"Test set:  {X_test.shape[0]} samples")

# ── Define Models ──
models = {
    'Decision Tree': DecisionTreeClassifier(random_state=42),
    'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
    'SVM': SVC(kernel='linear', random_state=42),
    'XGBoost': GradientBoostingClassifier(n_estimators=100, random_state=42),
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
    print(f"\nClassification Report:\n{classification_report(y_test, y_pred, target_names=['Ham', 'Spam'])}")
    print(f"Confusion Matrix:\n{confusion_matrix(y_test, y_pred)}")

# ── Comparison Table ──
print("\n" + "=" * 60)
print("MODEL COMPARISON (Email)")
print("=" * 60)

results_df = pd.DataFrame(results).drop(columns=['model_obj'])
results_df = results_df.sort_values('F1 Score', ascending=False).reset_index(drop=True)
print(results_df.to_string(index=False))

# ── Best Model ──
best = max(results, key=lambda x: x['F1 Score'])
print(f"\nBest Model: {best['Model']} (F1 Score: {best['F1 Score']:.4f})")

# ── Wrap and Save Best Model for API ──
print("\nWrapping best model in a Pipeline for API compatibility...")
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer

# Load cleaned text dataset to fit the vectorizer for the pipeline
try:
    print("Re-fitting vectorizer for unified pipeline...")
    df_cleaned = pd.read_csv(os.path.join(DATA_DIR, 'emails_cleaned.csv'))
    # Recreate original config from dataset_preprocessing.py
    vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2))
    vectorizer.fit(df_cleaned['processed_text'].fillna(''))
    
    # Build final pipeline
    final_pipeline = Pipeline([
        ('tfidf', vectorizer),
        ('classifier', best['model_obj'])
    ])
    
    # Save to training dir
    pkl_path = os.path.join(MODEL_DIR, 'email_model.pkl')
    joblib.dump(final_pipeline, pkl_path)
    print(f"Pipeline saved to: {pkl_path}")
    
    # Also push to backend dir directly
    backend_dir = os.path.join(os.path.dirname(BASE_DIR), 'backend', 'models')
    os.makedirs(backend_dir, exist_ok=True)
    backend_path = os.path.join(backend_dir, 'email_model.pkl')
    joblib.dump(final_pipeline, backend_path)
    print(f"✅ API-Compatible model deployed to: {backend_path}")
    
except Exception as e:
    print(f"⚠️ Warning: Could not build combined pipeline: {e}")
    # Fallback to original save
    pkl_path = os.path.join(MODEL_DIR, 'email_model.pkl')
    joblib.dump(best['model_obj'], pkl_path)
    print(f"Saved classifier only to: {pkl_path}")

print("\nEmail model training COMPLETE!")
