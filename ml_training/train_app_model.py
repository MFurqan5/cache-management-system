import os
import sys
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split, RandomizedSearchCV
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
print("APP MALWARE MODEL TRAINING (Drebin-215)")
print("=" * 60)

X = np.load(os.path.join(DATA_DIR, 'app_features.npy'))
y = np.load(os.path.join(DATA_DIR, 'app_labels.npy'))

print(f"Features shape: {X.shape}")
print(f"Labels shape:   {y.shape}")
print(f"Class distribution: Benign={sum(y==0)}, Malware={sum(y==1)}")

# ── Train/Test Split (80/20, stratified) ──
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"\nTrain set: {X_train.shape[0]} samples")
print(f"Test set:  {X_test.shape[0]} samples")

# ── Define Models ──
models = {
    'Decision Tree': DecisionTreeClassifier(random_state=42),
    'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
    'SVM': SVC(kernel='rbf', random_state=42, probability=True),
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
    print(f"\nClassification Report:\n{classification_report(y_test, y_pred, target_names=['Benign', 'Malware'])}")
    print(f"Confusion Matrix:\n{confusion_matrix(y_test, y_pred)}")

# ── Comparison Table ──
print("\n" + "=" * 60)
print("MODEL COMPARISON (App Malware)")
print("=" * 60)

results_df = pd.DataFrame(results).drop(columns=['model_obj'])
results_df = results_df.sort_values('F1 Score', ascending=False).reset_index(drop=True)
print(results_df.to_string(index=False))

# ── Hyperparameter Tuning ──
print("\n" + "=" * 60)
print("HYPERPARAMETER TUNING (RandomizedSearchCV)")
print("=" * 60)

tuning_configs = {
    'Decision Tree': {
        'model': DecisionTreeClassifier(random_state=42),
        'params': {
            'max_depth': [5, 10, 20, 30, 50, None],
            'min_samples_split': [2, 3, 5, 10],
            'min_samples_leaf': [1, 2, 4],
            'criterion': ['gini', 'entropy'],
        }
    },
    'Random Forest': {
        'model': RandomForestClassifier(random_state=42, n_jobs=-1),
        'params': {
            'n_estimators': [100, 200, 300, 500],
            'max_depth': [10, 20, 30, 50, None],
            'min_samples_split': [2, 3, 5],
            'min_samples_leaf': [1, 2],
            'max_features': ['sqrt', 'log2', None],
        }
    },
    'XGBoost': {
        'model': GradientBoostingClassifier(random_state=42),
        'params': {
            'n_estimators': [100, 200, 300, 500],
            'learning_rate': [0.01, 0.05, 0.1, 0.2],
            'max_depth': [3, 5, 7, 10],
            'min_samples_split': [2, 5, 10],
            'subsample': [0.8, 0.9, 1.0],
        }
    },
}

tuned_results = []

for name, config in tuning_configs.items():
    print(f"\n{'-' * 40}")
    print(f"Tuning: {name}")
    print(f"{'-' * 40}")

    grid = RandomizedSearchCV(
        config['model'],
        config['params'],
        n_iter=5,
        cv=3,
        scoring='f1',
        n_jobs=-1,
        random_state=42,
        verbose=0
    )

    grid.fit(X_train, y_train)
    y_pred = grid.best_estimator_.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    tuned_results.append({
        'Model': f"Tuned {name}",
        'Accuracy': acc,
        'Precision': prec,
        'Recall': rec,
        'F1 Score': f1,
        'model_obj': grid.best_estimator_
    })

    print(f"Best params: {grid.best_params_}")
    print(f"Accuracy:  {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall:    {rec:.4f}")
    print(f"F1 Score:  {f1:.4f}")

all_results = results + tuned_results

print("\n" + "=" * 60)
print("FINAL MODEL COMPARISON (Base + Tuned)")
print("=" * 60)

all_results_df = pd.DataFrame(all_results).drop(columns=['model_obj'])
all_results_df = all_results_df.sort_values('F1 Score', ascending=False).reset_index(drop=True)
print(all_results_df.to_string(index=False))

best = max(all_results, key=lambda x: x['F1 Score'])
print(f"\n*** Best Model: {best['Model']} (F1 Score: {best['F1 Score']:.4f}) ***")

pkl_path = os.path.join(MODEL_DIR, 'app_model.pkl')
joblib.dump(best['model_obj'], pkl_path)
print(f"Saved to: {pkl_path}")

backend_dir = os.path.join(os.path.dirname(BASE_DIR), 'backend', 'models')
os.makedirs(backend_dir, exist_ok=True)
backend_path = os.path.join(backend_dir, 'app_model.pkl')
joblib.dump(best['model_obj'], backend_path)
print(f"[OK] API-Compatible model deployed to: {backend_path}")

print("\nApp malware model training COMPLETE!")
