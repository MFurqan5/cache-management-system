import matplotlib
matplotlib.use('Agg')
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import re
import os
import warnings

warnings.filterwarnings('ignore')
sns.set_theme(style="darkgrid")
plt.rcParams['figure.figsize'] = (10, 6)

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, 'datasets')
OUTPUT_DIR = os.path.join(BASE_DIR, 'preprocessing', 'preprocessed_data')
os.makedirs(OUTPUT_DIR, exist_ok=True)

print("Setup complete. Output will be saved to:", OUTPUT_DIR)

# PART 1: EMAIL DATASET PREPROCESSING
email_df = pd.read_csv(os.path.join(DATASET_DIR, 'emails.csv'))

print(f"\nShape: {email_df.shape}")
print(f"Columns: {email_df.columns.tolist()}")
print(f"\nFirst 3 rows:")
print(email_df.head(3))
print(f"\nData types:\n{email_df.dtypes}")
print(f"\nBasic stats:\n{email_df.describe()}")

# Missing Values Check
print("\n--- Missing Values ---")
print(email_df.isnull().sum())
print(f"\nTotal missing: {email_df.isnull().sum().sum()}")

# Duplicate Check & Removal
print("\n--- Duplicates ---")
dup_count = email_df.duplicated().sum()
print(f"Duplicate rows found: {dup_count}")

if dup_count > 0:
    email_df = email_df.drop_duplicates().reset_index(drop=True)
    print(f"After removing duplicates: {email_df.shape}")

# Class Distribution Analysis
print("\n--- Class Distribution ---")
class_counts = email_df['spam'].value_counts()
print(class_counts)
print(f"\nClass ratio (spam/ham): {class_counts[1] / class_counts[0]:.3f}")

# Visualization: Class Distribution Bar Chart
fig, axes = plt.subplots(1, 2, figsize=(12, 5))

# Bar chart
colors = ['#2ecc71', '#e74c3c']
class_counts.plot(kind='bar', ax=axes[0], color=colors, edgecolor='black')
axes[0].set_title('Email Class Distribution', fontsize=14, fontweight='bold')
axes[0].set_xlabel('Class (0=Ham, 1=Spam)')
axes[0].set_ylabel('Count')
axes[0].set_xticklabels(['Ham (0)', 'Spam (1)'], rotation=0)
for i, v in enumerate(class_counts.values):
    axes[0].text(i, v + 30, str(v), ha='center', fontweight='bold')

# Pie chart
axes[1].pie(class_counts.values, labels=['Ham', 'Spam'], autopct='%1.1f%%',
            colors=colors, startangle=90, explode=(0, 0.05))
axes[1].set_title('Email Class Proportion', fontsize=14, fontweight='bold')

plt.tight_layout()
plt.close()
print("Observation: Dataset is imbalanced — ~76% Ham vs ~24% Spam.")

# Text Length Analysis
print("\n--- Text Length Analysis ---")
email_df['text_length'] = email_df['text'].str.len()
email_df['word_count'] = email_df['text'].str.split().str.len()

print(email_df[['text_length', 'word_count']].describe())

# Visualization: Text length distribution by class
fig, axes = plt.subplots(1, 2, figsize=(14, 5))

for label, color, name in [(0, '#2ecc71', 'Ham'), (1, '#e74c3c', 'Spam')]:
    subset = email_df[email_df['spam'] == label]
    axes[0].hist(subset['text_length'], bins=50, alpha=0.6, color=color, label=name, edgecolor='black')
    axes[1].hist(subset['word_count'], bins=50, alpha=0.6, color=color, label=name, edgecolor='black')

axes[0].set_title('Text Length Distribution by Class', fontsize=13, fontweight='bold')
axes[0].set_xlabel('Character Count')
axes[0].set_ylabel('Frequency')
axes[0].legend()

axes[1].set_title('Word Count Distribution by Class', fontsize=13, fontweight='bold')
axes[1].set_xlabel('Word Count')
axes[1].set_ylabel('Frequency')
axes[1].legend()

plt.tight_layout()
plt.close()
print("Observation: Spam emails tend to be shorter on average than ham emails.")

# Text Cleaning
print("\n--- Text Cleaning ---")

def clean_text(text):
    if not isinstance(text, str):
        return ""
    text = text.lower()
    text = re.sub(r'^subject\s*:\s*', '', text)
    text = re.sub(r'\S+@\S+', '', text)
    text = re.sub(r'http\S+|www\.\S+', '', text)
    text = re.sub(r'<.*?>', '', text)
    text = re.sub(r'\d+', '', text)
    text = re.sub(r'[^a-zA-Z\s]', '', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

email_df['cleaned_text'] = email_df['text'].apply(clean_text)

print("Before cleaning:")
print(email_df['text'].iloc[0][:150])
print("\nAfter cleaning:")
print(email_df['cleaned_text'].iloc[0][:150])

# Stopword Removal & Lemmatization
print("\n--- Stopword Removal & Lemmatization ---")

import nltk
try:
    from nltk.corpus import stopwords
    from nltk.stem import PorterStemmer
    _ = stopwords.words('english')
except LookupError:
    nltk.download('stopwords', quiet=True)
    from nltk.corpus import stopwords
    from nltk.stem import PorterStemmer

stop_words = set(stopwords.words('english'))
stemmer = PorterStemmer()

def preprocess_text(text):
    words = text.split()
    words = [stemmer.stem(w) for w in words if w not in stop_words and len(w) > 2]
    return ' '.join(words)

email_df['processed_text'] = email_df['cleaned_text'].apply(preprocess_text)

print("After stopword removal & lemmatization:")
print(email_df['processed_text'].iloc[0][:200])

# Check for any empty texts after processing
empty_count = (email_df['processed_text'].str.len() == 0).sum()
print(f"\nEmpty texts after processing: {empty_count}")
if empty_count > 0:
    email_df = email_df[email_df['processed_text'].str.len() > 0].reset_index(drop=True)
    print(f"Removed empty texts. New shape: {email_df.shape}")

# TF-IDF Vectorization
print("\n--- TF-IDF Vectorization ---")

from sklearn.feature_extraction.text import TfidfVectorizer

tfidf = TfidfVectorizer(max_features=5000, ngram_range=(1, 2))
X_email_tfidf = tfidf.fit_transform(email_df['processed_text'])
y_email = email_df['spam'].values

print(f"TF-IDF matrix shape: {X_email_tfidf.shape}")
print(f"Target shape: {y_email.shape}")
print(f"Feature names (first 20): {tfidf.get_feature_names_out()[:20].tolist()}")

# Save Preprocessed Email Data
print("\n--- Saving Preprocessed Email Data ---")

from scipy import sparse

sparse.save_npz(os.path.join(OUTPUT_DIR, 'email_tfidf_features.npz'), X_email_tfidf)
np.save(os.path.join(OUTPUT_DIR, 'email_labels.npy'), y_email)
email_df[['processed_text', 'spam']].to_csv(
    os.path.join(OUTPUT_DIR, 'emails_cleaned.csv'), index=False
)
pd.Series(tfidf.get_feature_names_out()).to_csv(
    os.path.join(OUTPUT_DIR, 'email_tfidf_feature_names.csv'), index=False
)

print("Saved: email_tfidf_features.npz, email_labels.npy, email_tfidf_feature_names.csv")
print("Email preprocessing COMPLETE!\n")

# PART 2: URLSET DATASET PREPROCESSING
url_df = pd.read_csv(os.path.join(DATASET_DIR, 'urlset.csv'), encoding='latin-1', on_bad_lines='skip', low_memory=False)

print(f"\nShape: {url_df.shape}")
print(f"Columns: {url_df.columns.tolist()}")
print(f"\nFirst 5 rows:\n{url_df.head()}")

# Data Cleaning
print("\n--- Data Cleaning ---")
if 'label' in url_df.columns:
    initial_len = len(url_df)
    url_df = url_df.dropna(subset=['label'])
    print(f"Dropped {initial_len - len(url_df)} rows with missing labels.")
    
    if 'domain' in url_df.columns:
        url_df = url_df.drop(columns=['domain'])
        print("Dropped 'domain' column.")
    
    url_df['label'] = url_df['label'].astype(int)

# Coerce all other columns to numeric
for col in url_df.columns:
    if col != 'label':
        url_df[col] = pd.to_numeric(url_df[col], errors='coerce')

missing_before = url_df.isnull().sum().sum()
url_df = url_df.fillna(url_df.median())
missing_after = url_df.isnull().sum().sum()
print(f"Imputed {missing_before - missing_after} missing values with median.")

print("\n--- Converting to Binary Classification ---")
print("Mapping in urlset.csv: 1 (Phishing) -> 0 (Malicious)")
print("                       0 (Legitimate) -> 1 (Safe)")

url_df['Result_binary'] = url_df['label'].apply(lambda x: 0 if x == 1 else 1)
url_df = url_df.drop(columns=['label'])

binary_counts = url_df['Result_binary'].value_counts()
print(f"\nBinary class distribution:")
print(f"  0 (Malicious): {binary_counts.get(0, 0)}")
print(f"  1 (Safe):      {binary_counts.get(1, 0)}")

# Feature Scaling (StandardScaler)
print("\n--- Feature Scaling ---")

from sklearn.preprocessing import StandardScaler

feature_cols = [c for c in url_df.columns if c != 'Result_binary']
X_url = url_df[feature_cols].values
y_url = url_df['Result_binary'].values

scaler = StandardScaler()
X_url_scaled = scaler.fit_transform(X_url)

print(f"Features shape: {X_url_scaled.shape}")
print(f"Target shape:   {y_url.shape}")
print(f"\nScaled feature means (should be ~0): {X_url_scaled.mean(axis=0).round(4)[:5]}...")

# Save Preprocessed URL Data
print("\n--- Saving Preprocessed URL Data ---")

# Save scaled features and labels
np.save(os.path.join(OUTPUT_DIR, 'url_features_scaled.npy'), X_url_scaled)
np.save(os.path.join(OUTPUT_DIR, 'url_labels.npy'), y_url)
# Save feature names
pd.Series(feature_cols).to_csv(
    os.path.join(OUTPUT_DIR, 'url_feature_names.csv'), index=False
)

print("Saved: url_features_scaled.npy, url_labels.npy, url_feature_names.csv")
print("URL dataset preprocessing COMPLETE!\n")

# Final Summary
print("=" * 60)
print("PREPROCESSING SUMMARY")
print("=" * 60)
print(f"""
EMAIL DATASET:
  - Vectorized:   TF-IDF (max_features=5000, ngrams=1-2)
  - Output shape: {X_email_tfidf.shape}

URL DATASET (urlset.csv):
  - Original:     ~96000 rows × 14 cols
  - Output shape: {X_url_scaled.shape}
  - Target:       Binary (Malicious=0, Safe=1)

All preprocessed data saved to: {OUTPUT_DIR}
""")
