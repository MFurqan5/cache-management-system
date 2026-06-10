import sys
import numpy as np
from pathlib import Path
import joblib

# Import feature extractor
from backend.url_features import extract_url_features_single, FEATURE_NAMES

def load_model(model_name: str):
    model_path = Path(f"backend/models/{model_name}.pkl")
    if model_path.exists():
        return joblib.load(model_path)
    print(f"Model not found at {model_path}")
    return None

def test_url(url: str, model):
    features_array = extract_url_features_single(url)
    
    # Calculate score
    proba = model.predict_proba(features_array)[0]
    score = float(proba[1])
    prediction = 1 if score > 0.5 else 0
    
    print(f"URL: {url}")
    print(f" - Prediction: {'Malicious' if prediction == 1 else 'Safe'}")
    print(f" - Threat Score: {score:.2%}")
    print("-" * 40)

if __name__ == "__main__":
    model = load_model("url_model")
    if model:
        print("Model loaded successfully.\n")
        test_urls = [
            "https://www.google.com",
            "http://example.com",
            "http://suspicious.com/login/verify/account",
            "http://192.168.1.1/update/wallet?claim=free-prize",
            "https://secure-banking-verify-update.com/signin",
            "https://github.com"
        ]
        
        for u in test_urls:
            test_url(u, model)
    else:
        print("Failed to load model.")
