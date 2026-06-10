"""
Shared App Feature Extraction Logic.
Used by the backend API to extract 215 binary features from uploaded APK files.
Matches the exact feature set from the Drebin-215 dataset.
"""
import zipfile
import re
import os
import numpy as np
import pandas as pd
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

_BASE_DIR = Path(__file__).resolve().parent.parent
_FEATURE_NAMES_PATH = _BASE_DIR / 'ml_training' / 'preprocessing' / 'preprocessed_data' / 'app_feature_names.csv'
_CATEGORIES_PATH = _BASE_DIR / 'ml_training' / 'datasets' / 'App Malware Datasets' / 'dataset-features-categories.csv'

try:
    _features_df = pd.read_csv(_FEATURE_NAMES_PATH)
    FEATURE_NAMES = _features_df['feature_name'].tolist()
except Exception:
    FEATURE_NAMES = []
    logger.warning("Could not load app_feature_names.csv, features list empty until loaded")

FEATURE_CATEGORIES = {}
try:
    _cat_df = pd.read_csv(_CATEGORIES_PATH, header=None, names=['feature', 'category'])
    for _, row in _cat_df.iterrows():
        FEATURE_CATEGORIES[row['feature']] = row['category']
except Exception:
    logger.warning("Could not load dataset-features-categories.csv")


def extract_apk_features(file_path: str) -> np.ndarray:
    """
    Extract 215 binary features from an APK file by statically scanning
    the AndroidManifest.xml and DEX bytecode for known permissions,
    API calls, intents, and command signatures.
    
    Returns: numpy array of shape (1, 215) with binary values (0 or 1).
    """
    if not FEATURE_NAMES:
        raise ValueError("Feature names not loaded. Check app_feature_names.csv exists.")
    
    features = np.zeros(len(FEATURE_NAMES), dtype=np.float32)
    
    try:
        with zipfile.ZipFile(file_path, 'r') as apk:
            searchable_content = []
            
            for entry in apk.namelist():
                entry_lower = entry.lower()
                
                if entry_lower == 'androidmanifest.xml':
                    try:
                        raw = apk.read(entry)
                        text = raw.decode('utf-8', errors='ignore')
                        searchable_content.append(text)
                        text_latin = raw.decode('latin-1', errors='ignore')
                        searchable_content.append(text_latin)
                    except Exception as e:
                        logger.debug(f"Could not read manifest: {e}")
                
                elif entry_lower.endswith('.dex'):
                    try:
                        raw = apk.read(entry)
                        text = raw.decode('utf-8', errors='ignore')
                        searchable_content.append(text)
                    except Exception as e:
                        logger.debug(f"Could not read DEX {entry}: {e}")
                
                elif entry_lower.endswith(('.xml', '.txt', '.properties', '.cfg')):
                    try:
                        raw = apk.read(entry)
                        if len(raw) < 1_000_000: 
                            text = raw.decode('utf-8', errors='ignore')
                            searchable_content.append(text)
                    except Exception:
                        pass
            
            full_content = '\n'.join(searchable_content)
            
            for i, feature_name in enumerate(FEATURE_NAMES):
                if feature_name in full_content:
                    features[i] = 1.0
                else:
                    if feature_name.isupper() or feature_name.startswith('android.'):
                        perm_string = f"android.permission.{feature_name}"
                        if perm_string in full_content or feature_name in full_content:
                            features[i] = 1.0
                    elif '.' in feature_name:
                        if feature_name in full_content:
                            features[i] = 1.0
    
    except zipfile.BadZipFile:
        logger.error(f"Invalid APK/ZIP file: {file_path}")
        raise ValueError("The uploaded file is not a valid APK file.")
    except Exception as e:
        logger.error(f"Error extracting APK features: {e}")
        raise ValueError(f"Could not analyze APK file: {str(e)}")
    
    detected_count = int(features.sum())
    logger.info(f"APK analysis complete: {detected_count}/{len(FEATURE_NAMES)} features detected")
    
    return features.reshape(1, -1)


def get_detected_features(features: np.ndarray) -> list:
    """Get list of detected feature names and their categories from a feature vector."""
    detected = []
    flat = features.flatten()
    for i, val in enumerate(flat):
        if val == 1.0 and i < len(FEATURE_NAMES):
            name = FEATURE_NAMES[i]
            category = FEATURE_CATEGORIES.get(name, 'Unknown')
            detected.append({
                'name': name,
                'category': category
            })
    return detected


def get_risk_indicators(features: np.ndarray) -> list:
    """Generate human-readable risk indicators from detected features."""
    detected = get_detected_features(features)
    indicators = []
    
    high_risk_perms = [
        'SEND_SMS', 'READ_SMS', 'RECEIVE_SMS', 'WRITE_SMS',
        'READ_PHONE_STATE', 'CALL_PHONE', 'READ_CALL_LOG', 'WRITE_CALL_LOG',
        'READ_CONTACTS', 'WRITE_CONTACTS', 'CAMERA', 'RECORD_AUDIO',
        'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
        'INSTALL_PACKAGES', 'DELETE_PACKAGES',
        'READ_LOGS', 'SYSTEM_ALERT_WINDOW', 'WRITE_SECURE_SETTINGS',
        'DEVICE_POWER', 'REBOOT', 'MASTER_CLEAR'
    ]
    
    suspicious_apis = [
        'DexClassLoader', 'Runtime.exec', 'Runtime.getRuntime',
        'System.loadLibrary', 'Runtime.load', 'Runtime.loadLibrary',
        'ProcessBuilder', 'createSubprocess', 'abortBroadcast',
        'ClassLoader', 'URLClassLoader', 'PathClassLoader',
        'defineClass', 'findClass'
    ]
    
    suspicious_cmds = ['chmod', 'chown', 'mount', 'remount', '/system/bin', '/system/app']
    
    for feat in detected:
        name = feat['name']
        if name in high_risk_perms:
            indicators.append(f"dangerous_permission_{name.lower()}")
        elif name in suspicious_apis:
            indicators.append(f"suspicious_api_{name.lower()}")
        elif name in suspicious_cmds:
            indicators.append(f"suspicious_command_{name.lower()}")
    
    return indicators
