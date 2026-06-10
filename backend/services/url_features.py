import re
import math
import pandas as pd
import numpy as np
from urllib.parse import urlparse, parse_qs


FEATURE_NAMES = [
    'url_length', 'dot_count', 'has_at_symbol', 'has_https', 'slash_count',
    'has_ip', 'hyphen_count', 'suspicious_keywords', 'domain_length', 'special_chars',
    'digit_count', 'digit_ratio', 'has_double_slash_redirect', 'subdomain_count',
    'path_depth', 'url_entropy', 'has_port', 'path_length', 'query_param_count',
    'has_encoded_chars', 'uppercase_ratio', 'has_www', 'avg_token_length',
    'longest_token_length', 'tilde_count',
]


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def extract_url_features_single(url: str) -> np.ndarray:
    url_lower = url.lower()
    url_len = len(url)

    try:
        parsed = urlparse(url if '://' in url else f'http://{url}')
        domain = parsed.netloc or ''
        path = parsed.path or ''
        query = parsed.query or ''
    except Exception:
        domain = ''
        path = ''
        query = ''

    features = []

    features.append(min(url_len / 2000, 1.0))
    features.append(min(url.count('.') / 20, 1.0))
    features.append(1.0 if '@' in url else 0.0)
    features.append(1.0 if 'https' in url_lower else 0.0)
    features.append(min(url.count('/') / 10, 1.0))
    features.append(1.0 if re.search(ip_pattern, url) else 0.0)
    features.append(1.0 if re.search(ip_pattern, url) else 0.0)
    features.append(min(url.count('-') / 10, 1.0))
    suspicious = ['login', 'verify', 'account', 'secure', 'update', 'confirm','signin', 'banking', 'paypal', 'amazon', 'suspicious', 'free', 'prize', 'claim', 'urgent', 'wallet']
    features.append(sum(1 for kw in suspicious if kw in url_lower) / len(suspicious))
    features.append(min(len(domain) / 100, 1.0))
    special_chars = sum(1 for c in url if c in '?=&%+')
    features.append(min(special_chars / 20, 1.0))

    digit_count = sum(c.isdigit() for c in url)
    features.append(min(digit_count / 50, 1.0))
    features.append(digit_count / max(url_len, 1))
    after_protocol = url.split('://', 1)[1] if '://' in url else url
    features.append(1.0 if '//' in after_protocol else 0.0)

    domain_clean = domain.split(':')[0]
    parts = domain_clean.split('.')
    subdomain_count = max(len(parts) - 2, 0)
    features.append(min(subdomain_count / 5, 1.0))
    path_parts = [p for p in path.split('/') if p]
    features.append(min(len(path_parts) / 10, 1.0))
    entropy = _shannon_entropy(url)
    features.append(min(entropy / 6.0, 1.0))
    features.append(min(len(path) / 500, 1.0))
    try:
        param_count = len(parse_qs(query))
    except Exception:
        param_count = 0
    features.append(min(param_count / 10, 1.0))
    features.append(1.0 if '%' in url else 0.0)
    upper_count = sum(c.isupper() for c in url)
    features.append(upper_count / max(url_len, 1))
    features.append(1.0 if 'www' in url_lower else 0.0)
    tokens = re.split(r'[/\-_.?=&%+@:~]', url)
    tokens = [t for t in tokens if t]
    avg_token = sum(len(t) for t in tokens) / max(len(tokens), 1)
    features.append(min(avg_token / 30, 1.0))
    longest = max((len(t) for t in tokens), default=0)
    features.append(min(longest / 100, 1.0))
    features.append(min(url.count('~') / 5, 1.0))
    return np.array(features).reshape(1, -1)


def extract_url_features_batch(url_series: pd.Series) -> np.ndarray:
    """Extract 25 features from a pandas Series of URLs. Returns shape (n, 25)."""
    print(f"Extracting {len(FEATURE_NAMES)} features from {len(url_series)} URLs...")
    results = []
    for url in url_series.fillna("").astype(str):
        results.append(extract_url_features_single(url)[0])
    return np.array(results)
