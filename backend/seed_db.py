"""
seed_db.py  —  Populates PostgreSQL, MongoDB, and Redis
with identical dummy cybersecurity threat data.

RUN:
    cd backend
    python seed_db.py
"""

import os
import json
import hashlib
import psycopg2
import redis

from pymongo import MongoClient
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone

dotenv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "URLs.env")
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)
else:
    load_dotenv()

# ─────────────────────────────────────────────────────────────
# Database URLs
# ─────────────────────────────────────────────────────────────

POSTGRES_URL = os.getenv("DATABASE_URL")
MONGO_URL    = os.getenv("MONGODB_URI")
REDIS_URL    = os.getenv("REDIS_URL")

# Debug prints
print("POSTGRES_URL =", POSTGRES_URL)
print("MONGO_URL =", MONGO_URL)
print("REDIS_URL =", REDIS_URL)

# ─────────────────────────────────────────────────────────────
# Seed Data
# ─────────────────────────────────────────────────────────────

SEED_DATA = [
    {
        "user_id": "22222222-2222-2222-2222-222222222222",
        "input_type": "url",
        "input_value": "http://paypal-secure-login.xyz/verify",
        "prediction_label": "malicious",
        "threat_type": "phishing",
        "confidence_score": 0.97,
        "explanation": "Domain impersonates PayPal.",
        "indicators": [
            "suspicious_tld",
            "login_form_detected",
            "brand_impersonation"
        ],
        "model_version": "rf-url-v2.1",
        "inference_ms": 82,
        "severity": "high",
        "action_taken": "blocked",
    },
    {
        "user_id": "11111111-1111-1111-1111-111111111111",
        "input_type": "url",
        "input_value": "https://google.com",
        "prediction_label": "safe",
        "threat_type": "clean",
        "confidence_score": 0.99,
        "explanation": "Known safe domain.",
        "indicators": [],
        "model_version": "rf-url-v2.1",
        "inference_ms": 71,
        "severity": "low",
        "action_taken": "none",
    },
]

DUMMY_USERS = [
    {
        "id": "11111111-1111-1111-1111-111111111111",
        "email": "analyst@securescan.com",
        "username": "admin_alice",
        "password_hash": "$2a$12$placeholder_hash_alice",
        "role": "analyst",
    },
    {
        "id": "22222222-2222-2222-2222-222222222222",
        "email": "user@company.com",
        "username": "bob_user",
        "password_hash": "$2a$12$placeholder_hash_bob",
        "role": "user",
    },
]

# ─────────────────────────────────────────────────────────────
# Utility Function
# ─────────────────────────────────────────────────────────────

def make_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()

# ─────────────────────────────────────────────────────────────
# PostgreSQL Seed
# ─────────────────────────────────────────────────────────────

def seed_postgres():
    print("\n[1/3] Seeding PostgreSQL...")

    conn = psycopg2.connect(POSTGRES_URL)
    cur = conn.cursor()

    # Insert users
    for u in DUMMY_USERS:
        cur.execute("""
            INSERT INTO users
            (id, email, username, password_hash, role)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (email) DO NOTHING
        """, (
            u["id"],
            u["email"],
            u["username"],
            u["password_hash"],
            u["role"]
        ))

    # Insert threat scan data
    for i, item in enumerate(SEED_DATA):

        request_id = f"aaaa{i:04d}-0000-0000-0000-000000000000"
        prediction_id = f"bbbb{i:04d}-0000-0000-0000-000000000000"

        input_hash = make_hash(item["input_value"])

        cur.execute("""
            INSERT INTO scan_requests
            (id, user_id, input_type, input_value, input_hash, status)
            VALUES (%s, %s, %s, %s, %s, 'complete')
            ON CONFLICT (input_hash) DO NOTHING
        """, (
            request_id,
            item["user_id"],
            item["input_type"],
            item["input_value"],
            input_hash
        ))

        cur.execute("""
            INSERT INTO ai_predictions
            (
                id,
                request_id,
                prediction_label,
                threat_type,
                confidence_score,
                explanation,
                indicators,
                model_version,
                inference_ms
            )
            VALUES
            (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)
            ON CONFLICT (request_id) DO NOTHING
        """, (
            prediction_id,
            request_id,
            item["prediction_label"],
            item["threat_type"],
            item["confidence_score"],
            item["explanation"],
            json.dumps(item["indicators"]),
            item["model_version"],
            item["inference_ms"]
        ))

        cur.execute("""
            INSERT INTO threat_logs
            (prediction_id, severity, action_taken, notes)
            VALUES (%s, %s, %s, %s)
        """, (
            prediction_id,
            item["severity"],
            item["action_taken"],
            f"Seeded threat log for {item['threat_type']}"
        ))

    conn.commit()
    cur.close()
    conn.close()

    print("PostgreSQL Seeding Complete")

# ─────────────────────────────────────────────────────────────
# MongoDB Seed
# ─────────────────────────────────────────────────────────────

def seed_mongodb():
    print("\n[2/3] Seeding MongoDB...")

    client = MongoClient(MONGO_URL)

    db = client["Cache_db"]
    col = db["cache_results"]

    col.create_index("cache_key", unique=True)
    col.create_index("expires_at", expireAfterSeconds=0)

    count = 0

    for item in SEED_DATA:

        input_hash = make_hash(item["input_value"])

        doc = {
            "cache_key": input_hash,
            "input_type": item["input_type"],
            "input_hash": input_hash,
            "result": {
                "prediction_label": item["prediction_label"],
                "threat_type": item["threat_type"],
                "confidence_score": item["confidence_score"],
                "explanation": item["explanation"],
                "indicators": item["indicators"],
            },
            "model_version": item["model_version"],
            "hit_count": 0,
            "created_at": datetime.now(timezone.utc),
            "expires_at": datetime.now(timezone.utc) + timedelta(hours=24),
        }

        try:
            col.insert_one(doc)
            count += 1
        except Exception:
            pass

    client.close()

    print(f"MongoDB Seeding Complete — {count} inserted")

# ─────────────────────────────────────────────────────────────
# Redis Seed
# ─────────────────────────────────────────────────────────────

def seed_redis():
    print("\n[3/3] Seeding Redis...")

    r = redis.from_url(REDIS_URL, decode_responses=True)

    # Test connection
    r.ping()

    count = 0

    for item in SEED_DATA:

        input_hash = make_hash(item["input_value"])

        cache_key = f"threat:v1:{input_hash}"

        value = json.dumps({
            "label": item["prediction_label"],
            "type": item["threat_type"],
            "score": item["confidence_score"],
            "indicators": item["indicators"],
        })

        r.setex(cache_key, 3600, value)

        count += 1

    print(f"Redis Seeding Complete — {count} inserted")

# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":

    print("=" * 60)
    print(" Cyber Threat Detector — Database Seed Script ")
    print("=" * 60)

    # PostgreSQL
    try:
        seed_postgres()
    except Exception as e:
        print("PostgreSQL Error:", e)

    # MongoDB
    try:
        seed_mongodb()
    except Exception as e:
        print("MongoDB Error:", e)

    # Redis
    try:
        seed_redis()
    except Exception as e:
        print("Redis Error:", e)

    print("\nAll database seeding completed.")