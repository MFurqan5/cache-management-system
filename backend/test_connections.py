import os
import psycopg2
import redis

from pymongo import MongoClient
from dotenv import load_dotenv
from pathlib import Path

env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

POSTGRES_URL = os.getenv("DATABASE_URL")
MONGO_URL    = os.getenv("MONGODB_URI")
REDIS_URL    = os.getenv("REDIS_URL")

print("POSTGRES_URL =", POSTGRES_URL)
print("MONGO_URL =", MONGO_URL)
print("REDIS_URL =", REDIS_URL)

# PostgreSQL
try:
    conn = psycopg2.connect(POSTGRES_URL)
    print("PostgreSQL Connected")
    conn.close()
except Exception as e:
    print("PostgreSQL Error:", e)

# MongoDB
try:
    client = MongoClient(MONGO_URL)
    client.admin.command("ping")
    print("MongoDB Connected")
except Exception as e:
    print("MongoDB Error:", e)

# Redis
try:
    r = redis.from_url(REDIS_URL, decode_responses=True)
    r.ping()
    print("Redis Connected")
except Exception as e:
    print("Redis Error:", e)