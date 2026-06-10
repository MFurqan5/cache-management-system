# backend/db/ml_integration.py
"""Integration layer between ML models and existing databases"""
import os
import json
import hashlib
import redis
import psycopg2
import psycopg2.extras
from pymongo import MongoClient
from backend.cache import cache_manager
from pymongo.server_api import ServerApi
from dotenv import load_dotenv
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import logging
import uuid

# Force load .env
dotenv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "URLs.env")
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)
else:
    load_dotenv()
logger = logging.getLogger(__name__)

# Database connections
POSTGRES_URL = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL")
REDIS_URL = os.getenv("REDIS_URL")
MONGO_URL = os.getenv("MONGO_URL") or os.getenv("MONGODB_URI")

class MLDatabaseIntegration:
    """Handles all database operations for ML predictions"""
    
    def __init__(self):
        self.postgres_conn = None
        self.redis_client = None
        self.mongo_client = None
        logger.info("MLDatabaseIntegration initialized")
    
    def get_postgres_connection(self):
        """Get PostgreSQL connection"""
        if self.postgres_conn is None or self.postgres_conn.closed:
            try:
                self.postgres_conn = psycopg2.connect(POSTGRES_URL)
                logger.info("PostgreSQL connected")
            except Exception as e:
                logger.error(f"PostgreSQL connection failed: {e}")
                raise
        return self.postgres_conn
    
    def get_redis_client(self):
        """Get Redis client"""
        if self.redis_client is None:
            try:
                self.redis_client = redis.from_url(REDIS_URL, decode_responses=True)
                self.redis_client.ping()
                logger.info("Redis connected")
            except Exception as e:
                logger.error(f"Redis connection failed: {e}")
                raise
        return self.redis_client
    
    def get_mongo_client(self):
        """Get MongoDB client"""
        if self.mongo_client is None and MONGO_URL:
            try:
                self.mongo_client = MongoClient(MONGO_URL, server_api=ServerApi('1'))
                self.mongo_client.admin.command('ping')
                logger.info("MongoDB connected")
            except Exception as e:
                logger.warning(f"MongoDB connection failed: {e}")
                return None
        return self.mongo_client
    
    def increment_cache_hit(self, cache_level):
        """Track cache hits for L1, L2, L3"""
        try:
            redis_client = self.get_redis_client()
            redis_client.hincrby(f"cache_stats:{cache_level}", "hits", 1)
            logger.debug(f"Cache hit tracked for {cache_level}")
        except Exception as e:
            logger.warning(f"Failed to track cache hit: {e}")
    
    def increment_cache_miss(self, cache_level):
        """Track cache misses for L1, L2, L3"""
        try:
            redis_client = self.get_redis_client()
            redis_client.hincrby(f"cache_stats:{cache_level}", "misses", 1)
            logger.debug(f"Cache miss tracked for {cache_level}")
        except Exception as e:
            logger.warning(f"Failed to track cache miss: {e}")
    
    def get_cache_stats(self):
        """Get real cache statistics from Redis for all three layers"""
        try:
            redis_client = self.get_redis_client()
            
            # Get L1 stats
            l1_hits = int(redis_client.hget("cache_stats:l1", "hits") or 0)
            l1_misses = int(redis_client.hget("cache_stats:l1", "misses") or 0)
            l1_total = l1_hits + l1_misses
            
            # Get L2 stats
            l2_hits = int(redis_client.hget("cache_stats:l2", "hits") or 0)
            l2_misses = int(redis_client.hget("cache_stats:l2", "misses") or 0)
            l2_total = l2_hits + l2_misses
            
            # Get L3 stats
            l3_hits = int(redis_client.hget("cache_stats:l3", "hits") or 0)
            l3_misses = int(redis_client.hget("cache_stats:l3", "misses") or 0)
            l3_total = l3_hits + l3_misses
            
            # Additional info
            redis_keys = 0
            try:
                redis_keys = len(redis_client.keys("threat:v1:*"))
            except Exception:
                pass
                
            mongo_count = 0
            try:
                mongo_client = self.get_mongo_client()
                if mongo_client:
                    db = mongo_client["Cache_db"]
                    collection = db["cache_results"]
                    mongo_count = collection.count_documents({})
            except Exception:
                pass
            
            return {
                "l1": {
                    "hits": l1_hits,
                    "misses": l1_misses,
                    "hit_rate": round(l1_hits / l1_total, 2) if l1_total > 0 else 0
                },
                "l2": {
                    "hits": l2_hits,
                    "misses": l2_misses,
                    "keys": redis_keys,
                    "hit_rate": round(l2_hits / l2_total, 2) if l2_total > 0 else 0
                },
                "l3": {
                    "hits": l3_hits,
                    "misses": l3_misses,
                    "documents": mongo_count,
                    "hit_rate": round(l3_hits / l3_total, 2) if l3_total > 0 else 0
                }
            }
        except Exception as e:
            logger.error(f"Failed to get cache stats: {e}")
            return {
                "l1": {"hits": 0, "misses": 0, "hit_rate": 0},
                "l2": {"hits": 0, "misses": 0, "keys": 0, "hit_rate": 0},
                "l3": {"hits": 0, "misses": 0, "documents": 0, "hit_rate": 0}
            }
    
    def save_prediction(self, request_id: str, user_id: str, input_type: str, 
                        input_value: str, prediction: Dict, model_version: str,
                        inference_ms: float, severity: str = "medium", 
                        action_taken: str = "flagged"):
        """Save ML prediction to all three databases"""
        
        input_hash = hashlib.sha256(input_value.encode()).hexdigest()
        logger.info(f"Saving prediction for {input_type} with hash {input_hash[:16]}...")
        
        saved = {"postgres": False, "redis": False, "mongodb": False}
        
        # 1. Save to PostgreSQL
        try:
            conn = self.get_postgres_connection()
            cur = conn.cursor()
            
            # Ensure users exist
            cur.execute("SELECT id FROM users WHERE id = %s::uuid", (user_id,))
            if not cur.fetchone():
                cur.execute("""
                    INSERT INTO users (id, email, username, password_hash, role)
                    VALUES (%s::uuid, %s, %s, %s, %s)
                    ON CONFLICT (id) DO NOTHING
                """, (user_id, f"user_{user_id[:8]}@example.com", f"user_{user_id[:8]}", "placeholder", "user"))
            
            # Insert into scan_requests
            cur.execute("""
                INSERT INTO scan_requests (id, user_id, input_type, input_value, input_hash, status, created_at)
                VALUES (%s::uuid, %s::uuid, %s, %s, %s, 'complete', %s)
                RETURNING id
            """, (request_id, user_id, input_type, input_value[:500], input_hash, datetime.utcnow()))
            
            result = cur.fetchone()
            final_request_id = result[0] if result else request_id
            
            # Insert into ai_predictions
            prediction_id = str(uuid.uuid4())
            cur.execute("""
                INSERT INTO ai_predictions
                    (id, request_id, prediction_label, threat_type, confidence_score,
                    explanation, indicators, model_version, inference_ms, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s)
                ON CONFLICT (request_id) DO NOTHING
            """, (
                prediction_id, final_request_id,
                prediction.get("label", "safe"),
                prediction.get("threat_type", "clean"),
                prediction.get("confidence", 0.5),
                prediction.get("explanation", ""),
                json.dumps(prediction.get("indicators", [])),
                model_version,
                int(inference_ms),
                datetime.utcnow()
            ))
            
            # Insert into threat_logs
            cur.execute("""
                INSERT INTO threat_logs (prediction_id, severity, action_taken, notes, created_at)
                VALUES (%s, %s, %s, %s, %s)
            """, (prediction_id, severity, action_taken, f"ML Prediction: {prediction.get('explanation', '')[:200]}", datetime.utcnow()))
            
            conn.commit()
            cur.close()
            saved["postgres"] = True
            logger.info(f"✅ Saved to PostgreSQL: {final_request_id}")
            
        except Exception as e:
            logger.error(f"❌ PostgreSQL save failed: {e}")
            try:
                conn.rollback()
            except Exception:
                pass
        
        # 1.5 Save to L1 Memory Cache & L2 Redis Cache
        redis_data = {
            "label": prediction.get("label"),
            "type": prediction.get("threat_type"),
            "score": prediction.get("confidence"),
            "indicators": prediction.get("indicators", []),
            "model": model_version,
            **{k: v for k, v in prediction.items() if k not in ["label", "threat_type", "confidence", "indicators", "model"]}
        }
        try:
            l1_key = cache_manager.get_prediction_cache_key(input_value, input_type)
            cache_manager.cache_prediction(l1_key, redis_data)
            logger.info(f"✅ Saved to L1 Cache: {l1_key}")
        except Exception as e:
            logger.warning(f"⚠️ L1 Cache save failed: {e}")

        try:
            redis_client = self.get_redis_client()
            cache_key = f"threat:v1:{input_hash}"
            redis_client.setex(cache_key, 3600, json.dumps(redis_data))
            saved["redis"] = True
            logger.info(f"✅ Saved to Redis: {cache_key}")
        except Exception as e:
            logger.warning(f"⚠️ Redis save failed: {e}")
        
        # 3. Save to MongoDB Cache (optional)
        if MONGO_URL:
            try:
                mongo_client = self.get_mongo_client()
                if mongo_client:
                    db = mongo_client["Cache_db"]
                    collection = db["cache_results"]
                    
                    mongo_doc = {
                        "cache_key": input_hash,
                        "input_type": input_type,
                        "input_hash": input_hash,
                        "result": {
                            "prediction_label": prediction.get("label"),
                            "threat_type": prediction.get("threat_type"),
                            "confidence_score": prediction.get("confidence"),
                            "explanation": prediction.get("explanation", ""),
                            "indicators": prediction.get("indicators", []),
                            **{k: v for k, v in prediction.items() if k not in ["label", "threat_type", "confidence", "explanation", "indicators"]}
                        },
                        "model_version": model_version,
                        "hit_count": 0,
                        "created_at": datetime.utcnow(),
                        "expires_at": datetime.utcnow() + timedelta(hours=24),
                        "request_id": final_request_id if saved["postgres"] else None
                    }
                    collection.update_one(
                        {"input_hash": input_hash},
                        {"$set": mongo_doc},
                        upsert=True
                    )
                    saved["mongodb"] = True
                    logger.info(f"✅ Saved to MongoDB: {input_hash}")
            except Exception as e:
                logger.warning(f"⚠️ MongoDB save failed: {e}")
        
        logger.info(f"Save completed - PostgreSQL: {saved['postgres']}, Redis: {saved['redis']}, MongoDB: {saved['mongodb']}")
        return {
            "request_id": request_id,
            "saved": saved,
            "from_cache": False
        }
    
    def check_cache(self, input_value: str, input_type: str):
        """Check L1 Memory, L2 Redis, and L3 MongoDB caches sequentially and track statistics"""
        input_hash = hashlib.sha256(input_value.encode()).hexdigest()
        l1_key = cache_manager.get_prediction_cache_key(input_value, input_type)
        
        # 1. Check L1 Memory Cache
        try:
            cached_l1 = cache_manager.prediction_cache.get(l1_key)
            if cached_l1:
                self.increment_cache_hit("l1")
                cache_manager.hits += 1
                logger.info(f"L1 memory cache hit for {input_type}")
                return {
                    "from_cache": "L1",
                    "result": cached_l1,
                    "input_hash": input_hash
                }
            else:
                self.increment_cache_miss("l1")
                cache_manager.misses += 1
                logger.info(f"L1 memory cache miss for {input_type}")
        except Exception as e:
            logger.warning(f"L1 memory cache check failed: {e}")

        # 2. Check L2 Redis Cache
        cache_key = f"threat:v1:{input_hash}"
        try:
            redis_client = self.get_redis_client()
            cached_l2_str = redis_client.get(cache_key)
            if cached_l2_str:
                self.increment_cache_hit("l2")
                logger.info(f"L2 Redis cache hit for {input_type}")
                cached_l2 = json.loads(cached_l2_str)
                
                # Populate back to L1 Memory
                try:
                    cache_manager.cache_prediction(l1_key, cached_l2)
                except Exception as ex:
                    logger.warning(f"Failed to populate L1 from L2: {ex}")
                
                return {
                    "from_cache": "L2",
                    "result": cached_l2,
                    "input_hash": input_hash
                }
            else:
                self.increment_cache_miss("l2")
                logger.info(f"L2 Redis cache miss for {input_type}")
        except Exception as e:
            logger.warning(f"L2 Redis cache check failed: {e}")

        # 3. Check L3 MongoDB Cache
        if MONGO_URL:
            try:
                mongo_client = self.get_mongo_client()
                if mongo_client:
                    db = mongo_client["Cache_db"]
                    collection = db["cache_results"]
                    cached_l3_doc = collection.find_one({"input_hash": input_hash})
                    
                    if cached_l3_doc:
                        self.increment_cache_hit("l3")
                        logger.info(f"L3 MongoDB cache hit for {input_type}")
                        
                        l3_res = cached_l3_doc.get("result", {})
                        result_data = {
                            "label": l3_res.get("prediction_label"),
                            "type": l3_res.get("threat_type"),
                            "score": l3_res.get("confidence_score"),
                            "indicators": l3_res.get("indicators", []),
                            "model": cached_l3_doc.get("model_version", "unknown"),
                            **{k: v for k, v in l3_res.items() if k not in ["prediction_label", "threat_type", "confidence_score", "indicators"]}
                        }
                        
                        # Populate back to L2 Redis and L1 Memory
                        try:
                            cache_manager.cache_prediction(l1_key, result_data)
                            redis_client = self.get_redis_client()
                            redis_client.setex(cache_key, 3600, json.dumps(result_data))
                        except Exception as ex:
                            logger.warning(f"Failed to populate L1/L2 from L3: {ex}")
                        
                        return {
                            "from_cache": "L3",
                            "result": result_data,
                            "input_hash": input_hash
                        }
                    else:
                        self.increment_cache_miss("l3")
                        logger.info(f"L3 MongoDB cache miss for {input_type}")
            except Exception as e:
                logger.warning(f"L3 MongoDB cache check failed: {e}")
        
        return None
    
    def get_user_id(self, email_or_username: str) -> Optional[str]:
        """Get user_id from existing users table"""
        try:
            conn = self.get_postgres_connection()
            cur = conn.cursor()
            cur.execute("SELECT id FROM users WHERE email = %s OR username = %s LIMIT 1", 
                       (email_or_username, email_or_username))
            result = cur.fetchone()
            cur.close()
            return result[0] if result else None
        except Exception as e:
            logger.error(f"Failed to get user_id: {e}")
            try:
                conn.rollback()
            except Exception:
                pass
            return None

    def create_user_postgres(self, username: str, email: str, password_hash: str) -> str:
        """Create a new user in PostgreSQL and return user id (UUID string)"""
        conn = self.get_postgres_connection()
        cur = conn.cursor()
        user_id = str(uuid.uuid4())
        try:
            cur.execute("""
                INSERT INTO users (id, username, email, password_hash, role)
                VALUES (%s::uuid, %s, %s, %s, 'user')
            """, (user_id, username, email, password_hash))
            conn.commit()
            return user_id
        except Exception as e:
            conn.rollback()
            logger.error(f"PostgreSQL create_user failed: {e}")
            raise
        finally:
            cur.close()

    def get_user_by_username_postgres(self, username: str) -> Optional[dict]:
        """Retrieve a user by username from PostgreSQL"""
        conn = self.get_postgres_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            cur.execute("SELECT id, username, email, password_hash, role, created_at FROM users WHERE username = %s", (username,))
            row = cur.fetchone()
            if row:
                return {
                    "id": str(row["id"]),
                    "username": row["username"],
                    "email": row["email"],
                    "password_hash": row["password_hash"],
                    "role": row.get("role", "user"),
                    "created_at": row["created_at"].isoformat() if row.get("created_at") else None
                }
            return None
        except Exception as e:
            conn.rollback()
            logger.error(f"PostgreSQL get_user_by_username failed: {e}")
            raise
        finally:
            cur.close()

    def get_user_by_email_postgres(self, email: str) -> Optional[dict]:
        """Retrieve a user by email from PostgreSQL"""
        conn = self.get_postgres_connection()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        try:
            cur.execute("SELECT id, username, email, password_hash, role, created_at FROM users WHERE email = %s", (email,))
            row = cur.fetchone()
            if row:
                return {
                    "id": str(row["id"]),
                    "username": row["username"],
                    "email": row["email"],
                    "password_hash": row["password_hash"],
                    "role": row.get("role", "user"),
                    "created_at": row["created_at"].isoformat() if row.get("created_at") else None
                }
            return None
        except Exception as e:
            conn.rollback()
            logger.error(f"PostgreSQL get_user_by_email failed: {e}")
            raise
        finally:
            cur.close()

# Global instance
ml_db = MLDatabaseIntegration()