# backend/db.py - Updated to handle both SQLite and Docker databases
import sqlite3
from datetime import datetime
from pathlib import Path
import json
from typing import List, Dict, Optional
import logging
import os

logger = logging.getLogger(__name__)

# SQLite path for local storage
SQLITE_PATH = Path("backend/data/sentinelcache.db")

class Database:
    """Unified Database Manager - Handles SQLite + PostgreSQL/Redis/MongoDB"""
    
    def __init__(self):
        # Initialize SQLite (always available)
        self.sqlite_path = SQLITE_PATH
        self.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_sqlite()
        
        # Try to initialize Docker databases (PostgreSQL, Redis, MongoDB)
        self.docker_available = False
        self.ml_integration = None
        
        try:
            from backend.db.ml_integration import MLDatabaseIntegration
            self.ml_integration = MLDatabaseIntegration()
            self.docker_available = True
            logger.info("Docker databases (PostgreSQL/Redis/MongoDB) connected")
        except Exception as e:
            logger.warning(f"Docker databases not available: {e}. Using SQLite only.")
    
    # ============ SQLite Methods (Local Storage) ============
    
    def get_sqlite_connection(self):
        """Get SQLite database connection"""
        conn = sqlite3.connect(self.sqlite_path)
        conn.row_factory = sqlite3.Row
        return conn
        
    def get_connection(self):
        """Get SQLite database connection (alias for get_sqlite_connection)"""
        return self.get_sqlite_connection()
    
    def init_sqlite(self):
        """Initialize SQLite database tables"""
        with self.get_sqlite_connection() as conn:
            cursor = conn.cursor()
            
            # Scans table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_type TEXT NOT NULL,
                    input_hash TEXT NOT NULL,
                    input_preview TEXT,
                    is_malicious INTEGER NOT NULL,
                    confidence REAL NOT NULL,
                    prediction_time_ms REAL NOT NULL,
                    features_used TEXT,
                    session_id TEXT,
                    threat_type TEXT,
                    explanation TEXT,
                    timestamp TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes for faster queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp 
                ON scans(timestamp DESC)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_scan_type 
                ON scans(scan_type)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_malicious 
                ON scans(is_malicious)
            """)
            
            # Models table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS models (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    model_name TEXT UNIQUE NOT NULL,
                    model_version TEXT NOT NULL,
                    file_path TEXT,
                    loaded_at TEXT,
                    is_active INTEGER DEFAULT 1
                )
            """)

            # Users table (SQLite fallback — PostgreSQL is primary)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)
            """)

            conn.commit()
            logger.info("SQLite database initialized successfully at: %s", self.sqlite_path)
    
    def save_scan_sqlite(self, scan_data: dict):
        """Save scan result to SQLite"""
        with self.get_sqlite_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scans (
                    scan_type, input_hash, input_preview, is_malicious,
                    confidence, prediction_time_ms, features_used, 
                    session_id, threat_type, explanation, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_data.get('scan_type'),
                scan_data.get('input_hash', ''),
                scan_data.get('input_preview', '')[:200],
                1 if scan_data.get('is_malicious') else 0,
                scan_data.get('confidence', 0),
                scan_data.get('prediction_time_ms', 0),
                json.dumps(scan_data.get('features_used', [])),
                scan_data.get('session_id'),
                scan_data.get('threat_type', 'unknown'),
                scan_data.get('explanation', ''),
                scan_data.get('timestamp', datetime.now().isoformat())
            ))
            conn.commit()
            return cursor.lastrowid
    
    def get_scans_sqlite(self, limit: int = 100, offset: int = 0, 
                         scan_type: Optional[str] = None, 
                         malicious_only: bool = False) -> List[dict]:
        """Get scans from SQLite with filters"""
        query = "SELECT * FROM scans WHERE 1=1"
        params = []
        
        if scan_type:
            query += " AND scan_type = ?"
            params.append(scan_type)
        
        if malicious_only:
            query += " AND is_malicious = 1"
        
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        with self.get_sqlite_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    
    def get_stats_sqlite(self, hours: int = 24) -> dict:
        """Get aggregated statistics from SQLite"""
        with self.get_sqlite_connection() as conn:
            cursor = conn.cursor()
            
            # Total scans in timeframe
            cursor.execute("""
                SELECT COUNT(*) as total,
                       SUM(CASE WHEN scan_type = 'url' THEN 1 ELSE 0 END) as url_count,
                       SUM(CASE WHEN scan_type = 'email' THEN 1 ELSE 0 END) as email_count,
                       SUM(CASE WHEN is_malicious = 1 THEN 1 ELSE 0 END) as malicious_total,
                       AVG(confidence) as avg_confidence,
                       AVG(prediction_time_ms) as avg_time
                FROM scans 
                WHERE julianday('now') - julianday(timestamp) <= ?
            """, (hours / 24.0,))
            
            stats = dict(cursor.fetchone())
            
            # Get additional metrics
            cursor.execute("""
                SELECT scan_type, 
                       COUNT(*) as count,
                       SUM(CASE WHEN is_malicious = 1 THEN 1 ELSE 0 END) as malicious_count
                FROM scans
                WHERE julianday('now') - julianday(timestamp) <= ?
                GROUP BY scan_type
            """, (hours / 24.0,))
            
            by_type = {}
            for row in cursor.fetchall():
                by_type[row['scan_type']] = {
                    "total": row['count'],
                    "malicious": row['malicious_count']
                }
            
            return {
                "source": "sqlite",
                "period_hours": hours,
                "total_scans": stats.get('total', 0),
                "by_type": by_type,
                "malicious_total": stats.get('malicious_total', 0),
                "avg_confidence": round((stats.get('avg_confidence') or 0) * 100, 2),
                "avg_prediction_time_ms": round(stats.get('avg_time') or 0, 2)
            }
    
    def create_user(self, username: str, email: str, password_hash: str) -> str:
        """Create a new user — PostgreSQL primary, SQLite fallback"""
        if self.docker_available and self.ml_integration:
            try:
                return self.ml_integration.create_user_postgres(username, email, password_hash)
            except Exception as e:
                logger.error(f"PostgreSQL create_user failed, falling back to SQLite: {e}")
        with self.get_sqlite_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, password_hash)
            )
            conn.commit()
            return str(cursor.lastrowid)

    def get_user_by_username(self, username: str) -> Optional[dict]:
        """Retrieve a user by username — PostgreSQL primary, SQLite fallback"""
        if self.docker_available and self.ml_integration:
            try:
                return self.ml_integration.get_user_by_username_postgres(username)
            except Exception as e:
                logger.error(f"PostgreSQL get_user_by_username failed, falling back to SQLite: {e}")
        with self.get_sqlite_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_user_by_email(self, email: str) -> Optional[dict]:
        """Retrieve a user by email — PostgreSQL primary, SQLite fallback"""
        if self.docker_available and self.ml_integration:
            try:
                return self.ml_integration.get_user_by_email_postgres(email)
            except Exception as e:
                logger.error(f"PostgreSQL get_user_by_email failed, falling back to SQLite: {e}")
        with self.get_sqlite_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def log_model_load(self, model_name: str, version: str = "1.0.0"):
        """Log model loading event to SQLite"""
        with self.get_sqlite_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO models 
                (model_name, model_version, loaded_at, is_active)
                VALUES (?, ?, ?, 1)
            """, (model_name, version, datetime.now().isoformat()))
            conn.commit()
            logger.info(f"Model {model_name} v{version} logged in SQLite")

# Global database instance
db = Database()