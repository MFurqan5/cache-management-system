# backend/db/__init__.py
"""Database module for SENTINELCACHE AI"""
import logging

logger = logging.getLogger(__name__)

# Try to import SQLite database (if exists)
try:
    from backend.database import db as sqlite_db
    db = sqlite_db
    logger.info("✅ Using SQLite database from backend.database")
except ImportError:
    logger.warning("⚠️ backend.database not found, SQLite disabled")
    db = None

# Try to import ML integration (PostgreSQL/Redis/MongoDB)
try:
    from backend.db.ml_integration import ml_db
    logger.info("✅ ML Integration (Docker databases) available")
except ImportError as e:
    logger.warning(f"⚠️ ML Integration not available: {e}")
    ml_db = None

# If no database is available, create a dummy db
if db is None and ml_db is None:
    logger.warning("⚠️ No database available, creating dummy database")
    class DummyDB:
        def save_scan(self, *args, **kwargs):
            logger.debug("Dummy save_scan called")
            return None
        
        def get_scans(self, *args, **kwargs):
            return []
        
        def get_stats(self, *args, **kwargs):
            return {"total_scans": 0, "by_type": {}, "malicious_total": 0}
        
        def log_model_load(self, *args, **kwargs):
            pass
    
    db = DummyDB()
    ml_db = DummyDB()

# Export both for convenience
__all__ = ['db', 'ml_db']