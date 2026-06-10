import sys
import os

# Add backend to path so we can import ml_integration
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.append(project_root)
    from backend.db.ml_integration import ml_db
    print("Flushing Redis...")
    if hasattr(ml_db, 'get_redis_client'):
        r = ml_db.get_redis_client()
        if r:
            r.flushall()
            print("Redis flushed successfully.")
        else:
            print("No Redis client available.")
            
    print("Flushing MongoDB...")
    if hasattr(ml_db, 'get_mongo_client'):
        m = ml_db.get_mongo_client()
        if m:
            db = m["Cache_db"]
            # Check what collections exist
            for coll_name in db.list_collection_names():
                db[coll_name].delete_many({})
                print(f"Cleared MongoDB collection: {coll_name}")
            print("MongoDB flushed successfully.")
        else:
            print("No MongoDB client available.")
            
    print("Flushing PostgreSQL (L1 cache)...")
    if hasattr(ml_db, 'l1_cache'):
        ml_db.l1_cache.clear()
        print("L1 memory cache cleared.")
        
except Exception as e:
    print(f"Error: {e}")
