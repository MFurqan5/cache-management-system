import os
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()

MONGO_URL = os.getenv("MONGO_URL")

print("=" * 50)
print("Testing MongoDB Connection")
print("=" * 50)

try:
    # Connect with timeout
    client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=10000)
    
    # Test connection
    client.admin.command('ping')
    print("✅ MongoDB: CONNECTED SUCCESSFULLY!")
    
    # Test write permission
    db = client["Cache_db"]
    result = db.test_collection.insert_one({"test": "working", "timestamp": "2025"})
    print("✅ MongoDB: WRITE SUCCESSFUL!")
    
    # Clean up test
    db.test_collection.delete_one({"_id": result.inserted_id})
    print("✅ MongoDB: DELETE SUCCESSFUL!")
    
    client.close()
    print("\n🎉 MongoDB is fully working!")
    
except Exception as e:
    print(f"❌ MongoDB Error: {e}")
    print("\nTroubleshooting:")
    print("1. Check if password is correct")
    print("2. Make sure your IP is whitelisted in MongoDB Atlas")
    print("   Go to: Network Access → Add IP Address → Add 0.0.0.0/0")