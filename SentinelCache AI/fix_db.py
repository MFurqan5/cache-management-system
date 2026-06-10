import psycopg2
import os

db_url = os.environ.get("DATABASE_URL", "postgresql://admin:password123@localhost:5432/cyberguard")

def fix_db():
    conn = psycopg2.connect(db_url)
    conn.autocommit = True
    cur = conn.cursor()
    try:
        # Check constraint name
        cur.execute("""
            SELECT constraint_name 
            FROM information_schema.table_constraints 
            WHERE table_name = 'scan_requests' AND constraint_type = 'UNIQUE'
        """)
        constraints = cur.fetchall()
        print("Constraints:", constraints)
        
        for (cname,) in constraints:
            if "input_hash" in cname:
                print(f"Dropping constraint {cname}...")
                cur.execute(f"ALTER TABLE scan_requests DROP CONSTRAINT {cname};")
                print("Dropped.")
                
    except Exception as e:
        print("Error:", e)
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    fix_db()
