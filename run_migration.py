"""
Database migration script to add profile fields to users table
Run this with: python run_migration.py
"""

from database import get_connection

def run_migration():
    conn = get_connection()
    if conn is None:
        print("❌ Database connection failed")
        return
    
    cur = conn.cursor()
    
    try:
        # Add profile_picture column
        print("Adding profile_picture column...")
        cur.execute("""
            ALTER TABLE users 
            ADD COLUMN IF NOT EXISTS profile_picture VARCHAR(255)
        """)
        
        # Add bio column
        print("Adding bio column...")
        cur.execute("""
            ALTER TABLE users 
            ADD COLUMN IF NOT EXISTS bio TEXT
        """)
        
        conn.commit()
        print("✅ Migration completed successfully!")
        print("   - Added profile_picture column")
        print("   - Added bio column")
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        conn.rollback()
    
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    run_migration()
