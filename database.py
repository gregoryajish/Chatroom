import psycopg2
import os

def get_connection():
    try:
        conn = psycopg2.connect(
            os.environ.get("DATABASE_URL")
        )
        return conn
    except Exception as e:
        print("Database connection error:", e)
        return None
