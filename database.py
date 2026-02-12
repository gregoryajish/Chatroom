import psycopg2

def get_connection():
    try:
        conn = psycopg2.connect(
            host="localhost",
            database="chatroom_db",
            user="postgres",        # change if needed
            password="1234",# change this
            port="5432"
        )
        return conn
    except Exception as e:
        print("Database connection error:", e)
        return None
