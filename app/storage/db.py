"""MySQL users table + salted hashing (no chat storage).""" 

# app/utils/db_utils.py
import os
import sys
import mysql.connector
from mysql.connector import errorcode
from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env

DB_CONFIG = {
    "user": os.getenv("DB_USER", "scuser"),
    "password": os.getenv("DB_PASSWORD", "scpass"),
    "host": os.getenv("DB_HOST", "127.0.0.1"),
    "database": os.getenv("DB_NAME", "securechat"),
    "port": int(os.getenv("DB_PORT", 3306))
}

ROOT_DB_CONFIG = {
    "user": os.getenv("DB_ROOT_USER", "root"),
    "password": os.getenv("DB_ROOT_PASSWORD", "rootpass"),
    "host": os.getenv("DB_HOST", "127.0.0.1"),
    "port": int(os.getenv("DB_PORT", 3306))
}


def get_db_connection():
    """Return a MySQL connection as the application user."""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        print("[+] Database connection established as application user.")
        return conn
    except mysql.connector.Error as err:
        print(f"[!] Failed to connect to database as app user: {err}")
        raise


def get_root_connection():
    """Return a MySQL connection as the root user (for initialization)."""
    try:
        conn = mysql.connector.connect(**ROOT_DB_CONFIG)
        print("[+] Database connection established as root user.")
        return conn
    except mysql.connector.Error as err:
        print(f"[!] Failed to connect to database as root: {err}")
        raise

TABLES = {
    "users": """
        CREATE TABLE IF NOT EXISTS users (
            email VARCHAR(255) NOT NULL,
            username VARCHAR(100) NOT NULL UNIQUE,
            salt VARBINARY(16) NOT NULL,
            pwd_hash CHAR(64) NOT NULL,
            PRIMARY KEY (username)
        ) ENGINE=InnoDB;
    """
}

def init_db():
    """Initialize database, user, and tables."""
    try:
        root_cnx = get_root_connection()
        root_cursor = root_cnx.cursor()

        print(f"Ensuring user '{DB_CONFIG['user']}' exists...")
        root_cursor.execute(f"""
            CREATE USER IF NOT EXISTS '{DB_CONFIG['user']}'@'%'
            IDENTIFIED WITH caching_sha2_password BY '{DB_CONFIG['password']}';
        """)
        root_cursor.execute(f"""
            GRANT ALL PRIVILEGES ON {DB_CONFIG['database']}.* TO '{DB_CONFIG['user']}'@'%';
        """)
        root_cursor.execute("FLUSH PRIVILEGES;")
        print(f"Ensuring database '{DB_CONFIG['database']}' exists...")
        root_cursor.execute(
            f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['database']} DEFAULT CHARACTER SET 'utf8mb4'"
        )
        root_cursor.close()
        root_cnx.close()

        cnx = get_db_connection()
        cursor = cnx.cursor()
        for name, ddl in TABLES.items():
            print(f"Creating table '{name}'... ", end="")
            cursor.execute(ddl)
            print("OK")

        cursor.close()
        cnx.close()
        print("Database setup complete.")

    except Exception as err:
        print(f"MySQL Error: {err}")
        sys.exit(1)

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--init":
        init_db()
    else:
        print("Usage: python -m app.storage.db --init")