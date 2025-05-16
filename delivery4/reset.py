import os
import sqlite3

def reset_database(db_path: str, schema_path: str):
    if os.path.exists(db_path):
        os.remove(db_path)
        print(f"Deleted existing database: {db_path}")
    else: print("No existing database found. Creating a new one.")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    with open(schema_path, "r") as schema_file:
        schema_sql = schema_file.read()
        cursor.executescript(schema_sql)
        print(f"Applied schema from {schema_path}")
    conn.commit()
    conn.close()
    print("Database reset complete.")

if __name__ == "__main__":
    reset_database("database.db", "schema.sql")
