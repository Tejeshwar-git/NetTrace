import sqlite3
import os

DB_FILE = "forensic_system.db"

def get_connection():
    return sqlite3.connect(DB_FILE)

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            badge_id TEXT NOT NULL,
            department TEXT NOT NULL
        )
    ''')
    
    # Cases table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            suspect TEXT,
            investigator TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Reports table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            file_name TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            artifact_type TEXT NOT NULL,
            score REAL NOT NULL,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Auto-migration check: ensure 'details' column exists in reports
    cursor.execute("PRAGMA table_info(reports)")
    columns = [row[1] for row in cursor.fetchall()]
    if 'details' not in columns:
        cursor.execute("ALTER TABLE reports ADD COLUMN details TEXT")
    
    # Insert default admin user if missing
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        cursor.execute(
            "INSERT INTO users (username, password, full_name, badge_id, department) VALUES (?, ?, ?, ?, ?)",
            ("admin", "admin123", "Lead Investigator", "INV-001", "DFIR Unit")
        )
        
    conn.commit()
    conn.close()

def authenticate_user(username, password):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT full_name, badge_id FROM users WHERE username = ? AND password = ?", (username, password))
    user = cursor.fetchone()
    conn.close()
    return user

def register_user(username, password, name, badge, dept):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password, full_name, badge_id, department) VALUES (?, ?, ?, ?, ?)",
            (username, password, name, badge, dept)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def get_user_cases(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT case_id, title FROM cases WHERE investigator = ?", (username,))
    cases = cursor.fetchall()
    conn.close()
    return cases

def create_case(case_id, title, suspect, username):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO cases (case_id, title, suspect, investigator) VALUES (?, ?, ?, ?)",
            (case_id, title, suspect, username)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def save_report(case_id, file_name, sha256, artifact_type, score, details=""):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO reports (case_id, file_name, sha256, artifact_type, score, details) VALUES (?, ?, ?, ?, ?, ?)",
        (case_id, file_name, sha256, artifact_type, score, details)
    )
    conn.commit()
    conn.close()

def get_case_reports(case_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT file_name, artifact_type, sha256, score, timestamp, details FROM reports WHERE case_id = ? ORDER BY timestamp DESC",
        (case_id,)
    )
    reports = cursor.fetchall()
    conn.close()
    return reports

def delete_reports_by_hashes(case_id, hashes):
    if not hashes:
        return True
    conn = get_connection()
    cursor = conn.cursor()
    query = f"DELETE FROM reports WHERE case_id = ? AND sha256 IN ({','.join(['?']*len(hashes))})"
    cursor.execute(query, [case_id] + hashes)
    conn.commit()
    conn.close()
    return True

def clear_case_reports(case_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM reports WHERE case_id = ?", (case_id,))
    conn.commit()
    conn.close()
    return True