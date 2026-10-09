import sqlite3
import pandas as pd
import shutil
import tempfile
import os

def parse_chrome_history(file_path: str) -> pd.DataFrame:
    if not os.path.exists(file_path):
        return pd.DataFrame()

    tmp_dir = tempfile.mkdtemp()
    tmp_path = os.path.join(tmp_dir, "history_temp.db")
    
    try:
        shutil.copy2(file_path, tmp_path)
    except Exception:
        tmp_path = file_path

    df = pd.DataFrame()
    try:
        conn = sqlite3.connect(tmp_path)
        query = "SELECT url, title, visit_count, last_visit_time FROM urls WHERE url IS NOT NULL AND url != ''"
        df = pd.read_sql_query(query, conn)
        conn.close()
    except Exception as e:
        print(f"Error parsing SQLite: {e}")
    finally:
        try:
            if os.path.exists(tmp_path) and tmp_path != file_path:
                os.remove(tmp_path)
            if os.path.exists(tmp_dir):
                shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass

    return df