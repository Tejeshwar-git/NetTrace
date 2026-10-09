import sqlite3

conn = sqlite3.connect('test_history.db')
c = conn.cursor()
c.execute('CREATE TABLE IF NOT EXISTS urls (url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER)')
c.execute('INSERT INTO urls VALUES ("http://192.168.1.1/verify_login/bank_account", "Bank Verification", 5, 13350000000000000)')
c.execute('INSERT INTO urls VALUES ("https://google.com", "Google Search", 42, 13350000000000000)')
conn.commit()
conn.close()
print("Database created successfully!")