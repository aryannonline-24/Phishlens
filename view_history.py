from database import get_connection

rows = get_connection().execute("SELECT * FROM scan_history").fetchall()
for row in rows:
    print(dict(row))