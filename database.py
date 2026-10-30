"""Local SQLite persistence with backwards-compatible schema migration."""
import json
import os
import sqlite3
from pathlib import Path
from contextlib import contextmanager

DB_NAME = os.environ.get('PHISHLENS_DB', str(Path(__file__).with_name('phishlens.db')))


def get_connection(path=None):
    conn = sqlite3.connect(path or DB_NAME, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys=ON')
    return conn


@contextmanager
def connection(path=None):
    conn = get_connection(path)
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init_db(path=None):
    with connection(path) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, message_text TEXT, url TEXT,
            computed_score INTEGER, computed_risk TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        columns = {r['name'] for r in conn.execute('PRAGMA table_info(scan_history)')}
        for name in ['findings_json', 'ruleset_version', 'expires_at']:
            if name not in columns:
                conn.execute(f'ALTER TABLE scan_history ADD COLUMN {name} TEXT')
        conn.execute('CREATE INDEX IF NOT EXISTS history_timestamp ON scan_history(timestamp)')
        conn.execute('''CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL REFERENCES scan_history(id) ON DELETE CASCADE,
            suggested_label TEXT NOT NULL, reviewed_label TEXT,
            status TEXT NOT NULL DEFAULT 'pending', note TEXT NOT NULL DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS evaluation_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            report_json TEXT NOT NULL)''')


def log_scan(message_text, url, score, risk, result=None, path=None, retention_days=0):
    with connection(path) as conn:
        cursor = conn.execute('''INSERT INTO scan_history
            (message_text,url,computed_score,computed_risk,findings_json,ruleset_version,expires_at)
            VALUES (?,?,?,?,?,?,CASE WHEN ? > 0 THEN datetime('now', ?) ELSE NULL END)''', (message_text, url, score, risk,
            json.dumps(result, ensure_ascii=False) if result else None,
            result.get('ruleset_version') if result else None, retention_days, f'+{retention_days} days'))
        return cursor.lastrowid


def prune_expired(path=None):
    with connection(path) as conn:
        return conn.execute("DELETE FROM scan_history WHERE expires_at IS NOT NULL AND expires_at <= datetime('now')").rowcount


def list_scans(search='', risk='', page=1, path=None):
    where, args = ['1=1'], []
    if search:
        where.append('(instr(lower(message_text),lower(?))>0 OR instr(lower(url),lower(?))>0)')
        args += [search, search]
    if risk:
        where.append('computed_risk=?'); args.append(risk)
    clause = ' AND '.join(where)
    with connection(path) as conn:
        total = conn.execute('SELECT COUNT(*) FROM scan_history WHERE ' + clause, args).fetchone()[0]
        rows = conn.execute('SELECT id,message_text,url,computed_score,computed_risk,timestamp,ruleset_version,expires_at FROM scan_history WHERE ' + clause + ' ORDER BY id DESC LIMIT 20 OFFSET ?', args + [(page - 1)*20]).fetchall()
    return dict(items=[dict(r) for r in rows], total=total, page=page, page_size=20)


def get_scan(id, path=None):
    with connection(path) as conn:
        row = conn.execute('SELECT * FROM scan_history WHERE id=?', (id,)).fetchone()
    if row is None:
        return None
    item = dict(row)
    item['result'] = json.loads(item.pop('findings_json')) if item.get('findings_json') else None
    return item


def delete_scan(id=None, path=None):
    with connection(path) as conn:
        cursor = conn.execute('DELETE FROM scan_history WHERE id=?', (id,)) if id is not None else conn.execute('DELETE FROM scan_history')
        return cursor.rowcount
