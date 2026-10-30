import unittest
import tempfile
import sqlite3
from pathlib import Path
import database as db
from rules import run_analysis

class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.path=str(Path(self.temp.name)/'test.db');db.init_db(self.path)
    def tearDown(self):self.temp.cleanup()
    def test_save_filter_detail_delete(self):
        r=run_analysis('Send your password')
        id=db.log_scan('Send your password','',r['score'],r['risk'],r,self.path)
        self.assertEqual(db.list_scans('password','medium',path=self.path)['total'],1)
        self.assertEqual(db.get_scan(id,self.path)['result']['ruleset_version'],'2.1.0')
        self.assertEqual(db.delete_scan(id,self.path),1);self.assertIsNone(db.get_scan(id,self.path))
    def test_legacy_migration(self):
        legacy=str(Path(self.temp.name)/'old.db')
        with sqlite3.connect(legacy) as c:
            c.execute('CREATE TABLE scan_history(id INTEGER PRIMARY KEY,message_text TEXT,url TEXT,computed_score INTEGER,computed_risk TEXT,timestamp TEXT)')
            c.execute("INSERT INTO scan_history VALUES(1,'Legacy','',0,'low','2026-01-01')")
        c.close()
        db.init_db(legacy);db.init_db(legacy)
        self.assertEqual(db.get_scan(1,legacy)['message_text'],'Legacy')
        self.assertIsNone(db.get_scan(1,legacy)['result'])

if __name__=='__main__':unittest.main()
