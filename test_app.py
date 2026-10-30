import unittest
import tempfile
import re
from pathlib import Path
from app import create_app
import database as db

class AppTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.path=str(Path(self.temp.name)/'api.db')
        self.app=create_app({'TESTING':True,'DATABASE':self.path,'SECRET_KEY':'testing'})
        self.client=self.app.test_client()
        response=self.client.get('/')
        self.token=re.search(r'name="csrf-token" content="([^"]+)"',response.get_data(as_text=True)).group(1)
        self.headers={'X-CSRF-Token':self.token}
    def tearDown(self):self.temp.cleanup()
    def post(self,data):return self.client.post('/analyze',json=data,headers=self.headers)
    def test_home_and_assets(self):
        self.assertEqual(self.client.get('/').status_code,200)
        for path in ['/static/style.css','/static/app.js']:
            response=self.client.get(path);self.assertEqual(response.status_code,200);response.close()
    def test_analysis_and_history(self):
        r=self.post({'message':'Send me your password','save_history':True});self.assertEqual(r.status_code,200)
        id=r.json['scan_id'];self.assertTrue(r.json['saved'])
        self.assertEqual(self.client.get('/api/history').json['total'],1)
        self.assertIsNotNone(self.client.get(f'/api/history/{id}').json['result'])
        self.assertEqual(self.client.delete(f'/api/history/{id}',headers=self.headers).status_code,200)
    def test_private_scan(self):
        self.assertFalse(self.post({'message':'Hello','save_history':False}).json['saved'])
        self.assertEqual(db.list_scans(path=self.path)['total'],0)
    def test_invalid_inputs(self):
        for body in [{},[],None,{'message':123},{'url':123},{'message':'x','save_history':'yes'}, {'url':'http://[bad'},{'message':'x'*20001}]:
            r=self.client.post('/analyze',data='null' if body is None else __import__('json').dumps(body),content_type='application/json',headers=self.headers)
            self.assertEqual(r.status_code,400,body)
        self.assertEqual(self.client.post('/analyze',data='{',content_type='application/json',headers=self.headers).status_code,400)
    def test_csrf(self):
        self.assertEqual(self.client.post('/analyze',json={'message':'hello'}).status_code,403)
    def test_history_validation(self):
        for q in ['page=0','page=no','risk=unknown']:self.assertEqual(self.client.get('/api/history?'+q).status_code,400)
        self.assertEqual(self.client.get('/api/history/99').status_code,404)
    def test_clear(self):
        self.post({'message':'Hello','save_history':True});self.assertEqual(self.client.delete('/api/history',headers=self.headers).json['deleted'],1)
    def test_large_request(self):
        self.assertEqual(self.client.post('/analyze',data='x'*140000,content_type='application/json',headers=self.headers).status_code,413)

if __name__=='__main__':unittest.main()
