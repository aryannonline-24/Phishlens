import io
import json
import socket
import unittest
from unittest.mock import patch, Mock
from email.message import EmailMessage
import test_app
import database as db
from ingestion import email_extract, HTMLText
from model import train, predict, load_model
from context_analysis import analyze_context
from safe_fetch import public_target, fetch
from inspection_worker import inspect_url
import network_checks


class AdvancedAPITests(unittest.TestCase):
    setUp = test_app.AppTests.setUp
    tearDown = test_app.AppTests.tearDown
    post = test_app.AppTests.post

    def call(self, path, data):
        return self.client.post(path, json=data, headers=self.headers)

    def test_model_does_not_alter_rule_score_or_save(self):
        result = self.post({'message': 'Please send your password'}).json
        self.assertEqual(result['score'], 25)
        self.assertIn('model', result)
        self.assertEqual(result['triage'], 'review')
        self.assertFalse(result['saved'])
        self.assertEqual(db.list_scans(path=self.path)['total'], 0)

    def test_context_changes_and_validation(self):
        response = self.post(dict(message='Use account 99887766', previous_messages='Use account 11223344',
                                  sender='new@example.com', previous_sender='old@example.com', initiated=True))
        self.assertEqual(len(response.json['context']['findings']), 2)
        self.assertEqual(response.json['score'], 0)
        self.assertEqual(response.json['triage'], 'review')
        for extra in [{'previous_messages':5}, {'sender':[]}, {'initiated':'yes'}]:
            self.assertEqual(self.post({'message':'hello', **extra}).status_code, 400)

    def test_email_extraction_signed_provenance(self):
        msg = EmailMessage()
        msg['From']='bank@example.com';msg['Reply-To']='thief@evil.com'
        msg['Authentication-Results']='trusted.example; spf=pass; dkim=pass'
        msg.set_content('<a href="https://evil.com">https://paypal.com</a><script>alert(1)</script>', subtype='html')
        response = self.client.post('/api/extract', data={'file':(io.BytesIO(msg.as_bytes()),'message.eml')}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        data = response.json
        self.assertEqual(len(data['findings']), 2)
        self.assertNotIn('alert(1)', data['text'])
        self.assertIn('not trusted', ' '.join(data['warnings']))
        result = self.post({'message':data['text'], 'extraction_token':data['extraction_token']}).json
        self.assertEqual(result['source']['kind'], 'email')
        self.assertEqual(result['triage'], 'review')
        self.assertFalse(result['source']['text_edited'])
        self.assertEqual(self.post({'message':'hello','extraction_token':'forged'}).status_code, 400)

    def test_upload_limits_and_types(self):
        for filename, content in [('file.exe',b'bad'),('pic.png',b'not an image'),('large.eml',b'x'*(5*1024*1024+1))]:
            response=self.client.post('/api/extract',data={'file':(io.BytesIO(content),filename)},headers=self.headers)
            self.assertEqual(response.status_code,400)
            response.request.environ['wsgi.input'].close()
            response.close()
        self.assertEqual(self.client.post('/api/extract',data={}).status_code,403)

    def test_feedback_review_export_and_cascade(self):
        scan = self.post({'message':'hello','save_history':True}).json['scan_id']
        response=self.call('/api/feedback',{'scan_id':scan,'label':'legitimate','note':'Expected message'})
        self.assertEqual(response.status_code,201)
        id=response.json['id']
        self.assertEqual(self.client.get('/api/feedback/export').json,[])
        self.assertEqual(self.call(f'/api/feedback/{id}/review',{'label':'legitimate'}).status_code,200)
        self.assertEqual(self.client.get('/api/feedback/export').json[0]['label'],'legitimate')
        self.client.delete(f'/api/history/{scan}',headers=self.headers)
        self.assertEqual(self.client.get('/api/dashboard').json['feedback'],[])
        self.assertEqual(self.call('/api/feedback',{'scan_id':scan,'label':'phishing'}).status_code,400)

    def test_feedback_rejection_and_validation(self):
        scan=self.post({'message':'hi','save_history':True}).json['scan_id']
        id=self.call('/api/feedback',{'scan_id':scan,'label':'phishing'}).json['id']
        self.call(f'/api/feedback/{id}/review',{'label':'reject'})
        self.assertEqual(self.client.get('/api/feedback/export').json,[])
        self.assertEqual(self.call('/api/feedback',{'scan_id':scan,'label':'safe'}).status_code,400)

    def test_evaluation_dashboard(self):
        response=self.call('/api/evaluations',{'split':'heldout'})
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json['hybrid']['samples'],96)
        self.assertIn('categories',response.json)
        self.assertEqual(len(self.client.get('/api/dashboard').json['runs']),1)

    def test_network_consent_and_fail_closed(self):
        with patch('network_checks.reputation') as lookup:
            self.assertEqual(self.call('/api/network/reputation',{'url':'https://example.com'}).status_code,400)
            lookup.assert_not_called()
        with patch.dict('os.environ',{'PHISHLENS_ENABLE_INSPECTION':'0'}):
            response=self.call('/api/network/inspect',{'url':'https://example.com','consent':True})
            self.assertEqual(response.status_code,400)
        self.assertEqual(self.client.get('/',headers={'Host':'attacker.example'}).status_code,400)


class OfflineTests(unittest.TestCase):
    def test_model_training_boundary(self):
        self.assertEqual(load_model()['training_samples'],28)
        with self.assertRaises(ValueError):train([{'text':'test','label':'phishing','split':'heldout'}])
        self.assertFalse(predict('')['assessed'])
        self.assertFalse(predict('test')['calibrated'])

    def test_email_attachments_never_extracted(self):
        msg=EmailMessage();msg.set_content('Hello')
        msg.add_attachment(b'send your password',maintype='application',subtype='octet-stream',filename='payload.exe')
        result=email_extract(msg.as_bytes())
        self.assertNotIn('send your password',result['text'])
        self.assertEqual(result['attachments'],['payload.exe'])

    def test_context_initiation_does_not_assert_trust(self):
        result=analyze_context('hello',initiated=True)
        self.assertIn('does not establish trust',result['note'])

    def test_display_brand_and_bare_link_mismatch(self):
        msg=EmailMessage();msg['From']='PayPal Support <support@evil.com>'
        msg.set_content('<a href="https://evil.com">paypal.com</a>',subtype='html')
        result=email_extract(msg.as_bytes())
        self.assertEqual(len(result['findings']),2)

    def test_qr_decoding(self):
        try:
            import cv2
            from ingestion import image_extract
        except ImportError:
            self.skipTest('Optional image dependencies not installed')
        qr=cv2.QRCodeEncoder_create().encode('https://example.com/qr')
        qr=cv2.copyMakeBorder(qr,4,4,4,4,cv2.BORDER_CONSTANT,value=255)
        qr=cv2.resize(qr,None,fx=10,fy=10,interpolation=cv2.INTER_NEAREST)
        _,raw=cv2.imencode('.png',qr)
        with patch('ingestion.shutil.which',return_value=None),patch('ingestion.subprocess.run',return_value=Mock(returncode=0,stdout='{"text":""}')):
            result=image_extract(raw.tobytes())
        self.assertEqual(result['qr_values'],['https://example.com/qr'])


class NetworkSafetyTests(unittest.TestCase):
    def answers(self, *ips):
        return [(socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,443)) for ip in ips]

    def test_block_private_special_and_mixed_dns(self):
        for ip in ['127.0.0.1','10.0.0.1','169.254.169.254','::1','224.0.0.1','0.0.0.0','::ffff:8.8.8.8']:
            with self.subTest(ip=ip),patch('safe_fetch.socket.getaddrinfo',return_value=self.answers(ip)):
                with self.assertRaises(ValueError):public_target('https://example.com')
        with patch('safe_fetch.socket.getaddrinfo',return_value=self.answers('8.8.8.8','192.168.1.1')):
            with self.assertRaises(ValueError):public_target('https://example.com')

    def test_block_schemes_credentials_ports(self):
        for url in ['file:///etc/passwd','http://user:pass@example.com','http://example.com:8080','https://example.com\r\nX:a']:
            with self.subTest(url=url),self.assertRaises(ValueError):public_target(url)

    def test_pin_connection_and_validate_redirect(self):
        response=Mock(status=302)
        response.getheader.side_effect=lambda name,*args:'http://127.0.0.1/' if name=='Location' else None
        conn=Mock();conn.getresponse.return_value=response
        with patch('safe_fetch.socket.getaddrinfo',side_effect=[self.answers('8.8.8.8'),self.answers('127.0.0.1')]), \
             patch('safe_fetch.socket.create_connection') as connect, \
             patch('safe_fetch.http.client.HTTPConnection',return_value=conn):
            with self.assertRaises(ValueError):fetch('http://example.com')
            connect.assert_called_once_with(('8.8.8.8',80),timeout=5)

    def test_inspect_static_forms_without_executing(self):
        data=dict(url='https://example.com',status=200,chain=[],body='<title>Login</title><input type=password><form action="https://other.com/pay"><script>fetch("http://127.0.0.1")</script>')
        with patch('inspection_worker.fetch',return_value=data):
            result=inspect_url('https://example.com')
        self.assertEqual(result['password_fields'],1)
        self.assertEqual(result['cross_host_forms'],['https://other.com/pay'])

    def test_docker_isolation_flags(self):
        with patch.dict('os.environ',{'PHISHLENS_ENABLE_INSPECTION':'1'}), \
             patch('network_checks.shutil.which',return_value='docker'), \
             patch('network_checks.subprocess.run',return_value=Mock(stdout='{"status":200}',returncode=0)) as run:
            network_checks.inspect('https://example.com')
            args=run.call_args_list[0].args[0]
            for flag in ['--read-only','--cap-drop=ALL','--network=bridge','--pull=never','--user=65534:65534']:
                self.assertIn(flag,args)
            self.assertNotIn('--volume',args)
            self.assertEqual(run.call_args_list[-1].args[0][1:3],['rm','-f'])

    def test_reputation_cache_and_missing_key(self):
        network_checks.CACHE.clear()
        with patch.dict('os.environ',{'URLHAUS_AUTH_KEY':''}),patch('network_checks.fetch',side_effect=ValueError('offline')) as lookup:
            a=network_checks.reputation('https://example.com')
            b=network_checks.reputation('https://example.com')
            self.assertEqual(a['urlhaus']['status'],'unavailable')
            self.assertTrue(b['cached']);lookup.assert_called_once()


if __name__=='__main__':unittest.main()
