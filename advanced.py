"""Advanced local workflows; all mutations retain the app's CSRF protection."""
import json
import os
from pathlib import Path
import shutil
from flask import Blueprint, current_app, jsonify, request
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import database as db
from context_analysis import analyze_context
from ingestion import email_extract, image_extract, MAX_FILE
from model import predict
from rules import run_analysis, MAX_MESSAGE, RULESET_VERSION
from evaluation_cases import build_cases
from evaluate import metrics
import network_checks

bp = Blueprint('advanced', __name__)


def payload():
    data = request.get_json()
    if not isinstance(data, dict):
        raise ValueError('Send a JSON object.')
    return data


def serializer():
    return URLSafeTimedSerializer(current_app.secret_key, salt='phishlens-extraction-v1')


def enrich(result, text, data):
    result['application_version'] = '3.0.0'
    previous = data.get('previous_messages', '')
    sender, prior = data.get('sender', ''), data.get('previous_sender', '')
    initiated = data.get('initiated', False)
    if (not isinstance(previous, str) or len(previous) > MAX_MESSAGE or
            any(not isinstance(s, str) or len(s) > 500 for s in (sender, prior)) or type(initiated) is not bool):
        raise ValueError('Invalid conversation context or length.')
    result['context'] = analyze_context(text, previous, sender, prior, initiated)
    try:
        result['model'] = predict(text)
    except (ValueError, OSError, KeyError, TypeError):
        result['model'] = {'assessed': False, 'warning': 'Model unavailable. Rule analysis remains available.'}
    token = data.get('extraction_token', '')
    if not isinstance(token, str):
        raise ValueError('Invalid extraction token.')
    if token:
        try:
            extracted = serializer().loads(token, max_age=1800)
        except (BadSignature, SignatureExpired) as exc:
            raise ValueError('File extraction expired or changed. Import the file again.') from exc
        extracted['text_edited'] = extracted.pop('text') != text
        result['source'] = extracted
        result['warnings'].extend(extracted.get('warnings', []))
    review = (result['risk'] != 'low' or bool(result['context']['findings']) or
              bool(result.get('source', {}).get('findings')) or
              (result['model'].get('assessed') and result['model']['score'] >= .85))
    result['triage'] = 'review' if review else 'few_indicators'
    result['warnings'].append('Hybrid triage combines separate signals; model output never lowers the rule score.')
    return result


@bp.errorhandler(ValueError)
def invalid(exc):
    return jsonify(error=str(exc)), 400


@bp.get('/api/capabilities')
def capabilities():
    import importlib.util
    return jsonify(ocr_engine=bool(os.environ.get('PHISHLENS_TESSERACT') or shutil.which('tesseract') or os.name == 'nt'),
                   image_packages=all(importlib.util.find_spec(p) for p in ['PIL', 'cv2', 'pytesseract']),
                   reputation_configured=bool(os.environ.get('URLHAUS_AUTH_KEY')),
                   inspector_enabled=os.environ.get('PHISHLENS_ENABLE_INSPECTION') == '1',
                   docker_available=bool(shutil.which('docker')))


@bp.post('/api/extract')
def extract():
    upload = request.files.get('file')
    if not upload:
        raise ValueError('Choose an email or image file.')
    raw = upload.read(MAX_FILE + 1)
    if len(raw) > MAX_FILE:
        raise ValueError('File exceeds 5 MB.')
    extension = Path(upload.filename or '').suffix.lower()
    if extension == '.eml':
        try:
            result = email_extract(raw)
        except (LookupError, TypeError, RecursionError) as exc:
            raise ValueError('Could not parse this email.') from exc
    elif extension in {'.png', '.jpg', '.jpeg', '.webp'}:
        result = image_extract(raw)
    else:
        raise ValueError('Use .eml, .png, .jpg or .webp files.')
    return jsonify(**result, extraction_token=serializer().dumps(result))


@bp.post('/api/network/<kind>')
def network(kind):
    data = payload()
    if data.get('consent') is not True:
        raise ValueError('Confirm sharing this URL before running network checks.')
    url = data.get('url')
    if not isinstance(url, str) or not url or len(url) > 2048:
        raise ValueError('Enter one URL up to 2,048 characters.')
    if kind == 'reputation':
        return jsonify(network_checks.reputation(url))
    if kind == 'inspect':
        return jsonify(network_checks.inspect(url))
    raise ValueError('Unknown network check.')


@bp.post('/api/feedback')
def feedback():
    data = payload()
    scan_id, label, note = data.get('scan_id'), data.get('label'), data.get('note', '')
    if type(scan_id) is not int or label not in {'phishing', 'legitimate'} or not isinstance(note, str) or len(note) > 1000:
        raise ValueError('Choose a saved scan and a valid label; notes must be under 1,000 characters.')
    path = current_app.config['DATABASE']
    db.prune_expired(path)
    if not db.get_scan(scan_id, path):
        raise ValueError('Scan no longer exists. Save it before providing feedback.')
    with db.connection(path) as conn:
        row = conn.execute('INSERT INTO feedback(scan_id,suggested_label,note) VALUES(?,?,?)', (scan_id, label, note))
        return jsonify(id=row.lastrowid, status='pending'), 201


@bp.post('/api/feedback/<int:id>/review')
def review(id):
    data = payload()
    label = data.get('label')
    if label not in {'phishing', 'legitimate', 'reject'}:
        raise ValueError('Choose phishing, legitimate, or reject.')
    with db.connection(current_app.config['DATABASE']) as conn:
        cursor = conn.execute('UPDATE feedback SET reviewed_label=?,status=? WHERE id=?',
                              (None if label == 'reject' else label, 'rejected' if label == 'reject' else 'reviewed', id))
    if not cursor.rowcount:
        return jsonify(error='Feedback not found.'), 404
    return jsonify(updated=True)


@bp.get('/api/feedback/export')
def export():
    path = current_app.config['DATABASE']
    db.prune_expired(path)
    with db.connection(path) as conn:
        rows = conn.execute('''SELECT s.id AS scan_id,s.message_text AS text,s.url,f.reviewed_label AS label
            FROM scan_history s JOIN feedback f ON f.scan_id=s.id
            WHERE f.status='reviewed' AND f.id=(SELECT MAX(f2.id) FROM feedback f2 WHERE f2.scan_id=s.id AND f2.status='reviewed')''').fetchall()
    return jsonify([dict(r) for r in rows])


def compare(cases):
    rows, models, hybrid = [], [], []
    for case in cases:
        result = run_analysis(case['text'], case['url'])
        model = predict(case['text'])
        actual = case['label'] == 'phishing'
        rule_positive = result['risk'] != 'low'
        model_positive = model['assessed'] and model['score'] >= .85
        rows.append(dict(actual=actual, predicted=rule_positive, category=case['category']))
        models.append(dict(actual=actual, predicted=model_positive, category=case['category']))
        hybrid.append(dict(actual=actual, predicted=rule_positive or model_positive, category=case['category']))
    return dict(rule=metrics(rows), model=metrics(models), hybrid=metrics(hybrid),
                categories={category: {'rule': metrics([r for r in rows if r['category'] == category]),
                                       'hybrid': metrics([r for r in hybrid if r['category'] == category])}
                            for category in sorted({r['category'] for r in rows})},
                ruleset_version=RULESET_VERSION, model_version=predict('')['version'],
                warning='Synthetic correlated variants, not real-world validation. Model threshold 0.85 is a design choice, not calibrated.')


@bp.post('/api/evaluations')
def evaluate():
    data = payload()
    split = data.get('split', 'heldout')
    if split not in {'dev', 'heldout'}:
        raise ValueError('Choose dev or heldout.')
    report = dict(**compare(build_cases(split)), split=split)
    with db.connection(current_app.config['DATABASE']) as conn:
        conn.execute('INSERT INTO evaluation_runs(report_json) VALUES(?)', (json.dumps(report),))
        conn.execute('DELETE FROM evaluation_runs WHERE id NOT IN (SELECT id FROM evaluation_runs ORDER BY id DESC LIMIT 20)')
    return jsonify(report)


@bp.get('/api/dashboard')
def dashboard():
    path = current_app.config['DATABASE']
    db.prune_expired(path)
    with db.connection(path) as conn:
        feedback = [dict(r) for r in conn.execute('''SELECT f.*,substr(s.message_text,1,500) AS message
            FROM feedback f JOIN scan_history s ON f.scan_id=s.id ORDER BY f.id DESC LIMIT 100''')]
        runs = [dict(id=r['id'], created_at=r['created_at'], report=json.loads(r['report_json']))
                for r in conn.execute('SELECT * FROM evaluation_runs ORDER BY id DESC LIMIT 20')]
        counts = {r['computed_risk']: r['n'] for r in conn.execute('SELECT computed_risk,COUNT(*) AS n FROM scan_history GROUP BY computed_risk')}
        reviewed = [dict(r) for r in conn.execute('''SELECT s.message_text AS text,s.url,f.reviewed_label AS label,
            'reviewed_feedback' AS category FROM scan_history s JOIN feedback f ON f.scan_id=s.id
            WHERE f.status='reviewed' AND f.id=(SELECT MAX(f2.id) FROM feedback f2 WHERE f2.scan_id=s.id AND f2.status='reviewed')
            ORDER BY f.id DESC LIMIT 100''')]
    # Historical reports provide comparison with the earlier implementation.
    baseline = json.loads(Path(__file__).with_name('evaluation-heldout.json').read_text(encoding='utf-8'))
    reviewed_report = compare(reviewed) if reviewed else None
    if reviewed_report:
        reviewed_report['warning'] = 'Latest 100 reviewed saved scans, scored with current rules/model on text and URL only. Context and email findings are excluded. Feedback is selected by users, not an independent test set.'
    return jsonify(feedback=feedback, runs=runs, history_counts=counts, reviewed_report=reviewed_report,
                   baseline={k: baseline[k] for k in ['ruleset_version', 'samples', 'precision', 'recall', 'false_positive', 'false_negative']})
