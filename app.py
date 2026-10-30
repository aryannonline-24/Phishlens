"""Local PhishLens web application. Run with python app.py."""
import os
import secrets
import sqlite3
from flask import Flask, render_template, request, jsonify, session
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge
from rules import run_analysis, MAX_MESSAGE, MAX_URL
import database as db
from advanced import bp, enrich


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(SECRET_KEY=os.environ.get('PHISHLENS_SECRET', secrets.token_hex(32)),
        DATABASE=db.DB_NAME, MAX_CONTENT_LENGTH=6*1024*1024, SESSION_COOKIE_SAMESITE='Strict',
        SESSION_COOKIE_HTTPONLY=True)
    if config:
        app.config.update(config)
    db.init_db(app.config['DATABASE'])
    app.register_blueprint(bp)

    @app.before_request
    def protect_mutations():
        if request.host.split(':')[0].lower() not in {'localhost', '127.0.0.1'}:
            return jsonify(error='This application accepts localhost requests only.'), 400
        if request.endpoint != 'advanced.extract' and request.content_length and request.content_length > 128*1024:
            return jsonify(error='Request is too large.'), 413
        if request.method in {'POST', 'DELETE'}:
            supplied = request.headers.get('X-CSRF-Token', '')
            if not supplied or not secrets.compare_digest(supplied, session.get('csrf', '')):
                return jsonify(error='Refresh the page and try again.'), 403
        if request.endpoint in {'home', 'analyze', 'history', 'detail'}:
            db.prune_expired(app.config['DATABASE'])

    @app.after_request
    def headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        response.headers['Cache-Control'] = 'no-store'
        return response

    @app.get('/')
    def home():
        session.setdefault('csrf', secrets.token_hex(32))
        return render_template('index.html', csrf=session['csrf'])

    @app.post('/analyze')
    def analyze():
        if not request.is_json:
            return jsonify(error='Send a JSON object.'), 400
        data = request.get_json()
        if not isinstance(data, dict):
            return jsonify(error='Send a JSON object.'), 400
        text, url, save = data.get('message', ''), data.get('url', ''), data.get('save_history', False)
        retention = data.get('retention_days', 30)
        if type(retention) is not int or retention not in {0, 7, 30, 90}:
            return jsonify(error='Retention must be 0, 7, 30 or 90 days.'), 400
        if not isinstance(text, str) or not isinstance(url, str) or not isinstance(save, bool):
            return jsonify(error='Message and URL must be strings; save_history must be true or false.'), 400
        if not text.strip() and not url.strip():
            return jsonify(error='Enter a message or URL.'), 400
        if len(text) > MAX_MESSAGE or len(url) > MAX_URL:
            return jsonify(error='Message or URL exceeds the allowed length.'), 400
        try:
            result = enrich(run_analysis(text, url), text, data)
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        result['saved'] = False
        if save:
            try:
                result['scan_id'] = db.log_scan(text, url, result['score'], result['risk'], result, app.config['DATABASE'], retention)
                result['retention_days'] = retention
                result['saved'] = True
            except sqlite3.Error:
                app.logger.exception('History save failed')
                result['warnings'].append('Analysis succeeded, but history could not be saved.')
        return jsonify(result)

    @app.get('/api/history')
    def history():
        risk = request.args.get('risk', '')
        try:
            page = int(request.args.get('page', '1'))
            if page < 1 or page > 100000 or risk not in {'', 'low', 'medium', 'high'}:
                raise ValueError
        except ValueError:
            return jsonify(error='Invalid history filter or page.'), 400
        return jsonify(db.list_scans(request.args.get('q', '')[:200], risk, page, app.config['DATABASE']))

    @app.get('/api/history/<int:id>')
    def detail(id):
        item = db.get_scan(id, app.config['DATABASE'])
        return jsonify(item) if item else (jsonify(error='Scan not found.'), 404)

    @app.delete('/api/history/<int:id>')
    def remove(id):
        count = db.delete_scan(id, app.config['DATABASE'])
        return (jsonify(deleted=count), 200) if count else (jsonify(error='Scan not found.'), 404)

    @app.delete('/api/history')
    def clear():
        return jsonify(deleted=db.delete_scan(path=app.config['DATABASE']))

    @app.errorhandler(BadRequest)
    def invalid_json(exc):
        return jsonify(error='Malformed JSON request.'), 400

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(exc):
        return jsonify(error='Request is too large.'), 413

    @app.errorhandler(sqlite3.Error)
    def database_error(exc):
        app.logger.exception('Database operation failed')
        return jsonify(error='History is temporarily unavailable.'), 503

    return app


if __name__ == '__main__':
    create_app().run(host='127.0.0.1', port=5000, debug=os.environ.get('PHISHLENS_DEBUG') == '1')
