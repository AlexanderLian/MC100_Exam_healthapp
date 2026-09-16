import logging
import os
import time
from datetime import timedelta

from flask import Flask, jsonify, render_template, request, session

from app import models
from app.controllers.api import api
from app.controllers.appointments import appointments
from app.controllers.assistant import assistant
from app.controllers.auth import auth
from app.controllers.documents import documents
from app.controllers.notes import notes
from app.limiter import limiter

SECURITY_LOG = os.path.join(models.BASE_DIR, 'security.log')


# a function, not a module-level app, so each test can build a fresh one
def create_app():
    secret_key = os.environ.get('SECRET_KEY')
    # no generated fallback, a new key on every restart would log everyone out
    if not secret_key:
        raise RuntimeError('SECRET_KEY is not set, add it to .env before starting')

    app = Flask(__name__)
    app.config['SECRET_KEY'] = secret_key
    # HttpOnly is already on by default in Flask, so only SameSite needs setting
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    # off by default because the app runs over plain HTTP locally
    app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() in ('1', 'true', 'yes')
    # Flask rejects a cookie older than this, so a copied one stops working after 30 idle minutes
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
    # Flask refuses a bigger request before reading it, so one upload cannot fill the disk
    app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

    security_log = logging.getLogger('healthapp.security')
    # tests call create_app many times, and every extra handler would write each line again
    if not security_log.handlers:
        handler = logging.FileHandler(SECURITY_LOG, encoding='utf-8')
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s', '%Y-%m-%d %H:%M:%S')
        # UTC, the same clock as the timestamps in the database
        formatter.converter = time.gmtime
        handler.setFormatter(formatter)
        security_log.addHandler(handler)

    limiter.init_app(app)

    app.register_blueprint(auth)
    app.register_blueprint(notes)
    app.register_blueprint(api)
    app.register_blueprint(appointments)
    app.register_blueprint(documents)
    app.register_blueprint(assistant)

    @app.errorhandler(429)
    def too_many_requests(error):
        # %r escapes a newline, so a url can never add a fake line to the log
        security_log.warning('rate limit hit user_id=%s route=%s %r',
                             session.get('user_id'), request.method, request.path)
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Too many requests'}), 429
        return error

    @app.route('/')
    def index():
        return render_template('base.html')

    return app
