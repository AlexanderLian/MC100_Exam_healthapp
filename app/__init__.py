import logging
import os
import time
from datetime import timedelta

from flask import Flask, render_template

from app import models
from app.controllers.api import api
from app.controllers.appointments import appointments
from app.controllers.auth import auth
from app.controllers.documents import documents
from app.controllers.notes import notes

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
    # lab_3 has no limit, so one upload could fill the disk. Flask refuses the request before reading it
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

    app.register_blueprint(auth)
    app.register_blueprint(notes)
    app.register_blueprint(api)
    app.register_blueprint(appointments)
    app.register_blueprint(documents)

    @app.route('/')
    def index():
        return render_template('base.html')

    return app
