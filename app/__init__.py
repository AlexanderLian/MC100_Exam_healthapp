import os
from datetime import timedelta

from flask import Flask, render_template

from app.controllers.auth import auth


# a function, not a module-level app, so each test can build a fresh one
def create_app():
    secret_key = os.environ.get('SECRET_KEY')
    # no generated fallback, a new key on every restart would log everyone out
    if not secret_key:
        raise RuntimeError('SECRET_KEY is not set, add it to .env before starting')

    app = Flask(__name__)
    app.config['SECRET_KEY'] = secret_key
    # javascript cannot read the session cookie, so an XSS bug cannot steal it
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    # off by default because the app runs over plain HTTP locally
    app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() in ('1', 'true', 'yes')
    # Flask rejects a cookie older than this, so a copied one stops working after 30 idle minutes
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

    app.register_blueprint(auth)

    @app.route('/')
    def index():
        return render_template('base.html')

    return app
