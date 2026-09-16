import logging

import pytest

import app as app_package
from app import create_app, models

SEED_PASSWORD = 'test seed password'


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv('SECRET_KEY', 'test-secret-key-that-is-long-enough-for-signing')
    monkeypatch.setenv('SEED_PASSWORD', SEED_PASSWORD)
    monkeypatch.setenv('SESSION_COOKIE_SECURE', 'false')
    monkeypatch.setattr(models, 'DATABASE', str(tmp_path / 'test.db'))
    # a temp folder, or every test run drops files in the real uploads folder
    upload_folder = tmp_path / 'uploads'
    upload_folder.mkdir()
    monkeypatch.setattr(models, 'UPLOAD_FOLDER', str(upload_folder))
    monkeypatch.setattr(app_package, 'SECURITY_LOG', str(tmp_path / 'security.log'))
    # 4 rounds keeps the suite fast, test_bcrypt_work_factor_is_12 guards the real value
    monkeypatch.setattr(models, 'BCRYPT_ROUNDS', 4)

    # create_app only adds a log handler once, so drop the last test's handler first
    security_log = logging.getLogger('healthapp.security')
    for handler in list(security_log.handlers):
        security_log.removeHandler(handler)
        handler.close()

    models.init_db()
    yield create_app()

    # close the file so Windows can delete the temp folder
    for handler in list(security_log.handlers):
        security_log.removeHandler(handler)
        handler.close()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def login(client):
    def log_in(name, password=SEED_PASSWORD):
        return client.post('/login', data={'email': name + '@healthapp.test', 'password': password})
    return log_in


@pytest.fixture
def register(client):
    def sign_up(**fields):
        form = {
            'email': 'new@healthapp.test',
            'full_name': 'New Patient',
            'password': 'password123',
            'national_id': '12345678901',
        }
        form.update(fields)
        return client.post('/register', data=form)
    return sign_up
