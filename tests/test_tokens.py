import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone

import app as app_package
from app import models

GENERIC_MESSAGE = 'If that email is registered, a reset code has been sent.'
NEW_PASSWORD = 'a brand new password'


def printed_token(capsys):
    # the token is printed to the console instead of emailed, see README
    match = re.search(r'RESET TOKEN for \S+: (\S+)', capsys.readouterr().out)
    if match is None:
        return ''
    return match.group(1)


def request_token(client, capsys, name):
    client.post('/forgot-password', data={'email': name + '@healthapp.test'})
    return printed_token(capsys)


def reset(client, token, password=NEW_PASSWORD):
    return client.post('/reset-password', data={'token': token, 'password': password})


def test_valid_token_resets_password(client, login, capsys):
    reset(client, request_token(client, capsys, 'patient1'))
    assert login('patient1', password=NEW_PASSWORD).status_code == 302


def test_reset_changes_only_the_token_owners_password(client, login, capsys):
    reset(client, request_token(client, capsys, 'patient1'))
    owner = login('patient1', password=NEW_PASSWORD).status_code
    other = login('patient2').status_code
    assert (owner, other) == (302, 302)


def test_only_token_hash_is_stored(client, capsys):
    token = request_token(client, capsys, 'patient1')
    conn = models.get_connection()
    row = conn.execute('SELECT token_hash FROM reset_tokens').fetchone()
    conn.close()
    assert row is not None and row['token_hash'] == hashlib.sha256(token.encode('utf-8')).hexdigest()


def test_unknown_token_is_rejected(client):
    assert reset(client, 'not-a-real-token').status_code == 401


def test_expired_token_is_rejected(client, capsys, monkeypatch):
    token = request_token(client, capsys, 'patient1')
    # 31 minutes later, one minute past the limit, in the SQLite time format
    # on the same day a time with a T in it would compare wrong as text, so this catches that too
    later = (datetime.now(timezone.utc) + timedelta(minutes=31)).strftime('%Y-%m-%d %H:%M:%S')
    monkeypatch.setattr(models, 'now', lambda: later)
    assert reset(client, token).status_code == 401


def test_used_token_is_rejected(client, login, capsys):
    token = request_token(client, capsys, 'patient1')
    reset(client, token)
    second = reset(client, token, password='another new password').status_code
    # the login shows the first reset worked, otherwise this passes when no token works at all
    assert (second, login('patient1', password=NEW_PASSWORD).status_code) == (401, 302)


def test_reset_invalidates_other_outstanding_tokens(client, login, capsys):
    older = request_token(client, capsys, 'patient1')
    newer = request_token(client, capsys, 'patient1')
    reset(client, newer)
    second = reset(client, older, password='another new password').status_code
    # the login shows the newer token worked, otherwise this passes when no token works at all
    assert (second, login('patient1', password=NEW_PASSWORD).status_code) == (401, 302)


def test_reset_rejects_password_under_8_bytes(client, capsys):
    token = request_token(client, capsys, 'patient1')
    assert reset(client, token, password='1234567').status_code == 400


def test_reset_password_limit_counts_bytes_not_characters(client, capsys):
    token = request_token(client, capsys, 'patient1')
    # 37 characters but 74 bytes, so a character count would pass it on and bcrypt would crash
    assert reset(client, token, password='ø' * 37).status_code == 400


def test_forgot_password_response_is_same_for_unknown_email(client):
    known = client.post('/forgot-password', data={'email': 'patient1@healthapp.test'})
    unknown = client.post('/forgot-password', data={'email': 'nobody@healthapp.test'})
    # the message check stops two identical error pages from passing
    assert GENERIC_MESSAGE in known.get_data(as_text=True) and known.get_data() == unknown.get_data()


def test_forgot_password_page_does_not_show_token(client, capsys):
    page = client.post('/forgot-password', data={'email': 'patient1@healthapp.test'}).get_data(as_text=True)
    token = printed_token(capsys)
    assert GENERIC_MESSAGE in page and token != '' and token not in page


def test_token_is_not_written_to_security_log(client, capsys):
    token = request_token(client, capsys, 'patient1')
    with open(app_package.SECURITY_LOG, encoding='utf-8') as f:
        log = f.read()
    # log files get kept and copied, so a token in there stays usable for 30 minutes
    assert token != '' and token not in log


def test_token_comes_from_secrets(client, capsys, monkeypatch):
    made = []
    real_token_hex = secrets.token_hex

    def recording_token_hex(nbytes=None):
        token = real_token_hex(nbytes)
        made.append((nbytes, token))
        return token

    # a random token and a secrets token look the same, so the test watches the call
    monkeypatch.setattr(secrets, 'token_hex', recording_token_hex)
    printed = request_token(client, capsys, 'patient1')
    # the printed token has to be the one secrets made, or calling it and then using random would pass
    assert made == [(32, printed)]
