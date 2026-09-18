import re

import bcrypt
from itsdangerous import TimestampSigner

import app as app_package
from app import models

# each link only shows in one state, so a crashing page cannot pass for either
LOGGED_OUT_LINK = 'href="/register"'
LOGGED_IN_LINK = 'href="/logout"'


def error_message(response):
    return re.search(r'<strong>(.*?)</strong>', response.get_data(as_text=True)).group(1)


def test_login_sets_session_for_correct_password(client, login):
    login('clinician1')
    assert LOGGED_IN_LINK in client.get('/').get_data(as_text=True)


def test_wrong_password_and_unknown_email_get_same_message(login):
    wrong_password = login('clinician1', password='not the password')
    unknown_email = login('nobody', password='not the password')
    assert error_message(wrong_password) == error_message(unknown_email)


def test_unknown_email_still_runs_bcrypt(app, monkeypatch):
    calls = []
    real_checkpw = bcrypt.checkpw

    def counting_checkpw(password, hashed):
        calls.append(hashed)
        return real_checkpw(password, hashed)

    # counts the hash check instead of timing it, because timing tests are flaky
    monkeypatch.setattr(bcrypt, 'checkpw', counting_checkpw)
    models.verify_login('nobody@healthapp.test', 'any password')
    assert len(calls) == 1


def test_logout_clears_session(client, login):
    login('clinician1')
    client.get('/logout')
    assert LOGGED_OUT_LINK in client.get('/').get_data(as_text=True)


def test_session_cookie_is_httponly(login):
    assert 'HttpOnly' in login('clinician1').headers['Set-Cookie']


def test_session_cookie_is_samesite_lax(login):
    assert 'SameSite=Lax' in login('clinician1').headers['Set-Cookie']


def test_session_expires_after_idle_timeout(client, login, monkeypatch):
    real_timestamp = TimestampSigner.get_timestamp
    # sign the login cookie 31 minutes ago, one minute past the limit
    with monkeypatch.context() as clock:
        clock.setattr(TimestampSigner, 'get_timestamp', lambda signer: real_timestamp(signer) - 31 * 60)
        login('clinician1')
    assert LOGGED_OUT_LINK in client.get('/').get_data(as_text=True)


def test_password_under_8_bytes_is_rejected(register):
    assert register(password='1234567').status_code == 400


def test_password_limit_counts_bytes_not_characters(register):
    # 37 characters but 74 bytes, so a character count would pass it on and bcrypt would crash
    assert register(password='ø' * 37).status_code == 400


def test_register_ignores_role_field(register):
    register(role='admin')
    assert models.get_user_by_email('new@healthapp.test')['role'] == 'patient'


def test_bcrypt_work_factor_is_12():
    # the fixture lowers the rounds for speed, so nothing else would notice the real value dropping
    assert models.BCRYPT_ROUNDS == 12


def security_log():
    with open(app_package.SECURITY_LOG, encoding='utf-8') as f:
        return f.read()


def test_failed_login_is_logged_with_the_account_id(login):
    login('patient1', password='not the password')
    patient_id = models.get_user_by_email('patient1@healthapp.test')['id']
    assert 'login failed user_id=%d' % patient_id in security_log()


def test_failed_login_log_never_holds_what_was_typed(login):
    login('patient1', password='typed-secret-123')
    log = security_log()
    # the line has to be there, or leaving out the password proves nothing
    assert 'login failed' in log and 'typed-secret-123' not in log and 'patient1@healthapp.test' not in log
