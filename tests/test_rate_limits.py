import io

import app as app_package
from tests.conftest import SEED_PASSWORD


def statuses(send, times):
    return [send().status_code for _ in range(times)]


def test_login_is_limited_after_five_attempts(client):
    def wrong_password():
        return client.post('/login', data={'email': 'patient1@healthapp.test', 'password': 'not the password'})
    # the first five are normal refusals, so the sixth can only be the limit
    assert statuses(wrong_password, 6) == [401] * 5 + [429]


def test_forgot_password_is_limited(client):
    def ask_for_code():
        return client.post('/forgot-password', data={'email': 'nobody@healthapp.test'})
    assert statuses(ask_for_code, 4) == [200] * 3 + [429]


def test_reset_password_is_limited(client):
    def guess_code():
        return client.post('/reset-password', data={'token': 'guessed', 'password': 'a long enough password'})
    assert statuses(guess_code, 6) == [401] * 5 + [429]


def test_register_is_limited(client):
    def sign_up():
        return client.post('/register', data={'email': 'new@healthapp.test', 'full_name': 'New', 'password': 'short'})
    assert statuses(sign_up, 4) == [400] * 3 + [429]


def test_api_limit_is_shared_by_every_endpoint(client):
    patients = statuses(lambda: client.get('/api/patients'), 30)
    appointments = statuses(lambda: client.get('/api/appointments'), 31)
    # 30 and 30 used up the shared 60, so the next call is refused on a different endpoint
    assert patients + appointments == [401] * 60 + [429]


def test_api_rate_limit_answers_in_json(client):
    for _ in range(61):
        last = client.get('/api/patients')
    assert (last.status_code, last.get_json()) == (429, {'error': 'Too many requests'})


def test_upload_is_limited(client, login):
    login('patient1')

    def upload():
        return client.post('/documents', data={'document': (io.BytesIO(b'file'), 'referral.pdf')},
                           content_type='multipart/form-data')
    assert statuses(upload, 11) == [302] * 10 + [429]


def test_global_limit_applies_to_every_page(client):
    def front_page():
        return client.get('/')
    assert statuses(front_page, 201) == [200] * 200 + [429]


def test_assistant_limit_is_per_account_not_per_cookie(app, client, login, monkeypatch):
    monkeypatch.delenv('OPENROUTER_API_KEY', raising=False)
    login('patient1')
    # no key set, so each allowed question ends in 502 and never reaches OpenRouter
    first = [client.post('/assistant', data={'question': 'hello'}).status_code for _ in range(5)]

    # a new browser has no cookies, so only a limit kept on the server can still refuse it
    fresh_browser = app.test_client()
    fresh_browser.post('/login', data={'email': 'patient1@healthapp.test', 'password': SEED_PASSWORD})
    same_account = fresh_browser.post('/assistant', data={'question': 'hello'}).status_code

    # same address, different account, so a limit per address would wrongly refuse this one
    other_patient = app.test_client()
    other_patient.post('/login', data={'email': 'patient2@healthapp.test', 'password': SEED_PASSWORD})
    other_account = other_patient.post('/assistant', data={'question': 'hello'}).status_code

    assert (first, same_account, other_account) == ([502] * 5, 429, 502)


def test_limit_on_one_route_does_not_block_others(client):
    for _ in range(6):
        last = client.post('/login', data={'email': 'patient1@healthapp.test', 'password': 'not the password'})
    # locked out of guessing, but the rest of the site still works
    assert (last.status_code, client.get('/forgot-password').status_code) == (429, 200)


def test_rate_limit_hit_is_logged(client):
    for _ in range(6):
        client.post('/login', data={'email': 'patient1@healthapp.test', 'password': 'not the password'})
    with open(app_package.SECURITY_LOG, encoding='utf-8') as f:
        log = f.read()
    assert 'rate limit' in log and '/login' in log
