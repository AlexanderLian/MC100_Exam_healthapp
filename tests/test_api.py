import hashlib
import re
from datetime import datetime, timedelta, timezone

import app as app_package
from app import models

PATIENTS_URL = '/api/patients'
APPOINTMENTS_URL = '/api/appointments'


def user_id(name):
    return models.get_user_by_email(name + '@healthapp.test')['id']


def notes_url(name):
    return '/api/patients/%d/notes' % user_id(name)


def api_token(client, login, name):
    login(name)
    page = client.post('/api-tokens').get_data(as_text=True)
    # log out, so a test that still passes can only be using the token
    client.get('/logout')
    match = re.search(r'New API token: ([0-9a-f]+)', page)
    if match is None:
        return ''
    return match.group(1)


def header(token):
    return {'X-API-Key': token}


def test_api_rejects_request_without_token(client):
    assert client.get(PATIENTS_URL).status_code == 401


def test_api_rejects_unknown_token(client):
    assert client.get(PATIENTS_URL, headers=header('not-a-real-token')).status_code == 401


def test_api_rejects_expired_token(client, login, monkeypatch):
    token = api_token(client, login, 'clinician1')
    # one day past the 30 day limit
    later = (datetime.now(timezone.utc) + timedelta(days=31)).strftime('%Y-%m-%d %H:%M:%S')
    monkeypatch.setattr(models, 'now', lambda: later)
    assert client.get(PATIENTS_URL, headers=header(token)).status_code == 401


def test_revoked_token_is_rejected(client, login):
    token = api_token(client, login, 'clinician1')
    login('clinician1')
    client.post('/api-tokens/revoke')
    client.get('/logout')
    assert client.get(PATIENTS_URL, headers=header(token)).status_code == 401


def test_regenerating_replaces_the_old_token(client, login):
    old = api_token(client, login, 'clinician1')
    new = api_token(client, login, 'clinician1')
    refused = client.get(PATIENTS_URL, headers=header(old)).status_code
    # the new one has to work, or this passes when no token works at all
    assert (refused, client.get(PATIENTS_URL, headers=header(new)).status_code) == (401, 200)


def test_api_ignores_session_cookie(client, login):
    login('clinician1')
    # logged in but no header, or another site could call the API with the browser's cookie
    assert client.get(PATIENTS_URL).status_code == 401


def test_api_ignores_token_in_query_string(client, login):
    token = api_token(client, login, 'clinician1')
    # tokens in a URL end up in browser history and server logs
    assert client.get(PATIENTS_URL + '?api_key=' + token).status_code == 401


def test_clinician_token_reads_linked_patient_notes(client, login):
    models.create_note(user_id('patient1'), user_id('clinician1'), 'note read over the api')
    token = api_token(client, login, 'clinician1')
    response = client.get(notes_url('patient1'), headers=header(token))
    assert response.status_code == 200 and 'note read over the api' in response.get_data(as_text=True)


def test_clinician_token_cannot_read_unlinked_patient(client, login):
    token = api_token(client, login, 'clinician1')
    linked = client.get(notes_url('patient1'), headers=header(token)).status_code
    # both halves, or this passes when every url is a 404
    assert (linked, client.get(notes_url('patient2'), headers=header(token)).status_code) == (200, 404)


def test_patient_token_cannot_read_notes(client, login):
    patient = api_token(client, login, 'patient1')
    clinician = api_token(client, login, 'clinician1')
    refused = client.get(notes_url('patient1'), headers=header(patient)).status_code
    # the clinician half shows the url works, so the patient half means the role check did it
    assert (refused, client.get(notes_url('patient1'), headers=header(clinician)).status_code) == (404, 200)


def test_patient_token_cannot_list_patients(client, login):
    patient = api_token(client, login, 'patient1')
    clinician = api_token(client, login, 'clinician1')
    refused = client.get(PATIENTS_URL, headers=header(patient)).status_code
    # the patient list has no appointment check of its own, so only the role check stops this
    assert (refused, client.get(PATIENTS_URL, headers=header(clinician)).status_code) == (404, 200)


def test_patient_token_reads_own_appointments(client, login):
    token = api_token(client, login, 'patient1')
    response = client.get(APPOINTMENTS_URL, headers=header(token))
    # the seeded appointment is with Kari Lege
    assert response.status_code == 200 and 'Kari Lege' in response.get_data(as_text=True)


def test_appointments_show_only_the_token_owners_own(client, login):
    models.book_appointment(user_id('patient2'), user_id('clinician2'), models.available_slots()[0])
    token = api_token(client, login, 'patient1')
    page = client.get(APPOINTMENTS_URL, headers=header(token)).get_data(as_text=True)
    # patient1 keeps their own appointment and never sees patient2's clinician
    assert 'Kari Lege' in page and 'Ola Lege' not in page


def test_clinician_token_cannot_read_appointments(client, login):
    clinician = api_token(client, login, 'clinician1')
    patient = api_token(client, login, 'patient1')
    refused = client.get(APPOINTMENTS_URL, headers=header(clinician)).status_code
    assert (refused, client.get(APPOINTMENTS_URL, headers=header(patient)).status_code) == (404, 200)


def test_api_note_is_written_as_token_owner(client, login):
    token = api_token(client, login, 'clinician1')
    client.post(notes_url('patient1'), json={'body': 'written over the api'}, headers=header(token))
    conn = models.get_connection()
    row = conn.execute('SELECT clinician_id FROM notes').fetchone()
    conn.close()
    assert row is not None and row['clinician_id'] == user_id('clinician1')


def test_api_rejects_a_note_that_is_not_text(client, login):
    token = api_token(client, login, 'clinician1')
    # 400 and not a 500 crash, and nothing written
    assert client.post(notes_url('patient1'), json={'body': 123}, headers=header(token)).status_code == 400


def test_only_api_token_hash_is_stored(client, login):
    token = api_token(client, login, 'clinician1')
    conn = models.get_connection()
    row = conn.execute('SELECT token_hash FROM api_tokens').fetchone()
    conn.close()
    assert row is not None and row['token_hash'] == hashlib.sha256(token.encode('utf-8')).hexdigest()


def test_rejected_token_is_not_written_to_security_log(client, login):
    token = api_token(client, login, 'clinician1')
    client.get(PATIENTS_URL, headers=header(token + 'x'))
    with open(app_package.SECURITY_LOG, encoding='utf-8') as f:
        log = f.read()
    # the line has to be there, and the token must not be, it would work for 30 days
    assert 'api token rejected' in log and token not in log


def test_token_page_shows_only_prefix(client, login):
    token = api_token(client, login, 'clinician1')
    login('clinician1')
    page = client.get('/api-tokens').get_data(as_text=True)
    assert token != '' and token[:4] in page and token not in page
