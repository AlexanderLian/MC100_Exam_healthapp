import pytest

import app as app_package
from app import models


def user_id(name):
    return models.get_user_by_email(name + '@healthapp.test')['id']


def notes_url(name):
    return '/patient/%d/notes' % user_id(name)


def add_appointment(patient, clinician, slot_start):
    conn = models.get_connection()
    conn.execute('INSERT INTO appointments (patient_id, clinician_id, slot_start) VALUES (?, ?, ?)',
                 (user_id(patient), user_id(clinician), slot_start))
    conn.commit()
    conn.close()


def test_unauthenticated_request_gets_401(client):
    assert client.get(notes_url('patient1')).status_code == 401


# without this, a route that 404s for everyone would pass every denial test below
def test_clinician_with_appointment_can_read_notes(client, login):
    login('clinician1')
    assert client.get(notes_url('patient1')).status_code == 200


def test_clinician_without_appointment_cannot_read(client, login):
    login('clinician1')
    assert client.get(notes_url('patient2')).status_code == 404


def test_clinician_without_appointment_cannot_write(client, login):
    login('clinician1')
    client.post(notes_url('patient2'), data={'body': 'should not be saved'})
    conn = models.get_connection()
    count = conn.execute('SELECT COUNT(*) FROM notes').fetchone()[0]
    conn.close()
    assert count == 0


# straight to the model, because the route checks the appointment before this guard is ever reached
def test_create_note_refuses_unlinked_pair(app):
    assert models.create_note(user_id('patient2'), user_id('clinician1'), 'should not be saved') is False


@pytest.mark.parametrize('name', ['admin', 'patient2'])
def test_non_clinician_cannot_read_notes_even_with_appointment(client, login, name):
    # an appointment naming them means the role check is the only thing in the way
    add_appointment('patient1', name, '2026-10-02 09:00:00')
    login(name)
    assert client.get(notes_url('patient1')).status_code == 404


def test_denied_page_is_identical_to_missing_page(client, login):
    login('clinician1')
    denied = client.get(notes_url('patient2'))
    missing = client.get('/no-such-page')
    assert (denied.status_code, denied.get_data()) == (missing.status_code, missing.get_data())


def test_empty_note_to_unlinked_patient_is_404_not_400(client, login):
    login('clinician1')
    assert client.post(notes_url('patient2'), data={'body': ''}).status_code == 404


def test_second_appointment_does_not_duplicate_notes(client, login):
    login('clinician1')
    client.post(notes_url('patient1'), data={'body': 'first note'})
    add_appointment('patient1', 'clinician1', '2026-11-01 09:00:00')
    assert len(models.get_notes_for_clinician(user_id('patient1'), user_id('clinician1'))) == 1


def test_denial_is_logged_without_note_text(client, login):
    login('clinician1')
    client.post(notes_url('patient2'), data={'body': 'private note text'})
    with open(app_package.SECURITY_LOG, encoding='utf-8') as f:
        log = f.read()
    # both halves, because a log that leaves out the note text only counts if the line was written
    assert 'patient_id=%d' % user_id('patient2') in log and 'private note text' not in log


def test_clinician_sees_only_own_patients(client, login):
    login('clinician2')
    # the empty-list message, so a crashing page fails instead of passing
    assert 'You have no patients with appointments.' in client.get('/patients').get_data(as_text=True)
