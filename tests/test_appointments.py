import pytest

from app import models


def user_id(name):
    return models.get_user_by_email(name + '@healthapp.test')['id']


def free_slot():
    # the first slot the page offers, the seeded appointment is on another date
    return models.available_slots()[0]


def book(client, clinician='clinician1', slot=None, **extra):
    form = {'clinician_id': user_id(clinician), 'slot_start': slot or free_slot()}
    form.update(extra)
    return client.post('/book', data=form)


def appointment_count():
    conn = models.get_connection()
    count = conn.execute('SELECT COUNT(*) FROM appointments').fetchone()[0]
    conn.close()
    return count


def test_patient_can_book_available_clinician(client, login):
    login('patient1')
    slot = free_slot()
    book(client, slot=slot)
    conn = models.get_connection()
    row = conn.execute('SELECT patient_id FROM appointments WHERE slot_start = ?', (slot,)).fetchone()
    conn.close()
    assert row is not None and row['patient_id'] == user_id('patient1')


def test_clinician_cannot_be_double_booked(client, login):
    slot = free_slot()
    login('patient1')
    book(client, slot=slot)
    login('patient2')
    refused = book(client, slot=slot)
    # 409, and still one row, or the second booking only looked like it failed
    assert (refused.status_code, appointment_count()) == (409, 2)


def test_double_booking_is_refused_by_the_model(app):
    slot = free_slot()
    models.book_appointment(user_id('patient1'), user_id('clinician1'), slot)
    # the same check as the route, one level down, so a future route cannot skip it
    with pytest.raises(models.ClinicianUnavailableError):
        models.book_appointment(user_id('patient2'), user_id('clinician1'), slot)


def test_booking_uses_the_session_patient(client, login):
    login('patient1')
    slot = free_slot()
    # booking is what gives a clinician access to a record, so a patient_id in the form must be ignored
    book(client, slot=slot, patient_id=user_id('patient2'))
    conn = models.get_connection()
    row = conn.execute('SELECT patient_id FROM appointments WHERE slot_start = ?', (slot,)).fetchone()
    conn.close()
    assert row is not None and row['patient_id'] == user_id('patient1')


def test_clinician_cannot_book(client, login):
    login('clinician2')
    refused = book(client).status_code
    # a clinician booking themselves a patient would hand themselves that record
    assert (refused, appointment_count()) == (404, 1)


def test_unauthenticated_booking_is_401(client):
    assert book(client).status_code == 401


def test_booking_rejects_an_unknown_clinician(client, login):
    login('patient1')
    refused = book(client, clinician='patient2').status_code
    assert (refused, appointment_count()) == (400, 1)


def test_booking_rejects_a_slot_that_is_not_offered(client, login):
    login('patient1')
    # a slot in the past, which is not on the list the page offers
    refused = book(client, slot='2020-01-01 09:00:00').status_code
    assert (refused, appointment_count()) == (400, 1)
