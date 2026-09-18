import io
import os

from app import models


def user_id(name):
    return models.get_user_by_email(name + '@healthapp.test')['id']


def upload(client, filename='referral.pdf', content=b'referral body'):
    return client.post('/documents', data={'document': (io.BytesIO(content), filename)},
                       content_type='multipart/form-data')


def upload_as(client, login, name, filename='referral.pdf', content=b'referral body'):
    login(name)
    upload(client, filename, content)
    client.get('/logout')
    conn = models.get_connection()
    row = conn.execute('SELECT id, stored_name FROM documents ORDER BY id DESC').fetchone()
    conn.close()
    return row


def download(client, document_id):
    return client.get('/documents/%d' % document_id)


def document_count():
    conn = models.get_connection()
    count = conn.execute('SELECT COUNT(*) FROM documents').fetchone()[0]
    conn.close()
    return count


def test_patient_can_upload_and_download_own_document(client, login):
    document = upload_as(client, login, 'patient1', content=b'my referral')
    login('patient1')
    response = download(client, document['id'])
    assert response.status_code == 200 and response.get_data() == b'my referral'


def test_other_patient_cannot_download(client, login):
    document = upload_as(client, login, 'patient1')
    login('patient2')
    assert download(client, document['id']).status_code == 404


def test_linked_clinician_can_download(client, login):
    document = upload_as(client, login, 'patient1')
    # clinician1 has the seeded appointment with patient1
    login('clinician1')
    assert download(client, document['id']).status_code == 200


def test_unlinked_clinician_cannot_download(client, login):
    document = upload_as(client, login, 'patient1')
    login('clinician2')
    assert download(client, document['id']).status_code == 404


def test_admin_cannot_download(client, login):
    document = upload_as(client, login, 'patient1')
    login('admin')
    assert download(client, document['id']).status_code == 404


def test_clinician_cannot_upload(client, login):
    login('clinician1')
    refused = upload(client).status_code
    login('patient1')
    # the patient half shows uploading works, so the clinician half means the role check did it
    assert (refused, upload(client).status_code, document_count()) == (404, 302, 1)


def test_unauthenticated_upload_is_401(client):
    assert (upload(client).status_code, document_count()) == (401, 0)


def test_upload_rejects_a_disallowed_extension(client, login):
    login('patient1')
    assert (upload(client, filename='evil.exe').status_code, document_count()) == (400, 0)


def test_uploaded_name_is_not_used_on_disk(client, login):
    # an allowed extension, so the name is the only attack left
    document = upload_as(client, login, 'patient1', filename='../../app/models.pdf')
    # a random name with a checked extension, so nothing the user typed reaches a path
    assert '..' not in document['stored_name'] and os.path.basename(document['stored_name']) == document['stored_name']


def test_two_uploads_with_the_same_name_are_both_kept(client, login):
    first = upload_as(client, login, 'patient1', content=b'first file')
    second = upload_as(client, login, 'patient2', content=b'second file')
    login('patient1')
    # the same filename twice, and the first patient still gets their own bytes
    assert first['stored_name'] != second['stored_name'] and download(client, first['id']).get_data() == b'first file'


def test_upload_over_the_size_limit_is_refused(client, login):
    login('patient1')
    # one byte over 5 MB, refused before the file is read, or one upload could fill the disk
    refused = upload(client, content=b'x' * (5 * 1024 * 1024 + 1)).status_code
    assert (refused, document_count()) == (413, 0)


def test_download_is_sent_as_an_attachment(client, login):
    document = upload_as(client, login, 'patient1', filename='note.txt', content=b'<script>alert(1)</script>')
    login('patient1')
    # downloaded, never rendered on our own origin, or an uploaded file could run as a page
    assert 'attachment' in download(client, document['id']).headers.get('Content-Disposition', '')


def test_linked_clinician_sees_patient_documents(client, login):
    upload_as(client, login, 'patient1', filename='referral.pdf')
    login('clinician1')
    page = client.get('/patient/%d/notes' % user_id('patient1')).get_data(as_text=True)
    assert 'referral.pdf' in page


def test_notes_page_shows_only_that_patients_documents(client, login):
    upload_as(client, login, 'patient1', filename='mine.pdf')
    upload_as(client, login, 'patient2', filename='theirs.pdf')
    login('clinician1')
    page = client.get('/patient/%d/notes' % user_id('patient1')).get_data(as_text=True)
    assert 'mine.pdf' in page and 'theirs.pdf' not in page


def test_documents_for_patient_needs_an_appointment(client, login):
    upload_as(client, login, 'patient2', filename='theirs.pdf')
    owner_sees = [d['original_name'] for d in models.get_documents_for_owner(user_id('patient2'))]
    # the file has to exist, or an empty list proves nothing. clinician1 has no appointment with patient2
    assert (owner_sees, models.get_documents_for_patient(user_id('patient2'), user_id('clinician1'))) == (['theirs.pdf'], [])


def test_document_metadata_is_stored(client, login):
    upload_as(client, login, 'patient1', filename='referral.pdf', content=b'referral body')
    conn = models.get_connection()
    row = conn.execute('SELECT owner_id, original_name, size_bytes FROM documents').fetchone()
    conn.close()
    assert (row['owner_id'], row['original_name'], row['size_bytes']) == (user_id('patient1'), 'referral.pdf', 13)
