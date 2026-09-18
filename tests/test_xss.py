from app import models

SCRIPT = "<script>alert('hacked')</script>"
ESCAPED = '&lt;script&gt;alert(&#39;hacked&#39;)&lt;/script&gt;'


def test_script_in_note_is_escaped_on_render(client, login):
    url = '/patient/%d/notes' % models.get_user_by_email('patient1@healthapp.test')['id']
    login('clinician1')
    client.post(url, data={'body': SCRIPT})
    page = client.get(url).get_data(as_text=True)
    assert ESCAPED in page and SCRIPT not in page


# a patient controls their own name, and it is rendered on a clinician's page
def test_script_in_patient_name_is_escaped_on_patient_list(client, login, register):
    register(full_name=SCRIPT)
    conn = models.get_connection()
    conn.execute('INSERT INTO appointments (patient_id, clinician_id, slot_start) VALUES (?, ?, ?)',
                 (models.get_user_by_email('new@healthapp.test')['id'],
                  models.get_user_by_email('clinician1@healthapp.test')['id'], '2026-10-03 09:00:00'))
    conn.commit()
    conn.close()
    login('clinician1')
    page = client.get('/patients').get_data(as_text=True)
    assert ESCAPED in page and SCRIPT not in page
