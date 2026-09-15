import os

import pytest

from app import models


@pytest.mark.parametrize('email', ["' OR '1'='1", "' OR 1=1 --", "admin@healthapp.test' --"])
def test_sql_injection_in_login_email_fails(client, email):
    # the real seed password, so a query built from strings would log in as the first user it matched
    response = client.post('/login', data={'email': email, 'password': os.environ['SEED_PASSWORD']})
    assert response.status_code == 401


def test_sql_injection_in_name_is_stored_as_text(register):
    name = "Robert'); DROP TABLE users; --"
    register(full_name=name)
    conn = models.get_connection()
    row = conn.execute('SELECT full_name FROM users WHERE email = ?', ('new@healthapp.test',)).fetchone()
    conn.close()
    assert row is not None and row['full_name'] == name
