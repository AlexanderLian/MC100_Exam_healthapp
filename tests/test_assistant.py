import pytest

import app as app_package
from app import models
from app.controllers import assistant as assistant_module

API_KEY = 'sk-or-v1-test-key-not-a-real-one'


class FakeCompletions:
    def __init__(self, sent, reply, error):
        self.sent = sent
        self.reply = reply
        self.error = error

    def create(self, **kwargs):
        self.sent.append(kwargs)
        if self.error is not None:
            raise self.error
        message = type('Message', (), {'content': self.reply})
        choice = type('Choice', (), {'message': message})
        return type('Response', (), {'choices': [choice]})


class FakeClient:
    def __init__(self, sent, reply, error, **kwargs):
        self.chat = type('Chat', (), {'completions': FakeCompletions(sent, reply, error)})


@pytest.fixture
def fake_model(monkeypatch):
    # every request that would have left the server
    sent = []

    def install(reply='The clinic is open on weekdays.', error=None):
        monkeypatch.setenv('OPENROUTER_API_KEY', API_KEY)
        monkeypatch.setattr(assistant_module, 'OpenAI',
                            lambda **kwargs: FakeClient(sent, reply, error, **kwargs))
        return sent

    return install


def ask(client, question='When is the clinic open?'):
    return client.post('/assistant', data={'question': question})


def sent_text(sent):
    return ' '.join(str(message) for call in sent for message in call['messages'])


def test_assistant_requires_login(client, fake_model):
    fake_model()
    assert ask(client).status_code == 401


def test_question_over_the_limit_is_refused(client, login, fake_model):
    sent = fake_model()
    login('patient1')
    refused = ask(client, question='a' * 501).status_code
    # nothing sent either, or the bound only hides a request that still went out
    assert (refused, sent) == (400, [])


def test_national_id_is_redacted_before_sending(client, login, fake_model):
    sent = fake_model()
    login('patient1')
    ask(client, question='My national id is 12345678901, can you check my file?')
    assert '12345678901' not in sent_text(sent) and 'REDACTED' in sent_text(sent)


def test_password_like_text_is_redacted(client, login, fake_model):
    sent = fake_model()
    login('patient1')
    ask(client, question='I cannot log in, password=SuperSecret123 does not work')
    assert 'SuperSecret123' not in sent_text(sent) and 'REDACTED' in sent_text(sent)


def test_no_patient_data_is_sent(client, login, fake_model):
    models.create_note(models.get_user_by_email('patient1@healthapp.test')['id'],
                       models.get_user_by_email('clinician1@healthapp.test')['id'],
                       'patient has a rare condition')
    sent = fake_model()
    login('patient1')
    ask(client, question='What does my journal say about me?')
    # the question goes out, the record does not
    assert 'journal' in sent_text(sent) and 'rare condition' not in sent_text(sent)


def test_system_prompt_is_sent_with_every_question(client, login, fake_model):
    sent = fake_model()
    login('patient1')
    ask(client)
    # the prompt is what keeps the model in its role, a question alone would not
    assert sent[0]['messages'][0]['role'] == 'system' and 'cannot see any patient records' in sent[0]['messages'][0]['content']


def test_answer_is_escaped_on_the_page(client, login, fake_model):
    fake_model(reply='<script>alert(1)</script>')
    login('patient1')
    page = ask(client).get_data(as_text=True)
    assert '&lt;script&gt;' in page and '<script>alert(1)</script>' not in page


def test_api_key_never_reaches_the_page_or_the_log(client, login, fake_model):
    fake_model()
    login('patient1')
    page = ask(client).get_data(as_text=True)
    with open(app_package.SECURITY_LOG, encoding='utf-8') as f:
        log = f.read()
    assert API_KEY not in page and API_KEY not in log


def test_upstream_failure_shows_a_message(client, login, fake_model):
    fake_model(error=RuntimeError('connection refused by openrouter'))
    login('patient1')
    response = ask(client)
    page = response.get_data(as_text=True)
    # a plain message, never the exception text or a traceback
    assert response.status_code == 502 and 'Traceback' not in page and 'connection refused' not in page


def test_rate_limit_refuses_the_sixth_question(client, login, fake_model):
    sent = fake_model()
    login('patient1')
    for _ in range(5):
        ask(client)
    refused = ask(client).status_code
    # five calls left the server, the sixth did not
    assert (refused, len(sent)) == (429, 5)
