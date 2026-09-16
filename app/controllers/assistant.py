import logging
import os
import re
import time

from flask import Blueprint, render_template, request, session
from openai import OpenAI

from app.controllers.auth import login_required

assistant = Blueprint('assistant', __name__)

security_log = logging.getLogger('healthapp.security')

# a cap on what one question can cost
MAX_QUESTION = 500
MAX_ANSWER = 2000
MAX_PER_MINUTE = 5

# a chat model by name, the free routing pools can land on one that only labels content
DEFAULT_MODEL = 'google/gemma-4-31b-it:free'

SECRET_PATTERNS = [
    (re.compile(r'(?i)(api[_-]?key\s*[=:]\s*)[^\s,;]+'), r'\1[REDACTED]'),
    (re.compile(r'(?i)(password\s*[=:]\s*)[^\s,;]+'), r'\1[REDACTED]'),
    (re.compile(r'(?i)(token\s*[=:]\s*)[^\s,;]+'), r'\1[REDACTED]'),
    # 11 digits is a fodselsnummer, it must never leave the clinic
    (re.compile(r'\b[0-9]{11}\b'), '[REDACTED]'),
]

SYSTEM_PROMPT = (
    'You are the help assistant for a clinic web portal in Norway. '
    'Patients can register and log in, book an appointment, upload documents and '
    'reset a password. Clinicians can read and write journal notes for patients '
    'they have an appointment with. Never mention anything else the portal can do. '
    'You cannot see any patient records, so never say that you can. '
    'Do not give medical advice, tell the person to contact the clinic. '
    'Keep answers short, three sentences at most. '
    'Write the answer only, never your reasoning.'
)


def redact(text):
    for pattern, replacement in SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def recent_ask_times():
    minute_ago = time.time() - 60
    return [asked for asked in session.get('assistant_times', []) if asked > minute_ago]


def assistant_page(answer=None, question=None, error=None):
    return render_template('assistant.html', answer=answer, question=question, error=error)


@assistant.route('/assistant', methods=['GET', 'POST'])
@login_required
def ask():
    if request.method == 'GET':
        return assistant_page()

    question = request.form.get('question', '').strip()
    # the form already requires it, this is for a request that skips the form
    if not question:
        return assistant_page(), 400
    if len(question) > MAX_QUESTION:
        return assistant_page(error='Questions can be at most %d characters.' % MAX_QUESTION,
                              question=question), 400

    asked = recent_ask_times()
    # every question costs money, so one account cannot spend the quota in a loop
    if len(asked) >= MAX_PER_MINUTE:
        return assistant_page(error='Too many questions. Wait a minute and try again.', question=question), 429

    asked.append(time.time())
    session['assistant_times'] = asked

    try:
        client = OpenAI(base_url='https://openrouter.ai/api/v1', api_key=os.environ['OPENROUTER_API_KEY'])
        response = client.chat.completions.create(
            model=os.environ.get('OPENROUTER_MODEL', DEFAULT_MODEL),
            messages=[
                {'role': 'system', 'content': SYSTEM_PROMPT},
                # redacted first, so a national id or a password never leaves the server
                {'role': 'user', 'content': redact(question)},
            ],
            max_completion_tokens=400,
            temperature=0,
        )
        answer = response.choices[0].message.content or ''
    except Exception:
        # no exception text on the page, it can carry the key, the url or a stack trace
        security_log.warning('assistant call failed user_id=%s', session.get('user_id'))
        return assistant_page(error='The assistant is not available right now.', question=question), 502

    # Jinja2 escapes the answer, nothing runs it
    return assistant_page(answer=answer[:MAX_ANSWER], question=question)
