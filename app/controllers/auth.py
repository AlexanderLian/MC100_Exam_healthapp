import functools
import logging
import re
import sqlite3

from flask import Blueprint, render_template, request, redirect, url_for, session, abort

from app import models
from app.limiter import limiter

auth = Blueprint('auth', __name__)

security_log = logging.getLogger('healthapp.security')


# raises, so nothing after a deny() call runs
def deny(patient_id=None):
    # ids and route only, never the note text
    security_log.warning('access denied user_id=%s role=%s route=%s %s patient_id=%s',
                         session.get('user_id'), session.get('role'), request.method, request.path, patient_id)
    # 404 not 403, or an attacker learns which records exist
    abort(404)


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return render_template('login.html', error='Log in to see this page.'), 401
        return view(*args, **kwargs)
    return wrapped


def role_required(role):
    def decorator(view):
        # includes the login check, so stacking the two in the wrong order cannot turn a 401 into a 404
        @functools.wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            # exact match, admin is a separate set of permissions and not a higher one
            if session.get('role') != role:
                deny(kwargs.get('patient_id'))
            return view(*args, **kwargs)
        return wrapped
    return decorator


@auth.route('/register', methods=['GET', 'POST'])
@limiter.limit('3 per minute', methods=['POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    email = request.form.get('email', '').strip()
    full_name = request.form.get('full_name', '').strip()
    password = request.form.get('password', '')
    national_id = request.form.get('national_id', '').strip()

    # bytes not characters, because æ ø å are two bytes each and bcrypt refuses more than 72
    password_length = len(password.encode('utf-8'))

    error = None
    if '@' not in email:
        error = 'Enter a valid email address.'
    elif not full_name:
        error = 'Enter your full name.'
    elif password_length < 8:
        error = 'Password must be at least 8 characters.'
    elif password_length > 72:
        error = 'Password is too long.'
    # [0-9] not \d, because \d also matches Arabic-Indic digits
    elif not re.fullmatch(r'[0-9]{11}', national_id):
        error = 'National ID must be 11 digits.'

    if error:
        return render_template('register.html', error=error, email=email, full_name=full_name), 400

    try:
        # always 'patient', a role field in the form is never read
        models.create_user(email, password, 'patient', full_name, national_id)
    except sqlite3.IntegrityError:
        # one message for a taken email or national id, so the page does not say which
        error = 'Could not create the account. If you already have one, log in.'
        return render_template('register.html', error=error, email=email, full_name=full_name), 400

    return redirect(url_for('auth.login'))


@auth.route('/login', methods=['GET', 'POST'])
# bcrypt makes each guess slow, this caps how many guesses there are
@limiter.limit('5 per minute', methods=['POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    email = request.form.get('email', '')
    password = request.form.get('password', '')

    user = models.verify_login(email, password)
    if user is None:
        account = models.get_user_by_email(email)
        # the account id and address only, a typed email or password never reaches the log
        security_log.warning('login failed user_id=%s address=%s',
                             account['id'] if account else None, request.remote_addr)
        # one message for both failures, so login never says which emails exist
        return render_template('login.html', error='Wrong email or password.', email=email), 401

    # start from an empty session so nothing from before login carries over
    session.clear()
    session.permanent = True
    session['user_id'] = user['id']
    session['role'] = user['role']
    return redirect(url_for('index'))


@auth.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit('3 per minute', methods=['POST'])
def forgot_password():
    if request.method == 'GET':
        return render_template('forgot_password.html')

    email = request.form.get('email', '').strip().lower()
    token = models.create_reset_token(email)
    if token is not None:
        # not shown on the page, or anyone who types an email could reset that account
        print('RESET TOKEN for %s: %s' % (email, token))
        print('(this would be emailed in production, see README)')

    # same page for every email, so the form does not tell who has an account
    return render_template('reset_password.html', message='If that email is registered, a reset code has been sent.')


@auth.route('/reset-password', methods=['GET', 'POST'])
@limiter.limit('5 per minute', methods=['POST'])
def reset_password():
    if request.method == 'GET':
        return render_template('reset_password.html')

    token = request.form.get('token', '').strip()
    password = request.form.get('password', '')

    # checked before the token, so a typo in the password does not use up the token
    password_length = len(password.encode('utf-8'))
    if password_length < 8:
        return render_template('reset_password.html', error='Password must be at least 8 characters.'), 400
    # bytes not characters, because æ ø å are two bytes each and bcrypt refuses more than 72
    if password_length > 72:
        return render_template('reset_password.html', error='Password is too long.'), 400

    if not models.reset_password(token, password):
        # one message for unknown, expired and used, so the page does not say which
        return render_template('reset_password.html', error='That reset code is not valid or has expired.'), 401

    return redirect(url_for('auth.login'))


@auth.route('/api-tokens', methods=['GET', 'POST'])
@login_required
def api_tokens():
    if request.method == 'GET':
        return render_template('api_tokens.html', token_row=models.get_api_token(session['user_id']))

    # shown once here, the database only keeps the hash
    token = models.create_api_token(session['user_id'])
    return render_template('api_tokens.html', token_row=models.get_api_token(session['user_id']), new_token=token)


@auth.route('/api-tokens/revoke', methods=['POST'])
@login_required
def revoke_api_token():
    # the session decides whose token goes, so there is no id in the form to change
    models.delete_api_token(session['user_id'])
    return redirect(url_for('auth.api_tokens'))


# GET for now, becomes POST when CSRF protection goes in
@auth.route('/logout')
def logout():
    # clears the browser's copy only, a copied cookie stays valid until it expires
    session.clear()
    return redirect(url_for('auth.login'))
