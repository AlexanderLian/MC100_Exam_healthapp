import re
import sqlite3

from flask import Blueprint, render_template, request, redirect, url_for, session

from app import models

auth = Blueprint('auth', __name__)


@auth.route('/register', methods=['GET', 'POST'])
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
    elif password_length < 8 or password_length > 72:
        error = 'Password must be between 8 and 72 bytes.'
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
def login():
    if request.method == 'GET':
        return render_template('login.html')

    email = request.form.get('email', '')
    password = request.form.get('password', '')

    user = models.verify_login(email, password)
    if user is None:
        # one message for both failures, so login never says which emails exist
        return render_template('login.html', error='Wrong email or password.', email=email), 401

    # start from an empty session so nothing from before login carries over
    session.clear()
    session.permanent = True
    session['user_id'] = user['id']
    session['role'] = user['role']
    return redirect(url_for('index'))


# GET for now, becomes POST when CSRF protection goes in
@auth.route('/logout')
def logout():
    # clears the browser's copy only, a copied cookie stays valid until it expires
    session.clear()
    return redirect(url_for('auth.login'))
