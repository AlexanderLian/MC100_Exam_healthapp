import hashlib
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

import bcrypt

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE = os.path.join(BASE_DIR, 'healthapp.db')
SCHEMA = os.path.join(BASE_DIR, 'schema.sql')

# 12 rounds is about a quarter second per hash, slow on purpose so guessing is expensive
BCRYPT_ROUNDS = 12

SLOT_TIMES = ('09:00:00', '13:00:00')

# lab_3's own list. The folder is under the app, not a path from one machine
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')


# the course example raises DoctorUnavailableError, same idea with our names
class ClinicianUnavailableError(Exception):
    pass

# checked against when the email is unknown, so a missing account takes as long as a wrong password
DUMMY_HASH = bcrypt.hashpw(b'no such user', bcrypt.gensalt(rounds=BCRYPT_ROUNDS))


# not isoformat, its 'T' sorts above a space and breaks expires_at comparisons
def now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


def get_connection():
    conn = sqlite3.connect(DATABASE)
    # foreign keys are off by default and the setting is not saved in the file
    conn.execute('PRAGMA foreign_keys = ON')
    conn.row_factory = sqlite3.Row
    return conn


# lab_3 makes the folder at startup too, so a fresh copy of the app has somewhere to write
def init_uploads():
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)


def init_db():
    # check before connecting, because connecting creates the file
    if os.path.exists(DATABASE):
        return

    with open(SCHEMA, encoding='utf-8') as f:
        schema = f.read()

    conn = get_connection()
    try:
        conn.executescript(schema)
        conn.close()
        seed()
    except Exception:
        # Windows will not delete a file that is still open
        conn.close()
        # a half-built file would be skipped on the next start and never seeded
        if os.path.exists(DATABASE):
            os.remove(DATABASE)
        raise


# role is a parameter the calling code sets, never a field read from the request
def create_user(email, password, role, full_name, national_id=None):
    email = email.strip().lower()
    # the salt is random per user, so two identical passwords hash differently
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=BCRYPT_ROUNDS))

    conn = get_connection()
    # without finally, a failed insert leaves the connection open and the database locked
    try:
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO users (email, password_hash, role, full_name, national_id) VALUES (?, ?, ?, ?, ?)',
            (email, password_hash.decode('utf-8'), role, full_name, national_id)
        )
        conn.commit()
        user_id = cursor.lastrowid
    finally:
        conn.close()
    return user_id


def get_user_by_email(email):
    email = email.strip().lower()
    conn = get_connection()
    cursor = conn.cursor()
    # named columns, so the national id is not pulled into every login
    cursor.execute('SELECT id, email, password_hash, role FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    return user


def verify_login(email, password):
    password_bytes = password.encode('utf-8')
    # bcrypt 5 raises above 72 bytes, which should be a failed login and not a crash
    if len(password_bytes) > 72:
        return None

    user = get_user_by_email(email)
    if user is None:
        bcrypt.checkpw(password_bytes, DUMMY_HASH)
        return None

    if bcrypt.checkpw(password_bytes, user['password_hash'].encode('utf-8')):
        return user
    return None


# sha256 is enough here, the token is 32 random bytes so there is nothing to guess
def hash_token(token):
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


# secrets not random, a token anyone can guess is not a token
def generate_token():
    return secrets.token_hex(32)


# returns None for an unknown email, the route shows the same page either way
def create_reset_token(email):
    user = get_user_by_email(email)
    if user is None:
        return None

    token = generate_token()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        # datetime() gives the same text format as now(), so expires_at compares right
        cursor.execute(
            "INSERT INTO reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, datetime(?, '+30 minutes'))",
            (user['id'], hash_token(token), now())
        )
        conn.commit()
    finally:
        conn.close()
    return token


def reset_password(token, new_password):
    token_hash = hash_token(token)
    # bcrypt is slow, so hash first and keep the database lock short
    password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt(rounds=BCRYPT_ROUNDS))
    current_time = now()

    conn = get_connection()
    try:
        cursor = conn.cursor()
        # check and claim in one statement, so two requests cannot both use the same token
        cursor.execute(
            'UPDATE reset_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?',
            (current_time, token_hash, current_time)
        )
        if cursor.rowcount != 1:
            return False

        # the user id comes from the token row, the form never says who to reset
        cursor.execute('SELECT user_id FROM reset_tokens WHERE token_hash = ?', (token_hash,))
        user_id = cursor.fetchone()['user_id']

        cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (password_hash.decode('utf-8'), user_id))
        # the used row has to stay, or used_at stops blocking reuse
        cursor.execute('DELETE FROM reset_tokens WHERE user_id = ? AND used_at IS NULL', (user_id,))
        conn.commit()
    finally:
        conn.close()
    return True


# one row per user, so a new token replaces the old one (Assignment 2 does the same)
def create_api_token(user_id):
    token = generate_token()
    conn = get_connection()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO api_tokens (user_id, token_hash, token_prefix, expires_at)"
            " VALUES (?, ?, ?, datetime(?, '+30 days'))",
            (user_id, hash_token(token), token[:4], now())
        )
        conn.commit()
    finally:
        conn.close()
    return token


# the prefix and the dates only, the page has nothing to leak
def get_api_token(user_id):
    conn = get_connection()
    row = conn.execute('SELECT token_prefix, created_at, expires_at FROM api_tokens WHERE user_id = ?', (user_id,)).fetchone()
    conn.close()
    return row


def delete_api_token(user_id):
    conn = get_connection()
    try:
        conn.execute('DELETE FROM api_tokens WHERE user_id = ?', (user_id,))
        conn.commit()
    finally:
        conn.close()


# the expiry is part of the lookup, so an old token finds no user at all
def get_user_by_api_token(token):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT u.id, u.email, u.role FROM users u
          JOIN api_tokens t ON t.user_id = u.id
         WHERE t.token_hash = ? AND t.expires_at > ?
    ''', (hash_token(token), now()))
    user = cursor.fetchone()
    conn.close()
    return user


# the page offers this list and the booking checks against the same one, so nothing typed gets through
def available_slots():
    today = datetime.now(timezone.utc).date()
    slots = []
    # from tomorrow, which also keeps every offered slot in the future
    for day in range(1, 8):
        date = (today + timedelta(days=day)).strftime('%Y-%m-%d')
        for slot_time in SLOT_TIMES:
            slots.append('%s %s' % (date, slot_time))
    return slots


def get_clinicians():
    conn = get_connection()
    clinicians = conn.execute("SELECT id, full_name FROM users WHERE role = 'clinician' ORDER BY full_name").fetchall()
    conn.close()
    return clinicians


# None for any id that is not a clinician, so a patient id in the form books nothing
def get_clinician(clinician_id):
    conn = get_connection()
    row = conn.execute("SELECT id, full_name FROM users WHERE id = ? AND role = 'clinician'", (clinician_id,)).fetchone()
    conn.close()
    return row


def get_appointments_for_patient(patient_id):
    conn = get_connection()
    appointments = conn.execute('''
        SELECT ap.slot_start, u.full_name FROM appointments ap
          JOIN users u ON u.id = ap.clinician_id
         WHERE ap.patient_id = ?
         ORDER BY ap.slot_start
    ''', (patient_id,)).fetchall()
    conn.close()
    return appointments


def book_appointment(patient_id, clinician_id, slot_start):
    conn = get_connection()
    try:
        conn.execute('INSERT INTO appointments (patient_id, clinician_id, slot_start) VALUES (?, ?, ?)',
                     (patient_id, clinician_id, slot_start))
        conn.commit()
    except sqlite3.IntegrityError:
        # UNIQUE (clinician_id, slot_start) refuses it, so two requests at once cannot both get the slot
        raise ClinicianUnavailableError()
    finally:
        conn.close()


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# a random name plus the extension allowed_file() just approved, so nothing typed reaches a path
def stored_name_for(filename):
    return '%s.%s' % (secrets.token_hex(16), filename.rsplit('.', 1)[1].lower())


def create_document(owner_id, stored_name, original_name, size_bytes):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO documents (owner_id, stored_name, original_name, size_bytes) VALUES (?, ?, ?, ?)',
                       (owner_id, stored_name, original_name, size_bytes))
        conn.commit()
        document_id = cursor.lastrowid
    finally:
        conn.close()
    return document_id


def get_documents_for_owner(owner_id):
    conn = get_connection()
    documents = conn.execute('''
        SELECT id, original_name, size_bytes, uploaded_at FROM documents
         WHERE owner_id = ?
         ORDER BY uploaded_at DESC, id DESC
    ''', (owner_id,)).fetchall()
    conn.close()
    return documents


# the same appointment rule as the notes, inside the query
def get_documents_for_patient(patient_id, clinician_id):
    conn = get_connection()
    documents = conn.execute('''
        SELECT d.id, d.original_name, d.size_bytes, d.uploaded_at FROM documents d
         WHERE d.owner_id = ?
           AND EXISTS (SELECT 1 FROM appointments ap
                        WHERE ap.patient_id = d.owner_id AND ap.clinician_id = ?)
         ORDER BY d.uploaded_at DESC, d.id DESC
    ''', (patient_id, clinician_id)).fetchall()
    conn.close()
    return documents


# one query for both roles, so no route can forget half of the rule
def get_document_for_user(document_id, user_id, role):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT d.stored_name, d.original_name FROM documents d
         WHERE d.id = ?
           AND (
                (? = 'patient' AND d.owner_id = ?)
                OR
                (? = 'clinician' AND EXISTS (SELECT 1 FROM appointments ap
                                              WHERE ap.patient_id = d.owner_id AND ap.clinician_id = ?))
               )
    ''', (document_id, role, user_id, role, user_id))
    document = cursor.fetchone()
    conn.close()
    return document


def get_patients_for_clinician(clinician_id):
    conn = get_connection()
    cursor = conn.cursor()
    # DISTINCT, because a patient with two appointments would otherwise be listed twice
    cursor.execute('''
        SELECT DISTINCT u.id, u.full_name FROM users u
          JOIN appointments ap ON ap.patient_id = u.id
         WHERE ap.clinician_id = ?
         ORDER BY u.full_name
    ''', (clinician_id,))
    patients = cursor.fetchall()
    conn.close()
    return patients


# None means no appointment links them, and the route cannot tell that apart from no such patient
def get_linked_patient(patient_id, clinician_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT u.id, u.full_name FROM users u
         WHERE u.id = ? AND u.role = 'patient'
           AND EXISTS (SELECT 1 FROM appointments ap
                        WHERE ap.patient_id = u.id AND ap.clinician_id = ?)
    ''', (patient_id, clinician_id))
    patient = cursor.fetchone()
    conn.close()
    return patient


# takes the clinician's id, so no code path reads a note without an identity
def get_notes_for_clinician(patient_id, clinician_id):
    conn = get_connection()
    cursor = conn.cursor()
    # EXISTS not JOIN, because a JOIN returns every note once per appointment
    cursor.execute('''
        SELECT n.id, n.body, n.created_at, author.full_name AS author_name FROM notes n
          JOIN users author ON author.id = n.clinician_id
         WHERE n.patient_id = ?
           AND EXISTS (SELECT 1 FROM appointments ap
                        WHERE ap.patient_id = n.patient_id AND ap.clinician_id = ?)
         ORDER BY n.created_at DESC, n.id DESC
    ''', (patient_id, clinician_id))
    notes = cursor.fetchall()
    conn.close()
    return notes


# check and write in one statement, so an appointment cannot disappear between them
def create_note(patient_id, clinician_id, body):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO notes (patient_id, clinician_id, body)
            SELECT ?, ?, ?
             WHERE EXISTS (SELECT 1 FROM appointments
                            WHERE patient_id = ? AND clinician_id = ?)
        ''', (patient_id, clinician_id, body, patient_id, clinician_id))
        conn.commit()
        written = cursor.rowcount == 1
    finally:
        conn.close()
    return written


# replaces admin account management, no graded task needs user CRUD routes
def seed():
    password = os.environ.get('SEED_PASSWORD')
    if not password:
        raise RuntimeError('SEED_PASSWORD is not set, add it to .env before the first start')
    # same 8 to 72 byte rule as /register, or the seed accounts get weaker passwords than patients
    password_length = len(password.encode('utf-8'))
    if password_length < 8 or password_length > 72:
        raise RuntimeError('SEED_PASSWORD must be between 8 and 72 bytes')

    # .test is a reserved domain, so these addresses can never belong to anyone
    create_user('admin@healthapp.test', password, 'admin', 'Ada Admin')
    clinician_id = create_user('clinician1@healthapp.test', password, 'clinician', 'Kari Lege')
    create_user('clinician2@healthapp.test', password, 'clinician', 'Ola Lege')

    # obviously fake national ids that cannot pass for a real fodselsnummer
    patient_id = create_user('patient1@healthapp.test', password, 'patient', 'Per Pasient', '00000000001')
    create_user('patient2@healthapp.test', password, 'patient', 'Pia Pasient', '00000000002')

    # only clinician1 and patient1 are linked, so every other clinician and patient pair is refused
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO appointments (patient_id, clinician_id, slot_start) VALUES (?, ?, ?)',
            (patient_id, clinician_id, '2026-10-01 09:00:00')
        )
        conn.commit()
    finally:
        conn.close()
