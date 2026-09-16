-- HealthApp - database schema
-- SQLite. Run by models.init_db() on first start.
--
-- SQLite over PostgreSQL: the file is created on first run, so the app works
-- on the examiner's machine with no server or connection string. Cost: SQLite
-- has no database roles, so the app process can reach every table. Recorded
-- in known limitations.
--
-- All timestamps are TEXT in UTC, written as 'YYYY-MM-DD HH:MM:SS' by
-- models.now(). Never datetime.isoformat() - the 'T' separator sorts above a
-- space, so a mixed-format expires_at compares wrong and an expired token
-- would validate.

-- Per-connection, not stored in the file. models.get_connection() sets it on
-- every connection.
PRAGMA foreign_keys = ON;


-- One table for all three roles. Role is assigned server-side at
-- registration; a role field in the request body is ignored.
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL CHECK (role IN ('patient', 'clinician', 'admin')),
    full_name     TEXT    NOT NULL,
    -- Fodselsnummer, patients only. Stored to verify identity, never used as
    -- a lookup key (personopplysningsloven section 12).
    national_id   TEXT    UNIQUE,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);


-- Booking is what grants a clinician access to a patient's record, so this
-- table is the access control, not just a calendar. patient_id comes from the
-- session, never from the form.
CREATE TABLE IF NOT EXISTS appointments (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id   INTEGER NOT NULL REFERENCES users(id),
    clinician_id INTEGER NOT NULL REFERENCES users(id),
    slot_start   TEXT    NOT NULL,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    -- Double booking is blocked by the engine, not by application logic.
    UNIQUE (clinician_id, slot_start)
);


-- Article 9 health data. A clinician may read a row only if an appointment
-- links them to that patient. Stored in plaintext: the key would sit on the
-- same host, so encryption here would only defend against disk theft.
-- Declared as a known limitation rather than half-implemented.
CREATE TABLE IF NOT EXISTS notes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id   INTEGER NOT NULL REFERENCES users(id),
    clinician_id INTEGER NOT NULL REFERENCES users(id),
    body         TEXT    NOT NULL,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);


-- Metadata only. The bytes live in uploads/ under stored_name, which is
-- secrets.token_hex(16) plus a validated extension - that one control answers
-- path traversal, collisions, double extensions and null bytes. original_name
-- is a display label and never touches a path.
CREATE TABLE IF NOT EXISTS documents (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id      INTEGER NOT NULL REFERENCES users(id),
    stored_name   TEXT    NOT NULL UNIQUE,
    original_name TEXT    NOT NULL,
    size_bytes    INTEGER NOT NULL,
    uploaded_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);


-- Time-limited, single-use, bound to one user. Only the hash is stored, so a
-- database leak does not hand out working reset links. A reset sets used_at
-- on its own row and deletes the user's other unused rows.
CREATE TABLE IF NOT EXISTS reset_tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    token_hash TEXT    NOT NULL UNIQUE,
    expires_at TEXT    NOT NULL,
    used_at    TEXT
);


CREATE INDEX IF NOT EXISTS idx_appointments_pair ON appointments (clinician_id, patient_id);
CREATE INDEX IF NOT EXISTS idx_notes_patient     ON notes (patient_id);
CREATE INDEX IF NOT EXISTS idx_documents_owner   ON documents (owner_id);