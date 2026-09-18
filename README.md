# HealthApp

A clinic portal for patients, clinicians and administrators. Python 3.12, Flask, SQLite, MVC.

## 1. Set up

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
```

Open `.env` and set:

- `SECRET_KEY` — generate one and paste it:
  ```powershell
  python -c "import secrets; print(secrets.token_hex(32))"
  ```
- `SEED_PASSWORD` — pick any password (8 to 72 characters). It becomes the login password for all the test accounts below.
- `OPENROUTER_API_KEY` — optional, only the assistant uses it. Leave blank to skip that one feature.

## 2. Run

```powershell
python app.py
```

Open http://127.0.0.1:5000. The database is created and the test accounts are added on the first start.
(Use `python app.py`, not `flask run`.)

## 3. Test accounts

All log in with the `SEED_PASSWORD` you chose in step 1.

| Email | Role | Notes |
|---|---|---|
| `patient1@healthapp.test` | Patient | has an appointment with clinician1 |
| `patient2@healthapp.test` | Patient | |
| `clinician1@healthapp.test` | Clinician | can see patient1 |
| `clinician2@healthapp.test` | Clinician | no patients |
| `admin@healthapp.test` | Administrator | no access to clinical data |

New patients can also self-register at `/register`.

## 4. Run the automated tests

```powershell
pytest
```

## 5. Try the features by hand

- **Patient** — log in as `patient1`, book an appointment, and upload a document under Documents.
- **Clinician** — log in as `clinician1`, open Patients, then read and write patient1's journal notes.
- **Admin** — log in as `admin` and confirm the clinical pages are not reachable.
- **Password reset** — on the login page click "Forgot password?", enter `patient1`'s email, copy the `RESET TOKEN` line printed in the terminal, and set a new password.
- **API** — log in, open "API token", generate one, then call the API with it:
  ```powershell
  curl.exe -H "X-API-Key: PASTE_TOKEN" http://127.0.0.1:5000/api/appointments
  ```
- **Assistant** (optional, needs `OPENROUTER_API_KEY`) — log in, open Assistant, and ask a general question.
