from flask import Blueprint, render_template, request, redirect, url_for, session

from app import models
from app.controllers.auth import role_required, deny

notes = Blueprint('notes', __name__)

MAX_NOTE_LENGTH = 5000


@notes.route('/patients')
@role_required('clinician')
def patient_list():
    patients = models.get_patients_for_clinician(session['user_id'])
    return render_template('patients.html', patients=patients)


@notes.route('/patient/<int:patient_id>/notes', methods=['GET', 'POST'])
@role_required('clinician')
def patient_notes(patient_id):
    clinician_id = session['user_id']

    # before the form is read, so an empty note on someone else's patient is a 404 and not a 400
    patient = models.get_linked_patient(patient_id, clinician_id)
    if patient is None:
        deny(patient_id)

    if request.method == 'GET':
        return render_template('notes.html', patient=patient, notes=models.get_notes_for_clinician(patient_id, clinician_id))

    body = request.form.get('body', '').strip()

    error = None
    if not body:
        error = 'The note is empty.'
    elif len(body) > MAX_NOTE_LENGTH:
        error = 'The note can be at most %d characters.' % MAX_NOTE_LENGTH

    if error:
        return render_template('notes.html', patient=patient, notes=models.get_notes_for_clinician(patient_id, clinician_id),
                               error=error, body=body), 400

    # the insert checks the appointment again, in case it was removed after the check above
    if not models.create_note(patient_id, clinician_id, body):
        deny(patient_id)

    return redirect(url_for('notes.patient_notes', patient_id=patient_id))
