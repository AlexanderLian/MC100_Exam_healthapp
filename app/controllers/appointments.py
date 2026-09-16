from flask import Blueprint, render_template, request, redirect, url_for, session

from app import models
from app.controllers.auth import role_required

appointments = Blueprint('appointments', __name__)


# the same three lookups are needed for the form and for every refusal
def booking_page(error=None):
    return render_template('book.html',
                           clinicians=models.get_clinicians(),
                           slots=models.available_slots(),
                           appointments=models.get_appointments_for_patient(session['user_id']),
                           error=error)


@appointments.route('/book', methods=['GET', 'POST'])
@role_required('patient')
def book():
    if request.method == 'GET':
        return booking_page()

    clinician = models.get_clinician(request.form.get('clinician_id', ''))
    slot_start = request.form.get('slot_start', '')

    if clinician is None:
        return booking_page('Choose a clinician from the list.'), 400
    # checked against the list the page offers, so a typed time or a past time is refused
    if slot_start not in models.available_slots():
        return booking_page('Choose a time from the list.'), 400

    try:
        # the patient comes from the session, never the form, or a patient could book for someone else
        models.book_appointment(session['user_id'], clinician['id'], slot_start)
    except models.ClinicianUnavailableError:
        return booking_page('That time is already taken. Pick another one.'), 409

    return redirect(url_for('appointments.book'))
