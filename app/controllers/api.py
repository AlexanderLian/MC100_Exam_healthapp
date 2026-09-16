import functools
import logging

from flask import Blueprint, jsonify, request, g

from app import models
from app.controllers.notes import MAX_NOTE_LENGTH
from app.limiter import limiter

api = Blueprint('api', __name__)
# one count for the whole api, so a stolen token cannot get 60 calls on every endpoint
limiter.shared_limit('60 per minute', scope='api')(api)

security_log = logging.getLogger('healthapp.security')


def api_key_required(role):
    def decorator(view):
        # without wraps every route is named 'wrapped' and Flask refuses the second one
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            # header only. A cookie would let another site call this, and a query
            # string would put the token in server logs
            token = request.headers.get('X-API-Key', '')
            user = models.get_user_by_api_token(token) if token else None
            if user is None:
                # no token value in the log, it would still work for 30 days
                security_log.warning('api token rejected route=%s %s', request.method, request.path)
                return jsonify({'error': 'Authentication failed'}), 401

            # exact match, admin is a separate set of permissions and not a higher one
            if user['role'] != role:
                security_log.warning('access denied user_id=%s role=%s route=%s %s patient_id=%s',
                                     user['id'], user['role'], request.method, request.path, kwargs.get('patient_id'))
                return jsonify({'error': 'Not found'}), 404

            g.user = user
            return view(*args, **kwargs)
        return wrapped
    return decorator


@api.route('/api/patients')
@api_key_required('clinician')
def patient_list():
    patients = models.get_patients_for_clinician(g.user['id'])
    return jsonify({'patients': [{'id': p['id'], 'full_name': p['full_name']} for p in patients]})


@api.route('/api/appointments')
@api_key_required('patient')
def own_appointments():
    # the patient comes from the token, so there is no id in the request to change
    appointments = models.get_appointments_for_patient(g.user['id'])
    # named fields, so a column added to the query later is not published by accident
    return jsonify({'appointments': [{'slot_start': a['slot_start'], 'clinician': a['full_name']}
                                     for a in appointments]})


@api.route('/api/patients/<int:patient_id>/notes')
@api_key_required('clinician')
def patient_notes(patient_id):
    if models.get_linked_patient(patient_id, g.user['id']) is None:
        return jsonify({'error': 'Not found'}), 404

    notes = models.get_notes_for_clinician(patient_id, g.user['id'])
    return jsonify({'notes': [{'id': n['id'], 'body': n['body'], 'created_at': n['created_at'],
                               'author_name': n['author_name']} for n in notes]})


@api.route('/api/patients/<int:patient_id>/notes', methods=['POST'])
@api_key_required('clinician')
def create_patient_note(patient_id):
    # before the body is read, so an empty note for someone else's patient is a 404 and not a 400
    if models.get_linked_patient(patient_id, g.user['id']) is None:
        return jsonify({'error': 'Not found'}), 404

    data = request.get_json(silent=True) or {}
    body = data.get('body')

    # a number or a list would crash .strip(), and a bad request should answer 400 and not 500
    if not isinstance(body, str):
        return jsonify({'error': 'The note must be text.'}), 400

    body = body.strip()
    if not body:
        return jsonify({'error': 'The note is empty.'}), 400
    if len(body) > MAX_NOTE_LENGTH:
        return jsonify({'error': 'The note can be at most %d characters.' % MAX_NOTE_LENGTH}), 400

    # the insert checks the appointment again, in case it was removed after the check above
    if not models.create_note(patient_id, g.user['id'], body):
        return jsonify({'error': 'Not found'}), 404

    return jsonify({'message': 'Note created'}), 201
