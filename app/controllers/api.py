import functools
import logging

from flask import Blueprint, jsonify, request, g

from app import models
from app.controllers.notes import MAX_NOTE_LENGTH

api = Blueprint('api', __name__)

security_log = logging.getLogger('healthapp.security')


def api_key_required(role):
    def decorator(view):
        # lab_7 leaves @wraps out, and then a second route overwrites the first
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            # the header only, never the query string, or the token lands in server logs
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

            # g, the same way lab_4 carries the authenticated user
            g.user = user
            return view(*args, **kwargs)
        return wrapped
    return decorator


# the API never reads the session cookie, so another site cannot call it with the browser's login
@api.route('/api/patients')
@api_key_required('clinician')
def patient_list():
    patients = models.get_patients_for_clinician(g.user['id'])
    return jsonify({'patients': [{'id': p['id'], 'full_name': p['full_name']} for p in patients]})


@api.route('/api/patients/<int:patient_id>/notes')
@api_key_required('clinician')
def patient_notes(patient_id):
    if models.get_linked_patient(patient_id, g.user['id']) is None:
        return jsonify({'error': 'Not found'}), 404

    notes = models.get_notes_for_clinician(patient_id, g.user['id'])
    return jsonify({'notes': [dict(note) for note in notes]})


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
        return jsonify({'error': 'The note is empty.'}), 400

    body = body.strip()
    if not body:
        return jsonify({'error': 'The note is empty.'}), 400
    if len(body) > MAX_NOTE_LENGTH:
        return jsonify({'error': 'The note can be at most %d characters.' % MAX_NOTE_LENGTH}), 400

    # the insert checks the appointment again, in case it was removed after the check above
    if not models.create_note(patient_id, g.user['id'], body):
        return jsonify({'error': 'Not found'}), 404

    return jsonify({'message': 'Note created'}), 201
