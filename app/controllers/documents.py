import os

from flask import Blueprint, render_template, request, redirect, url_for, session, send_from_directory
from werkzeug.utils import secure_filename

from app import models
from app.controllers.auth import login_required, role_required, deny

documents = Blueprint('documents', __name__)


def documents_page(error=None):
    return render_template('documents.html', documents=models.get_documents_for_owner(session['user_id']), error=error)


@documents.route('/documents', methods=['GET', 'POST'])
@role_required('patient')
def document_list():
    if request.method == 'GET':
        return documents_page()

    if 'document' not in request.files or request.files['document'].filename == '':
        return documents_page('Choose a file.'), 400

    upload = request.files['document']
    if not models.allowed_file(upload.filename):
        return documents_page('Allowed types: %s.' % ', '.join(sorted(models.ALLOWED_EXTENSIONS))), 400

    stored_name = models.stored_name_for(upload.filename)
    path = os.path.join(models.UPLOAD_FOLDER, stored_name)
    upload.save(path)

    # the user's name is a label only. secure_filename can strip it to nothing, then the random name is shown
    original_name = secure_filename(upload.filename) or stored_name
    models.create_document(session['user_id'], stored_name, original_name, os.path.getsize(path))
    return redirect(url_for('documents.document_list'))


@documents.route('/documents/<int:document_id>')
@login_required
def download(document_id):
    # the rule lives in the query, so an owner check cannot be forgotten here
    document = models.get_document_for_user(document_id, session['user_id'], session['role'])
    if document is None:
        deny()

    # as_attachment, so a file is never rendered in the browser on our own origin
    return send_from_directory(models.UPLOAD_FOLDER, document['stored_name'],
                               as_attachment=True, download_name=document['original_name'])
