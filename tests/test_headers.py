import io

from app import models

CSP = "default-src 'self'; frame-ancestors 'none'"


def header(response, name):
    return response.status_code, response.headers.get(name)


def test_pages_forbid_being_framed(client):
    assert header(client.get('/login'), 'X-Frame-Options') == (200, 'DENY')


def test_pages_forbid_type_sniffing(client):
    assert header(client.get('/login'), 'X-Content-Type-Options') == (200, 'nosniff')


def test_csp_only_allows_own_site(client):
    assert header(client.get('/login'), 'Content-Security-Policy') == (200, CSP)


def test_referrer_is_not_sent(client):
    assert header(client.get('/login'), 'Referrer-Policy') == (200, 'no-referrer')


def test_pages_are_not_cached_but_the_stylesheet_is(client, login):
    login('patient1')
    token_page = client.post('/api-tokens')
    stylesheet = client.get('/static/style.css')
    stylesheet_is_no_store = 'no-store' in stylesheet.headers.get('Cache-Control', '')
    # the token page holds the full token, the stylesheet holds nothing private
    assert (header(token_page, 'Cache-Control'), stylesheet_is_no_store) == ((200, 'no-store'), False)


def test_downloads_also_get_headers(client, login):
    login('patient1')
    client.post('/documents', data={'document': (io.BytesIO(b'<script>alert(1)</script>'), 'note.txt')},
                content_type='multipart/form-data')
    conn = models.get_connection()
    document_id = conn.execute('SELECT id FROM documents').fetchone()['id']
    conn.close()
    download = client.get('/documents/%d' % document_id)
    assert (download.status_code, download.headers.get('X-Content-Type-Options'),
            download.headers.get('Content-Security-Policy')) == (200, 'nosniff', CSP)


def test_api_responses_also_get_headers(client):
    response = client.get('/api/patients')
    assert (response.status_code, response.headers.get('X-Frame-Options'),
            response.headers.get('X-Content-Type-Options')) == (401, 'DENY', 'nosniff')
