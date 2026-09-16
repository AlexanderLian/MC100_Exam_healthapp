from flask import session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# one count per address for the whole app, not one per page
limiter = Limiter(get_remote_address, application_limits=['200 per minute'], storage_uri='memory://')


# the assistant costs money per question, so the limit follows the account and not the cookie
def account_key():
    return 'user-%s' % session.get('user_id')
