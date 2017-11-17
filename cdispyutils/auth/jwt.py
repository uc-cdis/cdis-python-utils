from collections import OrderedDict

import flask
import jwt
import requests

from .errors import JWTValidationError


def get_public_keys(user_api=None):
    """
    Get the public keys from the '/keys' endpoint at the user API. If
    ``user_api`` is not provided, use the URL from the Flask app config.

    Args:
        user_api (str): the URL of the user API to get the keys from

    Return:
        List[Tuple[str, str]]: list of associations from key ids to public keys

    Raises:
        ValueError: if user_api is not provided or set in app config
    """
    user_api = user_api or flask.current_app.config.get('USER_API')
    if not user_api:
        raise ValueError('no URL provided for user API')
    return requests.get(user_api + 'keys').json()


def refresh_public_keys():
    """
    Update the public keys that the Flask app is currently using to validate
    JWTs.

    Return:
        None

    Side Effects:
        - Reassign ``flask.current_app.public_keys`` to the keys obtained from
          ``get_public_keys``.
    """
    flask.current_app.public_keys = OrderedDict(get_public_keys())


def validate_jwt(request=None, aud=None):
    """
    Verify the JWT authorization header from a Flask request.

    Behavior:
    - Get the JWT from the header
    - Get the public key for validation from the current Flask app

    Args:
        request (flask.Request): request containing JWT header to validate
        aud (List[str]): list of audiences which the JWT must have

    Return:
        dict: the validated JWT

    Raises:
        JWTValidationError: if any step of the validation fails
    """
    request = request or flask.request
    aud = set(aud) or set()
    encoded_token = request.headers['Authorization'].split(' ')[1]
    token_headers = jwt.get_unverified_header(encoded_token)
    kid = token_headers.get('kid')
    # If key id is provided in the token headers, look it up in the list of
    # public keys currently held by the Flask app, refreshing the list if
    # necessary, and insist that a key exist with the given id. Otherwise, the
    # token must validate using the first public key in the list.
    if kid:
        need_refresh = (
            not hasattr(flask.current_app, 'public_keys')
            or kid not in flask.current_app.public_keys
        )
        if need_refresh:
            refresh_public_keys()
        try:
            public_key = flask.current_app.public_keys['kid']
        except KeyError:
            raise JWTValidationError('no key exists with this key id')
    else:
        # Grab the key from the first in the list of keys.
        public_key = flask.current_app.public_keys.items()[0][1]
    token = jwt.decode(encoded_token, key=public_key, algorithms=['RS256'])

    # PyJWT validates iat and exp fields; everything else must happen here.

    # Token must be for access, i.e. have 'access' in audience field.
    if 'access' not in token['aud']:
        raise JWTValidationError('not access token')

    if aud:
        # The audiences listed in the token must completely satisfy the
        # required audiences if they are provided.
        missing = aud - token['aud']
        if missing:
            raise JWTValidationError('missing audiences: ' + str(missing))

    return token
