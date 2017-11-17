from collections import OrderedDict
import json

import flask
import jwt
import requests

from .errors import JWTValidationError


def refresh_public_keys(user_api=None):
    """
    Update the public keys that the Flask app is currently using to validate
    JWTs.

    Response from ``/keys`` should look like this:

    .. code-block:: javascript

    {
        "keys": [
            [
                "default",
                "-----BEGIN PUBLIC KEY---- ... -----END PUBLIC KEY-----\n"
            ],
            [
                "key-id-for-some-other-key",
                "-----BEGIN PUBLIC KEY---- ... -----END PUBLIC KEY-----\n"
            ]
        ]
    }

    Take out the array of keys, put it in an ordered dictionary, and assign
    that to ``flask.current_app.public_keys``.

    Args:
        user_api (Optional[str]):
            the URL of the user API to get the keys from; default to whatever
            the flask app is configured to use

    Return:
        None

    Side Effects:
        - Reassign ``flask.current_app.public_keys`` to the keys obtained from
          ``get_public_keys``, as an OrderedDict.

    Raises:
        ValueError: if user_api is not provided or set in app config
    """
    user_api = user_api or flask.current_app.config.get('USER_API')
    if not user_api:
        raise ValueError('no URL provided for user API')
    public_keys = requests.get(user_api + 'keys').json()['keys']
    flask.current_app.logger.info(
        'refreshing public keys; updated to:\n'
        + json.dumps(public_keys, indent=4)
    )
    flask.current_app.public_keys = OrderedDict(public_keys)


def get_public_key_for_kid(kid):
    """
    Given a key id ``kid``, get the public key from the flask app belonging to
    this key id. The key id is allowed to be None, in which case, use the the
    first key in the OrderedDict.

    Args:
        kid (Optional[str]): the key id; default to the first public key

    Return:
        str: the public key

    Side Effects:
        - From ``refresh_public_keys``: reassign
          ``flask.current_app.public_keys`` to the keys obtained from
          ``get_public_keys``.

    Raises:
        JWTValidationError:
            if the key id is provided and public key with that key id is found
    """
    # If key id is provided in the token headers, look it up in the list of
    # public keys currently held by the Flask app, refreshing the list if
    # necessary, and insist that a key exist with the given id. Otherwise, the
    # token must validate using the first public key in the list.
    need_refresh = (
        not hasattr(flask.current_app, 'public_keys')
        or (kid and kid not in flask.current_app.public_keys)
    )
    if need_refresh:
        # refresh_public_keys assigns to flask.current_app.public_keys
        refresh_public_keys()
    if kid:
        try:
            return flask.current_app.public_keys['kid']
        except KeyError:
            raise JWTValidationError('no key exists with this key id')
    else:
        # Grab the key from the first in the list of keys.
        return flask.current_app.public_keys.items()[0][1]


def validate_request_jwt(request=None, aud=None):
    """
    Verify the JWT authorization header from a Flask request.

    Pull the JWT out of the request header and pass this and the audiences to
    ``validate_jwt``, which actually handles the verification; this function
    just wraps with the request handling and public key retrieval from the
    flask app.

    - If current flask app is not holding public keys (ordered dictionary) or
      key id is in token headers and the key id does not appear in those public
      keys, refresh the public keys by calling ``refresh_public_keys()``
    - If key id is provided in the token headers:
      - If key id does not appear in public keys, fail
      - Use public key with this key id
    - If key id is not provided:
      - Use first public key in the ordered dictionary

    Args:
        request (Optional[flask.Request]):
            request containing JWT header to validate; default to
            ``flask.request``
        aud (Optional[Iterable[str]]):
            iterable of audiences which the JWT must have, which is converted
            to a set; default to empty set (so audience check is NOT performed
            by default here)

    Return:
        dict: the validated JWT

    Raises:
        JWTValidationError:
            from ``validate_jwt``, if any step of the validation fails
    """
    request = request or flask.request
    aud = set(aud) if aud is not None else set()
    encoded_token = request.headers['Authorization'].split(' ')[1]
    token_headers = jwt.get_unverified_header(encoded_token)
    public_key = get_public_key_for_kid(token_headers.get('kid'))
    return validate_jwt(encoded_token, public_key, aud)


def validate_jwt(encoded_token, public_key, aud):
    """
    Validate the encoded JWT ``encoded_token``, which must satisfy the
    audiences ``aud``.

    - Decode JWT using public key; PyJWT will fail if iat or exp fields are
      invalid
    - Check audiences: token audiences must be a superset of required audiences
      (the ``aud`` argument); fail if not satisfied

    Args:
        encoded_token (str): encoded JWT
        public_key (str): public key to validate the JWT signature
        aud (set): set of audiences the JWT must satisfy

    Return:
        dict: the decoded and validated JWT

    Raises:
        JWTValidationError: if any step of the validation fails
    """
    token = jwt.decode(encoded_token, key=public_key, algorithms=['RS256'])

    # PyJWT validates iat and exp fields; everything else must happen here.

    if aud:
        # The audiences listed in the token must completely satisfy the
        # required audiences if they are provided.
        missing = aud - token['aud']
        if missing:
            raise JWTValidationError('missing audiences: ' + str(missing))

    return token
