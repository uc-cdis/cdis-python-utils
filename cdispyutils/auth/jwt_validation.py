from collections import OrderedDict
import functools
import json

import flask
import jwt
import requests

from .errors import (
    JWTValidationError,
    JWTAudienceError,
)


def refresh_jwt_public_keys(user_api=None):
    """
    Update the public keys that the Flask app is currently using to validate
    JWTs.

    Response from ``/keys`` should look like this:

    .. code-block:: javascript

    {
        "keys": [
            [
                "key-id-01",
                "-----BEGIN PUBLIC KEY---- ... -----END PUBLIC KEY-----\n"
            ],
            [
                "key-id-02",
                "-----BEGIN PUBLIC KEY---- ... -----END PUBLIC KEY-----\n"
            ]
        ]
    }

    Take out the array of keys, put it in an ordered dictionary, and assign
    that to ``flask.current_app.jwt_public_keys``.

    Args:
        user_api (Optional[str]):
            the URL of the user API to get the keys from; default to whatever
            the flask app is configured to use

    Return:
        None

    Side Effects:
        - Reassign ``flask.current_app.jwt_public_keys`` to the keys obtained
          from ``get_jwt_public_keys``, as an OrderedDict.

    Raises:
        ValueError: if user_api is not provided or set in app config
    """
    user_api = user_api or flask.current_app.config.get('USER_API')
    if not user_api:
        raise ValueError('no URL provided for user API')
    path = '/'.join(path.strip('/') for path in [user_api, 'keys'])
    jwt_public_keys = requests.get(path).json()['keys']
    flask.current_app.logger.info(
        'refreshing public keys; updated to:\n'
        + json.dumps(jwt_public_keys, indent=4)
    )
    flask.current_app.jwt_public_keys = OrderedDict(jwt_public_keys)


def get_public_key_for_kid(kid):
    """
    Given a key id ``kid``, get the public key from the flask app belonging to
    this key id. The key id is allowed to be None, in which case, use the the
    first key in the OrderedDict.

    - If current flask app is not holding public keys (ordered dictionary) or
      key id is in token headers and the key id does not appear in those public
      keys, refresh the public keys by calling ``refresh_jwt_public_keys()``
    - If key id is provided in the token headers:
      - If key id does not appear in public keys, fail
      - Use public key with this key id
    - If key id is not provided:
      - Use first public key in the ordered dictionary

    Args:
        kid (Optional[str]): the key id; default to the first public key

    Return:
        str: the public key

    Side Effects:
        - From ``refresh_jwt_public_keys``: reassign
          ``flask.current_app.jwt_public_keys`` to the keys obtained from
          ``get_jwt_public_keys``.

    Raises:
        JWTValidationError:
            if the key id is provided and public key with that key id is found
    """
    need_refresh = (
        not hasattr(flask.current_app, 'jwt_public_keys')
        or (kid and kid not in flask.current_app.jwt_public_keys)
    )
    if need_refresh:
        # refresh_jwt_public_keys assigns to flask.current_app.jwt_public_keys
        refresh_jwt_public_keys()
    if kid:
        try:
            return flask.current_app.jwt_public_keys[kid]
        except KeyError:
            raise JWTValidationError('no key exists with this key id')
    else:
        # Grab the key from the first in the list of keys.
        return flask.current_app.jwt_public_keys.items()[0][1]


def validate_request_jwt(aud, request=None):
    """
    Verify the JWT authorization header from a Flask request.

    Pull the JWT out of the request header and pass this and the audiences to
    ``validate_jwt``, which actually handles the verification; this function
    just wraps with the request handling and public key retrieval from the
    flask app.

    Args:
        aud (Iterable[str]):
            iterable of audiences which the JWT must have, which is converted
            to a set; must be non-empty, since tokens issued by fence will
            contain at minimum either ``access`` or ``request`` in the
            audiences, and the validator must identify with at least one
            audience in the token
        request (Optional[flask.Request]):
            request containing JWT header to validate; default to
            ``flask.request``

    Return:
        dict: the validated JWT

    Raises:
        JWTValidationError:
            - if no audiences are provided in the ``aud`` set
            - from ``validate_jwt``, if any step of the validation fails
    """
    aud = set(aud)
    if not aud:
        raise JWTAudienceError('no audiences provided')
    request = request or flask.request
    try:
        encoded_token = request.headers['Authorization'].split(' ')[1]
    except KeyError:
        raise JWTValidationError('no authorization token provided')
    token_headers = jwt.get_unverified_header(encoded_token)
    public_key = get_public_key_for_kid(token_headers.get('kid'))
    return validate_jwt(encoded_token, public_key, aud)


def require_jwt(aud):
    """
    Define a decorator for utility which calls ``validate_request_jwt`` using
    the given audiences to require a JWT authorization header.

    Args:
        aud (Iterable[str]): audiences to require in the JWT

    Return:
        Callable[[Any], Any]: decorated function
    """
    def decorator(f):
        """
        Define the actual decorator, which takes the decorated function as an
        argument.

        Args:
            Callable[[Any], Any]: function to decorate

        Return:
            Callable[[Any], Any]: the same type as the function
        """
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            """Validate the JWT and call the actual function here."""
            validate_request_jwt(aud)
            return f(*args, **kwargs)
        return wrapper
    return decorator


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
        aud (set): non-empty set of audiences the JWT must satisfy

    Return:
        dict: the decoded and validated JWT

    Raises:
        JWTValidationError: if any step of the validation fails
    """
    # To satisfy PyJWT, since the token will contain an aud field, decode has
    # to be passed one of the audiences to check here (so PyJWT doesn't raise
    # an InvalidAudienceError). Per the JWT specification, if the token
    # contains an aud field, the validator MUST identify with one of the
    # audiences listed in that field. This implementation is more strict, and
    # allows the validator to demand multiple audiences which must all be
    # satisfied by the token (see below).
    aud = set(aud)
    random_aud = list(aud)[0]
    try:
        token = jwt.decode(
            encoded_token, key=public_key, algorithms=['RS256'],
            audience=random_aud
        )
    except jwt.InvalidAudienceError as e:
        raise JWTAudienceError(e)

    # PyJWT validates iat and exp fields (and aud...sort of); everything else
    # must happen here.

    # The audiences listed in the token must completely satisfy all the
    # required audiences provided. Note that this is stricter than the
    # specification suggested in RFC 7519.
    missing = aud - set(token['aud'])
    if missing:
        raise JWTAudienceError('missing audiences: ' + str(missing))

    return token
