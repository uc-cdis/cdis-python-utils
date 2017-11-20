from datetime import datetime, timedelta
import os
import uuid

import jwt
import pytest


@pytest.fixture(scope='session')
def default_audiences():
    """
    Return some default audiences to put in the claims of a JWT.
    """
    return ['access', 'user']


@pytest.fixture(scope='session')
def claims(default_audiences):
    """
    Return some generic claims to put in a JWT.

    Return:
        dict: dictionary of claims
    """
    now = datetime.now()
    iat = int(now.strftime('%s'))
    exp = int((now + timedelta(seconds=60)).strftime('%s'))
    return {
        'aud': default_audiences,
        'sub': '1234',
        'iss': 'https://api.test.net',
        'iat': iat,
        'exp': exp,
        'jti': str(uuid.uuid4()),
        'context': {
            'user': {
                'name': 'test-user',
                'projects': [
                ],
            },
        },
    }


@pytest.fixture
def encoded_jwt(claims, private_key):
    """
    Return an example JWT containing the claims and encoded with the private
    key.

    Args:
        claims (dict): fixture
        private_key (str): fixture

    Return:
        str: JWT containing claims encoded with private key
    """
    return jwt.encode(claims, key=private_key, algorithm='RS256')


@pytest.fixture(scope='session')
def example_keys_endpoint_response(public_key, different_public_key):
    """
    Return an example response JSON returned from the ``/keys`` endpoint in
    fence.

    Args:
        public_key (str): fixture
        different_public_key (str): fixture

    Return:
        TODO
    """
    return {"keys": [["key-01", public_key], ["key-02", different_public_key]]}


@pytest.fixture(scope='session')
def public_key():
    """
    Return a public key for testing.
    """
    os.path.dirname(os.path.realpath(__file__))
    here = os.path.dirname(os.path.realpath(__file__))
    with open(os.path.join(here, 'test_public_key.pem')) as f:
        return f.read()


@pytest.fixture(scope='session')
def different_public_key():
    """
    Return a public key for testing that doesn't form a correct keypair with
    ``private_key``.
    """
    os.path.dirname(os.path.realpath(__file__))
    here = os.path.dirname(os.path.realpath(__file__))
    with open(os.path.join(here, 'test_public_key_2.pem')) as f:
        return f.read()


@pytest.fixture(scope='session')
def private_key():
    """
    Return a private key for testing. (Use only a private key that is
    specifically set aside for testing, and never actually used for auth.)
    """
    os.path.dirname(os.path.realpath(__file__))
    here = os.path.dirname(os.path.realpath(__file__))
    with open(os.path.join(here, 'test_private_key.pem')) as f:
        return f.read()


@pytest.fixture
def patch_fence_keys_endpoint(monkeypatch):
    """
    Provide a function to patch the value of the JSON returned by the ``/keys``
    endpoint in fence.

    (NOTE that this only patches what will return from ``requests.get`` so if
    the implementation of ``refresh_jwt_public_keys`` is changed to use a
    different method to access the fence endpoint, this should be updated.)

    Args:
        monkeypatch (pytest.monkeypatch.MonkeyPatch): fixture

    Return:
        Calllable[dict, None]: function which sets the /keys reponse JSON
    """
    def do_patch(keys_response_json):
        """
        Args:
            keys_response (dict): value to set /keys return value to

        Return:
            None

        Side Effects:
            Patch the /keys endpoint.
        """

        monkeypatch.setattr(
            'requests.Response.json',
            lambda: keys_response_json
        )
    return do_patch
