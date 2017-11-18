from datetime import datetime, timedelta
import os
import uuid

import jwt
import pytest

from cdispyutils import auth


@pytest.fixture(scope='session')
def claims():
    """
    Return some generic claims to put in a JWT.

    Return:
        dict: dictionary of claims
    """
    now = datetime.now()
    iat = int(now.strftime('%s'))
    exp = int((now + timedelta(seconds=60)).strftime('%s'))
    return {
        'aud': ['access', 'user'],
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
def public_key():
    """
    Return a public key for testing.
    """
    os.path.dirname(os.path.realpath(__file__))
    here = os.path.dirname(os.path.realpath(__file__))
    with open(os.path.join(here, 'test_public_key.pem')) as f:
        return f.read()


@pytest.fixture(scope='session')
def wrong_public_key():
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


def test_valid_signature(encoded_jwt, public_key):
    """
    Do a basic test of the expected functionality with the sample payload in
    the fence README.
    """
    assert auth.validate_jwt(encoded_jwt, public_key, {'access', 'user'})


def test_invalid_signature_rejected(encoded_jwt, wrong_public_key):
    """
    Test that ``validate_jwt`` rejects JWTs signed with a private key not
    corresponding to the public key it is given.
    """
    with pytest.raises(jwt.DecodeError):
        auth.validate_jwt(encoded_jwt, wrong_public_key, {'access'})


def test_invalid_aud_rejected(encoded_jwt, public_key):
    """
    Test that if ``validate_jwt`` is passed values for ``aud`` which do not
    appear in the token, a ``JWTValidationError`` is raised.
    """
    with pytest.raises(jwt.InvalidAudienceError):
        auth.validate_jwt(encoded_jwt, public_key, {'not-in-aud'})
