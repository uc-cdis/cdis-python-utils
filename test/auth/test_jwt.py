import jwt
import pytest

from cdispyutils import auth


def test_valid_signature(encoded_jwt, public_key, default_audiences):
    """
    Do a basic test of the expected functionality with the sample payload in
    the fence README.
    """
    assert auth.validate_jwt(encoded_jwt, public_key, default_audiences)


def test_invalid_signature_rejected(
        encoded_jwt, different_public_key, default_audiences):
    """
    Test that ``validate_jwt`` rejects JWTs signed with a private key not
    corresponding to the public key it is given.
    """
    with pytest.raises(jwt.DecodeError):
        auth.validate_jwt(encoded_jwt, different_public_key, default_audiences)


def test_invalid_aud_rejected(encoded_jwt, public_key):
    """
    Test that if ``validate_jwt`` is passed values for ``aud`` which do not
    appear in the token, a ``JWTValidationError`` is raised.
    """
    with pytest.raises(jwt.InvalidAudienceError):
        auth.validate_jwt(encoded_jwt, public_key, {'not-in-aud'})
