# pylint: disable=unused-argument

from collections import OrderedDict

import jwt
import flask
import pytest
import requests

from cdispyutils.auth.errors import JWTValidationError, JWTAudienceError
from cdispyutils.auth.jwt_validation import (
    get_public_key_for_kid,
    require_jwt,
    validate_jwt,
)

from .conftest import TEST_RESPONSE_JSON


def test_valid_signature(claims, encoded_jwt, public_key, default_audiences, iss):
    """
    Do a basic test of the expected functionality with the sample payload in
    the fence README.
    """
    decoded_token = validate_jwt(encoded_jwt, public_key, default_audiences, iss)
    assert decoded_token
    assert decoded_token == claims


def test_invalid_signature_rejected(
    encoded_jwt, different_public_key, default_audiences, iss
):
    """
    Test that ``validate_jwt`` rejects JWTs signed with a private key not
    corresponding to the public key it is given.
    """
    with pytest.raises(JWTValidationError):
        validate_jwt(encoded_jwt, different_public_key, default_audiences, iss)


def test_invalid_aud_rejected(encoded_jwt, public_key, iss):
    """
    Test that if ``validate_jwt`` is passed values for ``aud`` which do not
    appear in the token, a ``JWTAudienceError`` is raised.
    """
    with pytest.raises(JWTValidationError):
        validate_jwt(encoded_jwt, public_key, {"not-in-aud"}, iss)


def test_invalid_iss_rejected(encoded_jwt, public_key, iss):
    """
    Test that if ``validate_jwt`` receives a token whose value for ``iss``
    does not match the expected value, a ``JWTValidationError`` is raised.
    """
    wrong_iss = iss + "garbage"
    with pytest.raises(JWTValidationError):
        validate_jwt(encoded_jwt, public_key, {"not-in-aud"}, wrong_iss)


def test_get_public_key(app, example_keys_response, mock_get):
    """
    Test the functionality of retrieving the public keys from the keys
    endpoint.
    """
    mock_get()
    test_kid, expected_key = example_keys_response["keys"][0]
    expected_jwt_public_keys_dict = OrderedDict(example_keys_response["keys"])
    key = get_public_key_for_kid(test_kid)
    requests.get.assert_called_once()
    assert key
    assert key == expected_key
    assert app.jwt_public_keys == expected_jwt_public_keys_dict


def test_get_nonexistent_public_key_fails(app, mock_get):
    """
    Test that if there is no key found for the provided key id, a
    JWTValidationError is raised.
    """
    mock_get()
    with pytest.raises(JWTValidationError):
        get_public_key_for_kid("nonsense")


def test_validate_request_jwt(client, auth_header, mock_get):
    """
    Test that a request including a valid JWT works.
    """
    mock_get()
    response = client.get("/test", headers=auth_header)
    assert response.status_code == 200
    assert response.json == TEST_RESPONSE_JSON


def test_validate_request_no_jwt_fails(client, mock_get):
    """
    Test that if no authorization header is included, a JWTValidationError is
    raised.
    """
    mock_get()
    with pytest.raises(JWTValidationError):
        client.get("/test")


def test_validate_request_jwt_bad_header(client, mock_get, encoded_jwt):
    mock_get()
    incorrect_headers = {"Authorization": encoded_jwt}
    with pytest.raises(JWTValidationError):
        client.get("/test", headers=incorrect_headers)


def test_validate_request_jwt_incorrect_usage(app, client, auth_header, mock_get):
    """
    Test that if a ``require_jwt`` caller does not give it any audiences, a
    JWTAudienceError is raised.
    """
    mock_get()

    # This should raise JWTValidationError, since no audiences are provided.
    @app.route("/test_incorrect_usage")
    @require_jwt({})
    def bad():
        return flask.jsonify({"foo": "bar"})

    with pytest.raises(JWTAudienceError):
        client.get("/test_incorrect_usage", headers=auth_header)


def test_validate_request_jwt_missing(app, client, auth_header, mock_get):
    """
    Test that if the JWT is completely missing an audience which is required by
    an endpoint, a ``jwt.JWTValidationError`` is raised.
    """
    mock_get()

    # This should raise jwt.InvalidAudienceError, since the audience it
    # requires does not appear in the default JWT anywhere.
    @app.route("/test_missing_audience")
    @require_jwt({"missing_audience"})
    def bad():
        return flask.jsonify({"foo": "bar"})

    with pytest.raises(JWTValidationError):
        client.get("/test_missing_audience", headers=auth_header)


def test_validate_request_jwt_missing_some(app, client, auth_header, mock_get):
    """
    Test that if the JWT satisfies some audiences but is missing at least one
    audience which is required by an endpoint, a ``jwt.InvalidAudienceError``
    is raised.
    """
    mock_get()

    # This should raise jwt.InvalidAudienceError, since the audience it
    # requires does not appear in the default JWT anywhere.
    @app.route("/test_missing_audience")
    @require_jwt({"access", "missing_audience"})
    def bad():
        return flask.jsonify({"foo": "bar"})

    with pytest.raises(JWTValidationError):
        client.get("/test_missing_audience", headers=auth_header)
