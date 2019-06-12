"""
Provides hmac4 utils for signing request.
This module is inspired by requests_aws4auth

Authentication utils class providing functions that generate and check
HMACv4 for HTTP requests. Implements header-based authentication only


Basic usage on server side to verify the requests.
-----------
>>> from flask import request
>>> from cdispyutils.hmac4 import verify_hmac
>>> def get_secret_key(access_key):
>>>   return 'secret_key_from_db'
>>> verify_hmac(request, 'submission', get_secret_key)

Basic usage on client side to sign the request
-----------
>>> from cdispyutils.hmac4 import get_auth
>>> import requests
>>> auth = get_auth(access_key, secret_key, 'submission')
>>> endpoint = 'link.to.service'
>>> response = requests.get(endpoint, auth=auth)

"""

import datetime
import cdispyutils.constants as constants

from .hmac4_signing_key import HMAC4SigningKey
from .hmac4_auth import HMAC4Auth
from .hmac4_auth_parser import parse_access_key_and_signature
from .hmac4_auth_validator import verify
from .hmac4_auth_generator import generate_presigned_url


def get_auth(access_key, secret_key, service):
    """
    Get a requests auth object

    :param access_key: user access_key
    :param secret_key: user secret key
    :param service: the service user tried to request, eg: 'submission'

    Returns requests auth object
    """
    sig_key = HMAC4SigningKey(secret_key, service)
    return HMAC4Auth(access_key, sig_key)


def verify_hmac(request, service, get_secret_key):
    """
    Check if the request is hmac authed

    :param request: flask request object
    :param service: the service user tried to request, eg: 'submission'
    :param get_secret_key: function to get secret key from access key

    Returns access_key
    """
    access_key, signature = parse_access_key_and_signature(request)
    secret_key = get_secret_key(access_key)
    return verify(service, request, secret_key)


def generate_aws_presigned_url(
    url, method, cred, service, region, expires, additional_signed_qs
):
    request_date = datetime.datetime.utcnow()
    session_token = cred.get("aws_session_token", None)
    sig_key = HMAC4SigningKey(
        cred.get("aws_secret_access_key"),
        service,
        region=region,
        date=request_date.strftime(constants.ABRIDGED_DATE_TIME_FORMAT),
        prefix="AWS4",
        postfix="aws4_request",
    )
    return generate_presigned_url(
        url,
        method,
        cred.get("aws_access_key_id"),
        sig_key,
        request_date.strftime(constants.FULL_DATE_TIME_FORMAT),
        expires,
        additional_signed_qs,
        session_token,
    )
