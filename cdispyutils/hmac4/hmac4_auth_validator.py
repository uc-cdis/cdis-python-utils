# Licensed under the MIT License:
# http://opensource.org/licenses/MIT

import datetime
import cdispyutils.constants as constants
import re

from . import hmac4_auth_parser as parser
from . import hmac4_auth_generator as generator

from .error import ExpiredTimeError, DateFormatError, UnauthorizedError
from .hmac4_signing_key import HMAC4SigningKey


def check_expired_time(req_date):
    return req_date + datetime.timedelta(minutes=15) > datetime.datetime.utcnow()


def get_exact_request_time(req):
    """
    Try to pull a date from the request by looking first at the
    x-amz-date header, and if that's not present then the Date header.

    Return a datetime.date object, or None if neither date header
    is found or is in a recognisable format.

    req -- a requests PreparedRequest object

    """
    date = None
    for header in [constants.REQUEST_DATE_HEADER, "date"]:
        if header not in req.headers:
            continue
        try:
            date = datetime.datetime.strptime(
                req.headers[header], constants.FULL_DATE_TIME_FORMAT
            )
        except DateFormatError:
            continue
        else:
            break

    return date


def get_signed_headers(req):
    try:
        authorization_header = req.headers[constants.AUTHORIZATION_HEADER]
        signed_headers = re.match(
            r".*SignedHeaders=(\S*?),.*", authorization_header
        ).group(1)
        signed_headers = signed_headers.split(";")
        return signed_headers
    except Exception as ex:
        raise AttributeError(
            "No authentication provided or SignedHeaders missing!: {}".format(ex)
        )


# TODO (thanh): write unit-test for:
# - parse_access_key_and_signature
# - get_exact_request_time
# - get_sign_string_from_req
# - generate_signature
def verify(service, req, secret_key):
    access_key, signature = parser.parse_access_key_and_signature(req)
    signed_headers = get_signed_headers(req)
    req_date = get_exact_request_time(req)
    if not check_expired_time(req_date):
        raise ExpiredTimeError("Request expired!")

    sig_string = parser.get_sign_string_from_req(req, service, include=signed_headers)
    signing_key = HMAC4SigningKey(
        secret_key, service, req_date.strftime(constants.ABRIDGED_DATE_TIME_FORMAT)
    )
    regenerate_signature = generator.generate_signature(signing_key.key, sig_string)

    if signature != regenerate_signature:
        raise UnauthorizedError("Server and client signatures don't match!")
    return access_key
