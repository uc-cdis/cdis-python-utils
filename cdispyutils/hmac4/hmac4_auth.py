from requests.auth import AuthBase
from .hmac4_auth_generator import sign_request
import cdispyutils.constants as constants
import datetime


class HMAC4Auth(AuthBase):
    """
    Requests authentication class providing AWS version 4 authentication for
    HTTP requests. Implements header-based authentication only, GET URL
    parameter and POST parameter authentication are not supported.

    You can reuse HMAC4Auth instances to sign as many requests as you need.

    Basic usage on client side to sign the request
    -----------
    >>> from cdispyutils.hmac4.hmac4_signing_key import HMAC4SigningKey
    >>> import requests
    >>> sig_key = HMAC4SigningKey(secret_key, service)
    >>> auth = HMAC4Auth(access_key, sig_key)
    >>> endpoint = 'link.to.service'
    >>> response = requests.get(endpoint, auth=auth)
    """

    def __init__(self, access_key, signing_key, raise_invalid_date=False):
        """
        HMAC4Auth instances can be created by supplying key scope parameters
        directly or by using an AWS4SigningKey instance:

        >>> auth = HMAC4Auth(access_key, signing_key[, raise_invalid_date=False])

        access_key   -- This is your AWS access ID
        signing_key -- An AWS4SigningKey instance.
        raise_invalid_date
                    -- Must be supplied as keyword argument. AWS4Auth tries to
                       parse a date from the X-Amz-Date and Date headers of the
                       request, first trying X-Amz-Date, and then Date if
                       X-Amz-Date is not present or is in an unrecognised
                       format. If one or both of the two headers are present
                       yet neither are in a format which AWS4Auth recognises
                       then it will remove both headers and replace with a new
                       X-Amz-Date header using the current date.

                       If this behaviour is not wanted, set the
                       raise_invalid_date keyword argument to True, and
                       instead an InvalidDateError will be raised when neither
                       date is recognised. If neither header is present at all
                       then an X-Amz-Date header will still be added containing
                       the current date.

                       See the AWS4Auth class docstring for supported date
                       formats.
        """
        self.access_key = access_key
        self.signing_key = signing_key
        self.service = self.signing_key.service

        if raise_invalid_date in [True, False]:
            self.raise_invalid_date = raise_invalid_date
        else:
            raise ValueError(
                "raise_invalid_date must be True or False in AWS4Auth.__init__()"
            )

        super(HMAC4Auth, self).__init__()

    def __call__(self, req):
        req = sign_request(
            req,
            self.access_key,
            self.signing_key,
            self.service,
            datetime.datetime.utcnow().strftime(constants.FULL_DATE_TIME_FORMAT),
        )

        return req
