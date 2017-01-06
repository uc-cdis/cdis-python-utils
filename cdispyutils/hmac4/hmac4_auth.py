from requests.auth import AuthBase
from hmac4_signing_key import HMAC4SigningKey
from hmac4_auth_utils import sign_request

class HMAC4Auth(object):
    def __init__(self, *args, **kwargs):
        """
        AWS4Auth instances can be created by supplying key scope parameters
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
        session_token
                    -- Must be supplied as keyword argument. If session_token
                       is set, then it is used for the x-amz-security-token
                       header, for use with STS temporary credentials.

        """
        l = len(args)
        self.access_key = args[0]
        if isinstance(args[1], HMAC4SigningKey) and l == 2:
            # instantiate from signing key
            self.signing_key = args[1]
            self.region = self.signing_key.region
            self.service = self.signing_key.service
            self.date = self.signing_key.date

        raise_invalid_date = kwargs.get('raise_invalid_date', False)
        if raise_invalid_date in [True, False]:
            self.raise_invalid_date = raise_invalid_date
        else:
            raise ValueError('raise_invalid_date must be True or False in AWS4Auth.__init__()')

        # self.include_hdrs = kwargs.get('include_hdrs',
        #                                self.default_include_headers)
        AuthBase.__init__(self)

    def __call__(self, req):
        req = sign_request(req, self.access_key, self.signing_key, self.service)
        return req
