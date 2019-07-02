class DateFormatError(Exception):
    pass


class HMAC4Error(Exception):
    def __init__(self, message="", json=None):
        self.message = message
        self.json = json


class UnauthorizedError(HMAC4Error):
    def __init__(self, message="", json=None):
        super(UnauthorizedError, self).__init__(message, json)
        self.code = 401


class ExpiredTimeError(HMAC4Error):
    def __init__(self, message="", json=None):
        super(ExpiredTimeError, self).__init__(message, json)
        self.code = 401
