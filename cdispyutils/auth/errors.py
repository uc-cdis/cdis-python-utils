class JWTValidationError(Exception):
    pass


class JWTAudienceError(JWTValidationError):
    pass
