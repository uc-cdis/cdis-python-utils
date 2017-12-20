# `cdis-python-utils` Changelog

## 0.2.0 (2017-12-20)

- Add `auth` directory providing utility functions for validating JWTs issued by fence ([#15][]), exporting:
    - `get_public_key_for_kid`
    - `validate_jwt`
    - `validate_request_jwt`
- Add `auth` directory in tests including, `conftest.py` for fixtures, to test auth functions

### Requirements

- Added `PyJWT==1.5.3`
- Added `cryptography==2.1.2`

[#15]: https://github.com/uc-cdis/cdis-python-utils/pull/15
