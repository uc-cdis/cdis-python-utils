from oauth2 import OAuth2Client
import requests


class OAuth2Error:
    def __init__(self, message='', json=None):
        self.message = message
        self.code = 400


def authorize(self, user_api, get_code):
    code = get_code()
    if not code:
        raise OAuth2Error("No authorization code provided")

    token_response = OAuth2Client.get_token(code)
    access_token = token_response.get('access_token')
    if access_token:
        try:
            r = requests.get(user_api + "user/", headers={"Authorization": "Bearer " + access_token})
            user_response = r.json()
        except Exception as e:
            raise OAuth2Error("Fail to get user info: {}".format(e))
        username = user_response.get('username')
        if not username:
            raise OAuth2Error(json=user_response)
        else:
            return username

    else:
        raise OAuth2Error(json=token_response)
