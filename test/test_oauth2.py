from mock import patch
import json


class MockResponse(object):
    def __init__(self, r):
        self.r = r
        self._data = r.data
        self._json = json.loads(r.data)

    def json(self):
        return self._json

    @property
    def text(self):
        return self._data


def mock_request(userapi_client):
    class Requests(object):
        def post(self, url, data=None, headers={}):
            r = userapi_client.post(url, data=data, headers=headers)
            return MockResponse(r)

        def get(self, url, headers={}):
            r = userapi_client.get(url, headers=headers)
            return MockResponse(r)
    return Requests()


def test_oauth_flow(app, client, userapi_client):
    app.config['MOCK_AUTH'] = False
    assert client.get('/aws/v0/instances').status_code == 401
    redirect_url = client.get("/oauth2/v0/authorization_url").data
    r = userapi_client.get(redirect_url.replace('http://localhost', ''))
    assert r.status_code == 302
    code = r.headers['Location'].split("=")[-1]
    with patch("cdispyutils.oauth2.requests", mock_request(userapi_client)):
        with patch("cloud_middleware.api.oauth2_client.requests",
                   mock_request(userapi_client)):
            r = client.get("/oauth2/v0/authorize?code={}".format(code))
            assert 'Set-Cookie' in r.headers
    r = client.get("/aws/v0/instances")
    assert r.status_code != 401
    app.config['MOCK_AUTH'] = True
