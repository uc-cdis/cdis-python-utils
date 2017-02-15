from urlparse import urljoin
import requests
from urllib import urlencode
from ..log import get_logger

logger = get_logger('OAuth2Client')


class OAuth2Client(object):
    '''
    OAuth2 client that can be used by cdis internal
    microservices to acquire oauth token

    '''
    def __init__(self, client_id, client_secret, redirect_uri,
                 oauth_provider='https://bionimbus-pdc.opensciencedatacloud.org/api/oauth2/',
                 scope='user'):
        self.client_id = client_id
        self.client_secret = client_secret
        self.oauth_provider = oauth_provider
        self.redirect_uri = redirect_uri
        self.scope = scope

    @property
    def authorization_url(self):
        '''
        url to get temporary code
        this url can be used to get authorization code
        from browser if user is authenticated in oauth provider
        '''
        return (
            urljoin(self.oauth_provider, 'authorize') +
            '?' +
            urlencode(dict(client_id=self.client_id,
                           redirect_uri=self.redirect_uri,
                           response_type='code',
                           scope=self.scope))
        )

    def get_token(self, code):
        '''
        get access token from code

        Returns:
            A dict with oauth credential
            example:
            {u'access_token': u'9ydWQi1SqGU82hAGf8M0JoNJbXhxQ1',
             u'expires_in': 3600,
             u'refresh_token': u'Ll6PfksjrCSJHtkEQV41mRRbR4tUxU',
             u'scope': u'user',
             u'token_type': u'Bearer'}
        '''
        data = {
            'code': code,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'authorization_code',
            'redirect_uri': self.redirect_uri
        }
        try:
            r = requests.post(urljoin(self.oauth_provider, 'token'), data=data)
            return r.json()
        except Exception as e:
            logger.exception("Fail to reach oauth provider")
            return {'error': "Fail to reach oauth provider: " + str(e.message)}

    def refresh_token(self, refresh_token):
        '''
        refresh token
        '''
        data = {
            'refresh_token': refresh_token,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'refresh_token',
            'redirect_uri': self.redirect_uri
        }
        try:
            r = requests.post(urljoin(self.oauth_provider, 'token'), data=data)
            return r.json()
        except Exception as e:
            logger.exception("Fail to reach oauth provider")
            return {'error': "Fail to reach oauth provider: " + str(e.message)}
