import pytest


@pytest.fixture(scope='session')
def app():
    # fixture to setup userapi client
    app_init(userapi_app, UserapiTestSettings)
    userapi_app.test = True
    userapi_client_obj = userapi_app.test_client()
    oauth_client = utils.create_client(
        'internal_service',
        'https://localhost',
        app.config['DB_CONNECTION'],
        name='cloud_middleware', description='', auto_approve=True)

    app.config['OAUTH2'] = {
        'client_id': oauth_client[0],
        'client_secret': oauth_client[1],
        'oauth_provider': '/oauth2/',
        'redirect_uri': 'https://localhost',
    }
    app.config['USER_API'] = '/'
    app.oauth2 = OAuth2Client(**app.config['OAUTH2'])

    def fin():
        for tbl in reversed(Base.metadata.sorted_tables):
            app.db.engine.execute(tbl.delete())
    request.addfinalizer(fin)
    return userapi_client_obj