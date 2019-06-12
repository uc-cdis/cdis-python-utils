import flask
import mock
import pytest
import time

from cdispyutils import uwsgi


@pytest.fixture
def mod_uwsgi():
    return mock.Mock()


@pytest.fixture
def app(mod_uwsgi):
    app = flask.Flask("test")

    @app.route("/")
    def index():
        return "", 200

    # XXX: must not run tests within this `with` block
    with mock.patch.dict("sys.modules", uwsgi=mod_uwsgi):
        uwsgi.setup_user_harakiri(app)

    return app


def test_user_harakiri_no_effect_on_normal_requests(mod_uwsgi, app):
    with app.test_client() as c:
        assert c.get("/").status_code == 200
    mod_uwsgi.set_user_harakiri.assert_called_once_with(0)


def test_user_harakiri_with_environ(mod_uwsgi, app):
    with app.test_client() as c:
        assert (
            c.get(
                "/",
                environ_overrides=dict(
                    GEN3_REQUEST_TIMESTAMP=time.time(), GEN3_TIMEOUT_SECONDS="10.9"
                ),
            ).status_code
            == 200
        )
    assert mod_uwsgi.set_user_harakiri.call_args_list == [mock.call(10), mock.call(0)]


def test_user_harakiri_nginx_compat(mod_uwsgi, app):
    with app.test_client() as c:
        assert (
            c.get(
                "/",
                environ_overrides=dict(
                    GEN3_REQUEST_TIMESTAMP=time.time(), GEN3_TIMEOUT_SECONDS="10.9s"
                ),
            ).status_code
            == 200
        )
    assert mod_uwsgi.set_user_harakiri.call_args_list == [mock.call(10), mock.call(0)]


def test_user_harakiri_expired_in_backlog(mod_uwsgi, app):
    with app.test_client() as c:
        assert (
            c.get(
                "/",
                environ_overrides=dict(
                    GEN3_REQUEST_TIMESTAMP=time.time() - 20, GEN3_TIMEOUT_SECONDS="10.9"
                ),
            ).status_code
            == 504
        )
    mod_uwsgi.set_user_harakiri.assert_called_once_with(0)


def test_user_harakiri_less_than_1_sec(mod_uwsgi, app):
    with app.test_client() as c:
        assert (
            c.get(
                "/",
                environ_overrides=dict(
                    GEN3_REQUEST_TIMESTAMP=time.time(), GEN3_TIMEOUT_SECONDS="0.9"
                ),
            ).status_code
            == 504
        )
    mod_uwsgi.set_user_harakiri.assert_called_once_with(0)
