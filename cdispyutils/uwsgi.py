import time
from flask import request, abort


def setup_user_harakiri(app):
    """Configure given Flask app to have automatic user harakiri.

    Because a request may stay in uWSGI socket backlog for uncertain time, the reverse
    proxy may time out during or even before the handling of the request, and uWSGI may
    still handle the request with successful commitment. In order to avoid inconsistent
    result, this feature sets the user harakiri timeout on a per-request basis based on
    request arrival time and timeout values set by the reverse proxy as WSGI environment
    variables.
    """

    try:
        import uwsgi
    except ImportError:
        uwsgi = None
    else:
        if hasattr(uwsgi, "set_user_harakiri"):
            app.logger.info("Enabling automatic harakiri...")
        else:
            uwsgi = None

    @app.before_request
    def apply_reverse_proxy_timeout():
        timestamp = request.environ.get("GEN3_REQUEST_TIMESTAMP")
        timeout = request.environ.get("GEN3_TIMEOUT_SECONDS")
        if not timestamp or not timeout:
            return None
        timeout = float(timestamp) + float(timeout.rstrip("s")) - time.time()
        if timeout < 1:
            # We don't proceed if the time remaining is less than 1 second because the
            # minimal harakiri time is 1 second. Therefore it is important to set
            # GEN3_TIMEOUT_SECONDS larger than 1 second, not even close.
            app.logger.info("Not enough time to handle the request; discarding now.")
            abort(504)
        if uwsgi:
            # GOTCHA: the int here is intentional over round, because we need a smaller
            # timeout than reverse proxy
            timeout = int(timeout)
            uwsgi.set_user_harakiri(timeout)
            app.logger.debug("Set user harakiri in %d seconds.", timeout)

    @app.teardown_request
    def clear_harakiri(_):
        if uwsgi:
            try:
                # Setting user harakiri to 0 means to clear pending timeout if any
                uwsgi.set_user_harakiri(0)
            except:
                # teardown_request must not fail
                app.logger.exception("Failed to clear user harakiri")
