__all__ = ["Profiler"]


import cProfile
import datetime
import os

from werkzeug.contrib.profiler import ProfilerMiddleware


class Profiler(object):
    """
    Output profiling information for specified function calls and Flask requests.

    The profiler singleton for a flask application saves profiling files into the
    specified directory. All files use the standard format for python profiling; use
    ``pstats`` to tabulate the information from one or more files, or a visualization
    tool like ``snakeviz``.

    A typical output for a Flask application might look like this:

        profile/
          init/
            db_init-2018-11-28T11:47:51
            blueprints_init-2018-11-28T11:47:51
          flask/
            GET-fence.data.upload-2018-11-28T11:49:42
            GET-fence.data.upload-2018-11-28T11:56:55

    """

    def __init__(self, directory="profile", logger=None, enable=False):
        self.directory = directory
        self.logger = logger
        self._enable = enable
        if not os.path.isdir(self.directory):
            if os.path.isfile(self.directory):
                raise EnvironmentError(
                    "can't save profile output; file already exists: {}"
                    .format(self.directory)
                )
            os.mkdir(self.directory)
        if self.logger:
            self.logger.info("profiling enabled")

    def call(self, category, f, *args, **kwargs):
        if not self.enabled:
            return f(*args, **kwargs)
        profiler = cProfile.Profile()
        profiler.enable()
        result = f(*args, **kwargs)
        profiler.disable()
        self._make_profile_category(category)
        filename = "{}-{}".format(f.__name__, self._make_timestamp())
        path = os.path.join(self.directory, category, filename)
        profiler.dump_stats(path)
        return result

    @property
    def enabled(self):
        return (
            self._enable
            or os.environ.get("ENABLE_PYTHON_PROFILING", "").lower() == "true"
        )

    def profile_app(self, app):
        if self.enabled:
            path = self._make_profile_category("flask")
            app = ProfilerMiddleware(app, profile_dir=path)
        return app

    def _make_profile_category(self, name):
        path = os.path.join(self.directory, name)
        if not os.path.isdir(path):
            if os.path.isfile(path):
                raise EnvironmentError(
                    "can't save profile output; file already exists: {}".format(path)
                )
            os.mkdir(path)
        return path

    @staticmethod
    def _make_timestamp():
        return datetime.datetime.now().replace(microsecond=0).isoformat()
