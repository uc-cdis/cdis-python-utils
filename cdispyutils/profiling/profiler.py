__all__ = ["Profiler"]


import cProfile
import datetime
import os

from werkzeug.contrib.profiler import ProfilerMiddleware


class Profiler(object):
    """
        profile/
            init/
            api/
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
        path = self._make_profile_category("flask")
        app = ProfilerMiddleware(app, profile_dir=path)
        return app

    def _make_profile_category(self, name):
        path = os.path.join(self.directory, name)
        if not os.path.exists(path):
            os.mkdir(path)
        return path

    @staticmethod
    def _make_timestamp():
        return datetime.datetime.now().replace(microsecond=0).isoformat()
