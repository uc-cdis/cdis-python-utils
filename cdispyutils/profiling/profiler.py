__all__ = ["Profiler"]


import cProfile
import datetime
import os

from werkzeug.contrib.profiler import ProfilerMiddleware


class Profiler(object):
    """
    Output profiling information for specified function calls and Flask requests.

    Enable profiling either by passing ``enable=True`` to the profiler, or setting the
    environment variable ``ENABLE_PYTHON_PROFILING`` to ``True``. The profiler is
    intended to be used everywhere that profiling *might* be desirable; if enabled it
    will actually do the profiling and save the results, and otherwise it will just pass
    through function calls at no additional runtime cost (aside from its method call).

    The profiler singleton for a flask application saves profiling files into the
    directory specified at initialization. All files use the standard format for python
    profiling; use ``pstats`` to tabulate the information from one or more files, or a
    visualization tool like ``snakeviz``.

    Some example usage for a generic flask app, including profiling a couple setup
    functions, as well as the application's endpoints:

        def app_init(app):
            profiler = Profiler(logger=app.logger)
            init_functions = [app_register_blueprints, db_init]
            for f in init_functions:
                profiler.call("init", f, app)
            profiler.profile_app(app)

    A typical output for this Flask application might look like this:

        profile/
          2018-11-30T15:15:36.14/
            init/
              app_register_blueprints.prof
              db_init.prof
            wsgi/
              GET.root.000003ms.1543612537.prof
              GET._status.000019ms.1543612539.prof

    """

    def __init__(self, directory="profile", name=None, logger=None, enable=False):
        name = name or self._make_timestamp()
        self.directory = os.path.join(directory, name)
        self.logger = logger
        self._enable = enable
        if self.enabled:
            if not os.path.isdir(self.directory):
                if os.path.isfile(self.directory):
                    raise EnvironmentError(
                        "can't save profile output; file already exists: {}"
                        .format(self.directory)
                    )
                import pdb; pdb.set_trace()
                os.mkdir(self.directory)
            if self.logger:
                self.logger.info("profiling enabled")

    @property
    def enabled(self):
        """
        Return boolean indicating if the profiler should actually profile, or just pass
        through results from any calls it's asked to handle.
        """
        return (
            self._enable
            or os.environ.get("ENABLE_PYTHON_PROFILING", "").lower() == "true"
        )

    def call(self, category, f, *args, **kwargs):
        """
        Do a function call and (if the profiler is enabled) save profiling results to
        the directory for this category.
        """
        if not self.enabled:
            return f(*args, **kwargs)
        profiler = cProfile.Profile()
        result = f(*args, **kwargs)
        profiler.disable()
        self._make_profile_category(category)
        filename = f.__name__ + ".prof"
        path = os.path.join(self.directory, category, filename)
        profiler.dump_stats(path)
        return result

    def profile_app(self, app):
        """
        Enable WSGI's built-in profiler and include the output in the configured
        profiling directory.
        """
        if self.enabled:
            path = self._make_profile_category("wsgi")
            app.wsgi_app = ProfilerMiddleware(app.wsgi_app, profile_dir=path)

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
        """
        Return a timestamp to identify this profiling run.

        Output format is: ``2018-11-30T14:51:55.95``.
        (Truncate to hundredths of a second.)
        """
        return datetime.datetime.now().isoformat()[:-4]
