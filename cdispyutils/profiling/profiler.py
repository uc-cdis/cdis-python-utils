__all__ = ["Profiler"]

from collections import defaultdict
import cProfile
import datetime
import errno
import functools
import os
import time

from werkzeug.contrib.profiler import ProfilerMiddleware


def profile(category, *profiler_args, **profiler_kwargs):
    """
    Decorate a function to run a profiler on the execution of that function.

    Arguments are passed through to the ``Profiler`` initialization. Most relevant one
    would be ``output_style`` which can be set to either "detailed" or "simple". With
    "detailed" the profiler saves the complete ``.prof`` file, with "simple" it saves
    only a file with the execution time saved as text.
    """

    profiler = Profiler(name=_make_timestamp(), *profiler_args, **profiler_kwargs)

    def decorator(f):
        @functools.wraps(f)
        def wrapper(*f_args, **f_kwargs):
            return profiler.call(category, f, args=f_args, kwargs=f_kwargs)

        return wrapper

    return decorator


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

    The output for this Flask application might look like this:

        profile/
          2018-11-30T15:15:36.14/
            init/
              app_register_blueprints-1.prof
              db_init-1.prof
            run/
              traverse-1.prof
              traverse-2.prof
              traverse-3.prof
            wsgi/
              GET.root.000003ms.1543612537.prof
              GET._status.000019ms.1543612539.prof

    In this example the ``directory`` argument is ``"profile"``, and the ``name`` was
    ``None`` so it defaults to just a timestamp.
    """

    def __init__(
        self,
        name=None,
        logger=None,
        enable=False,
        output_style="detailed",
        directory="profile",
    ):
        name = name or _make_timestamp()
        self.directory = os.path.join(directory, name)
        self.logger = logger
        self.output_style = output_style
        self._enable = enable
        self._function_counts = defaultdict(lambda: defaultdict(int))
        if self.enabled:
            if not os.path.isdir(self.directory):
                if os.path.isfile(self.directory):
                    raise EnvironmentError(
                        "can't save profile output; file already exists: {}".format(
                            self.directory
                        )
                    )
                os.makedirs(self.directory, mode=0o744)
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

    def call(self, category, f, args=None, kwargs=None, output_style=None):
        """
        Do a function call and (if the profiler is enabled) save profiling results to
        the directory for this category.

        Args:
            category (str): category to save the result under
            f (Callable): function to call
            args (Optional[List]): arguments to pass to f call
            kwargs (Optional[Dict]): keyword arguments to pass to f call
            output_style (Optional[str]):
                whether to save complete profile files ("detailed") or only the
                execution time ("simple"); defaults to detailed

        Return:
            exactly the return from calling ``f(*args, **kwargs)``
        """
        args = args or []
        kwargs = kwargs or {}
        if not self.enabled:
            return f(*args, **kwargs)

        # count the number of times this function is executed in this category, so the
        # filenames are kept unique
        function_name = "{}.{}".format(f.__module__, f.__name__)
        self._function_counts[category][function_name] += 1

        output_style = output_style or self.output_style or "detailed"
        if self.output_style == "detailed":
            profiler = cProfile.Profile()
            profiler.enable()
            result = f(*args, **kwargs)
            profiler.disable()
            self._make_profile_category(category)
            filename = "{}-{}.prof".format(
                function_name, str(self._function_counts[category][function_name])
            )
            path = os.path.join(self.directory, category, filename)
            profiler.dump_stats(path)
            return result
        elif self.output_style == "simple":
            start = time.time()
            result = f(*args, **kwargs)
            execution_time = time.time() - start
            filename = "{}-{}.time".format(
                function_name, str(self._function_counts[category][function_name])
            )
            path = os.path.join(self.directory, category, filename)
            # if the file exists already (say we gave the Profiler a directory that
            # already exists, and re-ran the same function as the previous run), then
            # tick up the counter until we're writing out new files
            while os.path.exists(path):
                self._function_counts[category][function_name] += 1
                filename = "{}-{}.prof".format(
                    function_name, str(self._function_counts[category][function_name])
                )
                path = os.path.join(self.directory, category, filename)
            with open(path, "w") as output_file:
                output_file.write(str(execution_time))
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
        """
        Add a directory under the profiling directory given at initialization, for
        saving a category of results into.
        """
        path = os.path.join(self.directory, name)
        try:
            _mkdir_p(path)
        except OSError:
            raise EnvironmentError(
                "can't save profile output; file already exists: {}".format(path)
            )
        return path


def _mkdir_p(directory, mode=0o774):
    try:
        os.makedirs(directory, mode=mode)
    except OSError as e:
        if e.errno != errno.EEXIST or not os.path.isdir(directory):
            raise


def _make_timestamp():
    """
    Return a timestamp to identify this profiling run.

    Output format is: ``2018-11-30T14:51:55.95``.
    (Truncate to hundredths of a second.)
    """
    return datetime.datetime.now().isoformat()[:-4]
