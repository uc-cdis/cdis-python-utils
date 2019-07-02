__all__ = ["ProfilePlotter"]

from functools import reduce
import os
import pstats

import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import numpy as np


class StatsCollection(object):
    def __init__(self, directory, logger=None):
        self.stats = {}

        # if the program is interrupted or killed during execution then the profiler
        # output can be messed up---just ignore if this happens, and print the list of
        # these later
        corrupted = []

        def load_file(filepath):
            try:
                return pstats.Stats(filepath)
            except TypeError:
                # corrupted file: ignore & save
                corrupted.append(filepath)

        # walk all files in the profiling directory and save stats into the dictionary
        for path, _, files in os.walk(directory):
            files = [f for f in files if f.endswith(".prof")]
            split = path.split(os.sep)
            # walk down into the stats dictionary according to the split path list
            here = reduce(lambda acc, p: acc.get(p, {}), split[:-1], self.stats)
            # add entry to the stats dictionary
            here[split[-1]] = {f: load_file(os.path.join(path, f)) for f in files}
            here[split[-1]] = {f: stat for f, stat in here[split[-1]].items() if stat}

        if corrupted:
            msg = (
                "couldn't load profile from the following files (probably corrupted): "
                + str(corrupted)
            )
            if logger:
                logger.info(msg)
            else:
                print(msg)

        self.stats = self.stats[directory]


class ProfilePlotter(object):
    """
    Generate plots loaded from some profiling output previously recorded by a
    ``cdispyutils.profiling.Profiler``.
    """

    def __init__(self, directory="profile"):
        self.stats = StatsCollection(directory)

    def make_all_plots(self, save_file="profile_graphs.pdf"):
        """
        Using the stats loaded into the ``StatsCollection``, generate a series of plots
        for all the profiling files which are recorded, comparing the results from
        different runs for their shared profiling events.

        The stats in the ``StatsCollection`` have to be slightly reorganized for a
        couple of reasons:
        - We want to parametrize over separate runs, for every category
        - For WSGI's profiling output, we want to aggregate the results for each run
          into a single data point with an uncertainty value

        The ``results`` variable will look like this:

            {
                "init": {
                    "app_register_blueprints.prof": {
                        "run": ["2018-11-30T15:15:36.14", "2018-11-30T15:15:38.21"],
                        "results": [[0.03], [0.04]],
                    },
                },
                "wsgi": {
                    "GET.root.prof": {
                        "run": ["2018-11-30T15:15:36.14", "2018-11-30T15:15:38.21"],
                        "results": [[0.0001, 0.0002, 0.0004], [0.0001]],
                    },
                    "GET._status.prof": {
                        "run": ["2018-11-30T15:15:36.14", "2018-11-30T15:15:38.21"],
                        "results": [[0.002], [0.004]],
                    }
                },
            }

        Then we assemble plots for every profile in every category, where the data
        points are the run name as the x and the result time as the y.
        """
        results = {}
        for run, categories in self.stats.stats.items():
            for category, files in categories.items():
                if category not in results:
                    results[category] = {}
                aggregator = (
                    _aggregate_wsgi_filename
                    if category == "wsgi"
                    else _aggregate_profiler_filename
                )
                for filename, times in _aggregate_results(files, aggregator).items():
                    if filename not in results[category]:
                        results[category][filename] = {}
                    if run not in results[category][filename]:
                        results[category][filename][run] = []
                    results[category][filename][run].extend(times)

        with PdfPages(save_file) as pdf:
            for category, profiles in results.items():
                for profile, data in profiles.items():
                    figure = plt.figure()
                    figure.suptitle("{}: {}".format(category, profile), fontsize=16)
                    axes = figure.subplots()
                    axes.margins(0.05)
                    axes.set_xlabel("Run ID")
                    axes.set_ylabel("Time (s)")

                    scatter_x = []
                    scatter_y = []
                    errorbar_x = []
                    errorbar_y = []
                    errorbar_dy = []
                    for run, times in data.items():
                        if len(times) > 1:
                            axes.scatter(
                                len(times) * [run], times, s=3, c="C1", zorder=10
                            )
                            errorbar_x.append(run)
                            errorbar_y.append(np.mean(times))
                            errorbar_dy.append(np.std(times))
                        else:
                            scatter_x.append(run)
                            scatter_y.append(times[0])

                    axes.scatter(scatter_x, scatter_y, c="C0")
                    axes.errorbar(
                        errorbar_x, errorbar_y, yerr=errorbar_dy, fmt="oC0", capsize=4
                    )
                    plt.setp(
                        axes.get_xticklabels(), rotation=45, horizontalalignment="right"
                    )

                    pdf.savefig(figure, bbox_inches="tight")


def _aggregate_wsgi_filename(filename):
    """
    The WSGI profiler outputs files like this:

        GET.root.000003ms.1543612537.prof

    For comparison in our plotter we want them to look like this:

        GET.root
    """
    return ".".join(filename.split(".")[:2])


def _aggregate_profiler_filename(filename):
    """
    The Profiler class outputs files names like this:

        cdispyutils.profiling.vis._aggregate_profiler_filename-1.prof

    For the plotter we want to keep only this part for the names:

        cdispyutils.profiling.vis._aggregate_profiler_filename
    """
    return filename.split("-")[0]


def _aggregate_results(file_stats, f_aggregate):
    """
    Using the Profiler to run some functions multiple times in a given category will
    produce some results like this:

        run/
          a-1.prof
          b-1.prof
          a-2.prof
          a-3.prof
          b-2.prof

    Here we aggregate the timing results from repeated executions of the same function.

    For collecting profiling results from the WSGI output directory, we want to take
    something like this:

        wsgi/
            GET.root.000003ms.1543612537.prof
            GET.root.000002ms.1543612540.prof
            GET.root.000003ms.1543612541.prof
            GET.root.000003ms.1543612543.prof
            GET._status.000019ms.1543612539.prof

    And aggregate them so the results are like this (but collecting lists of timings):

        wsgi/
            GET.root.prof
            GET._status.prof

    Note that this methodology has a minor flaw: WSGI does not differentiate between
    multiple requests in the same second to the same endpoint which take the same length
    of time, so the variance in the results from this function may be inflated when this
    happens.

    Args:
        file_stats (Dict[str, pstats.Stats]): mapping from profile filename to stats

    Return:
        Dict[str, List[float]]

    Example:

        {"GET.root.prof": [0.003, 0.002, 0.003, 0.003], "GET._status.prof": [0.019]}
    """
    results = {}
    for filename, stat in file_stats.items():
        filename = f_aggregate(filename)
        if filename not in results:
            results[filename] = []
        results[filename].append(stat.total_tt)
    return results
