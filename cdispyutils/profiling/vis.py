from functools import reduce
import os
import pstats

import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import numpy as np


class StatsCollection(object):

    def __init__(self, directory):
        self.stats = {}
        for path, _, files in os.walk(directory):
            files = [f for f in files if f.endswith(".prof")]
            split = path.split(os.sep)
            here = reduce(lambda acc, p: acc.get(p, {}), split[:-1], self.stats)
            print(path)
            print(files)
            if files:
                print(os.path.join(path, files[0]))
            here[split[-1]] = {f: pstats.Stats(os.path.join(path, f)) for f in files}
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
                        "result": [0.03, 0.04],
                    },
                },
                "wsgi": {
                    "GET.root.prof": {
                        "run": ["2018-11-30T15:15:36.14", "2018-11-30T15:15:38.21"],
                        "result": [[0.0001, 0.0002, 0.0004], [0.0001]],
                    },
                    "GET._status.prof": {
                        "run": ["2018-11-30T15:15:36.14", "2018-11-30T15:15:38.21"],
                        "result": [[0.002], [0.004]],
                    }
                },
            }

        Then we assemble plots for every profile in every category, where the data
        points are the run name as the x and the result time as the y.
        """
        results = {}
        for run, categories in self.stats.stats.iteritems():
            for category, files in categories.iteritems():
                if category not in results:
                    results[category] = {}
                if category == "wsgi":
                    for filename, times in _aggregate_wsgi_results(files).iteritems():
                        if filename not in results[category]:
                            results[category][filename] = {"run": [], "result": []}
                        results[category][filename]["run"].extend(len(times) * [run])
                        results[category][filename]["result"].extend(times)
                else:
                    for filename, stat in files.iteritems():
                        if filename not in results[category]:
                            results[category][filename] = {"run": [], "result": []}
                        results[category][filename]["run"].append(run)
                        results[category][filename]["result"].append(stat.total_tt)

        with PdfPages(save_file) as pdf:
            for category, profiles in results.iteritems():
                if category == "wsgi":
                    for profile, data in profiles.iteritems():
                        figure = plt.figure()
                        figure.suptitle(profile, fontsize=16)
                        axes = figure.subplots()
                        y = []
                        dy = []
                        for result in data["result"]:
                            y.append(np.mean(result))
                            dy.append(np.std(result))
                        axes.errorbar(data["run"], y, yerr=dy, fmt='o')
                        axes.margins(0.05)
                        axes.set_xlabel("Run ID")
                        axes.set_ylabel("Time (s)")
                        pdf.savefig(figure, bbox_inches="tight")
                else:
                    for profile, data in profiles.iteritems():
                        figure = plt.figure()
                        figure.suptitle(profile, fontsize=16)
                        axes = figure.subplots()
                        axes.scatter(data["run"], data["result"])
                        axes.margins(0.05)
                        axes.set_xlabel("Run ID")
                        axes.set_ylabel("Time (s)")
                        pdf.savefig(figure, bbox_inches="tight")

            pdf.savefig()


def _make_wsgi_profile_generic(filename):
    """
    The WSGI profiler outputs files like this:

        GET.root.000003ms.1543612537.prof

    For comparison in our plotter we want them to look like this:

        GET.root.prof
    """
    return ".".join(filename.split(".")[:2]) + ".prof"


def _aggregate_wsgi_results(file_stats):
    """
    For collecting profiling results from the WSGI output directory, we want to take
    something like this:

        wsgi/
            GET.root.000003ms.1543612537.prof
            GET.root.000002ms.1543612540.prof
            GET.root.000003ms.1543612541.prof
            GET.root.000003ms.1543612543.prof
            GET._status.000019ms.1543612539.prof

    And aggregate them so the results are like this:

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
    filenames = file_stats.keys()
    results = {}
    for filename, stat in file_stats.iteritems():
        filename = _make_wsgi_profile_generic(filename)
        if filename not in results:
            results[filename] = []
        results[filename].append(stat.total_tt)
    return results
