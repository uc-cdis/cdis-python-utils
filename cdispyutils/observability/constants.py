"""
Path sets and label values shared by the observability helpers.
"""

# Recorded in place of the path of a request that matched no route, so that a scanner walking
# the URL space adds one time series instead of one per URL it tries.
UNMATCHED_PATH = "<unmatched>"

# Recorded in place of a label the caller's provider could not produce, so the counter keeps the
# label set it was created with.
UNKNOWN_LABEL_VALUE = "Unknown"

# Endpoints that exist to be polled or fetched by a browser.
#
# Do NOT add "/" here. `tracing.excluded_url_patterns` turns each of these into a regex anchored
# at the end of the URL, so a bare "/" becomes "/$", which matches every URL ending in a slash
# and would drop the trailing-slash form of every real route from tracing. The site root, the
# docs, and the OpenAPI spec are left out for the same reason they are cheap to record: traffic
# to them is low volume and worth seeing.
DEFAULT_UNMONITORED_PATHS = frozenset(
    {
        "/_status",
        "/_status/",
        "/_version",
        "/_version/",
        "/favicon.ico",
        "/favicon.ico/",
    }
)

DEFAULT_ENDPOINTS_WITHOUT_METRICS = DEFAULT_UNMONITORED_PATHS | frozenset(
    {"/metrics", "/metrics/"}
)
