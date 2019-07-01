# Licensed under the MIT License:
# http://opensource.org/licenses/MIT

import hashlib
import datetime
import re
import shlex
import posixpath
import cdispyutils.constants as constants
import copy


from .error import DateFormatError, UnauthorizedError
from urllib.parse import urlparse, parse_qs, quote, unquote


DEFAULT_INCLUDE_HEADERS = [
    "Host",
    "content-type",
    "date",
    constants.REQUEST_HEADER_PREFIX + "*",
]


def parse_access_key_and_signature(req):
    try:
        authorization_header = req.headers[constants.AUTHORIZATION_HEADER]
    except Exception as ex:
        raise UnauthorizedError("No authentication provided!: {}".format(ex))
    try:
        signature = re.match(r".*Signature=(\S*)", authorization_header).group(1)
        access_key = re.match(r".*Credential=(\S*?)\/.*", authorization_header).group(1)
        return access_key, signature
    except Exception as ex:
        raise UnauthorizedError(
            "Authorization header incorrect: "
            "missing signature or credential in header!: {}".format(ex)
        )


def get_sign_string_from_req(req, service, include=None):
    scope = get_request_scope(req, service)
    # generate signature
    cano_headers, signed_headers = get_canonical_headers(req, include)
    cano_req = get_canonical_request(req, cano_headers, signed_headers)
    sig_string = get_sig_string(req, cano_req, scope)
    return sig_string.encode("utf-8")


def get_sig_string(req, cano_req, scope):
    """
    Generate the AWS4 auth string to sign for the request.

    req      -- Requests PreparedRequest object. This should already
                include an x-amz-date header.
    cano_req -- The Canonical Request, as returned by
                get_canonical_request()

    """
    req_date = req.headers[constants.REQUEST_DATE_HEADER]
    hsh = hashlib.sha256(cano_req.encode())
    sig_items = [constants.ALGORITHM, req_date, scope, hsh.hexdigest()]
    sig_string = "\n".join(sig_items)
    return sig_string


def get_request_scope(req, service):
    date = get_request_date(req)

    date = date.strftime(constants.ABRIDGED_DATE_TIME_FORMAT)
    return "{}/{}/{}".format(date, service, constants.BIONIMBUS_REQUEST)


def normalize_date_format(date_str):
    """
    Check if date_str is in a recognised format and return an ISO
    yyyy-mm-dd format version if so. Raise DateFormatError if not.

    Recognised formats are:
    * RFC 7231 (e.g. Mon, 09 Sep 2011 23:36:00 GMT)
    * RFC 850 (e.g. Sunday, 06-Nov-94 08:49:37 GMT)
    * C time (e.g. Wed Dec 4 00:00:00 2002)
    * Amz-Date format (e.g. 20090325T010101Z)
    * ISO 8601 / RFC 3339 (e.g. 2009-03-25T10:11:12.13-01:00)

    date_str -- Str containing a date and optional time

    """
    months = [
        "jan",
        "feb",
        "mar",
        "apr",
        "may",
        "jun",
        "jul",
        "aug",
        "sep",
        "oct",
        "nov",
        "dec",
    ]
    formats = {
        # RFC 7231, e.g. 'Mon, 09 Sep 2011 23:36:00 GMT'
        r"^(?:\w{3}, )?(\d{2}) (\w{3}) (\d{4})\D.*$": lambda m: "{}-{:02d}-{}".format(
            m.group(3), months.index(m.group(2).lower()) + 1, m.group(1)
        ),
        # RFC 850 (e.g. Sunday, 06-Nov-94 08:49:37 GMT)
        # assumes current century
        r"^\w+day, (\d{2})-(\w{3})-(\d{2})\D.*$": lambda m: "{}{}-{:02d}-{}".format(
            str(datetime.date.today().year)[:2],
            m.group(3),
            months.index(m.group(2).lower()) + 1,
            m.group(1),
        ),
        # C time, e.g. 'Wed Dec 4 00:00:00 2002'
        r"^\w{3} (\w{3}) (\d{1,2}) \d{2}:\d{2}:\d{2} (\d{4})$": lambda m: "{}-{:02d}-{:02d}".format(
            m.group(3), months.index(m.group(1).lower()) + 1, int(m.group(2))
        ),
        # x-amz-date format dates, e.g. 20100325T010101Z
        r"^(\d{4})(\d{2})(\d{2})T\d{6}Z$": lambda m: "{}-{}-{}".format(*m.groups()),
        # ISO 8601 / RFC 3339, e.g. '2009-03-25T10:11:12.13-01:00'
        r"^(\d{4}-\d{2}-\d{2})(?:[Tt].*)?$": lambda m: m.group(1),
    }

    out_date = None
    for regex, xform in formats.items():
        m = re.search(regex, date_str)
        if m:
            out_date = xform(m)
            break

    if out_date is None:
        raise DateFormatError
    else:
        return out_date


def get_request_date(req):
    """
    Try to pull a date from the request by looking first at the
    x-amz-date header, and if that's not present then the Date header.

    Return a datetime.date object, or None if neither date header
    is found or is in a recognisable format.

    req -- a requests PreparedRequest object

    """
    date = None
    for header in [constants.REQUEST_DATE_HEADER, "date"]:
        if header not in req.headers:
            continue
        try:
            date_str = normalize_date_format(req.headers[header])
        except DateFormatError:
            continue
        try:
            date = datetime.datetime.strptime(date_str, "%Y-%m-%d")
        except ValueError:
            continue
        else:
            break

    return date


def get_canonical_request(req, cano_headers, signed_headers):
    """
    Create the AWS authentication Canonical Request string.

    req            -- Requests PreparedRequest object. Should already
                      include an x-amz-content-sha256 header
    cano_headers   -- Canonical Headers section of Canonical Request, as
                      returned by get_canonical_headers()
    signed_headers -- Signed Headers, as returned by
                      get_canonical_headers()

    """
    url = urlparse(req.url)
    path = format_cano_path(url.path)

    # The additional header 'Subdir' is used to resolve
    # the problem of the url changed in reversed proxy
    if "Subdir" in req.headers:
        path = req.headers["Subdir"] + path
    # AWS handles "extreme" querystrings differently to urlparse
    # (see post-vanilla-query-nonunreserved test in aws_testsuite)
    split = req.url.split("?", 1)
    qs = split[1] if len(split) == 2 else ""
    qs = format_cano_querystring(qs)
    payload_hash = req.headers[constants.HASHED_REQUEST_CONTENT]
    req_parts = [
        req.method.upper(),
        path,
        qs,
        cano_headers,
        signed_headers,
        payload_hash,
    ]
    cano_req = "\n".join(req_parts)
    return cano_req


def get_canonical_headers(req, include=None):
    """
    Generate the Canonical Headers section of the Canonical Request.

    Return the Canonical Headers and the Signed Headers strs as a tuple
    (canonical_headers, signed_headers).

    req     -- Requests PreparedRequest object
    include -- List of headers to include in the canonical and signed
               headers. It's primarily included to allow testing against
               specific examples from Amazon. If omitted or None it
               includes host, content-type and any header starting 'x-amz-'
               except for x-amz-client context, which appears to break
               mobile analytics auth if included. Except for the
               x-amz-client-context exclusion these defaults are per the
               AWS documentation.

    """
    if include is None:
        include = DEFAULT_INCLUDE_HEADERS
    include = [x.lower() for x in include]
    headers = copy.copy(dict(req.headers))
    # Temporarily include the host header - AWS requires it to be included
    # in the signed headers, but Requests doesn't include it in a
    # PreparedRequest
    headers["Host"] = urlparse(req.url).netloc.split(":")[0]

    # Aggregate for upper/lowercase header name collisions in header names,
    # AMZ requires values of colliding headers be concatenated into a
    # single header with lowercase name.  Although this is not possible with
    # Requests, since it uses a case-insensitive dict to hold headers, this
    # is here just in case you duck type with a regular dict
    cano_headers_dict = {}
    for hdr, val in headers.items():
        hdr = hdr.strip().lower()
        val = normalize_whitespace(val).strip()
        if (
            hdr in include
            or "*" in include
            or (
                "x-amz-*" in include
                and hdr.startswith(constants.REQUEST_HEADER_PREFIX)
                and not hdr == constants.CLIENT_CONTEXT_HEADER
            )
        ):
            vals = cano_headers_dict.setdefault(hdr, [])
            vals.append(val)
    # Flatten cano_headers dict to string and generate signed_headers
    cano_headers = ""
    signed_headers_list = []
    for hdr in sorted(cano_headers_dict):
        vals = cano_headers_dict[hdr]
        val = ",".join(sorted(vals))
        cano_headers += "{}:{}\n".format(hdr, val)
        signed_headers_list.append(hdr)
    signed_headers = ";".join(signed_headers_list)
    return (cano_headers, signed_headers)


def format_cano_path(path):
    """
    Generate the canonical path as per AWS4 auth requirements.

    Not documented anywhere, determined from aws4_testsuite examples,
    problem reports and testing against the live services.

    path -- request path

    """
    safe_chars = "/~"
    qs = ""
    fixed_path = path
    if "?" in fixed_path:
        fixed_path, qs = fixed_path.split("?", 1)
    fixed_path = posixpath.normpath(fixed_path)
    fixed_path = re.sub("/+", "/", fixed_path)
    if path.endswith("/") and not fixed_path.endswith("/"):
        fixed_path += "/"
    full_path = fixed_path
    # S3 seems to require unquoting first. 'host' service is used in
    # amz_testsuite tests
    # if self.service in ['s3', 'host']:
    #     full_path = unquote(full_path)
    full_path = quote(full_path, safe=safe_chars)
    if qs:
        full_path = "?".join((full_path, qs))
    return full_path


def format_cano_querystring(qs):
    """
    Parse and format querystring as per AWS4 auth requirements.

    Perform percent quoting as needed.

    qs -- querystring

    """
    safe_qs_amz_chars = "&=+"
    safe_qs_unresvd = "-_.~"
    qs = unquote(qs)
    qs = qs.split(" ")[0]
    qs = quote(qs, safe=safe_qs_amz_chars)
    qs_items = {}
    for name, vals in parse_qs(qs, keep_blank_values=True).items():
        name = quote(name, safe=safe_qs_unresvd)
        vals = [quote(val, safe=safe_qs_unresvd) for val in vals]
        qs_items[name] = vals
    qs_strings = []
    for name, vals in qs_items.items():
        for val in vals:
            qs_strings.append("=".join([name, val]))
    qs = "&".join(sorted(qs_strings))
    return qs


def normalize_whitespace(text):
    """
    Replace runs of whitespace with a single space.

    Ignore text enclosed in quotes.

    """
    return " ".join(shlex.split(text, posix=False))


def parse_service(req):
    # TODO: list all provided service from API
    raise NotImplementedError
