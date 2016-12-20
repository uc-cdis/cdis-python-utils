import hmac
import hashlib
import datetime
import re
import shlex
import posixpath
import constants

from six import PY2, text_type

try:
    from urllib.parse import urlparse, parse_qs, quote, unquote
except ImportError:
    from urlparse import urlparse, parse_qs
    from urllib import quote, unquote


class DateFormatError(Exception): pass

class HMAC4Auth(object):
    default_include_headers = ['host', 'content-type', 'date', constants.REQUEST_HEADER_PREFIX + '*']

    def __init__(self, service):
        self.service = service

    def get_sign_string_from_req(self, req, except_headers=None):
        req_date = self.get_request_date(req)
        scope = self.get_request_scope(req_date, self.service)

        # encode body and generate body hash
        if hasattr(req, 'body') and req.body is not None:
            self.encode_body(req)
            content_hash = hashlib.sha256(req.body)
        else:
            content_hash = hashlib.sha256(b'')
        req.headers[constants.ENCODED_REQUEST_CONTENT] = content_hash.hexdigest()

        # generate signature
        result = self.get_canonical_headers(req)
        cano_headers, signed_headers = result
        cano_req = self.get_canonical_request(req, cano_headers,
                                              signed_headers)
        sig_string = self.get_sig_string(req, cano_req, scope)
        return sig_string.encode('utf-8')

    def generate_signature(self, secret_key, sig_string):
        hsh = hmac.new(secret_key, sig_string, hashlib.sha256)
        sig = hsh.hexdigest()

    @staticmethod
    def parse_access_key_and_signature(req):
        authorization_header = req.headers[constants.AUTHORIZATION_HEADER]
        vals = re.split(': ', authorization_header)
        return vals[1], vals[2]

    @classmethod
    def get_request_scope(cls, date, service):
        return '{}/{}/{}'.format(date, service, constants.BIONIMBUS_REQUEST)

    @staticmethod
    def parse_date(date_str):
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
        months = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug',
                  'sep', 'oct', 'nov', 'dec']
        formats = {
            # RFC 7231, e.g. 'Mon, 09 Sep 2011 23:36:00 GMT'
            r'^(?:\w{3}, )?(\d{2}) (\w{3}) (\d{4})\D.*$':
                lambda m: '{}-{:02d}-{}'.format(
                                          m.group(3),
                                          months.index(m.group(2).lower())+1,
                                          m.group(1)),
            # RFC 850 (e.g. Sunday, 06-Nov-94 08:49:37 GMT)
            # assumes current century
            r'^\w+day, (\d{2})-(\w{3})-(\d{2})\D.*$':
                lambda m: '{}{}-{:02d}-{}'.format(
                                            str(datetime.date.today().year)[:2],
                                            m.group(3),
                                            months.index(m.group(2).lower())+1,
                                            m.group(1)),
            # C time, e.g. 'Wed Dec 4 00:00:00 2002'
            r'^\w{3} (\w{3}) (\d{1,2}) \d{2}:\d{2}:\d{2} (\d{4})$':
                lambda m: '{}-{:02d}-{:02d}'.format(
                                              m.group(3),
                                              months.index(m.group(1).lower())+1,
                                              int(m.group(2))),
            # x-amz-date format dates, e.g. 20100325T010101Z
            r'^(\d{4})(\d{2})(\d{2})T\d{6}Z$':
                lambda m: '{}-{}-{}'.format(*m.groups()),
            # ISO 8601 / RFC 3339, e.g. '2009-03-25T10:11:12.13-01:00'
            r'^(\d{4}-\d{2}-\d{2})(?:[Tt].*)?$':
                lambda m: m.group(1),
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

    @classmethod
    def get_request_date(cls, req):
        """
        Try to pull a date from the request by looking first at the
        x-amz-date header, and if that's not present then the Date header.

        Return a datetime.date object, or None if neither date header
        is found or is in a recognisable format.

        req -- a requests PreparedRequest object

        """
        date = None
        for header in [constants.REQUEST_DATE_HEADER, 'date']:
            if header not in req.headers:
                continue
            try:
                date_str = cls.parse_date(req.headers[header])
            except DateFormatError:
                continue
            try:
                date = datetime.datetime.strptime(date_str, '%Y-%m-%d').date()
            except ValueError:
                continue
            else:
                break

        return date

    @staticmethod
    def encode_body(req):
        """
        Encode body of request to bytes and update content-type if required.

        If the body of req is Unicode then encode to the charset found in
        content-type header if present, otherwise UTF-8, or ASCII if
        content-type is application/x-www-form-urlencoded. If encoding to UTF-8
        then add charset to content-type. Modifies req directly, does not
        return a modified copy.

        req -- Requests PreparedRequest object

        """
        if isinstance(req.body, text_type):
            split = req.headers.get('content-type', 'text/plain').split(';')
            if len(split) == 2:
                ct, cs = split
                cs = cs.split('=')[1]
                req.body = req.body.encode(cs)
            else:
                ct = split[0]
                if (ct == 'application/x-www-form-urlencoded' or
                        constants.REQUEST_HEADER_PREFIX in ct):
                    req.body = req.body.encode()
                else:
                    req.body = req.body.encode('utf-8')
                    req.headers['content-type'] = ct + '; charset=utf-8'


    def get_canonical_request(self, req, cano_headers, signed_headers):
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
        path = self.format_cano_path(url.path)
        # AWS handles "extreme" querystrings differently to urlparse
        # (see post-vanilla-query-nonunreserved test in aws_testsuite)
        split = req.url.split('?', 1)
        qs = split[1] if len(split) == 2 else ''
        qs = self.format_cano_querystring(qs)
        payload_hash = req.headers[constants.ENCODED_REQUEST_CONTENT]
        req_parts = [req.method.upper(), path, qs, cano_headers,
                     signed_headers, payload_hash]
        cano_req = '\n'.join(req_parts)
        return cano_req

    @classmethod
    def get_canonical_headers(cls, req, include=None):
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
            include = cls.default_include_headers
        include = [x.lower() for x in include]
        headers = req.headers.copy()
        # Temporarily include the host header - AWS requires it to be included
        # in the signed headers, but Requests doesn't include it in a
        # PreparedRequest
        if 'host' not in headers:
            headers['host'] = urlparse(req.url).netloc.split(':')[0]
        # Aggregate for upper/lowercase header name collisions in header names,
        # AMZ requires values of colliding headers be concatenated into a
        # single header with lowercase name.  Although this is not possible with
        # Requests, since it uses a case-insensitive dict to hold headers, this
        # is here just in case you duck type with a regular dict
        cano_headers_dict = {}
        for hdr, val in headers.items():
            hdr = hdr.strip().lower()
            val = cls.normalize_whitespace(val).strip()
            if (hdr in include or '*' in include or
                    ('x-amz-*' in include and hdr.startswith(constants.REQUEST_HEADER_PREFIX) and not
                    hdr == constants.CLIENT_CONTEXT_HEADER)):
                vals = cano_headers_dict.setdefault(hdr, [])
                vals.append(val)
        # Flatten cano_headers dict to string and generate signed_headers
        cano_headers = ''
        signed_headers_list = []
        for hdr in sorted(cano_headers_dict):
            vals = cano_headers_dict[hdr]
            val = ','.join(sorted(vals))
            cano_headers += '{}:{}\n'.format(hdr, val)
            signed_headers_list.append(hdr)
        signed_headers = ';'.join(signed_headers_list)
        return (cano_headers, signed_headers)


    def format_cano_path(self, path):
        """
        Generate the canonical path as per AWS4 auth requirements.

        Not documented anywhere, determined from aws4_testsuite examples,
        problem reports and testing against the live services.

        path -- request path

        """
        safe_chars = '/~'
        qs = ''
        fixed_path = path
        if '?' in fixed_path:
            fixed_path, qs = fixed_path.split('?', 1)
        fixed_path = posixpath.normpath(fixed_path)
        fixed_path = re.sub('/+', '/', fixed_path)
        if path.endswith('/') and not fixed_path.endswith('/'):
            fixed_path += '/'
        full_path = fixed_path
        # If Python 2, switch to working entirely in str as quote() has problems
        # with Unicode
        if PY2:
            full_path = full_path.encode('utf-8')
            safe_chars = safe_chars.encode('utf-8')
            qs = qs.encode('utf-8')
        # S3 seems to require unquoting first. 'host' service is used in
        # amz_testsuite tests
        # if self.service in ['s3', 'host']:
        #     full_path = unquote(full_path)
        full_path = quote(full_path, safe=safe_chars)
        if qs:
            qm = b'?' if PY2 else '?'
            full_path = qm.join((full_path, qs))
        if PY2:
            full_path = unicode(full_path)
        return full_path

    @staticmethod
    def format_cano_querystring(qs):
        """
        Parse and format querystring as per AWS4 auth requirements.

        Perform percent quoting as needed.

        qs -- querystring

        """
        safe_qs_amz_chars = '&=+'
        safe_qs_unresvd = '-_.~'
        # If Python 2, switch to working entirely in str
        # as quote() has problems with Unicode
        if PY2:
            qs = qs.encode('utf-8')
            safe_qs_amz_chars = safe_qs_amz_chars.encode()
            safe_qs_unresvd = safe_qs_unresvd.encode()
        qs = unquote(qs)
        space = b' ' if PY2 else ' '
        qs = qs.split(space)[0]
        qs = quote(qs, safe=safe_qs_amz_chars)
        qs_items = {}
        for name, vals in parse_qs(qs, keep_blank_values=True).items():
            name = quote(name, safe=safe_qs_unresvd)
            vals = [quote(val, safe=safe_qs_unresvd) for val in vals]
            qs_items[name] = vals
        qs_strings = []
        for name, vals in qs_items.items():
            for val in vals:
                qs_strings.append('='.join([name, val]))
        qs = '&'.join(sorted(qs_strings))
        if PY2:
            qs = unicode(qs)
        return qs

    @staticmethod
    def normalize_whitespace(text):
        """
        Replace runs of whitespace with a single space.

        Ignore text enclosed in quotes.

        """
        return ' '.join(shlex.split(text, posix=False))

    @staticmethod
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
        sig_string = '\n'.join(sig_items)
        return sig_string
