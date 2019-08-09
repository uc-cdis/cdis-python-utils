import hashlib
import cdispyutils.constants as constants
from . import hmac4_auth_parser as hmac4_parser
import hmac
from urllib.parse import urlparse, parse_qs, quote, unquote, quote_plus


def set_req_date(req, req_date):
    if constants.REQUEST_DATE_HEADER in req.headers:
        del req.headers[constants.REQUEST_DATE_HEADER]
    req.headers[constants.REQUEST_DATE_HEADER] = req_date


def set_encoded_body(req):
    # encode body and generate body hash
    if hasattr(req, "body") and req.body is not None:
        encode_body(req)
        content_hash = hashlib.sha256(req.body)
    else:
        content_hash = hashlib.sha256(b"")
    req.headers[constants.HASHED_REQUEST_CONTENT] = content_hash.hexdigest()


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
    if isinstance(req.body, str):
        split = req.headers.get("content-type", "text/plain").split(";")
        if len(split) == 2:
            ct, cs = split
            cs = cs.split("=")[1]
            req.body = req.body.encode(cs)
        else:
            ct = split[0]
            if (
                ct == "application/x-www-form-urlencoded"
                or constants.REQUEST_HEADER_PREFIX in ct
            ):
                req.body = req.body.encode()
            else:
                req.body = req.body.encode("utf-8")
                req.headers["content-type"] = ct + "; charset=utf-8"


def create_authentication_headers(access_key, scope, signed_headers, signature):
    auth_str = "{} ".format(constants.ALGORITHM)
    auth_str += "Credential={}/{}, ".format(access_key, scope)
    auth_str += "SignedHeaders={}, ".format(signed_headers)
    auth_str += "Signature={}".format(signature)
    return auth_str


def generate_signature(secret_key, sig_string):
    if isinstance(secret_key, str):
        secret_key = bytes(secret_key, "utf-8")
    if isinstance(sig_string, str):
        sig_string = bytes(sig_string, "utf-8")
    hsh = hmac.new(secret_key, sig_string, hashlib.sha256)
    sig = hsh.hexdigest()
    return sig


# TODO (thanh): write unit-test for:
# - set_req_date
# - set_encoded_body
# - get_sign_string_from_req
# - get_request_scope
# - generate_signature
# - get_canonical_headers
def sign_request(req, access_key, signing_key, service, req_date):
    set_req_date(req, req_date)
    set_encoded_body(req)
    scope = hmac4_parser.get_request_scope(req, service)

    sig_string = hmac4_parser.get_sign_string_from_req(req, service)
    signature = generate_signature(signing_key.key, sig_string)

    _, signed_headers = hmac4_parser.get_canonical_headers(req)
    req.headers[constants.AUTHORIZATION_HEADER] = create_authentication_headers(
        access_key, scope, signed_headers, signature
    )
    return req


def generate_presigned_url(
    url,
    method,
    access_key,
    signing_key,
    request_date,
    expires,
    additional_signed_qs,
    session_token=None,
):
    credential_scope = "/".join(
        [
            s
            for s in [
                signing_key.short_date_stamp,
                signing_key.region,
                signing_key.service,
                signing_key.postfix,
            ]
            if s is not None
        ]
    )

    querystring = {}
    querystring[constants.AWS_ALGORITHM_KEY] = constants.AWS_ALGORITHM
    querystring[constants.AWS_CREDENTIAL_KEY] = quote_plus(
        "/".join([access_key, credential_scope])
    )
    querystring[constants.AWS_DATE_KEY] = request_date
    querystring[constants.AWS_EXPIRES_KEY] = str(expires)
    if session_token:
        querystring["X-Amz-Security-Token"] = quote_plus(session_token)
    querystring[constants.AWS_SIGNED_HEADERS_KEY] = "host"

    canonical_qs = ""
    for key in sorted(querystring.keys()):
        canonical_qs += "&" + key + "=" + querystring[key]
    canonical_qs = canonical_qs[1:]
    for key in sorted(additional_signed_qs.keys()):
        canonical_qs += "&" + key + "=" + quote_plus(additional_signed_qs[key])

    url_parts = url.split("://")
    encoded_url = "://".join([quote(e) for e in url_parts])

    # generate the signature using the non-escaped URL, to match the
    # signature the provider generates using the non-escaped file name
    host_parts = url_parts[1].split("/")
    canonical_uri = quote(
        "/" + "/".join(host_parts[1:]) if len(host_parts) > 1 else "/"
    )
    canonical_request = "\n".join(
        [
            method.upper(),
            canonical_uri,
            canonical_qs,
            "host:" + host_parts[0] + "\n",
            "host",
            "UNSIGNED-PAYLOAD",
        ]
    )
    string_to_sign = "\n".join(
        [
            constants.AWS_ALGORITHM,
            request_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    signature = generate_signature(signing_key.key, string_to_sign)

    return (
        encoded_url
        + "?"
        + canonical_qs
        + "&"
        + constants.AWS_SIGNATURE_KEY
        + "="
        + signature
    )
