#!/usr/bin/env python
# coding: utf-8


import datetime
import sys
import re
import hashlib
from cdispyutils.hmac4.hmac4_auth import HMAC4Auth
from cdispyutils.hmac4.hmac4_signing_key import HMAC4SigningKey
from cdispyutils.hmac4.hmac4_auth_generator import encode_body
from cdispyutils.hmac4 import generate_aws_presigned_url
from urllib.parse import urlparse, quote_plus, quote

import requests
from test.mock_datetime import mock_datetime

sys.path = ["../../"] + sys.path


live_access_id = ""
live_secret_key = ""


def request_from_text(text):
    """
    Construct a Requests PreparedRequest using values provided in text.

    text should be a plaintext HTTP request, as defined in RFC7230.

    """
    lines = text.splitlines()
    match = re.search("^([a-z]+) (.*) (http/[0-9]\.[0-9])$", lines[0], re.I)
    method, path, version = match.groups()
    headers = {}
    for idx, line in enumerate(lines[1:], start=1):
        if not line:
            break
        hdr, val = [item.strip() for item in line.split(":", 1)]
        hdr = hdr.lower()
        vals = headers.setdefault(hdr, [])
        vals.append(val)
    headers = {hdr: ",".join(sorted(vals)) for hdr, vals in headers.items()}
    check_url = urlparse(path)
    if check_url.scheme and check_url.netloc:
        # absolute URL in path
        url = path
    else:
        # otherwise need to try to construct url from path and host header
        url = "".join(
            ["http://" if "host" in headers else "", headers.get("host", ""), path]
        )
    body = "\n".join(lines[idx + 1 :])
    req = requests.Request(method, url, headers=headers, data=body)
    return req.prepare()


def test_generate_key():
    """
    Using example data from:
    http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html

    """
    secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    service = "iam"
    date = "20110909"
    expected = [
        126,
        29,
        51,
        43,
        101,
        84,
        91,
        59,
        118,
        34,
        189,
        25,
        41,
        242,
        96,
        23,
        9,
        231,
        255,
        84,
        13,
        165,
        167,
        25,
        185,
        1,
        248,
        88,
        150,
        13,
        239,
        216,
    ]
    key = HMAC4SigningKey.generate_key(
        "HMAC4", "hmac4_request", secret_key, service, date
    )
    assert list(key) == expected


def test_instantiation_generate_key():
    """
    Using example data from:
    http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html

    """
    secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    service = "iam"
    date = "20110909"
    expected = [
        126,
        29,
        51,
        43,
        101,
        84,
        91,
        59,
        118,
        34,
        189,
        25,
        41,
        242,
        96,
        23,
        9,
        231,
        255,
        84,
        13,
        165,
        167,
        25,
        185,
        1,
        248,
        88,
        150,
        13,
        239,
        216,
    ]
    sig_key = HMAC4SigningKey(
        secret_key, service, prefix="HMAC4", postfix="hmac4_request", date=date
    )
    assert list(sig_key.key) == expected


def test_generate_signature():
    """
    Using example data from
    http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html

    """
    secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
    service = "iam"
    date = "20110909"
    key = HMAC4SigningKey(
        secret_key, service, prefix="HMAC4", postfix="hmac4_request", date=date
    )
    req_text = [
        "POST https://iam.amazonaws.com/ HTTP/1.1",
        "Host: iam.amazonaws.com",
        "Content-Type: application/x-www-form-urlencoded; charset=utf-8",
        "X-Amz-Date: 20110909T233600Z",
        "",
        "Action=ListUsers&Version=2010-05-08",
    ]
    req_text = "\n".join(req_text) + "\n"
    req = request_from_text(req_text)
    del req.headers["content-length"]

    target_date = datetime.datetime(2018, 2, 16)
    auth = HMAC4Auth("dummy", key)
    encode_body(req)
    hsh = hashlib.sha256(req.body)
    req.headers["x-amz-content-sha256"] = hsh.hexdigest()
    with mock_datetime(target_date, datetime):
        sreq = auth(req)
    signature = sreq.headers["Authorization"].split("=")[3]
    expected = "e2ed5dd809cff929abf86c687abedd3af09fc266da6c4ec485bda6aa" "111a5d04"
    assert signature == expected


def test_generate_presigned_url():
    cred = {
        "aws_access_key_id": "AKIDEXAMPLE",
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "aws_session_token": "FQoDYXdzEPv//////////wEaDD/RcZIzhOP3tz1Ut7NW7jud8VV53T59A2TNO2ZXkt",
    }
    url = "https://s3.amazonaws.com/cdis-presigned-url-test/testdata"
    date = datetime.date(2018, 2, 19)
    with mock_datetime(date, datetime):
        presigned_url = generate_aws_presigned_url(
            url,
            "GET",
            cred,
            "s3",
            "us-east-1",
            86400,
            {"user-id": "value2", "username": "value1@gmail.com"},
        )
    print(presigned_url)
    expected = (
        "{}?X-Amz-Algorithm=AWS4-HMAC-SHA256"
        "&X-Amz-Credential=AKIDEXAMPLE%2F20180219%2Fus-east-1%2Fs3%2Faws4_request"
        "&X-Amz-Date=20180219T000000Z"
        "&X-Amz-Expires=86400"
        "&X-Amz-Security-Token={}"
        "&X-Amz-SignedHeaders=host"
        "&user-id=value2"
        "&username=value1%40gmail.com"
        "&X-Amz-Signature=89af63e98712c6947d163c6c873a2b419b33a3c724ecd64c9fd6ddaf487fd4f9".format(
            url, quote_plus(cred.get("aws_session_token"))
        )
    )
    assert presigned_url == expected


def test_generate_presigned_url_escaped():
    cred = {
        "aws_access_key_id": "AKIDEXAMPLE",
        "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    }
    url = "https://s3.amazonaws.com/dummy/P0001_T1/[test]; .tar.gz"
    date = datetime.date(1999, 2, 19)
    with mock_datetime(date, datetime):
        presigned_url = generate_aws_presigned_url(
            url,
            "GET",
            cred,
            "s3",
            "us-east-1",
            86400,
            {"user-id": "value2", "username": "value1@gmail.com"},
        )

    expected = (
        "https://{}".format(quote("s3.amazonaws.com/dummy/P0001_T1/[test]; .tar.gz"))
        + "?X-Amz-Algorithm=AWS4-HMAC-SHA256"
        "&X-Amz-Credential=AKIDEXAMPLE%2F19990219%2Fus-east-1%2Fs3%2Faws4_request"
        "&X-Amz-Date=19990219T000000Z"
        "&X-Amz-Expires=86400"
        "&X-Amz-SignedHeaders=host"
        "&user-id=value2"
        "&username=value1%40gmail.com"
        "&X-Amz-Signature=ad46ace7fb67bf21f6bda544711c04dea3942c38da3099f037e441b6bdcc12b1"
    )
    assert presigned_url == expected
