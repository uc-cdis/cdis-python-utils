#!/usr/bin/env python
# coding: utf-8

from __future__ import unicode_literals, print_function

import datetime
import sys
import re
import hashlib
from cdispyutils.hmac4.hmac4_auth import HMAC4Auth
from cdispyutils.hmac4.hmac4_signing_key import HMAC4SigningKey
from cdispyutils.hmac4.hmac4_auth_generator import encode_body
from cdispyutils.hmac4 import generate_aws_presigned_url
from six import PY2, u

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

import requests

sys.path = ['../../'] + sys.path


live_access_id = ''
live_secret_key = ''


def request_from_text(text):
    """
    Construct a Requests PreparedRequest using values provided in text.

    text should be a plaintext HTTP request, as defined in RFC7230.

    """
    lines = text.splitlines()
    match = re.search('^([a-z]+) (.*) (http/[0-9]\.[0-9])$', lines[0], re.I)
    method, path, version = match.groups()
    headers = {}
    for idx, line in enumerate(lines[1:], start=1):
        if not line:
            break
        hdr, val = [item.strip() for item in line.split(':', 1)]
        hdr = hdr.lower()
        vals = headers.setdefault(hdr, [])
        vals.append(val)
    headers = {hdr: ','.join(sorted(vals)) for hdr, vals in headers.items()}
    check_url = urlparse(path)
    if check_url.scheme and check_url.netloc:
        # absolute URL in path
        url = path
    else:
        # otherwise need to try to construct url from path and host header
        url = ''.join(['http://' if 'host' in headers else '',
                       headers.get('host', ''),
                       path])
    body = '\n'.join(lines[idx+1:])
    req = requests.Request(method, url, headers=headers, data=body)
    return req.prepare()


def test_generate_key():
    """
    Using example data from:
    http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html

    """
    secret_key = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'
    service = 'iam'
    date = '20110909'
    # expected = [152, 241, 216, 137, 254, 196, 244, 66, 26, 220, 82, 43,
    #             171, 12, 225, 248, 46, 105, 41, 194, 98, 237, 21, 229,
    #             169, 76, 144, 239, 209, 227, 176, 231]
    expected = [126, 29, 51, 43, 101, 84, 91, 59, 118, 34, 189, 25, 41,
                242, 96, 23, 9, 231, 255, 84, 13, 165, 167, 25, 185, 1,
                248, 88, 150, 13, 239, 216]
    key = HMAC4SigningKey.generate_key("HMAC4", "hmac4_request", secret_key, service, date)
    key = [ord(x) for x in key] if PY2 else list(key)
    print(key)
    assert key == expected

#
# def test_instantiation_generate_key():
#     """
#     Using example data from:
#     http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
#
#     """
#     secret_key = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'
#     service = 'iam'
#     date = '20110909'
#     expected = [152, 241, 216, 137, 254, 196, 244, 66, 26, 220, 82, 43,
#                 171, 12, 225, 248, 46, 105, 41, 194, 98, 237, 21, 229,
#                 169, 76, 144, 239, 209, 227, 176, 231]
#     key = HMAC4SigningKey(secret_key, service, date).key
#     key = [ord(x) for x in key] if PY2 else list(key)
#     assert key == expected
#
#
# def test_generate_signature():
#     """
#     Using example data from
#     http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
#
#     """
#     secret_key = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'
#     service = 'iam'
#     date = '20110909'
#     key = HMAC4SigningKey(secret_key, service, date)
#     req_text = [
#         'POST https://iam.amazonaws.com/ HTTP/1.1',
#         'Host: iam.amazonaws.com',
#         'Content-Type: application/x-www-form-urlencoded; charset=utf-8',
#         'X-Amz-Date: 20110909T233600Z',
#         '',
#         'Action=ListUsers&Version=2010-05-08']
#     req_text = '\n'.join(req_text) + '\n'
#     req = request_from_text(req_text)
#     del req.headers['content-length']
#     auth = HMAC4Auth('dummy', key)
#     encode_body(req)
#     hsh = hashlib.sha256(req.body)
#     req.headers['x-amz-content-sha256'] = hsh.hexdigest()
#     sreq = auth(req)
#     signature = sreq.headers['Authorization'].split('=')[3]
#     expected = ('ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c541'
#                 '74deb456c')
#     assert signature == expected


def test_generate_presigned_url():
    access_key = 'AKIAJDEKHZXYKWVBVGBQ'
    secret_key = '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'
    url = 'https://s3.amazonaws.com/bpa-migration/AstraZeneca_P0001_T1/AstraZeneca_P0001_T1.tar.gz'
    date = datetime.date(2018, 02, 19)
    presigned_url = generate_aws_presigned_url(url, 'GET', access_key, secret_key,
                                               's3', 'us-east-1', 86400,
                                               {'user-id': 'value2', 'username': 'value1'}, date=date)

    expected = 'https://s3.amazonaws.com/bpa-migration/AstraZeneca_P0001_T1/AstraZeneca_P0001_T1.tar.gz' \
               '?X-Amz-Algorithm=AWS4-HMAC-SHA256' \
               '&X-Amz-Credential=AKIDEXAMPLE%2F20180216%2Fus-east-1%2Fservice%2Faws4_request' \
               '&X-Amz-Date=20180216T000000Z&X-Amz-Expires=86400' \
               '&X-Amz-SignedHeaders=host&user-id=value2&username=value1' \
               '&X-Amz-Signature=2d6c7e037dde0367d3725574eea3418d2a584911967de5bf9450ee0683d1865d'
    print(presigned_url)
    print(expected)
    assert presigned_url == expected
