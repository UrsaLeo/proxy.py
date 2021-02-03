# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import os
from datetime import datetime, timedelta

import jwt
from typing import Optional

from ..http.parser import HttpParser
from ..http.proxy import HttpProxyBasePlugin

GEMINI_JWT_PUK = os.environ.get('GEMINI_JWT_PUK', "")
# JWT_DEBUG_KEY = os.environ.get('JWT_DEBUG_KEY', "")


class AddJwtAuthorization(HttpProxyBasePlugin):
    def before_upstream_connection(self, request: HttpParser) -> Optional[HttpParser]:
        return request

    def handle_client_request(self, request: HttpParser) -> Optional[HttpParser]:
        if request.headers.get(b'authorization', None) is not None:
            return request

        now = datetime.utcnow()

        token = jwt.encode({
                'iat': now,                             # issued at
                'exp': now + timedelta(minutes=5),      # expiration time
                'nbf': now,                             # not before
                'aud': "phoenix/gemini"                 # audience
            },
            GEMINI_JWT_PUK,
            algorithm='RS512')

        # token = jwt.encode({
        #         'iat': now,                             # issued at
        #         'exp': now + timedelta(minutes=5),      # expiration time
        #         'nbf': now,                             # not before
        #         'aud': "phoenix/gemini"                 # audience
        #     },
        #     JWT_DEBUG_KEY,
        #     algorithm='HS512')

        request.add_header(b'Authorization', f"Bearer {str(token, encoding='utf-8')}".encode('utf-8'))
        return request

    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview:
        return chunk

    def on_upstream_connection_close(self) -> None:
        pass
