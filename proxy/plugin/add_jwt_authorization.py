# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from datetime import datetime, timedelta
from uuid import UUID

import jwt
from typing import Optional

# from ..common.utils import bytes_
from ..common.flags import Flags
from ..core.connection import TcpClientConnection
from ..core.event import EventQueue
from ..http.parser import HttpParser
from ..http.proxy import HttpProxyBasePlugin
# from ..http.methods import httpMethods

PRIVATE_KEY_PEM = """
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
"""

JWT_DEBUG_KEY = "something super secret!"


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
                # 'iss': 'auth',                          # issuer
                'aud': "phoenix/gemini"                 # audience
            },
            PRIVATE_KEY_PEM,
            algorithm='RS512')

        # token = jwt.encode({
        #         'iat': now,                             # issued at
        #         'exp': now + timedelta(minutes=5),      # expiration time
        #         'nbf': now,                             # not before
        #         # 'iss': 'auth',                          # issuer
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
