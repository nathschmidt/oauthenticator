"""Custom Authenticator to use TUDelft OAuth with JupyterHub"""

import json
import base64
import os

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import Unicode

from .oauth2 import OAuthLoginHandler, OAuthenticator

def _base64encode(s):
    return base64.encodebytes(s.encode('utf8')).decode('utf8').strip()

# Support github.com and github enterprise installations
TUDELFT_HOST = 'oauth.tudelft.nl'
TUDELFT_OAUTH_ENDPOINT = 'https://{}/OAuth/oauth2'.format(TUDELFT_HOST)
TUDELFT_API_ENDPOINT = 'https://{}/v1'.format(TUDELFT_HOST)


class TUDelftMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = "{}/authorize".format(TUDELFT_OAUTH_ENDPOINT)
    _OAUTH_ACCESS_TOKEN_URL = "{}/token".format(TUDELFT_OAUTH_ENDPOINT)


class TUDelftLoginHandler(OAuthLoginHandler, TUDelftMixin):
    pass


class TUDelftOAuthenticator(OAuthenticator):

    login_service = "TU Delft"
    client_id_env = 'GITHUB_CLIENT_ID'
    client_secret_env = 'GITHUB_CLIENT_SECRET'
    login_handler = TUDelftLoginHandler

    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "oauth callback made without a token")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        # Exchange the OAuth code for an access token
        # See: https://api.tudelft.nl/cms/developers-guide/oauth2/
        params = dict(
            client_id=self.client_id,
            code=code,
            grant_type="authorization_code",
            redirect_uri=self.oauth_callback_url
        )

        url = url_concat("{}/token".format(TUDELFT_OAUTH_ENDPOINT),
                         params)

        # API requires <client id>:<client secret> in the header
        # in a base64 encoded string (!)
        # https://api.tudelft.nl/cms/developers-guide/oauth2/
        auth = _base64encode(
            '{}:{}'
            .format(self.client_id, self.client_secret)
        )

        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencode",
            "Authorization": "Basic {}".format(auth),
        }

        req = HTTPRequest(
            url,
            method="POST",
            headers=headers,
            body='', # Body is required for a POST...
        )

        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']

        # Determine who the logged in user is
        # API requires access token to be sent base64 encoded because
        # is is "more secure"
        headers={
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "Bearer {}".format(_base64encode(access_token)),
        }
        req = HTTPRequest(
            "{}/tokeninfo".format(TUDELFT_API_ENDPOINT),
            method="GET",
            headers=headers
        )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        return resp_json["tokeninfo"]["webid"]


class LocalTUDelftAuthenticator(LocalAuthenticator, TUDelftOAuthenticator):

    """A version that mixes in local system user creation"""
    pass
