# -*- coding: utf-8 -*-
from oauth import OAuthConsumer, OAuthSignatureMethod_HMAC_SHA1 as HMAC,\
                  OAuthRequest, OAuthToken

class OAuth(object):
    signature_method = HMAC()

    def __init__(self, consumer_key, consumer_secret):
        self.consumer = OAuthConsumer(consumer_key, consumer_secret)

    def get_connection(self):
        """-> httplib.HTTPSConnection(service_provider)"""
        raise NotImplementedError

    def get_request_token_url(self):
        raise NotImplementedError

    def get_user_authorization_url(self):
        raise NotImplementedError

    def get_access_token_url(self):
        raise NotImplementedError

    def build_oauth_request(self, http_url, token=None,
                            http_method="GET", parameters=None):
        oauth_request = OAuthRequest.from_consumer_and_token(
            self.consumer, token=token, http_method=http_method,
            http_url=http_url, parameters=parameters
        )
        oauth_request.sign_request(self.signature_method, self.consumer, token)
        return oauth_request

    def execute(self, oauth_request):
        connection = self.get_connection()
        connection.request(oauth_request.http_method, oauth_request.to_url())
        response = connection.getresponse()
        return response.read()

    def get_unauthorized_request_token(self, oauth_callback=None):
        parameters = {}
        if oauth_callback:
            parameters = {"oauth_callback": oauth_callback}
        oauth_request = self.build_oauth_request(
            self.get_request_token_url(), parameters = parameters
        )
        response = self.execute(oauth_request)
        return OAuthToken.from_string(response)

    def get_authorization_url(self, token):
        oauth_request = self.build_oauth_request(
            self.get_user_authorization_url(), token
        )
        return oauth_request.to_url()

    def exchange_request_token_for_access_token(self, request_token, verifier):
        parameters = {"oauth_verifier": verifier}
        oauth_request = self.build_oauth_request(
            self.get_access_token_url(), request_token, parameters=parameters
        )
        response = self.execute(oauth_request)
        return OAuthToken.from_string(response)
