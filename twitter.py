# -*- coding:utf-8 -*-
import httplib
import logging

from oauth import OAuthToken
from oauth_tools import OAuth

__author__ = "Yuku Takahashi"

class TwitterOAuth(OAuth):
    check_auth_url = 'https://twitter.com/account/verify_credentials.json'
    friends_url = 'https://twitter.com/statuses/friends.json'
    update_status_url = 'https://twitter.com/statuses/update.json'

    def get_connection(self):
        return httplib.HTTPSConnection("twitter.com")

    def get_request_token_url(self):
        return 'https://twitter.com/oauth/request_token'

    def get_user_authorization_url(self):
        return 'http://twitter.com/oauth/authorize'

    def get_access_token_url(self):
        return 'https://twitter.com/oauth/access_token'

    def is_authenticated(self, access_token):
        if not isinstance(access_token, OAuthToken):
            access_token = OAuthToken.from_string(access_token)
        oauth_request = self.build_oauth_request(self.check_auth_url, access_token)
        response = self.execute(oauth_request)
        if "screen_name" in response:
            self.set_access_token(access_token)
            return True
        return False

    def set_access_token(self, access_token):
        if isinstance(access_token, OAuthToken):
            self.access_token = access_token
        else:
            self.access_token = OAuthToken.from_string(access_token)

    def get_access_token(self):
        if not hasattr(self, "access_token"):
            raise
        return self.access_token

    def update_status(self, status):
        oauth_request = self.build_oauth_request(
            self.update_status_url, token=self.get_access_token(),
            http_method="POST", parameters={"status": status}
        )
        return self.execute(oauth_request)

    def get_friends(self, page=0):
        oauth_request = self.build_oauth_request(
            self.friends_url, token=self.get_access_token, parameters={"page": page}
        )
        return self.execute(oauth_request)

class DjangoTwitterOAuth(TwitterOAuth):

    def __init__(self):
        try:
            from django.conf import settings
            from django.core.urlresolvers import reverse
            from django.contrib.sites.models import Site
        except ImportError:
            raise

        site = Site.objects.get_current()
        if hasattr(settings, "TWITTER_OAUTH_CALLBACK_URLNAME"):
            self.oauth_callback = "http://%s%s" % (site.domain, reverse(settings.TWITTER_OAUTH_CALLBACK_URLNAME))
        else:
            self.oauth_callback = None

        super(DjangoTwitterOAuth, self).__init__(
            settings.TWITTER_CONSUMER_KEY, settings.TWITTER_CONSUMER_SECRET
        )

    def return_helper(self, request, **kwargs):
        from django.http import Http404
        if not "request_token" in request.session:
            raise Http404()
        token = OAuthToken.from_string(request.session["request_token"])
        del request.session["request_token"]
        if token.key != request.GET.get("oauth_token", "no-token"):
            raise Http404()
        verifier = request.GET["oauth_verifier"]
        access_token = self.exchange_request_token_for_access_token(
            token, verifier
        )
        request.session["access_token"] = access_token.to_string()

    def update_status(self, request, status, oauth_callback=None):
        if not oauth_callback is None:
            self.oauth_callback = oauth_callback
        if "access_token" in request.session:
            if self.is_authenticated(request.session["access_token"]):
                super(DjangoTwitterOAuth, self).update_status(status)
                return True, None
            else:
                del request.session["access_token"]
        token = self.get_unauthorized_request_token(self.oauth_callback)
        auth_url = self.get_authorization_url(token)
        request.session["request_token"] = token.to_string()
        return False, auth_url

    def get_friends(self, request, page=0, oauth_callback=None):
        if not oauth_callback is None:
            self.oauth_callback = oauth_callback
        if "access_token" in request.session:
            if self.is_authenticated(request.session["access_token"]):
                return True, super(DjangoTwitterOAuth, self).get_friends(page)
            else:
                del request.session["access_token"]
        token = self.get_unauthorized_request_token(self.oauth_callback)
        auth_url = self.get_authorization_url(token)
        request.session["request_token"] = token.to_string()
        return False, auth_url
