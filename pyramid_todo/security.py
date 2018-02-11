import os
from pyramid.authentication import AuthTktAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.security import Authenticated, Allow, Everyone
from pyramid_todo.models import Profile
from passlib.hash import pbkdf2_sha256 as hasher


class Root(object):
    """ Root view with permissions. """
    def __init__(self, request):
        self.request = request

    __acl__ = [(Allow, Authenticated, 'view'), ]


class AuthenticationPolicy(AuthTktAuthenticationPolicy):
    """ Authentication policy. """

    def authenticated_userid(self, request):
        """ Return ``userid`` or ``None``. """
        user = request.user
        if user is not None:
            return user.id

    def effective_principals(self, request):
        """ Return a list of effective principals.

        If user is authenticated return: [Authenticated, 'user:{user_id}'].
        """
        principals = [Everyone]
        user = request.user
        if user is not None:
            principals.append(Authenticated)
            principals.append('user:' + user.username)
        return principals


def get_user(request):
    """Return user `profile` or `None`."""
    username = request.unauthenticated_userid
    if username is not None:
        user = request.dbsession.query(Profile).filter(Profile.username == username).first()
        return user


def includeme(config):
    """Include this security configuration for the configurator."""

    auth_secret = os.environ.get('AUTH_SECRET', 's00persekret')
    authn_policy = AuthenticationPolicy(secret=auth_secret, hashalg='sha512')
    authz_policy = ACLAuthorizationPolicy()

    config.set_authentication_policy(authn_policy)
    config.set_authorization_policy(authz_policy)
    config.add_request_method(get_user, 'user', reify=True)
    config.set_default_permission('view')
    config.set_root_factory(Root)
