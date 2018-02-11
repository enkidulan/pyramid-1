from pyramid.view import exception_view_config
from pyramid.view import forbidden_view_config
from pyramid.view import notfound_view_config
from .main import ValidationError


@notfound_view_config(renderer='json', append_slash=True)
def notfound_view(request):
    request.response.status = 404
    return {'error': 'Page not found'}


@forbidden_view_config(renderer='json')
def forbidden_view(exc, request):
    request.response.status = 403
    return {'error': 'You are not allowed'}


@exception_view_config(ValidationError, renderer='json')
def validation_error_view(request):
    request.response.status_code = 400
    return {'error': str(request.exception)}
