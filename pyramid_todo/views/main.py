"""View functions."""
from datetime import datetime
from collections import OrderedDict

from passlib.hash import pbkdf2_sha256 as hasher
from pyramid.security import NO_PERMISSION_REQUIRED, remember, forget
from pyramid.view import view_config, view_defaults

from pyramid_todo.models import Task, Profile


class ValidationError(Exception):
    pass


@view_config(
    route_name='info', renderer='json', permission=NO_PERMISSION_REQUIRED, request_method="GET"
)
def info_view(request):
    """List of routes for this API."""
    return OrderedDict((
        ('info', 'GET /api/v1'),
        ('register', 'POST /api/v1/accounts'),
        ('single profile detail', 'GET /api/v1/accounts/<username>'),
        ('edit profile', 'PUT /api/v1/accounts/<username>'),
        ('delete profile', 'DELETE /api/v1/accounts/<username>'),
        ('login', 'POST /api/v1/accounts/login'),
        ('logout', 'GET /api/v1/accounts/logout'),
        ('user\'s tasks', 'GET /api/v1/accounts/<username>/tasks'),
        ('create task', 'POST /api/v1/accounts/<username>/tasks'),
        ('task detail', 'GET /api/v1/accounts/<username>/tasks/<id>'),
        ('task update', 'PUT /api/v1/accounts/<username>/tasks/<id>'),
        ('delete task', 'DELETE /api/v1/accounts/<username>/tasks/<id>'),
    ))


class BaseView:
    def __init__(self, request):
        self.request = request
        self.context = request.context
        self.response = request.response
        self.dbsession = request.dbsession


@view_defaults(route_name='one_task', permission='manage', renderer='json')
class TaskCRUDView(BaseView):

    @property
    def received_data(self):
        return {f: self.request.json[f] for f in Task._editable_fields if f in self.request.json}

    @view_config(route_name='tasks-list')
    def tasks_list(self):
        """List tasks for one user."""
        return {
            'username': self.request.user.username,
            'tasks': [task.to_dict() for task in self.context],
        }

    @view_config(route_name='tasks-create')
    def task_create(self):
        """Create a new task for this user."""
        try:
            self.dbsession.add(Task(
                creation_date=datetime.now(),
                profile_id=self.request.user.id,
                profile=self.request.user,
                **self.received_data
            ))
            self.response.status_code = 201
            return {'msg': 'posted'}
        except KeyError:
            raise ValidationError('Some fields are missing.')

    @view_config(request_method='GET')
    def task_detail(self):
        """Get task detail for one user given a task ID."""
        return {'username': self.request.user.username, 'task': self.context.to_dict()}

    @view_config(request_method='PUT')
    def task_update(self):
        """Update task information for one user's task."""
        for field, value in self.received_data.items():
            setattr(self.context, field, value)
        return {'username': self.request.user.username, 'task': self.context.to_dict()}

    @view_config(request_method='DELETE')
    def task_delete(self):
        """Delete a task."""
        self.dbsession.delete(self.context)
        return {'username': self.request.user.username, 'msg': 'Deleted.'}


@view_defaults(route_name='one_profile', permission='manage', renderer='json')
class ProfileCRUDView(BaseView):

    @view_config(request_method='GET')
    def profile_detail(self):
        """Get detail for one profile."""
        return self.context.to_dict()

    @view_config(request_method='PUT')
    def profile_update(self):
        """Update an existing profile."""
        if 'username' in self.request.POST and self.request.POST['username'] != '':
            self.context.username = self.request.POST['username']
        if 'email' in self.request.POST and self.request.POST['email'] != '':
            self.context.email = self.request.POST['email']
        if 'password' in self.request.POST and 'password2' in self.request.POST and self.request.POST['password'] == self.request.POST['password2'] and self.request.POST['password'] != '':
            self.context.password = hasher.hash(self.request.POST['password'])
        self.dbsession.add(self.context)
        self.dbsession.flush()
        self.response.status_code = 202
        return {
            'msg': 'Profile updated.',
            'profile': self.context.to_dict(),
            'username': self.context.username
        }

    @view_config(request_method='DELETE')
    def profile_delete(self):
        """Delete an existing profile."""
        self.dbsession.delete(self.context)
        self.response.status_code = 204
        self.response.headers = forget(self.request)


@view_defaults(permission=NO_PERMISSION_REQUIRED, renderer='json')
class AuthViews(BaseView):

    @view_config(route_name='login', request_method='POST')
    def login(self):
        """Authenticate a user."""

        username = self.request.json.get('username', None)
        password = self.request.json.get('password', None)

        if not (username and password):
            raise ValidationError('Some fields are missing')

        profile = self.dbsession.query(Profile).filter(
            Profile.username == username).first()
        if not (profile and hasher.verify(password, profile.password)):
            raise ValidationError('Incorrect username/password combination.')

        headers = remember(self.request, username)
        self.response.status_code = 202
        self.response.headers.extend(headers)
        return {'msg': 'Authenticated'}

    @view_config(route_name='logout', request_method="GET")
    def logout(self):
        """Remove user authentication from requests."""
        headers = forget(self.request)
        self.response.headers.extend(headers)
        return {'msg': 'Logged out.'}

    @view_config(route_name='register', request_method='POST')
    def register(self):
        """Add a new user profile if it doesn't already exist."""
        needed = ['username', 'email', 'password', 'password2']

        if set(needed) - set(self.request.json):
            raise ValidationError('Some fields are missing')

        if self.request.json['password'] != self.request.json['password2']:
            raise ValidationError('Passwords don\'t match')

        username_is_taken = self.dbsession.query(
            Profile.username).filter(Profile.username == self.request.json['username']).count()
        if username_is_taken:
            raise ValidationError('Username "{}" is already taken'.format(self.request.json['username']))

        new_profile = Profile(
            username=self.request.json['username'],
            email=self.request.json['email'],
            password=hasher.hash(self.request.json['password']),
            date_joined=datetime.now(),
        )
        self.dbsession.add(new_profile)
        headers = remember(self.request, self.request.json['username'])
        self.response.status_code = 201
        self.response.headers.extend(headers)
        return {"msg": 'Profile created'}
