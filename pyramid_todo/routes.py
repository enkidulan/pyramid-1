from pyramid_todo.models import Task, Profile
from pyramid.httpexceptions import HTTPNotFound
from pyramid.security import Allow

username = '{username:[\w\-\.]+}'


def includeme(config):
    config.add_static_view('static', 'static', cache_max_age=3600)
    config.add_route('info', '/api/v1')
    config.add_route('register', '/api/v1/accounts')
    config.add_route('login', '/api/v1/accounts/login')
    config.add_route('logout', '/api/v1/accounts/logout')
    config.add_route('one_profile', '/api/v1/accounts/{username}', factory=profile_factory)
    config.add_route('tasks-create', '/api/v1/accounts/{username}/tasks', request_method='POST', factory=new_task_factory)
    config.add_route('tasks-list', '/api/v1/accounts/{username}/tasks', request_method='GET', factory=tasks_list_factory)
    config.add_route('one_task', '/api/v1/accounts/{username}/tasks/{id:\d+}', factory=task_factory)


def profile_factory(request):
    """ Load profile from storage and return it into viewas a context . """
    profile_username = request.matchdict['username']
    profile = request.dbsession.query(Profile).filter(Profile.username == profile_username).first()
    if profile is None:
        raise HTTPNotFound
    return profile


def tasks_list_factory(request):
    """ Return as a context tasks query with attached `__acl__`. """
    username = request.matchdict['username']
    tasks = request.dbsession.query(Task).filter(Task.profile == request.user)
    tasks.__acl__ = ((Allow, 'user:' + username, 'manage'), )
    return tasks


def task_factory(request):
    """ Load task from storage and return it into view as a context. """
    task_id = request.matchdict['id']
    task = tasks_list_factory(request).filter(Task.id == task_id).first()
    if task is None:
        raise HTTPNotFound
    return task


def new_task_factory(request):
    """ Define if a user can create a `task` within given context (`username`). """
    class CreateTaskACLContext:
        __acl__ = ((Allow, 'user:' + request.matchdict['username'], 'manage'), )
    return CreateTaskACLContext()
