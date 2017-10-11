from pyramid.view import view_config
from pyramid_todo.models import Profile, Task


@view_config(route_name='home', renderer='json')
def my_view(request):
    # query = request.dbsession.query(MyModel)
    # one = query.filter(MyModel.name == 'one').first()
    return {'one': 1, 'project': 'Pyramid To Do'}
