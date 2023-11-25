from django.urls import path
from .views import *

app_name = 'api'

urlpatterns = [
    path('', index, name='index'),

    # auth
    path('register', register, name='register'),
    path('admin-register', register_admin, name='register'),
    path('login', login, name='login'),
    path('logout', logout_user, name='logout_user'),
    path('islogedin', get_is_logedin, name='get_is_logedin'),
]