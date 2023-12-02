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
    
    path('user/prize/get', user_get_prize, name='user_get_prize'),
    path('user/prize/redeem', user_redeem_prize, name='user_redeem_prize'),
]