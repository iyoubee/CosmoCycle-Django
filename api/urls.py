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

    # admin
    path('admin/token', admin_get_user_by_token, name='admin_get_user_by_token'),
    path('admin/deposit/get', admin_get_deposit, name='admin_get_deposit'),
    path('admin/deposit/count', admin_get_deposit_count, name='admin_get_deposit_count'),
    path('admin/deposit/add', admin_add_deposit, name='admin_add_deposit'),

    # user
    path('user/data/get', user_get_data, name='user_get_data'),
    path('user/deposit/get', user_get_deposit, name='user_get_deposit'),
    path('user/withdraw/get', user_get_withdraw, name='user_get_withdraw'),
    path('user/withdraw/add', user_add_withdraw, name='user_add_withdraw'),
    path('user/prize/redeem/get', user_get_redeemed_prize, name='user_get_redeemed_prize'),
    path('user/prize/redeem/use', user_use_prize, name='user_use_prize'),

    # all
    path('islogedin', get_is_logedin, name='get_is_logedin'),
    
]