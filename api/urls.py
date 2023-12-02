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

    # admin
    path('admin/token', admin_get_user_by_token, name='admin_get_user_by_token'),
    path('admin/deposit/get', admin_get_deposit, name='admin_get_deposit'),
    path('admin/deposit/count', admin_get_deposit_count, name='admin_get_deposit_count'),
    path('admin/deposit/add', admin_add_deposit, name='admin_add_deposit'),
    path('admin/prize/get', admin_get_prize, name='admin_get_prize'),
    path('admin/prize/add', admin_add_prize, name='admin_add_prize'),
    path('admin/prize/del', admin_del_prize, name='admin_del_prize'),
    
    # user
    path('user/token', user_get_token_by_id, name='user_get_token_by_id'),
    path('user/data/get', user_get_data, name='user_get_data'),
    path('user/prize/get', user_get_prize, name='user_get_prize'),
    path('user/prize/redeem/get', user_get_redeemed_prize, name='user_get_redeemed_prize'),
    path('user/prize/redeem', user_redeem_prize, name='user_redeem_prize'),
    path('user/prize/redeem/use', user_use_prize, name='user_use_prize'),
    path('user/withdraw/get', user_get_withdraw, name='user_get_withdraw'),
    path('user/withdraw/add', user_add_withdraw, name='user_add_withdraw'),
    path('user/deposit/get', user_get_deposit, name='user_get_deposit'),

    # all
    path('islogedin', get_is_logedin, name='get_is_logedin'),
    
    path('user/prize/get', user_get_prize, name='user_get_prize'),
    path('user/prize/redeem', user_redeem_prize, name='user_redeem_prize'),
]