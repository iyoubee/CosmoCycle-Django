from django.contrib import admin
from .models import *
# Register your models here.

admin.site.register(UserData)
admin.site.register(Prize)
admin.site.register(RedeemedPrize)
admin.site.register(Deposit)
admin.site.register(Withdraw)