from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import string
import random

random_token = ''.join(random.choice(string.ascii_uppercase) for _ in range(6))

class UserData(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    username = models.CharField(max_length=150, unique=True)  # Adjust max_length as needed
    token = models.CharField(max_length=6, unique=True, default=random_token)
    poin = models.BigIntegerField(default=0)
    balance = models.BigIntegerField(default=0)

class Prize(models.Model):
    title = models.TextField()
    picture = models.TextField(default='')  # Add default value here
    poin = models.BigIntegerField()
    stok = models.BigIntegerField()
    desc = models.TextField()

class RedeemedPrize(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    stok = models.BigIntegerField(default=1)
    title = models.TextField(default='')
    desc = models.TextField(default='')

class Deposit(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    date = models.DateField(default=timezone.now)
    username = models.TextField(default='')
    waste_type = models.TextField(default='')
    weight = models.BigIntegerField()
    poin = models.BigIntegerField()
    total_price = models.BigIntegerField()

class Withdraw(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    date = models.DateField(default=timezone.now)
    method = models.TextField(default='')
    provider = models.TextField(default='')
    account_no = models.TextField(default='')
    amount = models.BigIntegerField(default=0)
    isApprove = models.TextField(default="PENDING")