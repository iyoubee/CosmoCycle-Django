from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class UserData(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    username = models.TextField()
    token = models.CharField(max_length=6, unique=True)
    poin = models.BigIntegerField(default=0)
    balance = models.BigIntegerField(default=0)

class Prize(models.Model):
    title = models.TextField()
    picture = models.TextField()
    poin = models.BigIntegerField()
    stok = models.BigIntegerField()
    desc = models.TextField()

class RedeemedPrize(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    stok = models.BigIntegerField(default=1)
    title = models.TextField()
    desc = models.TextField()

class Deposit(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    date = models.DateField(default=timezone.now)
    username = models.TextField()
    waste_type = models.TextField()
    weight = models.BigIntegerField()
    poin = models.BigIntegerField()
    total_price = models.BigIntegerField()

class Withdraw(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    date = models.DateField(default=timezone.now)
    method = models.TextField()
    provider = models.TextField()
    account_no = models.TextField()
    amount = models.BigIntegerField(default=0)
    isApprove = models.TextField(default="PENDING")