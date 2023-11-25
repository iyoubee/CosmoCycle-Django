from django.db import models
from django.contrib.auth.models import User
from datetime import datetime

class UserData(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    username = models.TextField()
    token = models.CharField(max_length=6, unique=True)
    poin = models.BigIntegerField(default=0)
    balance = models.BigIntegerField(default=0)

class Prize(models.Model):
    title = models.TextField()
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
    date = models.DateField(default=datetime.now)
    username = models.TextField()
    jenis = models.TextField()
    berat = models.BigIntegerField()
    poin = models.BigIntegerField()
    totalHarga = models.BigIntegerField()

class Withdraw(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    date = models.DateField(default=datetime.now())
    jumlah = models.TextField()
    isApprove = models.TextField(default="PENDING")