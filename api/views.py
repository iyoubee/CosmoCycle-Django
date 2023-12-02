# import respons util
from django.core import serializers
from django.http.response import JsonResponse

# import role util
from rolepermissions.roles import assign_role, get_user_roles
from project_django.roles import superUser, commonUser
from rolepermissions.checkers import has_role

# imoport model
from django.contrib.auth.models import User
from .models import UserData, Prize, RedeemedPrize, Deposit, Withdraw

# import auth util
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login as auth_login, logout

from django.forms.models import model_to_dict
from django.core.serializers import serialize
import json

def index(request):
    return JsonResponse({ "status": 200, "message": "Halo..." }, status=200)

@csrf_exempt
def register(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        if username and password:
            try:
                acc = User.objects.create(username=username)
                if acc:
                    acc.set_password(password)
                    acc.save()
                    UserData.objects.create(user=acc, username=username)
                    assign_role(acc, commonUser)
                    return JsonResponse({ "status": 200, "message": "Successfully Register!" }, status=200)
                else:
                    return JsonResponse({ "status": 500, "message": "Terjadi masalah!" }, status=500)
            except:
                return JsonResponse({ "status": 406, "message": "Username sudah pernah digunakan." }, status=406)
        else:
            return JsonResponse({ "status": 400, "message": "username dan password tidak boleh kosong" }, status=400)
    return JsonResponse({"status": 502, "message": "Method not allowed"}, status=502)

@csrf_exempt
def register_admin(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        if username and password:
            try:
                acc = User.objects.create(username=username)
                if acc:
                    acc.set_password(password)
                    acc.save()
                    UserData.objects.create(user=acc, username=username)
                    assign_role(acc, superUser)
                    return JsonResponse({ "status": 200, "message": "Successfully Register!" }, status=200)
                else:
                    return JsonResponse({ "status": 500, "message": "Terjadi masalah!" }, status=500)
            except:
                return JsonResponse({ "status": 406, "message": "Username sudah pernah digunakan." }, status=406)
        else:
            return JsonResponse({ "status": 400, "message": "username dan password tidak boleh kosong" }, status=400)
    return JsonResponse({"status": 502, "message": "Method not allowed"}, status=502)

@csrf_exempt
def login(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        if username and password:
            user = authenticate(username=username, password=password)
            if user is not None:
                auth_login(request, user)
                if (has_role(user, superUser)):
                    return JsonResponse({ "status": 200, "message": "Successfully Logged In!", "role":'admin' }, status=200)
                else:
                    return JsonResponse({ "status": 200, "message": "Successfully Logged In!", "role":'user' }, status=200)
            else:
                return JsonResponse({
                "status": 401,
                "message": "Failed to Login, check your email/password.",
                }, status=401)
        else:
            return JsonResponse({ "status": 400, "message": "username dan password tidak boleh kosong" }, status=400)
    return JsonResponse({"message": "Method not allowed", 'status':502}, status=502)

@csrf_exempt
def logout_user(request):
    logout(request)
    return JsonResponse({"message": "Berhasil logout", 'status':200}, status=200)

@csrf_exempt
def admin_get_user_by_token(request):
    user = request.user
    if has_role(user, superUser):
        token = request.POST.get('token')
        try:
            userData = UserData.objects.get(token=token)
            return JsonResponse({"id": userData.pk, "username": userData.username}, status=200)
        except UserData.DoesNotExist:
            return JsonResponse({"message": "User not found"}, status=404)
    return JsonResponse({"message": "Unauthorized"}, status=403)

@csrf_exempt
def admin_get_deposit(request):
    user = request.user
    if has_role(user, superUser):
        deposits = Deposit.objects.all().order_by('-pk')
        serialized_deposits = serialize("json", deposits)
        deposits_data = json.loads(serialized_deposits)  # Convert to Python object
        return JsonResponse(deposits_data, status=200, safe=False)
    return JsonResponse({"message": "Unauthorized"}, status=403)

@csrf_exempt
def admin_get_deposit_count(request):
    user = request.user
    if (has_role(user, superUser)):
        count = Deposit.objects.all().count()
        return JsonResponse({"count": count}, status=200)
    return JsonResponse({ "message": "Unauthorized" }, status=403)

@csrf_exempt
def admin_add_deposit(request):
    user = request.user
    if (has_role(user, superUser)):
        if request.method == 'POST':
            PAPER_PRICE = 4000
            PLASTIC_PRICE = 5000
            GLASS_PRICE = 7000
            METAL_PRICE = 10000
            username = request.POST.get('username')
            waste_type = request.POST.get('waste_type')
            weight = int(request.POST.get('weight'))
            userData = UserData.objects.get(username=username)
            if (weight > 0):
                total_price = 0
                if waste_type == "paper":
                    total_price = weight * PAPER_PRICE
                elif waste_type == "plastic":
                    total_price = weight * PLASTIC_PRICE
                elif waste_type == "glass":
                    total_price = weight * GLASS_PRICE
                elif waste_type == "metal":
                    total_price = weight * METAL_PRICE
                poin = total_price // 1000
                deposit = Deposit(weight=weight, waste_type=waste_type, total_price=total_price, poin=poin, user=userData.user, username=username)
                deposit.save()
                userData.poin += poin
                userData.balance += total_price
                userData.save()
                return JsonResponse({"message": "Deposit diajukan" ,"status":200}, status=200) 
            return JsonResponse({ "message": "Input tidak valid", "status":400}, status=400)
        return JsonResponse({"message": "Method not allowed", "status":502}, status=502)
    return JsonResponse({ "message": "Unauthorized" , "status":403}, status=403)

@csrf_exempt
def admin_add_prize(request):
    user = request.user
    if (has_role(user, superUser)):
        if request.method == 'POST':
            title = request.POST.get('title')
            picture = request.POST.get('picture')
            poin = int(request.POST.get('poin'))
            stok = int(request.POST.get('stok'))
            desc = request.POST.get('desc')
            if (poin > 0 and stok > 0):
                prize = Prize(title=title, poin=poin, stok=stok, desc=desc, picture=picture)
                prize.save()
                return JsonResponse({"message": "Prize Dibuat", 'status':200}, status=200) 
            return JsonResponse({"message": "Poin dan Stok tidak boleh 0", 'status':200}, status=200) 
        return JsonResponse({"message": "Method not allowed", 'status':502}, status=502)
    return JsonResponse({ "message": "Unauthorized" , "status":403}, status=403)

@csrf_exempt
def admin_get_prize(request):
    user = request.user
    if (has_role(user, superUser)):
        prize = Prize.objects.all().order_by('-pk')
        serialized_prize = serialize("json", prize)
        prize_data = json.loads(serialized_prize)  # Convert to Python object
        return JsonResponse(prize_data, status=200, safe=False)
    return JsonResponse({ "message": "Unauthorized" }, status=403)

@csrf_exempt
def admin_del_prize(request):
    user = request.user
    if (has_role(user, superUser)):
        if request.method == 'POST':
            idx = int(request.POST.get('id'))
            prize = Prize.objects.get(pk=idx)
            prize.delete()
            return JsonResponse({"message": "Deposit Diterima", 'status':200}, status=200) 
        return JsonResponse({"message": "Method not allowed", 'status':502}, status=502)
    return JsonResponse({ "message": "Unauthorized", 'status':403}, status=403)

@csrf_exempt
def admin_approve_withdraw(request):
    user = request.user
    if has_role(user, superUser):
        if request.method == 'POST':
            id = int(request.POST.get('id'))
            user_data = UserData.objects.get(user=user)
            withdraw = Withdraw.objects.get(pk=id)
            if (withdraw is not None and withdraw.isApprove == "PENDING"):
                withdraw.isApprove = "APPROVED"
                withdraw.save()
                user_data.balance -= withdraw.amount
                user.save()
                return JsonResponse({"message": "Penarikan Berhasil", 'status':200}, status=200) 
            return JsonResponse({"message": "Input tidak valid", 'status':300}, status=200) 
        return JsonResponse({"message": "Method not allowed", 'status':502}, status=502)
    return JsonResponse({ "message": "Unauthorized" , 'status':403}, status=403)

@csrf_exempt
def user_get_token(request):
    user = request.user
    if (has_role(user, commonUser)):
        userData = UserData.objects.get(user=user)
        return JsonResponse({"id": userData.pk, "token": userData.token}, status=200)
    return JsonResponse({ "message": "Unauthorized" }, status=403)

@csrf_exempt
def user_get_prize(request):
    user = request.user
    if has_role(user, commonUser):
        prize = Prize.objects.all().order_by('-pk')
        serialized_prize = serialize("json", prize)
        prize_data = json.loads(serialized_prize)  # Convert to Python object
        return JsonResponse(prize_data, status=200, safe=False)
    return JsonResponse({"message": "Unauthorized"}, status=403)

@csrf_exempt
def user_get_redeemed_prize(request):
    user = request.user
    if has_role(user, commonUser):
        redeemed_prizes = RedeemedPrize.objects.filter(user=user).order_by('-pk')
        serialized_redeemed_prizes = serialize("json", redeemed_prizes)
        redeemed_prizes_data = json.loads(serialized_redeemed_prizes)  # Convert to Python object
        return JsonResponse(redeemed_prizes_data, status=200, safe=False)
    return JsonResponse({"message": "Unauthorized"}, status=403)

@csrf_exempt
def user_redeem_prize(request):
    user = request.user
    if (has_role(user, commonUser)):
        if request.method == 'POST':
            itemId = int(request.POST.get('id'))
            prize = Prize.objects.get(pk=itemId)
            check_prize = RedeemedPrize.objects.filter(user=user, title=prize.title).first()
            if prize.stok > 0: # Stok harus ada
                userdata = UserData.objects.get(user=user)
                if (userdata.poin >= prize.poin): # Poin harus cukup
                    if(check_prize == None): # Berarti ini prize baru yang di-redeem sama user
                        redeemedprize = RedeemedPrize(
                            title=prize.title,
                            user=user,
                            desc=prize.desc
                        )
                        redeemedprize.save()
                    else: # Berarti jenis prize ini udah pernah di-redeem sama user, kita cuma perlu update stok-nya aja
                        redeemedprize = RedeemedPrize.objects.get(user=user, title=prize.title)
                        redeemedprize.stok += 1
                        redeemedprize.save()

                    prize.stok -= 1 # Set stok prize setelah redeem
                    prize.save()

                    userdata.poin -= prize.poin # Kurangi poin user setelah redeem
                    userdata.save()

                    return JsonResponse({"message": "Berhasil Redeem"}, status=200) 
                return JsonResponse({"message": "Poin Kurang"}, status=200) 
            return JsonResponse({"message": "Stok Habis"}, status=200) 
        return JsonResponse({"message": "Method not allowed"}, status=502)
    return JsonResponse({ "message": "Unauthorized" }, status=403)

@csrf_exempt
def user_use_prize(request):
    user = request.user
    role = get_user_roles(user)
    if (has_role(user, commonUser)):
        if request.method == 'POST':
            try:
                itemId = int(request.POST.get('id'))
                redeemedprize = RedeemedPrize.objects.get(user=user, pk=itemId) # Search redeemed prize
                if redeemedprize.stok == 1: # If there's only 1 prize, it will be deleted from database
                    redeemedprize.delete()
                else: # Stok redeemed prize lebih dari 1, berarti saat digunakan stok-nya akan berkurang
                    redeemedprize.stok -= 1
                    redeemedprize.save()
                return JsonResponse({"message": "Prize berhasil digunakan"}, status=200) 
            except:
                return JsonResponse({"message": "Ada yang salah"}, status=500)
        return JsonResponse({"message": "Method not allowed"}, status=502)
    return JsonResponse({ "message": "Unauthorized" }, status=403)

@csrf_exempt
def user_add_withdraw(request):
    user = request.user
    if has_role(user, commonUser):
        if request.method == 'POST':
            method = int(request.POST.get('method'))
            provider = int(request.POST.get('provider'))
            account_no = int(request.POST.get('account_no'))
            amount = int(request.POST.get('amount'))
            user = UserData.objects.get(user=user)
            str_account_no = str(account_no)
            if amount < 25000:
                return JsonResponse({"message": "Minimum 25.000", 'status':300}, status=200) 
            if method == "bank transfer" and not len(str_account_no) == 9:
                return JsonResponse({"message": "Input tidak valid", 'status':300}, status=200) 
            if method == "e-wallet" and (len(str_account_no) < 9 or not str_account_no.startswith("08")):
                return JsonResponse({"message": "Input tidak valid", 'status':300}, status=200) 
            if (amount > 0):
                if (user.balance >= amount):
                    withdraw = Withdraw(user=user, method=method, provider=provider, account_no=account_no, amount=amount)
                    withdraw.save()
                    return JsonResponse({"message": "Penarikan Berhasil", 'status':200}, status=200) 
                return JsonResponse({"message": "Saldo Kurang", 'status':300}, status=200) 
            return JsonResponse({"message": "Input tidak valid", 'status':300}, status=200) 
        return JsonResponse({"message": "Method not allowed", 'status':502}, status=502)
    return JsonResponse({ "message": "Unauthorized" , 'status':403}, status=403)

@csrf_exempt
def user_get_withdraw(request):
    user = request.user
    if has_role(user, commonUser):
        withdraws = Withdraw.objects.filter(user=user).order_by('-pk')
        serialized_withdraws = serialize("json", withdraws)
        withdraws_data = json.loads(serialized_withdraws)  # Convert to Python object
        return JsonResponse(withdraws_data, status=200, safe=False)
    return JsonResponse({"message": "Unauthorized"}, status=403)

@csrf_exempt
def user_get_deposit(request):
    user = request.user
    if has_role(user, commonUser):
        deposit = Deposit.objects.filter(user=user).order_by('-pk')
        serialized_deposit = serialize("json", deposit)
        deposit_data = json.loads(serialized_deposit)  # Convert to Python object
        return JsonResponse(deposit_data, safe=False, status=200)
    return JsonResponse({"message": "Unauthorized"}, status=403)

@csrf_exempt
def user_get_data(request):
    user = request.user
    if has_role(user, commonUser):
        userdata = UserData.objects.filter(user=user)
        serialized_userdata = serialize("json", userdata)
        userdata_data = json.loads(serialized_userdata)  # Convert to Python object
        return JsonResponse(userdata_data, status=200, safe=False)
    return JsonResponse({"message": "Unauthorized"}, status=403)

@csrf_exempt
def get_is_logedin(request):
    user = request.user
    if (has_role(user, commonUser)):
        return JsonResponse({ "isUser": "true", "role": "user"  }, status=200)
    elif (has_role(user, superUser)):
        return JsonResponse({ "isUser": "true", "role": "admin" }, status=200)
    return JsonResponse({ "message": "Unauthorized" }, status=403)