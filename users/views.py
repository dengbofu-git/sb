from django.http import HttpResponse, JsonResponse
from .models import UserProfile,Address,WeiboProfile
from dadashop.utils import md5
from django.views import View
import json
from dadashop.utils import jwt_encode, jwt_decode
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
import random
import base64
from django_redis import get_redis_connection
import re
from ronglian_sms_sdk import SmsSDK
import requests


def check(request):
    try:
        if not request.headers['Authorization']:
            context = {
                'code': 10001,
                'error': '非法用户'
            }
            return JsonResponse(context)
        payload = jwt_decode(request.headers['Authorization'])
        return payload
    except Exception as e:
        context = {
            'code': 10011,
            'error': '数据被篡改',
        }
        return JsonResponse(context)


def activate(request):
    base_str = request.GET.get('code')
    username = request.GET.get('username')
    info1 = base64.urlsafe_b64decode(base_str).decode('utf-8')
    conn = get_redis_connection()
    info2 = conn.get('activation_' + username)
    if not conn.exists('activation_' + username):
        context = {
            'code': 10003,
            'error': '激活链接无效',
        }
        return JsonResponse(context)
    if info1 != info2:
        context = {
            'code': 10001,
            'error': '激活失败',
        }
        return JsonResponse(context)

    try:
        UserProfile.objects.get(username=username)
        context = {
            'code': 200,
            'msg': '激活成功'
        }
    except Exception as e:
        context = {
            'code': 10002,
            'error': '用户名不存在'
        }
    return JsonResponse(context)


def register(request):
    conn = get_redis_connection()
    data = json.loads(request.body)
    uname = data.get('uname')
    password = data.get('password')
    phone = data.get('phone')
    email = data.get('email')
    verify = data.get('verify')
    # 数据校验
    # 校验用户名的长度是否合法(6~11位)
    if len(uname) < 6 or len(uname) > 11:
        context = {
            'code': 10001,
            'error': '用户名长度只能为6~11位之间'
        }
        return JsonResponse(context)
    # 校验用户名是否唯一
    try:
        UserProfile.objects.get(username=uname)
        context = {
            'code': 10002,
            'error': f'用户名{uname}已经被占用 '
        }
        return JsonResponse(context)
    except Exception as e:
        pass
    # 校验密码长度是否合法(6~12位)
    if len(password) < 6 or len(password) > 12:
        context = {
            'code': 10003,
            'error': '密码长度只能为6~12位之间'
        }
        return JsonResponse(context)

    # 校验邮箱的唯一性
    try:
        UserProfile.objects.get(email=email)
        context = {
            'code': 10004,
            'error': '邮箱已经被占用 '
        }
        return JsonResponse(context)
    except Exception as e:
        pass
    # 校验手机号的唯一性
    try:
        UserProfile.objects.get(phone=phone)
        context = {
            'code': 10004,
            'error': '手机号码已经被占用 '
        }
        return JsonResponse(context)
    except Exception as e:
        pass
    # 校验验证码是否为空
    if not verify:
        context = {
            'code': 10005,
            'error': '验证码不能为空'
        }
        return JsonResponse(context)
    if not conn.exists('verify_' + phone):
        context = {
            'code': 10007,
            'error': '验证码已过期'
        }
        return JsonResponse(context)
    if verify != conn.get('verify_' + phone):
        context = {
            'code': 10006,
            'error': '验证码错误'
        }
        return JsonResponse(context)
    # 写入数据
    try:
        user = UserProfile.objects.create(
            username=uname,
            password=md5(password),
            email=email,
            phone=phone
        )
        token = jwt_encode({'id': user.pk, 'username': user.username})
        context = {
            'code': 200,
            'username': uname,
            'token': token,
            'carts_count': 0
        }
        # 邮件发送
        subject = '达达商城注册激活邮件'
        # message = '您正在注册达达商城账号，此邮件仅用于测试，后续功能暂未开放，收到请勿回复。'
        message = ''
        from_email = settings.EMAIL_HOST_USER
        recipient_list = [email]
        code = (uname + str(random.randint(1000, 9999)))
        cache_key = f'activation_{uname}'
        conn.set(cache_key, code, 3 * 86400)
        code = base64.urlsafe_b64encode(code.encode()).decode()
        template_string = render_to_string('activation.html', {'username': uname, 'code': code})
        html_message = template_string
        send_mail(subject=subject, message=message, from_email=from_email, recipient_list=recipient_list,
                  html_message=html_message)
        UserProfile.objects.filter(username=uname).update(is_active=True)
        conn.delete(cache_key)
        conn.delete('verify_' + phone)
    except Exception as e:
        context = {
            'code': 10005,
            'error': '服务器异常'
        }
    return JsonResponse(context)


def code(request):
    data = json.loads(request.body)
    phone = data['phone']
    if not re.match(r'^1[3-9]\d{9}$', phone):
        context = {
            'code': 10001,
            'error': '手机号码格式不正确'
        }
        return JsonResponse(context)
    # try:
    #     UserProfile.objects.get(phone=phone)
    #     context = {
    #         'code': 10002,
    #         'error': '手机号码已经被占用'
    #     }
    #     return JsonResponse(context)
    # except Exception as e:
    #     pass
    # return HttpResponse('ok')
    if UserProfile.objects.filter(phone=phone).exists():
        context = {
            'code': 10002,
            'error': '手机号码已经被占用'
        }
        return JsonResponse(context)
    else:
        accId = settings.RONGLIAN_SMS_ACCOUNT_ID
        accToken = settings.RONGLIAN_SMS_ACCOUNT_TOKEN
        appId = settings.RONGLIAN_SMS_APP_ID
        smssdk_obj = SmsSDK(accId=accId, accToken=accToken, appId=appId)
        tid = settings.RONGLIAN_SMS_MODEL_ID
        conn = get_redis_connection()
        randnum = random.randint(1000, 9999)
        conn.set('verify_' + phone, randnum, 600)
        res = smssdk_obj.sendMessage(tid=tid, mobile=phone, datas=(randnum, 10))
        res = json.loads(res)
        if res['statusCode'] == '000000':
            context = {
                'code': 200,
                'msg': '短信发送成功'
            }
        else:
            context = {
                'code': 10003,
                'error': '短信发送失败'
            }
        return JsonResponse(context)


def login(request):
    data = json.loads(request.body)
    username = data.get('username')
    password = data.get('password')
    if not username:
        context = {
            'code': 10001,
            'error': '用户名不能为空'
        }
        return JsonResponse(context)
    if not password:
        context = {
            'code': 10002,
            'error': '密码不能为空'
        }
        return JsonResponse(context)
    try:
        user = UserProfile.objects.get(username=username, password=md5(password))
        token = jwt_encode({'id': user.pk, 'username': user.username})
        context = {
            'code': 200,
            'username': username,
            'token': token,
            'carts_count': 0
        }
    except Exception as e:
        context = {
            'code': 10003,
            'error': '用户密码错误'
        }
    return JsonResponse(context)


def weibo_authorization(request):
    context = {
        'code': 200,
        'oauth_url': f'https://api.weibo.com/oauth2/authorize?client_id={settings.WEIBO_APP_KEY}&response_type=code&redirect_uri={settings.WEIBO_REDIRECT_URI}'
    }
    return JsonResponse(context)


def weibo_users(request):
    code = request.GET.get('code')
    data = {
        'client_id': settings.WEIBO_APP_KEY,
        'client_secret': settings.WEIBO_APP_SECRET,
        'grant_type': 'authorization_code',
        'redirect_uri': settings.WEIBO_REDIRECT_URI,
        'code': code,
    }

    res = requests.post(url='https://api.weibo.com/oauth2/access_token', data=data)
    access_token = res.json()['access_token']
    uid = res.json()['uid']
    # params = {
    #     'access_token': res.json()['access_token'],
    #     'uid': res.json()['uid'],
    # }
    # info = requests.get(url='https://api.weibo.com/2/users/show.json', params=params)
    try:
        weibo_user = WeiboProfile.objects.get(access_token=access_token)
        if weibo_user.user_profile:
            context = {
                'code': 200,
                'username': weibo_user.user_profile.username,
                'token':access_token
            }
        else:
            context = {
                'code': 201,
                'uid': uid,
            }
    except Exception as e:
        WeiboProfile.objects.create(access_token=access_token,wuid=uid)
    return JsonResponse(context)


def find_password(request):
    data = json.loads(request.body)
    email = data.get('email')
    try:
        UserProfile.objects.get(email=email)
        context = {
            'code': 200,
            'data': '邮件发送成功',
        }
        number = random.randint(1000, 9999)
        conn = get_redis_connection()
        conn.set(f'find_password_{email}', number, 600)
        subject = '达达商城找回密码邮件'
        message = ''
        from_email = settings.EMAIL_HOST_USER
        recipient_list = [email]
        html_message = render_to_string('findpassword.html', {'email': email, 'number': number})
        send_mail(subject=subject, message=message, from_email=from_email, recipient_list=recipient_list,
                  html_message=html_message)
    except Exception as e:
        context = {
            'code': 10001,
            'error': '邮箱不存在'
        }
    return JsonResponse(context)


def verification(request):
    data = json.loads(request.body)
    code = data.get('code')
    email = data.get('email')
    conn = get_redis_connection()
    number = conn.get(f'find_password_{email}')
    if number != code:
        context = {
            'code': 10001,
            'error': '验证码错误'
        }
        return JsonResponse(context)
    else:
        context = {
            'code': 200,
            'data': '验证码通过',
            'email': email,
        }
        conn.delete(f'find_password_{email}')
    return JsonResponse(context)


def new_password(request):
    data = json.loads(request.body)
    email = data.get('email')
    password1 = data.get('password1')
    password2 = data.get('password2')
    if len(password1) > 12 or len(password1) < 6:
        context = {
            'code': 10001,
            'error': '密码长度只能为6~12位之间'
        }
        return JsonResponse(context)
    if password1 != password2:
        context = {
            'code': 10002,
            'error': '两次密码不一致'
        }
    else:
        user = UserProfile.objects.filter(email=data['email']).update(password=md5(password1))
        context = {
            'code': 200,
            'data': 'ok',
        }
    return JsonResponse(context)


def default(request, username):
    data = json.loads(request.body)
    payload = check(request)
    address_id = data.get('id')
    try:
        Address.objects.get(id=address_id)
    except Exception as e:
        context = {
            'code': 10001,
            'error': '地址信息不存在'
        }
        return JsonResponse(context)
    try:
        user = UserProfile.objects.get(username=payload['username'])
    except Exception as e:
        context = {
            'code': 10002,
            'error': '非法用户'
        }
        return JsonResponse(context)
    try:
        user.address_set.filter(is_delete=False).get(id=address_id)
    except:
        context = {
            'code': 10004,
            'error': '地址信息不属于当前用户'
        }
        return JsonResponse(context)
    try:
        user.address_set.filter(is_delete=False).update(is_default=False)
        Address.objects.filter(id=address_id).update(is_default=True)
        context = {
            'code': 200,
            'data': '设置成功',
        }
    except Exception as e:
        context = {
            'code': 10003,
            'error': '服务器异常'
        }
    return JsonResponse(context)


def password_change(request, username):
    data = json.loads(request.body)
    oldpassword = data.get('oldpassword')
    password1 = data.get('password1')
    password2 = data.get('password2')
    try:
        UserProfile.objects.filter(username=username).get(password=md5(oldpassword))
    except Exception as e:
        context = {
            'code': 10003,
            'error': '密码错误'
        }
        return JsonResponse(context)
    if not password1:
        context = {
            'code': 10004,
            'error': '新密码不能为空'
        }
        return JsonResponse(context)
    if len(password1) > 12 or len(password1) < 6:
        context = {
            'code': 10005,
            'error': '密码长度只能为6~12位之间'
        }
        return JsonResponse(context)
    if password1 != password2:
        context = {
            'code': 10002,
            'error': '两次密码不一致'
        }
        return JsonResponse(context)
    try:
        UserProfile.objects.filter(username=username).update(password=md5(password1))
        context = {
            'code': 200,
            'data': '修改成功'
        }
    except Exception as e:
        context = {
            'code': 10001,
            'error': '服务器异常'
        }
    return JsonResponse(context)


class AddressView(View):
    def get(self, request, username):
        payload = check(request)
        try:
            user = UserProfile.objects.get(username=payload['username'])
        except Exception as e:
            context = {
                'code': 10002,
                'error': '非法用户',
            }
            return JsonResponse(context)
        addresslist = user.address_set.values('id', 'address', 'receiver', 'receiver_mobile', 'tag', 'postcode',
                                              'is_default').filter(is_delete=False)
        try:
            context = {
                'code': 200,
                'addresslist': list(addresslist)
            }
        except Exception as e:
            context = {
                'code': 10001,
                'error': '服务器异常'
            }
        return JsonResponse(context)

    def post(self, request, username):
        payload = check(request)
        data = json.loads(request.body)
        receiver = data.get('receiver')
        if len(receiver) > 10 or not receiver:
            context = {
                'code': 10001,
                'error': '收件人姓名长度不符'
            }
            return JsonResponse(context)
        receiver_phone = data.get('receiver_phone')
        if len(receiver_phone) > 11 or not receiver_phone:
            context = {
                'code': 10002,
                'error': '收件人号码长度不符'
            }
            return JsonResponse(context)
        address = data.get('address')
        if len(address) > 100 or not address:
            context = {
                'code': 10003,
                'error': '收件人地址长度不符'
            }
            return JsonResponse(context)
        postcode = data.get('postcode')
        if len(postcode) > 7 or not postcode:
            context = {
                'code': 10004,
                'error': '收件人邮编长度不符'
            }
            return JsonResponse(context)
        tag = data.get('tag')
        if len(tag) > 10 or not tag:
            context = {
                'code': 10005,
                'error': '收件人标签长度不符'
            }
            return JsonResponse(context)
        try:
            user_profile = UserProfile.objects.get(username=payload['username'])
        except Exception as e:
            context = {
                'code': 10007,
                'error': '非法用户',
            }
            return JsonResponse(context)
        try:
            address_count = user_profile.address_set.filter(is_delete=False).count()
            Address.objects.create(
                receiver=receiver,
                receiver_mobile=receiver_phone,
                address=address,
                postcode=postcode,
                tag=tag,
                is_default=not address_count,
                user_profile=UserProfile.objects.get(username=payload['username']),
            )
            context = {
                'code': 200,
                'data': '新增地址成功!'
            }
        except Exception as e:
            context = {
                'code': 10006,
                'error': '服务器异常',
            }
        return JsonResponse(context)

    def put(self, request, username, id):
        # 1.保证该id地址信息必须存在    2.该id地址信息必须为当前用户地址
        payload = check(request)
        data = json.loads(request.body)
        receiver = data.get('receiver')
        receiver_mobile = data.get('receiver_mobile')
        address = data.get('address')
        tag = data.get('tag')
        address_id = data.get('id')
        try:
            Address.objects.get(id=address_id)
        except Exception as e:
            context = {
                'code': 10001,
                'error': '地址信息不存在'
            }
            return JsonResponse(context)
        try:
            user = UserProfile.objects.get(username=payload['username'])
        except Exception as e:
            context = {
                'code': 10003,
                'error': '非法用户'
            }
            return JsonResponse(context)
        try:
            user.address_set.filter(is_delete=False).get(id=address_id)
        except:
            context = {
                'code': 10002,
                'error': '地址信息不属于当前用户'
            }
            return JsonResponse(context)
        try:
            Address.objects.filter(id=address_id).update(
                receiver=receiver,
                receiver_mobile=receiver_mobile,
                address=address,
                tag=tag, )
            context = {
                'code': 200,
                'data': '修改地址成功'
            }
        except Exception as e:
            context = {
                'code': 10003,
                'error': '服务器异常'
            }
        return JsonResponse(context)

    def delete(self, request, username, id):
        data = json.loads(request.body)
        payload = check(request)
        try:
            user = UserProfile.objects.get(username=payload['username'])
        except Exception as e:
            context = {
                'code': 10001,
                'error': '非法用户'
            }
            return JsonResponse(context)
        address_id = data.get('id')
        address = Address.objects.filter(id=address_id)
        if address[0].is_default:
            context = {
                'code': 10001,
                'error': '默认地址不能删除'
            }
            return JsonResponse(context)

        try:
            address.update(is_delete=True)
            context = {
                'code': 200,
                'data': '删除地址成功'
            }
        except Exception as e:
            context = {
                'code': 10001,
                'error': '服务器异常'
            }
        return JsonResponse(context)

    def patch(self, request, username):
        return HttpResponse('patch')
