import hashlib
import jwt
from django.conf import settings


def md5(string):
    md5 = hashlib.md5()
    md5.update(string.encode())
    return md5.hexdigest()


def jwt_encode(payload):
    key = settings.JWT_SECRET_KEY
    jwt_string = jwt.encode(payload=payload, key=key, )
    return jwt_string


def jwt_decode(jwt_string):
    key = settings.JWT_SECRET_KEY
    payload = jwt.decode(jwt_string, key=key, algorithms='HS256')
    return payload
