from django.urls import path
from . import views
from .views import AddressView

urlpatterns = [
    path('register', views.register),
    path('login', views.login),
    path('<str:username>/address', AddressView.as_view()),
    path('<str:username>/address/<int:id>', AddressView.as_view()),
    path('<str:username>/address/default', views.default),
    path('<str:username>/password', views.password_change),
    path('activation', views.activate),
    path('password/sms', views.find_password),
    path('password/verification', views.verification),
    path('password/new', views.new_password),
    path('sms/code', views.code),
    path('weibo/authorization', views.weibo_authorization),
    path('weibo/users', views.weibo_users)
]
