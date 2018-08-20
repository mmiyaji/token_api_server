import os
from django.conf import settings
from django.conf.urls import include, url
from rest_framework_jwt.views import obtain_jwt_token
from rest_framework import routers

from . import views
from .views import *

app_name = 'arusuma'
urlpatterns = [
    url(r'^$', views.home, name='home'),
    url(r'^login/$', views.login_view, name='login'),
    url(r'^dashboard/$', views.dashboard, name='dashboard'),
    # url(r'^server/$', server.home, name='server_home'),
    # url(r'^server/(?P<target_uuid>\w{32})/$', server.detail, name='server_detail'),
    # url(r'^config/$', config.home, name='config_home'),
    # url(r'^config/(?P<target_uuid>\w{32})/$', config.detail, name='config_detail'),
    # url(r'^ostemplate/$', ostemplate.home, name='ostemplate_home'),
    # url(r'^ostemplate/(?P<target_uuid>\w{32})/$', ostemplate.detail, name='ostemplate_detail'),
    url(r'^jwt-token', obtain_jwt_token),
    url(r'^ping', views.PingViewSet.as_view()),

    url(r'^token/$', views.token_login, name='token_login'),
    url(r'^token/refresh/$', views.token_refresh, name='token_refresh'),
    url(r'^token/users/$', views.token_get_users, name='token_get_users'),
    url(r'^token/redirect/$', views.token_login_redirect, name='token_login_redirect'),
    # url(r'^register/$', AuthRegister.as_view()),

    # ONLY POST METHOD
    url(r'^signup/$', views.signup_view, name='signup'),
    
]
router = routers.DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'contracts', ContractViewSet)
router.register(r'devices', DeviceViewSet)
router.register(r'access_tokens', AccessTokenViewSet)
