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
    url(r'^login', views.login_view, name='login'),
    url(r'^dashboard', views.dashboard, name='dashboard'),
    # url(r'^server/$', server.home, name='server_home'),
    # url(r'^server/(?P<target_uuid>\w{32})/$', server.detail, name='server_detail'),
    # url(r'^config/$', config.home, name='config_home'),
    # url(r'^config/(?P<target_uuid>\w{32})/$', config.detail, name='config_detail'),
    # url(r'^ostemplate/$', ostemplate.home, name='ostemplate_home'),
    # url(r'^ostemplate/(?P<target_uuid>\w{32})/$', ostemplate.detail, name='ostemplate_detail'),
    url(r'^jwt-token', obtain_jwt_token),
    url(r'^ping', views.PingViewSet.as_view()),

    url(r'^token$', views.token_login, name='token_login'),
    url(r'^token/$', views.token_login, name='token_login'),
    url(r'^token/refresh$', views.token_refresh, name='token_refresh'),
    url(r'^token/user$', views.token_get_user, name='token_get_user'),
    url(r'^token/users$', views.token_get_users, name='token_get_users'),
    url(r'^token/contracts$', views.token_get_users, name='token_get_contracts'),
    url(r'^token/devices$', views.token_get_users, name='token_get_devices'),
    url(r'^token/redirect', views.token_login_redirect, name='token_login_redirect'),
    # url(r'^register/$', AuthRegister.as_view()),
    url(r'^token/devices/add$', views.device_add, name='device_add'),
    url(r'^token/devices/update$', views.device_add, name='device_add'),
    url(r'^api/login$', views.api_login, name='api_login'),
    url(r'^api/S001CON.asp$', views.api_login, name='api_login'),
    url(r'^api/S002API.asp$', views.api_login, name='api_login'),
    url(r'^api/S003API.asp$', views.api_login, name='api_login'),
    url(r'^api/S005API.asp$', views.S005API, name='S005API'),
    url(r'^api/S006API.asp$', views.api_login, name='api_login'),
    url(r'^api/S007API.asp$', views.api_login, name='api_login'),
    url(r'^api/S009API.asp$', views.api_login, name='api_login'),
    url(r'^api/S010API.asp$', views.api_login, name='api_login'),
    url(r'^api/S011API.asp$', views.api_login, name='api_login'),
    url(r'^api/S012API.asp$', views.api_login, name='api_login'),
    url(r'^api/S013API.asp$', views.api_login, name='api_login'),
    url(r'^api/S014API.asp$', views.api_login, name='api_login'),
    url(r'^api/S015API.asp$', views.api_login, name='api_login'),
    url(r'^api/S016API.asp$', views.api_login, name='api_login'),

    # ONLY POST METHOD
    url(r'^signup/$', views.signup_view, name='signup'),
    
]
router = routers.DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'contracts', ContractViewSet)
router.register(r'devices', DeviceViewSet)
router.register(r'access_tokens', AccessTokenViewSet)
