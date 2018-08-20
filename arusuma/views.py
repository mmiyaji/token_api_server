#!/usr/bin/env python
# encoding: utf-8
'''
views.py

Created by mmiyaji on 2018-08-18.
Copyright (c) 2018  ruhenheim.org. All rights reserved.
'''
from django.shortcuts import render
from django.http import HttpResponse

import os, re, sys, commands, time, datetime, random, logging
from django.http import HttpResponse, HttpResponseRedirect
from django.template import Context, loader
from django.template import RequestContext
from django.shortcuts import render_to_response
from django.core.urlresolvers import reverse
from django.contrib import auth
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_protect
from django.utils.encoding import force_unicode, smart_str
from django.core import serializers as sz
from django.conf import settings
from django.http import Http404
from django.utils.http import urlencode
from django.http import Http404

from django.template.loader import get_template
from arusuma.models import *

logger = logging.getLogger(__name__)

from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework import viewsets, filters
from django.views.decorators.csrf import csrf_exempt

from .serializer import *
from django.http.response import JsonResponse
from django.utils import timezone
import json

class PingViewSet(GenericAPIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, format=None):
        return Response(data={'username': request.user.username}, status=status.HTTP_200_OK)

class UserViewSet(viewsets.ModelViewSet):
    queryset = ArusumaUser.objects.all()
    serializer_class = UserSerializer

class ContractViewSet(viewsets.ModelViewSet):
    queryset = Contract.objects.all()
    serializer_class = ContractSerializer

class DeviceViewSet(viewsets.ModelViewSet):
    queryset = Device.objects.all()
    serializer_class = DeviceSerializer

class AccessTokenViewSet(viewsets.ModelViewSet):
    queryset = AccessToken.objects.all()
    serializer_class = AccessTokenSerializer

def home(request):
    """
    Case of GET REQUEST '/'
    home page
    """
    temp_values = {
        "subscroll":True,
    }
    return render(request, 'general/index.html', temp_values)
    # return render(request, 'general/dashboard.html', temp_values)

def dashboard(request):
    """
    Case of GET REQUEST '/'
    home page
    """
    temp_values = {
        "users":ArusumaUser.objects.all(),
        "contracts":Contract.objects.all(),
        "devices":Device.objects.all(),
        "access_tokens":AccessToken.objects.all(),
    }
    return render(request, 'general/dashboard.html', temp_values)

@csrf_exempt
def token_login(request):
    token = ""
    temp_values = {
        "message":"faild"
    }
    # print request.query_params
    req = ""
    try:
        params = json.loads(request.body.decode())
        print params
        if params:
            email = params["email"]
            password = params["password"]
            uuid  = params["devid"]
            req = "OK"
    except:
        if request.POST:
            email = request.POST['email']
            password = request.POST['password']
            uuid = request.POST['devid']
            req = "OK"
    if req:
        print email
        print password
        print uuid
        user = authenticate(email=email, password=password)
        if user is not None:
            d = Device.get_or_create(user, uuid)
            at = AccessToken.get_or_create_by_device(d)

            temp_values = {
                "user":user.email,
                "token":at.token,
                "refresh_token":at.refresh_token,
                "expired_at":at.expired_at,
            }
            print temp_values
    response = JsonResponse(temp_values)
    response["Access-Control-Allow-Origin"] = "*"
    response["Access-Control-Allow-Methods"] = "POST, GET, OPTIONS"
    response["Access-Control-Max-Age"] = "1000"
    response["Access-Control-Allow-Headers"] = "*"
    return response

@csrf_exempt
def token_refresh(request):
    token = ""
    temp_values = {
        "message":"faild"
    }
    if request.POST:
        email = request.POST['email']
        refresh_token = request.POST['refresh_token']
        if refresh_token:
            at = AccessToken.get_by_refresh_token(refresh_token)
            at.refresh_access_token()
            temp_values = {
                "user":at.device.user.email,
                "token":at.token,
                "refresh_token":at.refresh_token,
                "expired_at":at.expired_at,
            }
    return JsonResponse(temp_values)

@csrf_exempt
def token_get_users(request):
    token = ""
    temp_values = {
        "message":"faild"
    }
    access_token = request.META['HTTP_AUTHORIZATION']
    print access_token
    # refresh_token = request.POST['token']
    if access_token:
        at = AccessToken.get_by_access_token(access_token)
        print at
        # nd = datetime.datetime.now()
        nd = timezone.now()
        print nd
        print at.expired_at
        if at.expired_at < nd:
            temp_values = {
                "message":"token has been expired.",
            }
        else:
            temp_values = {
                "user":at.device.user.email,
            }
    return JsonResponse(temp_values)

@csrf_exempt
def token_login_redirect(request):
    token = ""
    access_token = ""
    temp_values = {
        "message":"faild"
    }
    try:
        access_token = request.META['HTTP_AUTHORIZATION']
    except:
        access_token = request.GET['AUTH']
    print access_token
    # refresh_token = request.POST['token']
    if access_token:
        at = AccessToken.get_by_access_token(access_token)
        print at
        # nd = datetime.datetime.now()
        nd = timezone.now()
        print nd
        print at.expired_at
        if at.expired_at < nd:
            temp_values = {
                "message":"token has been expired.",
            }
        else:
            user = at.device.user
            login(request, user)
            next_url = "/dashboard/"
            return HttpResponseRedirect(next_url)
    return JsonResponse(temp_values)

def login_view(request):
    #強制的にログアウト
    logout(request)
    password = ''
    first_name = last_name = email = ''
    error_list = []
    error_target = []
    next_url = "/"

    if request.GET:
        first_name = request.GET.get('first_name','')
        last_name = request.GET.get('last_name','')
        email = request.GET.get('email','')
        error_code = request.GET.get('error_code','')
    elif request.POST:
        print request.POST
        if 'signup' in request.POST:
            signup_view(request)
        else:
            email = request.POST['email']
            password = request.POST['password']
            next_url = request.POST.get('next', next_url)
            user = authenticate(email=email, password=password)
            if user is not None:
                if user.is_active:
                    login(request, user)
                    return HttpResponseRedirect(next_url)
                else:
                    error_list.append('login_failed')
            else:
                error_list.append('login_failed')

    temp_values = {
        "error_list": error_list,
        "error_target": error_target,
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
    }
    return render(request, 'general/login.html', temp_values)

def signup_view(request):
    password = password2 = ''

    first_name = last_name = email = ''
    error_list = []
    error_target = []

    if request.POST:
        # username = request.POST['username']
        password = request.POST['password']
        password2 = request.POST['password_confirm']
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        email = request.POST['email']
        # is_staff = request.POST['is_staff']

        if password == password2 and valid_pass(password) == 0:
            if not ArusumaUser.objects.filter(email=email):
                user = ArusumaUser.objects.create_user(email, password)
                user.first_name = first_name
                user.last_name = last_name
                user.save()
                user = authenticate(email=email, password=password)
                if user is not None:
                    if user.is_active:
                        login(request, user)
                        return HttpResponseRedirect('/')
            else:
                error_list.append('wrong_user')
                error_list.append('signup_failed')
        else:
            error_list.append('wrong_password')
            error_list.append('signup_failed')
            error_target.append('password')
            error_target.append('password2')
        temp_values = {
            "error_list": error_list,
            "error_target": error_target,
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
        }
        # query = urlencode(temp_values)
        # url = ''.join([
        #     reverse('dansible:login'),
        #     '?',
        # query])
        # return HttpResponseRedirect(url)
        return render(request, 'general/login.html', temp_values)
    else:
        raise Http404

def valid_pass(password):
    """
    validate password
    Arguments:
    - `password`:
    """
    if len(password) < 6:
        return 1
    return 0