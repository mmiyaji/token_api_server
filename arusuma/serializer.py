#!/usr/bin/env python
# encoding: utf-8
from rest_framework import serializers

from .models import ArusumaUser, Contract, Device, AccessToken


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = ArusumaUser
        fields = ('email', 'first_name', 'lst_name')


class ContractSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contract
        fields = ('title', 'body', 'created_at', 'user')

class DeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Device
        fields = ('uuid', 'token', 'expired_at', 'created_at', 'user')

class AccessTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = AccessToken
        fields = ('device', 'token', 'refresh_token', 'expired_at', 'created_at')


