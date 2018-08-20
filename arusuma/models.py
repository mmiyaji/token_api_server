# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
import datetime, time, uuid
from django.contrib.auth import models as auth_models
from django.core.mail import send_mail
from django.contrib.auth.models import PermissionsMixin
from django.contrib.auth.base_user import AbstractBaseUser
from django.utils.translation import ugettext_lazy as _
from django.utils import timezone
# class User(models.Model):
#     name = models.CharField(max_length=32)
#     mail = models.EmailField()
#     updated_at = models.DateTimeField(auto_now = True, db_index=True)
#     created_at = models.DateTimeField(auto_now_add = True, db_index=True)
# 
#     def getDeviceTokens(self):
#         pass
#     def __unicode__(self):
#         return self.name
#     def get_absolute_url(self):
#         return "/user/%s" % self.id
from django.db import models    
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
import random, string
from django.conf import settings

def randomname(n):
    random_str = ''.join([random.choice(string.ascii_letters + string.digits) for i in range(n)])
    return random_str
   # return ''.join(random.choice(string.ascii_letters + string.digits, k=n))
  
class ArusumaUserManager(BaseUserManager):
    # def create_user(self, email, password=None, **extra_fields):
    #     if not email:
    #         raise ValueError('Users must have a email address')
    # 
    #     email = ArusumaUserManager.normalize_email(email)
    #     user = self.model(email=email, **extra_fields)
    #     user.set_password(password)
    #     user.save(using=self._db)
    #     return user
    use_in_migrations = True
 
    def _create_user(self, email, password, **extra_fields):
        """メールアドレスでの登録を必須にする"""
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
 
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
 
    def create_user(self, email, password=None, **extra_fields):
        """is_staff(管理サイトにログインできるか)と、is_superuer(全ての権限)をFalseに"""
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)
 
    def create_superuser(self, email, password, **extra_fields):
        """スーパーユーザーは、is_staffとis_superuserをTrueに"""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
 
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
 
        return self._create_user(email, password, **extra_fields)

class ArusumaUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(max_length=128, unique=True)
    first_name = models.CharField(max_length=128, default="")
    last_name = models.CharField(max_length=128, default="")
    # isvalid = models.BooleanField(default=True, db_index=True)
    # updated_at = models.DateTimeField(auto_now = True, db_index=True)
    # created_at = models.DateTimeField(auto_now_add = True, db_index=True)
    is_staff = models.BooleanField(
        _('staff status'),
        default=False,
        help_text=_(
            'Designates whether the user can log into this admin site.'),
    )
    is_active = models.BooleanField(
        _('active'),
        default=True,
        help_text=_(
            'Designates whether this user should be treated as active. '
            'Unselect this instead of deleting accounts.'
        ),
    )
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)
 
    objects = ArusumaUserManager()
    EMAIL_FIELD = 'email'
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    class Meta:
        db_table = 'arusuma_user'
        swappable = 'AUTH_USER_MODEL'
        verbose_name = _('user')
        verbose_name_plural = _('users')
 
    def get_full_name(self):
        """Return the first_name plus the last_name, with a space in
        between."""
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()
 
    def get_short_name(self):
        """Return the short name for the user."""
        return self.first_name
 
    def email_user(self, subject, message, from_email=None, **kwargs):
        """Send an email to this user."""
        send_mail(subject, message, from_email, [self.email], **kwargs)
 
    @property
    def username(self):
        """username属性のゲッター
        他アプリケーションが、username属性にアクセスした場合に備えて定義
        メールアドレスを返す
        """
        return self.email
    @property
    def name(self):
        """username属性のゲッター
        他アプリケーションが、username属性にアクセスした場合に備えて定義
        メールアドレスを返す
        """
        return self.email

    def __unicode__(self):
        return "%s" % (self.email )


class Contract(models.Model):
    user = models.ForeignKey(ArusumaUser, related_name='contracts', on_delete=models.CASCADE)
    title = models.CharField(max_length=128)
    body = models.TextField()
    updated_at = models.DateTimeField(auto_now = True, db_index=True)
    created_at = models.DateTimeField(auto_now_add = True, db_index=True)

    def __unicode__(self):
        return self.title
    def get_absolute_url(self):
        return "/contract/%s" % self.id

class Device(models.Model):
    user = models.ForeignKey(ArusumaUser, related_name='devices', on_delete=models.CASCADE)
    uuid = models.CharField(max_length=300, blank=True, null=True)
    token = models.CharField(max_length=300, default="", blank=True, null=True)
    isvalid = models.BooleanField(default=True, db_index=True)
    expired_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(auto_now = True, db_index=True)
    created_at = models.DateTimeField(auto_now_add = True, db_index=True)

    @staticmethod
    def get_or_create(user, uuid):
        result = Device.get_by_uuid(uuid)
        if not result:
            result = Device()
            result.user = user
            result.uuid = uuid
            result.expired_at = datetime.datetime.now() + datetime.timedelta(days=settings.ACCESS_TOKEN_EXPIRES)
            result.save()
        return result

    @staticmethod
    def get_all():
        return Device.objects.filter(isvalid__exact=True)

    @staticmethod
    def get_by_uuid(uuid):
        result=None
        try:
            result = Device.objects.get(uuid=uuid)
        except:
            result = None
        return result
    @staticmethod
    def get_by_user(user=""):
        result=None
        try:
            result = Device.objects.filter(user=user).get()
        except:
            result = None
        return result

    def __unicode__(self):
        return "%s:%s" % (self.id, self.user.email )
    def get_absolute_url(self):
        return "/device_token/%s" % self.id

class AccessToken(models.Model):
    device = models.ForeignKey(Device, related_name='access', on_delete=models.CASCADE)
    token = models.CharField(max_length=300, blank=True, null=True, unique=True)
    refresh_token = models.CharField(max_length=300, blank=True, null=True, unique=True)
    isvalid = models.BooleanField(default=True, db_index=True)
    expired_at = models.DateTimeField()
    refresh_expired_at = models.DateTimeField(blank=True, null=True)
    updated_at = models.DateTimeField(auto_now = True, db_index=True)
    created_at = models.DateTimeField(auto_now_add = True, db_index=True)

    def refresh_access_token(self):
        nd = datetime.datetime.now()
        if self.refresh_expired_at < nd:
            return False
        cuuid = ""
        for i in range(0,30):
            cuuid = randomname(255)
            c = AccessToken.objects.filter(token__exact=cuuid).count()
            if c < 1:
                break
            else:
                print "conflict token"
        self.token = cuuid
        self.expired_at = nd + datetime.timedelta(days=settings.ACCESS_TOKEN_EXPIRES)
        self.save()
        return self.token

    def save(self, force_update=False, force_insert=False, isFirst = False):
        if isFirst:
            if not self.token:
                # 万が一uuidの被りがあった場合は再精製。最大10回繰り返す。
                cuuid = ""
                for i in range(0,30):
                    cuuid = randomname(255)
                    c = AccessToken.objects.filter(token__exact=cuuid).count()
                    if c < 1:
                        break
                self.token = cuuid
            if not self.refresh_token:
                # 万が一uuidの被りがあった場合は再精製。最大10回繰り返す。
                ruuid = ""
                for i in range(0,30):
                    ruuid = randomname(255)
                    c = AccessToken.objects.filter(refresh_token__exact=ruuid).count()
                    if c < 1:
                        break
                self.refresh_token = ruuid
        super(AccessToken, self).save(force_update, force_insert)

    @staticmethod
    def get_or_create_by_device(device):
        result = AccessToken.get_by_device(device)
        if not result:
            result = AccessToken()
            result.device = device
            result.expired_at = timezone.now() + datetime.timedelta(days=settings.ACCESS_TOKEN_EXPIRES)
            result.refresh_expired_at = timezone.now() + datetime.timedelta(days=settings.REFRESH_TOKEN_EXPIRES)
            result.save(isFirst = True)
        return result

    @staticmethod
    def get_all():
        return AccessToken.objects.filter(isvalid__exact=True)

    @staticmethod
    def get_by_device(device):
        result=None
        try:
            result = AccessToken.objects.get(device=device)
        except:
            result = None
        return result

    @staticmethod
    def get_by_access_token(access_token):
        print access_token
        result=None
        try:
            result = AccessToken.objects.get(token=access_token)
        except:
            result = None
        print result
        return result

    @staticmethod
    def get_by_refresh_token(refresh_token):
        result=None
        try:
            result = AccessToken.objects.get(refresh_token=refresh_token)
        except:
            result = None
        return result

    def __unicode__(self):
        return "%s:%s:%s" % (self.id, self.device.id, self.device.user.email )
    def get_absolute_url(self):
        return "/access_token/%s" % self.id

class Meta:
    ordering = ['-created_at']
