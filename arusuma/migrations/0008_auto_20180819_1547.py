# -*- coding: utf-8 -*-
# Generated by Django 1.11.15 on 2018-08-19 06:47
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('arusuma', '0007_auto_20180819_1539'),
    ]

    operations = [
        migrations.AlterField(
            model_name='device',
            name='token',
            field=models.CharField(blank=True, default='', max_length=300, null=True),
        ),
    ]
