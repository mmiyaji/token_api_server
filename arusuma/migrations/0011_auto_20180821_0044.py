# -*- coding: utf-8 -*-
# Generated by Django 1.11.15 on 2018-08-20 15:44
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('arusuma', '0010_auto_20180819_2223'),
    ]

    operations = [
        migrations.AlterField(
            model_name='device',
            name='expired_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
