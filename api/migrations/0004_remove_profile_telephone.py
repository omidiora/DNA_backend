# Generated by Django 3.0.8 on 2020-07-09 23:45

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0003_auto_20200709_2304'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='profile',
            name='telephone',
        ),
    ]
