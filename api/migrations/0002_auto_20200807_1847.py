# Generated by Django 3.0.8 on 2020-08-07 18:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='loan_record',
            name='interest_rate',
            field=models.DecimalField(decimal_places=2, max_digits=5),
        ),
    ]