# Generated by Django 5.1.3 on 2025-01-18 01:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('data', '0004_device_is_active'),
    ]

    operations = [
        migrations.AddField(
            model_name='device',
            name='training_minutes',
            field=models.IntegerField(null=True),
        ),
    ]
