# Generated by Django 5.1.3 on 2025-01-28 14:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('data', '0008_packet'),
    ]

    operations = [
        migrations.CreateModel(
            name='Notification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('message', models.TextField()),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('is_read', models.BooleanField(default=False)),
            ],
            options={
                'ordering': ['-timestamp'],
            },
        ),
    ]
