# Generated by Django 5.1.4 on 2025-02-28 07:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('trueAlign', '0002_message_edited_at'),
    ]

    operations = [
        migrations.AddField(
            model_name='chatgroup',
            name='last_activity',
            field=models.DateTimeField(auto_now=True),
        ),
    ]
