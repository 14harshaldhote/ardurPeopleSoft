# Generated by Django 5.1.4 on 2025-02-24 10:55

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('trueAlign', '0016_rename_added_at_groupmember_joined_at_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='message',
            name='direct_message',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='messages', to='trueAlign.directmessage'),
        ),
        migrations.AlterField(
            model_name='message',
            name='group',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='messages', to='trueAlign.chatgroup'),
        ),
    ]
