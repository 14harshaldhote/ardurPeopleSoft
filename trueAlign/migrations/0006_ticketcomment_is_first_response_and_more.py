# Generated by Django 5.0.2 on 2025-05-31 07:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('trueAlign', '0005_support_closed_at'),
    ]

    operations = [
        migrations.AddField(
            model_name='ticketcomment',
            name='is_first_response',
            field=models.BooleanField(default=False, help_text='Whether this is the first staff response'),
        ),
        migrations.AddField(
            model_name='ticketcomment',
            name='updated_at',
            field=models.DateTimeField(auto_now=True),
        ),
    ]
