# Generated by Django 5.0.2 on 2025-05-31 07:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('trueAlign', '0008_ticketattachment_file_size'),
    ]

    operations = [
        migrations.AddField(
            model_name='ticketattachment',
            name='mime_type',
            field=models.CharField(blank=True, max_length=100),
        ),
    ]
