# Generated by Django 5.1.4 on 2025-01-23 05:00

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('trueAlign', '0006_attendance_location_alter_attendance_clock_in_time_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='attendance',
            name='clock_in_time',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='attendance',
            name='clock_out_time',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]