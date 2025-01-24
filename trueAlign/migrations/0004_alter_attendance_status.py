# Generated by Django 5.1.4 on 2025-01-22 18:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('trueAlign', '0003_alter_attendance_clock_in_time_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='attendance',
            name='status',
            field=models.CharField(choices=[('Present', 'Present'), ('Absent', 'Absent'), ('Pending', 'Pending'), ('On Leave', 'On Leave'), ('Work From Home', 'Work From Home'), ('Weekend', 'Weekend'), ('Holiday', 'Holiday')], default='Pending', max_length=20),
        ),
    ]
