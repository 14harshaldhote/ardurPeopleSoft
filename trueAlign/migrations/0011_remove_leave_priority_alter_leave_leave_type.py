# Generated by Django 5.1.4 on 2025-03-24 12:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('trueAlign', '0010_userdetails_address_line1_userdetails_address_line2_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='leave',
            name='priority',
        ),
        migrations.AlterField(
            model_name='leave',
            name='leave_type',
            field=models.CharField(choices=[('Sick Leave', 'Sick Leave'), ('Casual Leave', 'Casual Leave'), ('Loss of Pay', 'Loss of Pay'), ('Emergency', 'Emergency')], max_length=50),
        ),
    ]
