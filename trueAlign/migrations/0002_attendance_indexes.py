# Generated migration for database optimization
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('trueAlign', '0001_initial'),  # Update to your latest migration
    ]

    operations = [
        # Add indexes for Attendance model
        migrations.AddIndex(
            model_name='attendance',
            index=models.Index(fields=['user', 'date'], name='attendance_user_date_idx'),
        ),
        migrations.AddIndex(
            model_name='attendance',
            index=models.Index(fields=['date'], name='attendance_date_idx'),
        ),
        migrations.AddIndex(
            model_name='attendance',
            index=models.Index(fields=['user'], name='attendance_user_idx'),
        ),
        migrations.AddIndex(
            model_name='attendance',
            index=models.Index(fields=['status'], name='attendance_status_idx'),
        ),
        migrations.AddIndex(
            model_name='attendance',
            index=models.Index(
                fields=['regularization_status'], 
                name='attendance_reg_status_idx'
            ),
        ),
        migrations.AddIndex(
            model_name='attendance',
            index=models.Index(
                fields=['date', 'status'], 
                name='attendance_date_status_idx'
            ),
        ),
        migrations.AddIndex(
            model_name='attendance',
            index=models.Index(
                fields=['user', 'date', 'status'], 
                name='attendance_user_date_status_idx'
            ),
        ),
        
        # Add index for AttendanceRegularization if it exists
        # migrations.AddIndex(
        #     model_name='attendanceregularization',
        #     index=models.Index(fields=['attendance', 'status'], name='att_reg_att_status_idx'),
        # ),
    ]
