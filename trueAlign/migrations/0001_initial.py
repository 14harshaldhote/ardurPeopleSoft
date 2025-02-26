# Generated by Django 5.1.4 on 2025-01-29 11:46

import datetime
import django.db.models.deletion
import django.utils.timezone
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='FeatureUsage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('feature_name', models.CharField(max_length=100)),
                ('usage_count', models.PositiveIntegerField()),
            ],
        ),
        migrations.CreateModel(
            name='SystemError',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('error_message', models.TextField()),
                ('error_time', models.DateTimeField(auto_now_add=True)),
                ('resolved', models.BooleanField(default=False)),
            ],
        ),
        migrations.CreateModel(
            name='SystemUsage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('peak_time_start', models.DateTimeField()),
                ('peak_time_end', models.DateTimeField()),
                ('active_users_count', models.PositiveIntegerField()),
            ],
        ),
        migrations.CreateModel(
            name='Break',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('break_type', models.CharField(choices=[('Tea Break 1', 'Tea Break 1'), ('Lunch/Dinner Break', 'Lunch/Dinner Break'), ('Tea Break 2', 'Tea Break 2')], max_length=50)),
                ('start_time', models.DateTimeField(auto_now_add=True)),
                ('end_time', models.DateTimeField(blank=True, null=True)),
                ('reason_for_extension', models.TextField(blank=True, null=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Break',
                'verbose_name_plural': 'Breaks',
                'ordering': ['-start_time'],
            },
        ),
        migrations.CreateModel(
            name='Chat',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('type', models.CharField(choices=[('personal', 'Personal'), ('group', 'Group')], max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('created_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='created_chats', to=settings.AUTH_USER_MODEL)),
                ('members', models.ManyToManyField(related_name='chats', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='ClientProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('company_name', models.CharField(max_length=100)),
                ('contact_info', models.TextField()),
                ('industry_type', models.CharField(max_length=100)),
                ('company_size', models.CharField(choices=[('Small', 'Small'), ('Medium', 'Medium'), ('Large', 'Large')], default='Small', max_length=50)),
                ('registration_number', models.CharField(blank=True, max_length=50, null=True)),
                ('business_location', models.CharField(blank=True, max_length=255, null=True)),
                ('website_url', models.URLField(blank=True, null=True)),
                ('year_established', models.IntegerField(blank=True, null=True)),
                ('annual_revenue', models.DecimalField(blank=True, decimal_places=2, max_digits=15, null=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='client_profile', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Employee',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('shift', models.CharField(choices=[('Day', 'Day'), ('Night', 'Night')], max_length=10)),
                ('leave_balance', models.IntegerField(default=18)),
                ('attendance_record', models.PositiveIntegerField(default=0)),
                ('late_arrivals', models.PositiveIntegerField(default=0)),
                ('early_departures', models.PositiveIntegerField(default=0)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='FailedLoginAttempt',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('attempt_time', models.DateTimeField(auto_now_add=True)),
                ('ip_address', models.GenericIPAddressField()),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='GlobalUpdate',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=255)),
                ('description', models.TextField()),
                ('status', models.CharField(choices=[('upcoming', 'Upcoming'), ('released', 'Just Released'), ('scheduled', 'Scheduled')], max_length=20)),
                ('scheduled_date', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('managed_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'permissions': [('manage_globalupdate', 'Can manage Global Updates')],
            },
        ),
        migrations.CreateModel(
            name='Leave',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('leave_type', models.CharField(choices=[('Sick Leave', 'Sick Leave'), ('Casual Leave', 'Casual Leave'), ('Earned Leave', 'Earned Leave'), ('Loss of Pay', 'Loss of Pay')], max_length=50)),
                ('start_date', models.DateField()),
                ('end_date', models.DateField()),
                ('leave_days', models.IntegerField(blank=True, null=True)),
                ('reason', models.TextField()),
                ('status', models.CharField(choices=[('Pending', 'Pending'), ('Approved', 'Approved'), ('Rejected', 'Rejected')], default='Pending', max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('approver', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='leave_approvals', to=settings.AUTH_USER_MODEL)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Message',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('content', models.TextField()),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('is_read', models.BooleanField(default=False)),
                ('chat', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='messages', to='trueAlign.chat')),
                ('read_by', models.ManyToManyField(related_name='read_messages', to=settings.AUTH_USER_MODEL)),
                ('sender', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sent_messages', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name_plural': 'Messages',
                'ordering': ['-timestamp'],
            },
        ),
        migrations.CreateModel(
            name='PasswordChange',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('old_password', models.CharField(max_length=255)),
                ('new_password', models.CharField(max_length=255)),
                ('change_time', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Project',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('description', models.TextField()),
                ('start_date', models.DateField(default=django.utils.timezone.now)),
                ('deadline', models.DateField()),
                ('status', models.CharField(choices=[('Completed', 'Completed'), ('In Progress', 'In Progress'), ('Pending', 'Pending'), ('On Hold', 'On Hold')], max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('clients', models.ManyToManyField(limit_choices_to={'groups__name': 'Client'}, related_name='projects_as_client', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='ClientParticipation',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('feedback', models.TextField(blank=True, null=True)),
                ('approved', models.BooleanField(default=False)),
                ('date', models.DateTimeField(auto_now_add=True)),
                ('is_active', models.BooleanField(default=True)),
                ('client', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='client_participations', to=settings.AUTH_USER_MODEL)),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='client_participations', to='trueAlign.project')),
            ],
        ),
        migrations.CreateModel(
            name='ProjectAssignment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('assigned_date', models.DateField(auto_now_add=True)),
                ('hours_worked', models.FloatField(default=0.0)),
                ('role_in_project', models.CharField(choices=[('Manager', 'Manager'), ('Employee', 'Employee'), ('Support', 'Support'), ('Appraisal', 'Appraisal'), ('QC', 'QC')], default='Employee', max_length=50)),
                ('end_date', models.DateField(blank=True, null=True)),
                ('is_active', models.BooleanField(default=True)),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='trueAlign.project')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.AddField(
            model_name='project',
            name='users',
            field=models.ManyToManyField(related_name='projects_assigned', through='trueAlign.ProjectAssignment', to=settings.AUTH_USER_MODEL),
        ),
        migrations.CreateModel(
            name='ProjectUpdate',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=200)),
                ('description', models.TextField()),
                ('status', models.CharField(choices=[('upcoming', 'Upcoming'), ('in_progress', 'In Progress'), ('completed', 'Completed')], default='upcoming', max_length=20)),
                ('scheduled_date', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='trueAlign.project')),
            ],
        ),
        migrations.CreateModel(
            name='RoleAssignmentAudit',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('role_assigned', models.CharField(max_length=50)),
                ('assigned_date', models.DateTimeField(auto_now_add=True)),
                ('assigned_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='role_assigned_by', to=settings.AUTH_USER_MODEL)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Support',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ticket_id', models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ('issue_type', models.CharField(choices=[('Hardware Issue', 'Hardware Issue'), ('Software Issue', 'Software Issue'), ('Network Issue', 'Network Issue'), ('Internet Issue', 'Internet Issue'), ('Application Issue', 'Application Issue'), ('HR Related Issue', 'HR Related Issue')], max_length=50)),
                ('subject', models.CharField(default='No subject', max_length=100)),
                ('description', models.TextField()),
                ('status', models.CharField(choices=[('Open', 'Open'), ('In Progress', 'In Progress'), ('Resolved', 'Resolved'), ('Closed', 'Closed')], default='Open', max_length=20)),
                ('assigned_to', models.CharField(choices=[('HR', 'HR'), ('Admin', 'Admin')], default='Admin', max_length=50)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='tickets', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='UserDetails',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('dob', models.DateField(blank=True, null=True)),
                ('blood_group', models.CharField(blank=True, choices=[('', '--------'), ('A+', 'A+'), ('A-', 'A-'), ('B+', 'B+'), ('B-', 'B-'), ('AB+', 'AB+'), ('AB-', 'AB-'), ('O+', 'O+'), ('O-', 'O-')], default='Unknown', max_length=10, null=True)),
                ('hire_date', models.DateField(blank=True, null=True)),
                ('gender', models.CharField(blank=True, choices=[('', '--------'), ('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')], max_length=10, null=True)),
                ('panno', models.CharField(blank=True, max_length=10, null=True)),
                ('job_description', models.TextField(blank=True, null=True)),
                ('employment_status', models.CharField(blank=True, choices=[('', '--------'), ('active', 'Active'), ('inactive', 'Inactive'), ('terminated', 'Terminated'), ('resigned', 'Resigned'), ('suspended', 'Suspended'), ('absconding', 'Absconding')], max_length=50, null=True)),
                ('emergency_contact_address', models.TextField(blank=True, null=True)),
                ('emergency_contact_primary', models.CharField(blank=True, max_length=10, null=True)),
                ('emergency_contact_name', models.CharField(blank=True, max_length=100, null=True)),
                ('start_date', models.DateField(blank=True, null=True)),
                ('work_location', models.CharField(blank=True, max_length=100, null=True)),
                ('contact_number_primary', models.CharField(blank=True, max_length=10, null=True)),
                ('personal_email', models.EmailField(blank=True, max_length=254, null=True)),
                ('aadharno', models.CharField(blank=True, max_length=14, null=True)),
                ('group', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='auth.group')),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Attendance',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('date', models.DateField()),
                ('status', models.CharField(choices=[('Present', 'Present'), ('Absent', 'Absent'), ('Pending', 'Pending'), ('On Leave', 'On Leave'), ('Work From Home', 'Work From Home'), ('Weekend', 'Weekend'), ('Holiday', 'Holiday')], default='Pending', max_length=20)),
                ('location', models.CharField(blank=True, choices=[('Office', 'Office'), ('Home', 'Work From Home'), ('Remote', 'Remote')], max_length=20, null=True)),
                ('clock_in_time', models.DateTimeField(blank=True, null=True)),
                ('clock_out_time', models.DateTimeField(blank=True, null=True)),
                ('total_hours', models.DurationField(blank=True, null=True)),
                ('last_updated', models.DateTimeField(auto_now=True)),
                ('notes', models.TextField(blank=True, null=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('leave_request', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='attendances', to='trueAlign.leave')),
            ],
            options={
                'indexes': [models.Index(fields=['user', 'date'], name='trueAlign_a_user_id_96129d_idx'), models.Index(fields=['date'], name='trueAlign_a_date_c92f26_idx')],
                'unique_together': {('user', 'date')},
            },
        ),
        migrations.CreateModel(
            name='Timesheet',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('week_start_date', models.DateField()),
                ('task_name', models.CharField(max_length=255)),
                ('hours', models.FloatField()),
                ('approval_status', models.CharField(choices=[('Pending', 'Pending'), ('Approved', 'Approved'), ('Rejected', 'Rejected')], default='Pending', max_length=10)),
                ('manager_comments', models.TextField(blank=True, null=True)),
                ('submitted_at', models.DateTimeField(auto_now_add=True)),
                ('reviewed_at', models.DateTimeField(blank=True, null=True)),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='timesheets', to='trueAlign.project')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='timesheets', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-week_start_date'],
                'unique_together': {('user', 'week_start_date', 'project', 'task_name')},
            },
        ),
        migrations.CreateModel(
            name='UserSession',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('session_key', models.CharField(max_length=40)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('login_time', models.DateTimeField(default=django.utils.timezone.now)),
                ('logout_time', models.DateTimeField(blank=True, null=True)),
                ('working_hours', models.DurationField(blank=True, null=True)),
                ('idle_time', models.DurationField(default=datetime.timedelta(0))),
                ('last_activity', models.DateTimeField(default=django.utils.timezone.now)),
                ('location', models.CharField(blank=True, max_length=50, null=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'indexes': [models.Index(fields=['user', 'login_time'], name='trueAlign_u_user_id_81ad70_idx')],
            },
        ),
    ]
