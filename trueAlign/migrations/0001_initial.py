# Generated migration to match existing database schema
# This migration represents your OLD database structure

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('contenttypes', '0002_remove_content_type_name'),
    ]

    operations = [
        # Appraisal
        migrations.CreateModel(
            name='Appraisal',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('title', models.CharField(max_length=255)),
                ('overview', models.TextField()),
                ('period_start', models.DateField()),
                ('period_end', models.DateField()),
                ('status', models.CharField(max_length=20)),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
                ('submitted_at', models.DateTimeField(null=True, blank=True)),
                ('approved_at', models.DateTimeField(null=True, blank=True)),
                ('manager', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='managed_appraisals', to=settings.AUTH_USER_MODEL)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='appraisals', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_appraisal',
            },
        ),

        # AppraisalAttachment
        migrations.CreateModel(
            name='AppraisalAttachment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('file', models.CharField(max_length=100)),
                ('title', models.CharField(max_length=255)),
                ('description', models.TextField()),
                ('upload_date', models.DateTimeField()),
                ('appraisal', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='attachments', to='trueAlign.appraisal')),
                ('uploaded_by', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='uploaded_appraisal_attachments', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_appraisalattachment',
            },
        ),

        # AppraisalItem
        migrations.CreateModel(
            name='AppraisalItem',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('category', models.CharField(max_length=20)),
                ('title', models.CharField(max_length=255)),
                ('description', models.TextField()),
                ('date', models.DateField(null=True, blank=True)),
                ('employee_rating', models.PositiveSmallIntegerField(null=True, blank=True)),
                ('manager_rating', models.PositiveSmallIntegerField(null=True, blank=True)),
                ('manager_comments', models.TextField()),
                ('appraisal', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='items', to='trueAlign.appraisal')),
            ],
            options={
                'db_table': 'trueAlign_appraisalitem',
            },
        ),

        # AppraisalWorkflow
        migrations.CreateModel(
            name='AppraisalWorkflow',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('from_status', models.CharField(max_length=20, null=True, blank=True)),
                ('to_status', models.CharField(max_length=20)),
                ('timestamp', models.DateTimeField()),
                ('comments', models.TextField()),
                ('action_by', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='appraisal_actions', to=settings.AUTH_USER_MODEL)),
                ('appraisal', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='workflow_history', to='trueAlign.appraisal')),
            ],
            options={
                'db_table': 'trueAlign_appraisalworkflow',
            },
        ),

        # Attendance
        migrations.CreateModel(
            name='Attendance',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('date', models.DateField(db_index=True)),
                ('status', models.CharField(max_length=20)),
                ('leave_type', models.CharField(max_length=50, null=True, blank=True)),
                ('clock_in_time', models.DateTimeField(null=True, blank=True)),
                ('clock_out_time', models.DateTimeField(null=True, blank=True)),
                ('breaks', models.TextField()),
                ('total_hours', models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)),
                ('expected_hours', models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)),
                ('is_weekend', models.BooleanField()),
                ('is_holiday', models.BooleanField()),
                ('holiday_name', models.CharField(max_length=100, null=True, blank=True)),
                ('location', models.CharField(max_length=50)),
                ('ip_address', models.CharField(max_length=39, null=True, blank=True)),
                ('device_info', models.TextField(null=True, blank=True)),
                ('late_minutes', models.IntegerField()),
                ('early_departure_minutes', models.IntegerField()),
                ('left_early', models.BooleanField()),
                ('last_modified', models.DateTimeField()),
                ('regularization_reason', models.TextField(null=True, blank=True)),
                ('regularization_status', models.CharField(max_length=20, null=True, blank=True)),
                ('total_sessions', models.IntegerField()),
                ('idle_time', models.BigIntegerField()),
                ('overtime_hours', models.DecimalField(max_digits=5, decimal_places=2)),
                ('is_overtime_approved', models.BooleanField()),
                ('is_employee_notified', models.BooleanField()),
                ('is_hr_notified', models.BooleanField()),
                ('last_regularization_date', models.DateTimeField(null=True, blank=True)),
                ('original_clock_in_time', models.DateTimeField(null=True, blank=True)),
                ('original_clock_out_time', models.DateTimeField(null=True, blank=True)),
                ('original_status', models.CharField(max_length=20, null=True, blank=True)),
                ('regularization_attempts', models.IntegerField()),
                ('remarks', models.TextField(null=True, blank=True)),
                ('requested_status', models.CharField(max_length=20, null=True, blank=True)),
                ('is_half_day', models.BooleanField()),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='attendances', to=settings.AUTH_USER_MODEL)),
                ('modified_by', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='modified_attendances', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_attendance',
            },
        ),

        # BankAccount
        migrations.CreateModel(
            name='BankAccount',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=255)),
                ('account_number', models.CharField(max_length=50, unique=True)),
                ('bank_name', models.CharField(max_length=255)),
                ('branch', models.CharField(max_length=255)),
                ('ifsc_code', models.CharField(max_length=20)),
                ('current_balance', models.DecimalField(max_digits=15, decimal_places=2)),
                ('is_active', models.BooleanField()),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
            ],
            options={
                'db_table': 'trueAlign_bankaccount',
            },
        ),

        # BankPayment
        migrations.CreateModel(
            name='BankPayment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('payment_id', models.CharField(max_length=50, unique=True)),
                ('party_name', models.CharField(max_length=255)),
                ('payment_reason', models.TextField()),
                ('amount', models.DecimalField(max_digits=15, decimal_places=2)),
                ('payment_date', models.DateField()),
                ('reference_number', models.CharField(max_length=100, null=True, blank=True)),
                ('status', models.CharField(max_length=20)),
                ('attachments', models.CharField(max_length=100, null=True, blank=True)),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
                ('bank_account', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='payments', to='trueAlign.bankaccount')),
                ('approved_by', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='approved_bank_payments', to=settings.AUTH_USER_MODEL)),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='created_bank_payments', to=settings.AUTH_USER_MODEL)),
                ('verified_by', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='verified_bank_payments', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_bankpayment',
            },
        ),

        # Break
        migrations.CreateModel(
            name='Break',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('break_type', models.CharField(max_length=50)),
                ('start_time', models.DateTimeField()),
                ('end_time', models.DateTimeField(null=True, blank=True)),
                ('reason_for_extension', models.TextField(null=True, blank=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='breaks', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_break',
            },
        ),

        # ChartOfAccount
        migrations.CreateModel(
            name='ChartOfAccount',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=255)),
                ('code', models.CharField(max_length=20, unique=True)),
                ('account_type', models.CharField(max_length=20)),
                ('description', models.TextField(null=True, blank=True)),
                ('is_active', models.BooleanField()),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
                ('parent', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='sub_accounts', to='trueAlign.chartofaccount')),
            ],
            options={
                'db_table': 'trueAlign_chartofaccount',
            },
        ),

        # ChatGroup
        migrations.CreateModel(
            name='ChatGroup',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=255)),
                ('description', models.TextField()),
                ('created_at', models.DateTimeField()),
                ('is_active', models.BooleanField()),
                ('last_activity', models.DateTimeField()),
                ('created_by', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='created_chat_groups', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_chatgroup',
            },
        ),

        # ClientInvoice
        migrations.CreateModel(
            name='ClientInvoice',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('invoice_number', models.CharField(max_length=50, unique=True)),
                ('billing_model', models.CharField(max_length=20)),
                ('billing_cycle_start', models.DateField()),
                ('billing_cycle_end', models.DateField()),
                ('order_count', models.IntegerField(null=True, blank=True)),
                ('fte_count', models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)),
                ('rate', models.DecimalField(max_digits=10, decimal_places=2)),
                ('subtotal', models.DecimalField(max_digits=15, decimal_places=2)),
                ('tax_amount', models.DecimalField(max_digits=15, decimal_places=2)),
                ('discount', models.DecimalField(max_digits=15, decimal_places=2)),
                ('total_amount', models.DecimalField(max_digits=15, decimal_places=2)),
                ('status', models.CharField(max_length=20)),
                ('due_date', models.DateField()),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
                ('approved_by', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='approved_client_invoices', to=settings.AUTH_USER_MODEL)),
                ('client', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='invoices', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_clientinvoice',
            },
        ),

        # ClientParticipation
        migrations.CreateModel(
            name='ClientParticipation',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('feedback', models.TextField(null=True, blank=True)),
                ('approved', models.BooleanField()),
                ('date', models.DateTimeField()),
                ('is_active', models.BooleanField()),
                ('client', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='project_participations', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_clientparticipation',
            },
        ),

        # ClientProfile
        migrations.CreateModel(
            name='ClientProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('company_name', models.CharField(max_length=100)),
                ('contact_info', models.TextField()),
                ('industry_type', models.CharField(max_length=100)),
                ('company_size', models.CharField(max_length=50)),
                ('registration_number', models.CharField(max_length=50, null=True, blank=True)),
                ('business_location', models.CharField(max_length=255, null=True, blank=True)),
                ('website_url', models.CharField(max_length=200, null=True, blank=True)),
                ('year_established', models.IntegerField(null=True, blank=True)),
                ('annual_revenue', models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='client_profile', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_clientprofile',
            },
        ),

        # CommentAttachment
        migrations.CreateModel(
            name='CommentAttachment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('file', models.CharField(max_length=100)),
                ('original_filename', models.CharField(max_length=255)),
                ('formatted_filename', models.CharField(max_length=255)),
                ('file_size', models.PositiveIntegerField()),
                ('content_type', models.CharField(max_length=100, null=True, blank=True)),
                ('uploaded_at', models.DateTimeField()),
                ('description', models.TextField(null=True, blank=True)),
                ('is_active', models.BooleanField()),
                ('uploaded_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='uploaded_comment_attachments', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'truealign_comment_attachment',
            },
        ),

        # CompOffRequest
        migrations.CreateModel(
            name='CompOffRequest',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('worked_date', models.DateField()),
                ('reason', models.TextField()),
                ('hours_worked', models.DecimalField(max_digits=4, decimal_places=1)),
                ('status', models.CharField(max_length=20)),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
                ('approver', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='approved_compoff_requests', to=settings.AUTH_USER_MODEL)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='compoff_requests', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_compoffrequest',
            },
        ),

        # DailyExpense
        migrations.CreateModel(
            name='DailyExpense',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('expense_id', models.CharField(max_length=50, unique=True)),
                ('date', models.DateField()),
                ('category', models.CharField(max_length=20)),
                ('description', models.TextField()),
                ('amount', models.DecimalField(max_digits=15, decimal_places=2)),
                ('status', models.CharField(max_length=20)),
                ('attachments', models.CharField(max_length=100, null=True, blank=True)),
                ('approved_at', models.DateTimeField(null=True, blank=True)),
                ('rejection_reason', models.TextField(null=True, blank=True)),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
                ('approved_by', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='approved_expenses', to=settings.AUTH_USER_MODEL)),
                ('paid_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='paid_expenses', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_dailyexpense',
            },
        ),

        # Department
        migrations.CreateModel(
            name='Department',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100, unique=True)),
            ],
            options={
                'db_table': 'trueAlign_department',
            },
        ),

        # DirectMessage
        migrations.CreateModel(
            name='DirectMessage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField()),
                ('is_active', models.BooleanField()),
                ('last_activity', models.DateTimeField()),
            ],
            options={
                'db_table': 'trueAlign_directmessage',
            },
        ),

        # DirectMessageParticipants (Many-to-Many through table)
        migrations.CreateModel(
            name='DirectMessageParticipants',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('directmessage', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='trueAlign.directmessage')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_directmessage_participants',
            },
        ),

        # FailedLoginAttempt
        migrations.CreateModel(
            name='FailedLoginAttempt',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('attempt_time', models.DateTimeField()),
                ('ip_address', models.CharField(max_length=39)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='failed_login_attempts', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_failedloginattempt',
            },
        ),

        # FeatureUsage
        migrations.CreateModel(
            name='FeatureUsage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('feature_name', models.CharField(max_length=100)),
                ('usage_count', models.PositiveIntegerField()),
            ],
            options={
                'db_table': 'trueAlign_featureusage',
            },
        ),

        # FinancialParameter
        migrations.CreateModel(
            name='FinancialParameter',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('key', models.CharField(max_length=100, db_index=True)),
                ('name', models.CharField(max_length=255)),
                ('category', models.CharField(max_length=20, db_index=True)),
                ('description', models.TextField(null=True, blank=True)),
                ('value', models.TextField()),
                ('value_type', models.CharField(max_length=20)),
                ('is_global', models.BooleanField()),
                ('object_id', models.PositiveIntegerField(null=True, blank=True)),
                ('valid_from', models.DateField(db_index=True)),
                ('valid_to', models.DateField(null=True, blank=True)),
                ('fiscal_year', models.CharField(max_length=9, null=True, blank=True, db_index=True)),
                ('fiscal_quarter', models.CharField(max_length=6, null=True, blank=True)),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
                ('is_approved', models.BooleanField()),
                ('approved_at', models.DateTimeField(null=True, blank=True)),
                ('approved_by', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='approved_financial_parameters', to=settings.AUTH_USER_MODEL)),
                ('content_type', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, to='contenttypes.contenttype')),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='created_financial_parameters', to=settings.AUTH_USER_MODEL)),
                ('updated_by', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='updated_financial_parameters', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_financialparameter',
            },
        ),

        # Add foreign keys for models that reference other models
        # DailyExpense -> Department
        migrations.AddField(
            model_name='dailyexpense',
            name='department',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='expenses', to='trueAlign.department'),
        ),

        # GameIcon
        migrations.CreateModel(
            name='GameIcon',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=50)),
                ('symbol', models.CharField(max_length=10)),
                ('is_active', models.BooleanField()),
                ('created_at', models.DateTimeField()),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='created_game_icons', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_gameicon',
            },
        ),

        # GameSpectator
        migrations.CreateModel(
            name='GameSpectator',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('joined_at', models.DateTimeField()),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='spectated_games', to=settings.AUTH_USER_MODEL)),
                ('game_id', models.CharField(max_length=32)),
            ],
            options={
                'db_table': 'trueAlign_gamespectator',
            },
        ),

        # GlobalUpdate
        migrations.CreateModel(
            name='GlobalUpdate',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('title', models.CharField(max_length=255)),
                ('description', models.TextField()),
                ('status', models.CharField(max_length=20)),
                ('scheduled_date', models.DateTimeField(null=True, blank=True)),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
                ('managed_by', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='managed_global_updates', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_globalupdate',
            },
        ),

        # GroupMember
        migrations.CreateModel(
            name='GroupMember',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('role', models.CharField(max_length=20)),
                ('joined_at', models.DateTimeField()),
                ('is_active', models.BooleanField()),
                ('last_seen', models.DateTimeField()),
                ('typing_status', models.DateTimeField(null=True, blank=True)),
                ('group', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='members', to='trueAlign.chatgroup')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='group_memberships', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_groupmember',
            },
        ),

        # Holiday
        migrations.CreateModel(
            name='Holiday',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('date', models.DateField()),
                ('recurring_yearly', models.BooleanField()),
                ('created_at', models.DateTimeField()),
            ],
            options={
                'db_table': 'trueAlign_holiday',
            },
        ),

        # LeavePolicy
        migrations.CreateModel(
            name='LeavePolicy',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('is_active', models.BooleanField()),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
                ('group', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='leave_policies', to='auth.group')),
            ],
            options={
                'db_table': 'trueAlign_leavepolicy',
            },
        ),

        # LeaveType
        migrations.CreateModel(
            name='LeaveType',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100, unique=True)),
                ('description', models.TextField(null=True, blank=True)),
                ('is_paid', models.BooleanField()),
                ('requires_approval', models.BooleanField()),
                ('requires_documentation', models.BooleanField()),
                ('count_weekends', models.BooleanField()),
                ('can_be_half_day', models.BooleanField()),
                ('is_active', models.BooleanField()),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
            ],
            options={
                'db_table': 'trueAlign_leavetype',
            },
        ),

        # LeaveAllocation
        migrations.CreateModel(
            name='LeaveAllocation',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('annual_days', models.DecimalField(max_digits=5, decimal_places=1)),
                ('carry_forward_limit', models.DecimalField(max_digits=5, decimal_places=1)),
                ('max_consecutive_days', models.IntegerField()),
                ('advance_notice_days', models.IntegerField()),
                ('policy', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='allocations', to='trueAlign.leavepolicy')),
                ('leave_type', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='allocations', to='trueAlign.leavetype')),
            ],
            options={
                'db_table': 'trueAlign_leaveallocation',
            },
        ),

        # LeaveRequest
        migrations.CreateModel(
            name='LeaveRequest',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('start_date', models.DateField()),
                ('end_date', models.DateField()),
                ('half_day', models.BooleanField()),
                ('leave_days', models.DecimalField(max_digits=5, decimal_places=1)),
                ('reason', models.TextField()),
                ('status', models.CharField(max_length=20)),
                ('rejection_reason', models.TextField(null=True, blank=True)),
                ('suggested_dates', models.TextField(null=True, blank=True)),
                ('documentation', models.CharField(max_length=100, null=True, blank=True)),
                ('is_retroactive', models.BooleanField()),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
                ('approver', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='approved_leave_requests', to=settings.AUTH_USER_MODEL)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='leave_requests', to=settings.AUTH_USER_MODEL)),
                ('leave_type', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='leave_requests', to='trueAlign.leavetype')),
            ],
            options={
                'db_table': 'trueAlign_leaverequest',
            },
        ),

        # Message
        migrations.CreateModel(
            name='Message',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('content', models.TextField()),
                ('message_type', models.CharField(max_length=20)),
                ('file_attachment', models.CharField(max_length=100, null=True, blank=True)),
                ('sent_at', models.DateTimeField()),
                ('edited_at', models.DateTimeField(null=True, blank=True)),
                ('is_deleted', models.BooleanField()),
                ('deleted_at', models.DateTimeField(null=True, blank=True)),
                ('direct_message', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.CASCADE, related_name='messages', to='trueAlign.directmessage')),
                ('group', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.CASCADE, related_name='messages', to='trueAlign.chatgroup')),
                ('sender', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sent_messages', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_message',
            },
        ),

        # MessageRead
        migrations.CreateModel(
            name='MessageRead',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('read_at', models.DateTimeField(null=True, blank=True)),
                ('message', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='read_receipts', to='trueAlign.message')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='message_reads', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_messageread',
            },
        ),

        # Notification
        migrations.CreateModel(
            name='Notification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('message', models.CharField(max_length=255)),
                ('notification_type', models.CharField(max_length=20)),
                ('is_read', models.BooleanField()),
                ('created_at', models.DateTimeField()),
                ('recipient', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='notifications', to=settings.AUTH_USER_MODEL)),
                ('game_id', models.CharField(max_length=32, null=True, blank=True)),
            ],
            options={
                'db_table': 'trueAlign_notification',
            },
        ),

        # PasswordChange
        migrations.CreateModel(
            name='PasswordChange',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('old_password', models.CharField(max_length=255)),
                ('new_password', models.CharField(max_length=255)),
                ('change_time', models.DateTimeField()),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='password_changes', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_passwordchange',
            },
        ),

        # PlayerStats
        migrations.CreateModel(
            name='PlayerStats',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('games_played', models.IntegerField()),
                ('games_won', models.IntegerField()),
                ('games_lost', models.IntegerField()),
                ('games_drawn', models.IntegerField()),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='player_stats', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_playerstats',
            },
        ),

        # Presence
        migrations.CreateModel(
            name='Presence',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('date', models.DateField()),
                ('status', models.CharField(max_length=20)),
                ('marked_at', models.DateTimeField()),
                ('notes', models.TextField(null=True, blank=True)),
                ('marked_by', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='marked_presences', to=settings.AUTH_USER_MODEL)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='presences', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_presence',
            },
        ),

        # Project
        migrations.CreateModel(
            name='Project',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('description', models.TextField()),
                ('start_date', models.DateField()),
                ('deadline', models.DateField()),
                ('status', models.CharField(max_length=20)),
                ('created_at', models.DateTimeField()),
                ('total_value', models.DecimalField(max_digits=12, decimal_places=2)),
                ('delivery_format', models.CharField(max_length=50)),
            ],
            options={
                'db_table': 'trueAlign_project',
            },
        ),

        # ProjectAssignment
        migrations.CreateModel(
            name='ProjectAssignment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('assigned_date', models.DateField()),
                ('hours_worked', models.FloatField()),
                ('role_in_project', models.CharField(max_length=50)),
                ('end_date', models.DateField(null=True, blank=True)),
                ('is_active', models.BooleanField()),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='assignments', to='trueAlign.project')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='project_assignments', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_projectassignment',
            },
        ),

        # ProjectUpdate
        migrations.CreateModel(
            name='ProjectUpdate',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('title', models.CharField(max_length=200)),
                ('description', models.TextField()),
                ('status', models.CharField(max_length=20)),
                ('scheduled_date', models.DateTimeField(null=True, blank=True)),
                ('created_at', models.DateTimeField()),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='created_project_updates', to=settings.AUTH_USER_MODEL)),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='updates', to='trueAlign.project')),
            ],
            options={
                'db_table': 'trueAlign_projectupdate',
            },
        ),

        # ProjectClients (Many-to-Many through table)
        migrations.CreateModel(
            name='ProjectClients',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='trueAlign.project')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_project_clients',
            },
        ),

        # RoleAssignmentAudit
        migrations.CreateModel(
            name='RoleAssignmentAudit',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('role_assigned', models.CharField(max_length=50)),
                ('assigned_date', models.DateTimeField()),
                ('assigned_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='role_assignments_made', to=settings.AUTH_USER_MODEL)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='role_assignment_history', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_roleassignmentaudit',
            },
        ),

        # ShiftMaster
        migrations.CreateModel(
            name='ShiftMaster',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=50)),
                ('start_time', models.TimeField()),
                ('end_time', models.TimeField()),
                ('shift_duration', models.DecimalField(max_digits=5, decimal_places=2)),
                ('break_duration', models.BigIntegerField()),
                ('grace_period', models.BigIntegerField()),
                ('work_days', models.CharField(max_length=20)),
                ('custom_work_days', models.CharField(max_length=255, null=True, blank=True)),
                ('is_active', models.BooleanField()),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
            ],
            options={
                'db_table': 'trueAlign_shiftmaster',
            },
        ),

        # ShiftAssignment
        migrations.CreateModel(
            name='ShiftAssignment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('effective_from', models.DateField()),
                ('effective_to', models.DateField(null=True, blank=True)),
                ('is_current', models.BooleanField(db_index=True)),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='shift_assignments', to=settings.AUTH_USER_MODEL)),
                ('shift', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='assignments', to='trueAlign.shiftmaster')),
            ],
            options={
                'db_table': 'trueAlign_shiftassignment',
            },
        ),

        # StatusLog
        migrations.CreateModel(
            name='StatusLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('old_status', models.CharField(max_length=30)),
                ('new_status', models.CharField(max_length=30)),
                ('changed_at', models.DateTimeField()),
                ('changed_by', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='status_changes', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_statuslog',
            },
        ),

        # Subscription
        migrations.CreateModel(
            name='Subscription',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=255)),
                ('vendor', models.CharField(max_length=255)),
                ('subscription_type', models.CharField(max_length=100)),
                ('amount', models.DecimalField(max_digits=15, decimal_places=2)),
                ('frequency', models.CharField(max_length=20)),
                ('start_date', models.DateField()),
                ('next_payment_date', models.DateField()),
                ('auto_renew', models.BooleanField()),
                ('status', models.CharField(max_length=20)),
                ('alert_days', models.IntegerField()),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
            ],
            options={
                'db_table': 'trueAlign_subscription',
            },
        ),

        # Support
        migrations.CreateModel(
            name='Support',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('ticket_id', models.CharField(max_length=100, unique=True)),
                ('issue_type', models.CharField(max_length=50)),
                ('subject', models.CharField(max_length=200)),
                ('description', models.TextField()),
                ('status', models.CharField(max_length=30, db_index=True)),
                ('priority', models.CharField(max_length=20, db_index=True)),
                ('created_at', models.DateTimeField(db_index=True)),
                ('updated_at', models.DateTimeField()),
                ('resolved_at', models.DateTimeField(null=True, blank=True, db_index=True)),
                ('due_date', models.DateTimeField(null=True, blank=True, db_index=True)),
                ('department', models.CharField(max_length=100)),
                ('location', models.CharField(max_length=100)),
                ('asset_id', models.CharField(max_length=50)),
                ('sla_breach', models.BooleanField()),
                ('resolution_summary', models.TextField()),
                ('resolution_time', models.BigIntegerField(null=True, blank=True)),
                ('satisfaction_rating', models.IntegerField(null=True, blank=True)),
                ('feedback', models.TextField()),
                ('assigned_group', models.CharField(max_length=50, null=True, blank=True)),
                ('escalation_level', models.PositiveSmallIntegerField()),
                ('response_time', models.BigIntegerField(null=True, blank=True)),
                ('sla_status', models.CharField(max_length=20, null=True, blank=True)),
                ('sla_target_date', models.DateTimeField(null=True, blank=True)),
                ('time_to_close', models.BigIntegerField(null=True, blank=True)),
                ('is_deleted', models.BooleanField()),
                ('reopen_count', models.PositiveSmallIntegerField()),
                ('assigned_to_user', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='assigned_tickets', to=settings.AUTH_USER_MODEL)),
                ('parent_ticket', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='child_tickets', to='trueAlign.support')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='support_tickets', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_support',
            },
        ),

        # SupportCCUsers (Many-to-Many through table)
        migrations.CreateModel(
            name='SupportCCUsers',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('support', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='trueAlign.support')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_support_cc_users',
            },
        ),

        # SystemError
        migrations.CreateModel(
            name='SystemError',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('error_message', models.TextField()),
                ('error_time', models.DateTimeField()),
                ('resolved', models.BooleanField()),
            ],
            options={
                'db_table': 'trueAlign_systemerror',
            },
        ),

        # SystemUsage
        migrations.CreateModel(
            name='SystemUsage',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('peak_time_start', models.DateTimeField()),
                ('peak_time_end', models.DateTimeField()),
                ('active_users_count', models.PositiveIntegerField()),
            ],
            options={
                'db_table': 'trueAlign_systemusage',
            },
        ),

        # TicketActivity
        migrations.CreateModel(
            name='TicketActivity',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('action', models.CharField(max_length=20)),
                ('timestamp', models.DateTimeField()),
                ('details', models.TextField()),
                ('ticket', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='activities', to='trueAlign.support')),
                ('user', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='ticket_activities', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_ticketactivity',
            },
        ),

        # TicketAttachment
        migrations.CreateModel(
            name='TicketAttachment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('file', models.CharField(max_length=100)),
                ('uploaded_at', models.DateTimeField()),
                ('description', models.CharField(max_length=255)),
                ('file_size', models.PositiveIntegerField()),
                ('file_type', models.CharField(max_length=100)),
                ('formatted_filename', models.CharField(max_length=255)),
                ('is_deleted', models.BooleanField()),
                ('original_filename', models.CharField(max_length=255)),
                ('ticket', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='attachments', to='trueAlign.support')),
                ('uploaded_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='uploaded_ticket_attachments', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_ticketattachment',
            },
        ),

        # TicketComment
        migrations.CreateModel(
            name='TicketComment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('content', models.TextField()),
                ('created_at', models.DateTimeField()),
                ('is_internal', models.BooleanField()),
                ('ticket', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='comments', to='trueAlign.support')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='ticket_comments', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_ticketcomment',
            },
        ),

        # TicTacToeGame
        migrations.CreateModel(
            name='TicTacToeGame',
            fields=[
                ('id', models.CharField(max_length=32, primary_key=True)),
                ('board', models.CharField(max_length=9)),
                ('status', models.CharField(max_length=20)),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
                ('last_move_at', models.DateTimeField()),
                ('allow_spectators', models.BooleanField()),
                ('creator', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='created_games', to=settings.AUTH_USER_MODEL)),
                ('creator_icon', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='creator_games', to='trueAlign.gameicon')),
                ('current_turn', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='current_turn_games', to=settings.AUTH_USER_MODEL)),
                ('opponent', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='opponent_games', to=settings.AUTH_USER_MODEL)),
                ('opponent_icon', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='opponent_games', to='trueAlign.gameicon')),
                ('winner', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='won_games', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_tictactoegame',
            },
        ),

        # Timesheet
        migrations.CreateModel(
            name='Timesheet',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('week_start_date', models.DateField()),
                ('task_name', models.CharField(max_length=255)),
                ('task_description', models.TextField()),
                ('hours', models.FloatField()),
                ('adjusted_hours', models.FloatField(null=True, blank=True)),
                ('approval_status', models.CharField(max_length=25)),
                ('rejection_reason', models.CharField(max_length=30, null=True, blank=True)),
                ('manager_comments', models.TextField(null=True, blank=True)),
                ('submitted_at', models.DateTimeField()),
                ('reviewed_at', models.DateTimeField(null=True, blank=True)),
                ('original_submission_id', models.IntegerField(null=True, blank=True)),
                ('version', models.PositiveIntegerField()),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='timesheets', to='trueAlign.project')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='timesheets', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_timesheet',
            },
        ),

        # UserActionLog
        migrations.CreateModel(
            name='UserActionLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('action_type', models.CharField(max_length=20)),
                ('timestamp', models.DateTimeField()),
                ('details', models.TextField(null=True, blank=True)),
                ('action_by', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='actions_performed', to=settings.AUTH_USER_MODEL)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='action_logs', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_useractionlog',
            },
        ),

        # UserDetails
        migrations.CreateModel(
            name='UserDetails',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('dob', models.DateField(null=True, blank=True)),
                ('blood_group', models.CharField(max_length=10, null=True, blank=True)),
                ('gender', models.CharField(max_length=20, null=True, blank=True)),
                ('marital_status', models.CharField(max_length=20, null=True, blank=True)),
                ('contact_number_primary', models.CharField(max_length=15, null=True, blank=True)),
                ('personal_email', models.CharField(max_length=254, unique=True, null=True, blank=True)),
                ('company_email', models.CharField(max_length=254, unique=True, null=True, blank=True)),
                ('current_address_line1', models.CharField(max_length=255, null=True, blank=True)),
                ('current_address_line2', models.CharField(max_length=255, null=True, blank=True)),
                ('current_city', models.CharField(max_length=100, null=True, blank=True)),
                ('current_state', models.CharField(max_length=100, null=True, blank=True)),
                ('current_postal_code', models.CharField(max_length=10, null=True, blank=True)),
                ('current_country', models.CharField(max_length=100, null=True, blank=True)),
                ('permanent_address_line1', models.CharField(max_length=255, null=True, blank=True)),
                ('permanent_address_line2', models.CharField(max_length=255, null=True, blank=True)),
                ('permanent_city', models.CharField(max_length=100, null=True, blank=True)),
                ('permanent_state', models.CharField(max_length=100, null=True, blank=True)),
                ('permanent_postal_code', models.CharField(max_length=10, null=True, blank=True)),
                ('permanent_country', models.CharField(max_length=100, null=True, blank=True)),
                ('is_current_same_as_permanent', models.BooleanField()),
                ('emergency_contact_name', models.CharField(max_length=255, null=True, blank=True)),
                ('emergency_contact_number', models.CharField(max_length=15, null=True, blank=True)),
                ('emergency_contact_relationship', models.CharField(max_length=50, null=True, blank=True)),
                ('secondary_emergency_contact_name', models.CharField(max_length=255, null=True, blank=True)),
                ('secondary_emergency_contact_number', models.CharField(max_length=15, null=True, blank=True)),
                ('secondary_emergency_contact_relationship', models.CharField(max_length=50, null=True, blank=True)),
                ('employee_type', models.CharField(max_length=20, null=True, blank=True, db_index=True)),
                ('hire_date', models.DateField(null=True, blank=True, db_index=True)),
                ('start_date', models.DateField(null=True, blank=True, db_index=True)),
                ('probation_end_date', models.DateField(null=True, blank=True)),
                ('notice_period_days', models.PositiveIntegerField()),
                ('job_description', models.TextField(null=True, blank=True)),
                ('work_location', models.CharField(max_length=100, null=True, blank=True, db_index=True)),
                ('employment_status', models.CharField(max_length=50, db_index=True)),
                ('exit_date', models.DateField(null=True, blank=True)),
                ('exit_reason', models.TextField(null=True, blank=True)),
                ('rehire_eligibility', models.BooleanField(null=True, blank=True)),
                ('salary_currency', models.CharField(max_length=3)),
                ('base_salary', models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)),
                ('salary_frequency', models.CharField(max_length=20)),
                ('pan_number', models.CharField(max_length=10, null=True, blank=True)),
                ('aadhar_number', models.CharField(max_length=12, null=True, blank=True)),
                ('passport_number', models.CharField(max_length=20, null=True, blank=True)),
                ('passport_expiry', models.DateField(null=True, blank=True)),
                ('bank_name', models.CharField(max_length=100, null=True, blank=True)),
                ('bank_account_number', models.CharField(max_length=30, null=True, blank=True)),
                ('bank_ifsc', models.CharField(max_length=11, null=True, blank=True)),
                ('previous_company', models.CharField(max_length=255, null=True, blank=True)),
                ('previous_position', models.CharField(max_length=100, null=True, blank=True)),
                ('previous_experience_years', models.PositiveIntegerField(null=True, blank=True)),
                ('onboarding_date', models.DateTimeField()),
                ('last_updated', models.DateTimeField()),
                ('last_status_change', models.DateTimeField(null=True, blank=True)),
                ('skills', models.TextField(null=True, blank=True)),
                ('confidential_notes', models.TextField(null=True, blank=True)),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
                ('onboarded_by', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='onboarded_users', to=settings.AUTH_USER_MODEL)),
                ('reporting_manager', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='team_members', to=settings.AUTH_USER_MODEL)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='user_details', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_userdetails',
            },
        ),

        # UserLeaveBalance
        migrations.CreateModel(
            name='UserLeaveBalance',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('year', models.IntegerField()),
                ('allocated', models.DecimalField(max_digits=5, decimal_places=1)),
                ('used', models.DecimalField(max_digits=5, decimal_places=1)),
                ('carried_forward', models.DecimalField(max_digits=5, decimal_places=1)),
                ('additional', models.DecimalField(max_digits=5, decimal_places=1)),
                ('leave_type', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='user_balances', to='trueAlign.leavetype')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='leave_balances', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_userleavebalance',
            },
        ),

        # UserSession
        migrations.CreateModel(
            name='UserSession',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('session_key', models.CharField(max_length=40)),
                ('ip_address', models.CharField(max_length=39, null=True, blank=True)),
                ('user_agent', models.TextField(null=True, blank=True)),
                ('login_time', models.DateTimeField()),
                ('logout_time', models.DateTimeField(null=True, blank=True)),
                ('working_hours', models.BigIntegerField(null=True, blank=True)),
                ('idle_time', models.BigIntegerField()),
                ('last_activity', models.DateTimeField(db_index=True)),
                ('location', models.CharField(max_length=50, null=True, blank=True)),
                ('session_duration', models.FloatField(null=True, blank=True)),
                ('is_active', models.BooleanField(db_index=True)),
                ('auto_logout_enabled', models.BooleanField()),
                ('background_time', models.BigIntegerField()),
                ('battery_level', models.FloatField(null=True, blank=True)),
                ('broadcast_messages_received', models.IntegerField()),
                ('broadcast_messages_sent', models.IntegerField()),
                ('browser_fingerprint', models.TextField(null=True, blank=True)),
                ('click_events', models.TextField()),
                ('connection_type', models.CharField(max_length=20, null=True, blank=True)),
                ('cross_tab_activity_syncs', models.IntegerField()),
                ('csrf_token', models.CharField(max_length=64, null=True, blank=True)),
                ('csrf_token_created', models.DateTimeField(null=True, blank=True)),
                ('custom_timeout', models.PositiveIntegerField(null=True, blank=True)),
                ('device_type', models.CharField(max_length=20, null=True, blank=True)),
                ('engagement_score', models.FloatField(null=True, blank=True)),
                ('error_events', models.TextField()),
                ('inactivity_warnings_sent', models.IntegerField()),
                ('is_primary_tab', models.BooleanField()),
                ('keyboard_events', models.TextField()),
                ('language', models.CharField(max_length=10, null=True, blank=True)),
                ('last_sync_time', models.DateTimeField(null=True, blank=True)),
                ('last_warning_time', models.DateTimeField(null=True, blank=True)),
                ('mouse_movements', models.IntegerField()),
                ('network_events', models.TextField()),
                ('offline_data', models.TextField()),
                ('page_views', models.TextField()),
                ('parent_session_id', models.CharField(max_length=50, null=True, blank=True, db_index=True)),
                ('pending_sync_count', models.IntegerField()),
                ('performance_metrics', models.TextField()),
                ('productivity_score', models.FloatField(null=True, blank=True)),
                ('screen_resolution', models.CharField(max_length=20, null=True, blank=True)),
                ('scroll_events', models.TextField()),
                ('security_incidents', models.TextField()),
                ('session_fingerprint', models.CharField(max_length=255, null=True, blank=True)),
                ('session_quality', models.CharField(max_length=20, null=True, blank=True)),
                ('tab_id', models.CharField(max_length=50, null=True, blank=True, db_index=True)),
                ('tab_last_focus', models.DateTimeField(null=True, blank=True)),
                ('tab_opened_time', models.DateTimeField(null=True, blank=True)),
                ('tab_switches', models.IntegerField()),
                ('tab_title', models.CharField(max_length=255, null=True, blank=True)),
                ('tab_total_focus_time', models.BigIntegerField()),
                ('tab_url', models.CharField(max_length=200, null=True, blank=True)),
                ('tab_visibility_log', models.TextField()),
                ('timezone_offset', models.IntegerField(null=True, blank=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='user_sessions', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_usersession',
            },
        ),

        # Voucher
        migrations.CreateModel(
            name='Voucher',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('voucher_number', models.CharField(max_length=50, unique=True)),
                ('type', models.CharField(max_length=20)),
                ('date', models.DateField()),
                ('reference_no', models.CharField(max_length=100, null=True, blank=True)),
                ('party_name', models.CharField(max_length=255)),
                ('purpose', models.TextField()),
                ('amount', models.DecimalField(max_digits=15, decimal_places=2)),
                ('status', models.CharField(max_length=25)),
                ('attachments', models.CharField(max_length=100, null=True, blank=True)),
                ('created_at', models.DateTimeField()),
                ('updated_at', models.DateTimeField()),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='created_vouchers', to=settings.AUTH_USER_MODEL)),
                ('department_approved_by', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='department_approved_vouchers', to=settings.AUTH_USER_MODEL)),
                ('finance_approved_by', models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='finance_approved_vouchers', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'trueAlign_voucher',
            },
        ),

        # VoucherDetail
        migrations.CreateModel(
            name='VoucherDetail',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ('debit_amount', models.DecimalField(max_digits=15, decimal_places=2)),
                ('credit_amount', models.DecimalField(max_digits=15, decimal_places=2)),
                ('description', models.TextField(null=True, blank=True)),
                ('account', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='voucher_details', to='trueAlign.chartofaccount')),
                ('voucher', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='details', to='trueAlign.voucher')),
            ],
            options={
                'db_table': 'trueAlign_voucherdetail',
            },
        ),

        # Add foreign keys for models that reference other models created later
        # ClientParticipation -> Project
        migrations.AddField(
            model_name='clientparticipation',
            name='project',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='client_participations', to='trueAlign.project'),
        ),

        # CommentAttachment -> TicketComment and TicketActivity
        migrations.AddField(
            model_name='commentattachment',
            name='comment',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='attachments', to='trueAlign.ticketcomment'),
        ),
        migrations.AddField(
            model_name='commentattachment',
            name='ticket_activity',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='attachments', to='trueAlign.ticketactivity'),
        ),

        # StatusLog -> Support (ticket)
        migrations.AddField(
            model_name='statuslog',
            name='ticket',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='status_logs', to='trueAlign.support'),
        ),

        # Attendance -> ShiftMaster (shift)
        migrations.AddField(
            model_name='attendance',
            name='shift',
            field=models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='attendances', to='trueAlign.shiftmaster'),
        ),

        # Attendance -> UserSession (first_session and last_session)
        migrations.AddField(
            model_name='attendance',
            name='first_session',
            field=models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='first_session_attendances', to='trueAlign.usersession'),
        ),
        migrations.AddField(
            model_name='attendance',
            name='last_session',
            field=models.ForeignKey(null=True, blank=True, on_delete=django.db.models.deletion.SET_NULL, related_name='last_session_attendances', to='trueAlign.usersession'),
        ),
    ]
