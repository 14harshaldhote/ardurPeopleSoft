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

        # CommentAttachment -> TicketComment and TicketActivity (will be added when those models are created)
    ]
