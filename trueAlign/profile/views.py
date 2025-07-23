from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib.auth.models import User
from django.contrib import messages
from django.views.generic import ListView, DetailView, UpdateView, CreateView
from django.http import HttpResponse
from django.db.models import Count, Q
from django.utils import timezone
from django.views.decorators.http import require_POST
import csv
import pandas as pd
from io import BytesIO

from trueAlign.models import UserDetails, UserActionLog, OfficeLocation
from .utilities import generate_employee_id, send_welcome_email
from .forms import UserDetailsCreateForm, UserDetailsUpdateForm, CSVImportForm

# Helpers
def is_hr_or_admin(user):
    """Check if user has HR or admin role"""
    try:
        # Check if user is in HR group
        if user.groups.filter(name='HR').exists():
            return True

        profile = user.profile
        job_description = profile.job_description or ''
        return user.is_superuser or profile.employee_type == 'hr' or 'HR' in job_description
    except (AttributeError, UserDetails.DoesNotExist):
        return False

# Mixins
class HRAdminRequiredMixin(UserPassesTestMixin):
    """Mixin to restrict views to HR and Admin users only"""
    def test_func(self):
        return is_hr_or_admin(self.request.user)

# Dashboard View
@login_required
def hr_dashboard(request):
    """HR Dashboard with user statistics"""
    if not is_hr_or_admin(request.user):
        messages.error(request, "You don't have permission to access the HR dashboard.")
        return redirect('home')

    from datetime import datetime, timedelta
    from django.utils import timezone

    # Get overall stats - count both User and UserDetails
    total_users = User.objects.filter(is_active=True).count()
    user_details_count = UserDetails.objects.count()

    # Use the higher count to show all users
    if user_details_count > total_users:
        total_users = user_details_count

    # Get active users based on employment status
    active_users = UserDetails.objects.filter(employment_status='active').count()

    # If no UserDetails records, check User.is_active
    if active_users == 0:
        active_users = User.objects.filter(is_active=True).count()

    # Calculate inactive users
    inactive_users = total_users - active_users if total_users > active_users else 0

    # Get stats by office location
    location_stats = UserDetails.objects.values('office_location__name')\
        .annotate(count=Count('id'))\
        .order_by('-count')

    # Get stats by employment status
    status_stats = UserDetails.objects.values('employment_status')\
        .annotate(count=Count('id'))\
        .order_by('-count')

    # Get recent logins - from User model
    recent_logins = User.objects.filter(last_login__isnull=False)\
        .order_by('-last_login')[:10]

    # Get new users this month
    thirty_days_ago = timezone.now() - timedelta(days=30)
    new_users = UserDetails.objects.filter(created_at__gte=thirty_days_ago)\
        .order_by('-created_at')[:10]

    # If no UserDetails with created_at, check User.date_joined
    if not new_users.exists():
        new_users_from_auth = User.objects.filter(date_joined__gte=thirty_days_ago)\
            .order_by('-date_joined')[:10]
        # Create a simple structure for new users
        new_users = []
        for user in new_users_from_auth:
            new_users.append({
                'user': user,
                'created_at': user.date_joined
            })

    # Count new hires this month
    new_hires_count = UserDetails.objects.filter(created_at__gte=thirty_days_ago).count()
    if new_hires_count == 0:
        new_hires_count = User.objects.filter(date_joined__gte=thirty_days_ago).count()

    context = {
        'total_users': total_users,
        'active_users': active_users,
        'inactive_users': inactive_users,
        'new_hires_count': new_hires_count,
        'location_stats': location_stats,
        'status_stats': status_stats,
        'recent_logins': recent_logins,
        'new_users': new_users,
    }

    return render(request, 'profile/dashboard.html', context)

# User List View
class UserListView(LoginRequiredMixin, ListView):
    model = UserDetails
    template_name = 'profile/user_list.html'
    context_object_name = 'users'
    paginate_by = 25

    def get_queryset(self):
        queryset = UserDetails.objects.select_related('user', 'office_location', 'reporting_manager')

        # Apply filters from GET parameters
        status = self.request.GET.get('status')
        location = self.request.GET.get('location')
        employee_type = self.request.GET.get('employee_type')
        search_query = self.request.GET.get('search')

        if status:
            queryset = queryset.filter(employment_status=status)

        if location:
            queryset = queryset.filter(office_location_id=location)

        if employee_type:
            queryset = queryset.filter(employee_type=employee_type)

        if search_query:
            queryset = queryset.filter(
                Q(user__username__icontains=search_query) |
                Q(user__first_name__icontains=search_query) |
                Q(user__last_name__icontains=search_query) |
                Q(user__email__icontains=search_query) |
                Q(company_email__icontains=search_query) |
                Q(personal_email__icontains=search_query) |
                Q(contact_number_primary__icontains=search_query)
            )

        return queryset.order_by('user__username')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['status_choices'] = UserDetails.EMPLOYMENT_STATUS_CHOICES
        context['employee_types'] = UserDetails.EMPLOYEE_TYPE_CHOICES
        context['locations'] = OfficeLocation.objects.filter(is_active=True)

        # Get current filter values for the template
        context['current_status'] = self.request.GET.get('status', '')
        context['current_location'] = self.request.GET.get('location', '')
        context['current_employee_type'] = self.request.GET.get('employee_type', '')
        context['search_query'] = self.request.GET.get('search', '')

        return context

# User Detail View
class UserDetailView(LoginRequiredMixin, DetailView):
    model = UserDetails
    template_name = 'profile/user_detail.html'
    context_object_name = 'user_profile'

    def get_object(self):
        return get_object_or_404(
            UserDetails.objects.select_related('user', 'office_location', 'reporting_manager'),
            user__id=self.kwargs['pk']
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user_profile = self.get_object()

        # Get user action logs for this user
        context['action_logs'] = UserActionLog.objects.filter(
            user=user_profile.user
        ).order_by('-timestamp')[:20]

        # Check if current user is HR/Admin or the user's manager
        is_manager = False
        try:
            if self.request.user == user_profile.reporting_manager:
                is_manager = True
        except:
            pass

        # Set context variables for template
        context['is_hr'] = is_hr_or_admin(self.request.user)
        context['can_edit'] = is_hr_or_admin(self.request.user) or is_manager

        return context

# User Create View - HR/Admin only
class UserCreateView(LoginRequiredMixin, HRAdminRequiredMixin, CreateView):
    model = UserDetails
    form_class = UserDetailsCreateForm
    template_name = 'profile/user_form.html'

    def form_valid(self, form):
        # Get form data
        email = form.cleaned_data.get('email')
        password = form.cleaned_data.get('password')
        first_name = form.cleaned_data.get('first_name')
        last_name = form.cleaned_data.get('last_name')
        work_location = form.cleaned_data.get('office_location')
        group = form.cleaned_data.get('group')

        try:
            # Generate employee ID based on location and role
            username = generate_employee_id(work_location=str(work_location) if work_location else None, group_id=str(group.id) if group else None)

            # Create user
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name
            )

            # Add user to the selected group
            if group:
                user.groups.add(group)

            # Associate user with the profile
            user_profile = form.save(commit=False)
            user_profile.user = user
            user_profile.onboarded_by = self.request.user
            user_profile.save()

            # Send welcome email
            try:
                send_welcome_email(user, password)
                messages.success(self.request, f'User account created for {username} and welcome email sent')
            except Exception as email_error:
                messages.warning(self.request, f'User account created for {username} but email failed: {str(email_error)}')

            # Log the action
            UserActionLog.objects.create(
                user=user,
                action_type='create',
                action_by=self.request.user,
                details=f"User created by {self.request.user.username}"
            )

            return redirect('profile:user-detail', pk=user.id)
        except Exception as e:
            messages.error(self.request, f'Error creating user: {str(e)}')
            return self.form_invalid(form)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = 'Create New User'
        return context

# User Update View
class UserUpdateView(LoginRequiredMixin, HRAdminRequiredMixin, UpdateView):
    model = UserDetails
    form_class = UserDetailsUpdateForm
    template_name = 'profile/user_form.html'

    def get_object(self):
        return get_object_or_404(UserDetails, user__id=self.kwargs['pk'])

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.get_object().user
        return kwargs

    def form_valid(self, form):
        user_profile = form.save()

        # Update the User model fields if provided
        user = user_profile.user
        first_name = form.cleaned_data.get('first_name')
        last_name = form.cleaned_data.get('last_name')
        email = form.cleaned_data.get('email')

        if first_name:
            user.first_name = first_name
        if last_name:
            user.last_name = last_name
        if email:
            user.email = email

        user.save()

        # Log the action
        UserActionLog.objects.create(
            user=user,
            action_type='update',
            action_by=self.request.user,
            details=f"User profile updated by {self.request.user.username}"
        )

        messages.success(self.request, 'User profile has been updated')
        return redirect('profile:user-detail', pk=user.id)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = 'Update User'
        user_profile = self.get_object()
        context['user_data'] = user_profile.user
        return context

# User Status Change View
@login_required
@require_POST
def change_user_status(request, pk):
    if not is_hr_or_admin(request.user):
        messages.error(request, "You don't have permission to change user status.")
        return redirect('profile:user-detail', pk=pk)

    user_profile = get_object_or_404(UserDetails, user__id=pk)
    new_status = request.POST.get('status')

    if new_status in dict(UserDetails.EMPLOYMENT_STATUS_CHOICES):
        old_status = user_profile.employment_status
        user_profile.employment_status = new_status
        user_profile.last_status_change = timezone.now()

        # If deactivating user, record exit date
        if new_status in ['inactive', 'terminated', 'resigned', 'absconding']:
            if not user_profile.exit_date:
                user_profile.exit_date = timezone.now().date()

            # Record exit reason if provided
            exit_reason = request.POST.get('exit_reason')
            if exit_reason:
                user_profile.exit_reason = exit_reason

            # Record rehire eligibility if provided
            rehire_eligibility = request.POST.get('rehire_eligibility')
            if rehire_eligibility is not None:
                user_profile.rehire_eligibility = rehire_eligibility == 'true'

        user_profile.save()

        # Log the action
        UserActionLog.objects.create(
            user=user_profile.user,
            action_type='status_change',
            action_by=request.user,
            details=f"Status changed from {old_status} to {new_status} by {request.user.username}"
        )

        messages.success(request, f'User status updated to {dict(UserDetails.EMPLOYMENT_STATUS_CHOICES)[new_status]}')
    else:
        messages.error(request, 'Invalid status provided')

    return redirect('profile:user-detail', pk=pk)

# Password Reset View
@login_required
@require_POST
def reset_user_password(request, pk):
    if not is_hr_or_admin(request.user):
        messages.error(request, "You don't have permission to reset passwords.")
        return redirect('profile:user-detail', pk=pk)

    user = get_object_or_404(User, id=pk)
    new_password = request.POST.get('new_password')

    if new_password:
        user.set_password(new_password)
        user.save()

        # Check if we should send email notification
        send_email = request.POST.get('send_email') == 'on'

        if send_email:
            try:
                send_welcome_email(user, new_password)
                messages.success(request, f'Password has been reset for {user.username} and notification email sent')
            except Exception as email_error:
                messages.warning(request, f'Password reset for {user.username} but email failed: {str(email_error)}')
        else:
            messages.success(request, f'Password has been reset for {user.username}')

        # Log the action
        UserActionLog.objects.create(
            user=user,
            action_type='password_reset',
            action_by=request.user,
            details=f"Password reset by {request.user.username}"
        )
    else:
        messages.error(request, 'No password provided')

    return redirect('profile:user-detail', pk=pk)

# CSV Export View
@login_required
def export_users_csv(request):
    if not is_hr_or_admin(request.user):
        messages.error(request, "You don't have permission to export user data.")
        return redirect('profile:user-list')

    # Apply the same filters as in the UserListView
    queryset = UserDetails.objects.select_related('user', 'office_location', 'reporting_manager')

    status = request.GET.get('status')
    location = request.GET.get('location')
    employee_type = request.GET.get('employee_type')
    search_query = request.GET.get('search')

    if status:
        queryset = queryset.filter(employment_status=status)

    if location:
        queryset = queryset.filter(office_location_id=location)

    if employee_type:
        queryset = queryset.filter(employee_type=employee_type)

    if search_query:
        queryset = queryset.filter(
            Q(user__username__icontains=search_query) |
            Q(user__first_name__icontains=search_query) |
            Q(user__last_name__icontains=search_query) |
            Q(user__email__icontains=search_query) |
            Q(company_email__icontains=search_query) |
            Q(personal_email__icontains=search_query) |
            Q(contact_number_primary__icontains=search_query)
        )

    # Create the HttpResponse object with CSV header
    response = HttpResponse(content_type='text/csv')
    timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
    response['Content-Disposition'] = f'attachment; filename="users_export_{timestamp}.csv"'

    # Create the CSV writer
    writer = csv.writer(response)
    writer.writerow([
        'Employee ID', 'Username', 'Full Name', 'Email', 'Company Email', 'Personal Email',
        'Contact Number', 'Office Location', 'Employment Status', 'Employee Type',
        'Hire Date', 'Start Date', 'Reporting Manager', 'Last Login'
    ])

    # Write data rows
    for user_profile in queryset:
        writer.writerow([
            user_profile.user.id,
            user_profile.user.username,
            user_profile.full_name,
            user_profile.user.email,
            user_profile.company_email or '',
            user_profile.personal_email or '',
            user_profile.contact_number_primary or '',
            user_profile.office_location.name if user_profile.office_location else '',
            dict(UserDetails.EMPLOYMENT_STATUS_CHOICES).get(user_profile.employment_status, ''),
            dict(UserDetails.EMPLOYEE_TYPE_CHOICES).get(user_profile.employee_type, ''),
            user_profile.hire_date.strftime('%Y-%m-%d') if user_profile.hire_date else '',
            user_profile.start_date.strftime('%Y-%m-%d') if user_profile.start_date else '',
            user_profile.reporting_manager.get_full_name() if user_profile.reporting_manager else '',
            user_profile.user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user_profile.user.last_login else ''
        ])

    # Log the export action
    UserActionLog.objects.create(
        user=request.user,
        action_type='update',
        action_by=request.user,
        details=f"User data exported to CSV by {request.user.username}"
    )

    return response

# Audit Log View
class AuditLogListView(LoginRequiredMixin, HRAdminRequiredMixin, ListView):
    model = UserActionLog
    template_name = 'profile/audit_logs.html'
    context_object_name = 'logs'
    paginate_by = 50

    def get_queryset(self):
        queryset = UserActionLog.objects.select_related('user', 'action_by')

        # Apply filters
        action_type = self.request.GET.get('action_type')
        user_id = self.request.GET.get('user_id')
        start_date = self.request.GET.get('start_date')
        end_date = self.request.GET.get('end_date')

        if action_type:
            queryset = queryset.filter(action_type=action_type)

        if user_id:
            queryset = queryset.filter(user_id=user_id)

        if start_date:
            try:
                start_date = datetime.datetime.strptime(start_date, '%Y-%m-%d').date()
                queryset = queryset.filter(timestamp__date__gte=start_date)
            except ValueError:
                pass

        if end_date:
            try:
                end_date = datetime.datetime.strptime(end_date, '%Y-%m-%d').date()
                queryset = queryset.filter(timestamp__date__lte=end_date)
            except ValueError:
                pass

        return queryset.order_by('-timestamp')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['action_types'] = UserActionLog.ACTION_TYPES
        context['users'] = User.objects.all()

        # Get current filter values
        context['current_action_type'] = self.request.GET.get('action_type', '')
        context['current_user_id'] = self.request.GET.get('user_id', '')
        context['current_start_date'] = self.request.GET.get('start_date', '')
        context['current_end_date'] = self.request.GET.get('end_date', '')

        return context


@login_required
def bulk_upload_users(request):
    """Bulk upload users from CSV/XLSX file"""
    if not is_hr_or_admin(request.user):
        messages.error(request, "You don't have permission to access this feature.")
        return redirect('profile:dashboard')

    if request.method == 'POST':
        form = CSVImportForm(request.POST, request.FILES)
        if form.is_valid():
            csv_file = request.FILES['csv_file']
            group = form.cleaned_data['group']
            office_location = form.cleaned_data['office_location']

            try:
                # Read file based on extension
                if csv_file.name.endswith('.csv'):
                    df = pd.read_csv(csv_file)
                elif csv_file.name.endswith(('.xlsx', '.xls')):
                    df = pd.read_excel(csv_file)
                else:
                    messages.error(request, 'Invalid file format. Please upload CSV or XLSX file.')
                    return render(request, 'profile/bulk_upload.html', {'form': form})

                # Expected columns: first_name, last_name, email, employee_type (optional)
                required_columns = ['first_name', 'last_name', 'email']
                missing_columns = [col for col in required_columns if col not in df.columns]

                if missing_columns:
                    messages.error(request, f'Missing required columns: {", ".join(missing_columns)}')
                    return render(request, 'profile/bulk_upload.html', {'form': form})

                success_count = 0
                error_count = 0
                errors = []

                for index, row in df.iterrows():
                    try:
                        # Validate required fields
                        if pd.isna(row['first_name']) or pd.isna(row['last_name']) or pd.isna(row['email']):
                            errors.append(f"Row {index + 2}: Missing required fields")
                            error_count += 1
                            continue

                        # Check if email already exists
                        if User.objects.filter(email=row['email']).exists():
                            errors.append(f"Row {index + 2}: Email {row['email']} already exists")
                            error_count += 1
                            continue

                        # Generate employee ID
                        username = generate_employee_id(
                            work_location=str(office_location),
                            group_id=str(group.id)
                        )

                        # Default password
                        password = "Welcome@123"

                        # Create user
                        user = User.objects.create_user(
                            username=username,
                            email=row['email'],
                            password=password,
                            first_name=row['first_name'],
                            last_name=row['last_name']
                        )

                        # Add user to group
                        user.groups.add(group)

                        # Create user profile
                        user_profile = UserDetails.objects.create(
                            user=user,
                            office_location=office_location,
                            employee_type=row.get('employee_type', 'full_time') if not pd.isna(row.get('employee_type')) else 'full_time',
                            employment_status='probation',
                            onboarded_by=request.user
                        )

                        # Try to send welcome email
                        try:
                            send_welcome_email(user, password)
                        except Exception as email_error:
                            errors.append(f"Row {index + 2}: User created but email failed - {str(email_error)}")

                        # Log the action
                        UserActionLog.objects.create(
                            user=user,
                            action_type='create',
                            action_by=request.user,
                            details=f"User created via bulk upload by {request.user.username}"
                        )

                        success_count += 1

                    except Exception as e:
                        errors.append(f"Row {index + 2}: {str(e)}")
                        error_count += 1

                # Show results
                if success_count > 0:
                    messages.success(request, f'Successfully created {success_count} users.')

                if error_count > 0:
                    messages.warning(request, f'{error_count} users failed to create.')
                    # Store errors in session for detailed view
                    request.session['bulk_upload_errors'] = errors

                return redirect('profile:user-list')

            except Exception as e:
                messages.error(request, f'Error processing file: {str(e)}')

    else:
        form = CSVImportForm()

    return render(request, 'profile/bulk_upload.html', {'form': form})


@login_required
def bulk_upload_errors(request):
    """Show detailed errors from bulk upload"""
    if not is_hr_or_admin(request.user):
        messages.error(request, "You don't have permission to access this feature.")
        return redirect('profile:dashboard')

    errors = request.session.get('bulk_upload_errors', [])
    context = {
        'errors': errors,
        'title': 'Bulk Upload Errors'
    }
    return render(request, 'profile/bulk_upload_errors.html', context)
