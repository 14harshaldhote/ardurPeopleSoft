from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse_lazy
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib.auth.models import User, Group
from django.contrib import messages
from django.views.generic import ListView, DetailView, UpdateView, CreateView
from django.http import HttpResponse, JsonResponse
from django.db.models import Count, Q, Avg, Sum, F, Case, When, IntegerField
from django.utils import timezone
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.cache import cache_page
from django.core.paginator import Paginator
from django.core.cache import cache
from django.db import transaction, IntegrityError
from django.core.exceptions import ValidationError
from datetime import datetime, timedelta
import csv
import pandas as pd
import json
import logging
from io import BytesIO

from trueAlign.models import UserDetails, UserActionLog, OfficeLocation, UserSession, SessionActivity
from .utilities import generate_employee_id, send_welcome_email, hr_admin_required, generate_secure_password
from .forms import UserDetailsCreateForm, UserDetailsUpdateForm, CSVImportForm, UserProfileForm
from .constants import (
    DEFAULT_PAGINATION_SIZE,
    MAX_CSV_FILE_SIZE_BYTES,
    CACHE_TIMEOUT_ANALYTICS,
    CACHE_TIMEOUT_DASHBOARD,
    ERROR_MESSAGES
)

# Configure logging
logger = logging.getLogger(__name__)

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
    """
    Dashboard view for HR and Admins.
    Displays key statistics and quick actions.
    """
    # Check if user is HR or Admin
    if not (request.user.is_superuser or request.user.groups.filter(name='HR').exists()):
        messages.error(request, "You do not have permission to access the HR Dashboard.")
        return redirect('profile:my-profile')

    # Base queryset
    users = UserDetails.objects.select_related('user', 'office_location').all()

    # Search functionality
    search_query = request.GET.get('search', '')
    if search_query:
        users = users.filter(
            Q(user__first_name__icontains=search_query) |
            Q(user__last_name__icontains=search_query) |
            Q(user__email__icontains=search_query) |
            Q(employee_id__icontains=search_query)
        )

    # Calculate statistics
    total_users = users.count()
    active_users = users.filter(employment_status='active').count()
    inactive_users = users.filter(employment_status__in=['inactive', 'terminated', 'resigned']).count()
    
    # New hires (joined in last 30 days)
    thirty_days_ago = timezone.now().date() - timedelta(days=30)
    new_hires = users.filter(hire_date__gte=thirty_days_ago).count()

    # Department/Group distribution (optimized - no N+1 query)
    department_stats = list(
        Group.objects.annotate(
            user_count=Count('user', filter=Q(user__profile__isnull=False))
        ).filter(user_count__gt=0).values('name', 'user_count').order_by('-user_count')
    )
    
    # Prepare chart data as JSON
    department_labels = json.dumps([stat['name'] for stat in department_stats])
    department_data = json.dumps([stat['user_count'] for stat in department_stats])

    # Recent activities (last 10, with select_related for performance)
    recent_activities = UserActionLog.objects.select_related(
        'user', 'action_by'
    ).order_by('-timestamp')[:10]

    pending_onboarding = users.filter(employment_status='probation').count()

    context = {
        'total_users': total_users,
        'active_users': active_users,
        'inactive_users': inactive_users,
        'new_hires': new_hires,
        'department_stats': department_stats,
        'department_labels_json': department_labels,
        'department_data_json': department_data,
        'recent_activities': recent_activities,
        'pending_onboarding': pending_onboarding,
        'search_query': search_query,
    }

    return render(request, 'profile/dashboard.html', context)

# User List View
class UserListView(LoginRequiredMixin, ListView):
    model = UserDetails
    template_name = 'profile/user_list.html'
    context_object_name = 'users'
    paginate_by = 10

    def get_queryset(self):
        queryset = UserDetails.objects.select_related('user', 'office_location').all().order_by('-created_at')
        
        # Search
        search_query = self.request.GET.get('search')
        if search_query:
            queryset = queryset.filter(
                Q(user__first_name__icontains=search_query) |
                Q(user__last_name__icontains=search_query) |
                Q(user__email__icontains=search_query) |
                Q(employee_id__icontains=search_query)
            )
        
        # Filter by Status
        status = self.request.GET.get('status')
        if status:
            queryset = queryset.filter(employment_status=status)
            
        # Filter by Location
        location = self.request.GET.get('location')
        if location:
            queryset = queryset.filter(office_location__id=location)
            
        # Filter by Employee Type
        emp_type = self.request.GET.get('type')
        if emp_type:
            queryset = queryset.filter(employee_type=emp_type)

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        # Add filter choices to context
        context['status_choices'] = UserDetails.EMPLOYMENT_STATUS_CHOICES
        context['type_choices'] = UserDetails.EMPLOYEE_TYPE_CHOICES
        context['locations'] = OfficeLocation.objects.filter(is_active=True)
        
        # Preserve filter parameters for pagination
        context['current_filters'] = self.request.GET.copy()
        if 'page' in context['current_filters']:
            del context['current_filters']['page']
            
        return context

# User Detail View
class UserDetailView(LoginRequiredMixin, DetailView):
    model = UserDetails
    template_name = 'profile/user_detail.html'
    context_object_name = 'user_profile'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.object.user
        
        # Add action logs
        context['action_logs'] = UserActionLog.objects.filter(user=user).order_by('-timestamp')
        
        # Check if user is a manager and get direct reports
        context['direct_reports'] = UserDetails.objects.filter(reporting_manager=user)
        
        # Permissions flags for template
        is_hr = self.request.user.groups.filter(name='HR').exists() or self.request.user.is_superuser
        context['is_hr'] = is_hr
        context['can_edit'] = is_hr or self.request.user == user
        
        return context

# User Create View - HR/Admin only
class UserCreateView(LoginRequiredMixin, CreateView):
    model = UserDetails
    form_class = UserDetailsCreateForm
    template_name = 'profile/user_form.html'
    success_url = reverse_lazy('profile:user-list')

    def dispatch(self, request, *args, **kwargs):
        # Only HR and Admin can create users
        if not (request.user.is_superuser or request.user.groups.filter(name='HR').exists()):
            messages.error(request, "You do not have permission to create users.")
            return redirect('profile:dashboard')
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        try:
            with transaction.atomic():
                # Generate secure password if not provided
                password = form.cleaned_data.get('password')
                if not password:
                    password = generate_secure_password()
                
                # Create User instance
                user = User.objects.create_user(
                    username=form.cleaned_data['email'],  # Use email as username
                    email=form.cleaned_data['email'],
                    password=password,
                    first_name=form.cleaned_data['first_name'],
                    last_name=form.cleaned_data['last_name']
                )

                # Add to group
                group = form.cleaned_data['group']
                if group:
                    user.groups.add(group)

                # Create UserDetails instance
                user_details = form.save(commit=False)
                user_details.user = user
                
                # Generate Employee ID
                work_location = user_details.office_location.city if user_details.office_location else "Remote"
                user_details.employee_id = generate_employee_id(work_location, str(group.id) if group else "1")
                
                user_details.save()

                # Log action
                UserActionLog.objects.create(
                    user=user,
                    action_type='create',
                    action_by=self.request.user,
                    details=f"User created by {self.request.user.username}"
                )

                # Send welcome email
                try:
                    send_welcome_email(user, password)
                    logger.info(f"Welcome email sent to {user.email}")
                except Exception as email_error:
                    logger.warning(f"User created but email failed for {user.email}: {str(email_error)}")
                    messages.warning(
                        self.request, 
                        f"User {user.get_full_name()} created successfully, but email notification failed."
                    )

                messages.success(self.request, f"User {user.get_full_name()} created successfully.")
                logger.info(f"User {user.email} created successfully by {self.request.user.username}")
                return redirect('profile:user-list')
                
        except ValidationError as e:
            logger.warning(f"Validation error creating user: {str(e)}")
            messages.error(self.request, f"Validation error: {str(e)}")
            return self.form_invalid(form)
        except IntegrityError as e:
            logger.error(f"Database integrity error creating user: {str(e)}")
            messages.error(self.request, "A user with this information already exists.")
            return self.form_invalid(form)
        except Exception as e:
            logger.exception(f"Unexpected error creating user: {str(e)}")
            messages.error(self.request, "An unexpected error occurred. Please contact support.")
            return self.form_invalid(form)

# User Update View
class UserUpdateView(LoginRequiredMixin, UpdateView):
    model = UserDetails
    form_class = UserDetailsUpdateForm
    template_name = 'profile/user_form.html'

    def get_success_url(self):
        return reverse_lazy('profile:user-detail', kwargs={'pk': self.object.pk})

    def dispatch(self, request, *args, **kwargs):
        # Check permissions
        obj = self.get_object()
        is_hr = request.user.groups.filter(name='HR').exists() or request.user.is_superuser
        if not (is_hr or request.user == obj.user):
            messages.error(request, "You do not have permission to edit this profile.")
            return redirect('profile:dashboard')
        return super().dispatch(request, *args, **kwargs)

    def get_initial(self):
        initial = super().get_initial()
        user = self.object.user
        initial['first_name'] = user.first_name
        initial['last_name'] = user.last_name
        initial['email'] = user.email
        if user.groups.exists():
            initial['group'] = user.groups.first()
        return initial

    def form_valid(self, form):
        try:
            with transaction.atomic():
                # Save UserDetails fields
                user_profile = form.save(commit=False)
                
                # Update User model fields
                user = user_profile.user
                user.first_name = form.cleaned_data.get('first_name')
                user.last_name = form.cleaned_data.get('last_name')
                user.email = form.cleaned_data.get('email')
                user.save()

                # Update Group
                group = form.cleaned_data.get('group')
                if group:
                    user.groups.clear()
                    user.groups.add(group)

                user_profile.save()

                # Log the action
                UserActionLog.objects.create(
                    user=user,
                    action_type='update',
                    action_by=self.request.user,
                    details=f"User profile updated by {self.request.user.username}"
                )

                messages.success(self.request, 'User profile has been updated successfully.')
                logger.info(f"User profile updated for {user.email} by {self.request.user.username}")
                return super().form_valid(form)
                
        except ValidationError as e:
            logger.warning(f"Validation error updating profile: {str(e)}")
            messages.error(self.request, f"Validation error: {str(e)}")
            return self.form_invalid(form)
        except IntegrityError as e:
            logger.error(f"Database integrity error updating profile: {str(e)}")
            messages.error(self.request, "A user with this information already exists.")
            return self.form_invalid(form)
        except Exception as e:
            logger.exception(f"Unexpected error updating profile: {str(e)}")
            messages.error(self.request, "An unexpected error occurred. Please contact support.")
            return self.form_invalid(form)

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
@hr_admin_required
def export_users_csv(request):
    """Export user data to CSV file"""
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
@hr_admin_required
def bulk_upload_users(request):
    """Bulk upload users from CSV/XLSX file"""
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
                    logger.warning(f"Invalid file format uploaded: {csv_file.name}")
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

                        # Generate secure password
                        password = generate_secure_password()

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
                    logger.info(f"Bulk upload: {success_count} users created by {request.user.username}")

                if error_count > 0:
                    messages.warning(request, f'{error_count} users failed to create.')
                    logger.warning(f"Bulk upload: {error_count} failures")
                    # Store errors in session for detailed view
                    request.session['bulk_upload_errors'] = errors[:100]  # Limit to 100 errors

                return redirect('profile:user-list')

            except Exception as e:
                logger.exception(f"Error processing bulk upload file: {str(e)}")
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


# User Profile Views
@login_required
def my_profile(request):
    """View user's own profile"""
    try:
        user_profile = UserDetails.objects.get(user=request.user)
    except UserDetails.DoesNotExist:
        # Auto-create UserDetails if it doesn't exist
        user_profile = UserDetails.objects.create(
            user=request.user,
            role='developer',  # Default role
            employee_type='full_time',  # Default employee type
            employment_status='active'  # Default status
        )

    context = {
        'user_profile': user_profile,
        'user': request.user,
        'user_detail': user_profile,  # For template compatibility
        'username': request.user.username,
        'role': user_profile.get_role_display() if user_profile else 'Employee'
    }
    return render(request, 'profile/my_profile.html', context)


@login_required
def edit_my_profile(request):
    """Edit user's own profile"""
    try:
        user_profile, created = UserDetails.objects.get_or_create(user=request.user)
    except Exception as e:
        messages.error(request, f"Error loading profile: {str(e)}")
        return redirect('profile:my-profile')

    if request.method == 'POST':
        form = UserProfileForm(request.POST, instance=user_profile, user=request.user)
        if form.is_valid():
            # Update UserDetails
            form.save()

            # Update User model fields if provided
            first_name = form.cleaned_data.get('first_name')
            last_name = form.cleaned_data.get('last_name')

            if first_name:
                request.user.first_name = first_name
            if last_name:
                request.user.last_name = last_name

            request.user.save()

            # Log the action
            UserActionLog.objects.create(
                user=request.user,
                action_type='update',
                action_by=request.user,
                details="Profile updated by user"
            )

            messages.success(request, 'Your profile has been updated successfully.')
            return redirect('profile:my-profile')
    else:
        form = UserProfileForm(instance=user_profile, user=request.user)

    context = {
        'form': form,
        'user_profile': user_profile
    }
    return render(request, 'profile/edit_my_profile.html', context)


# Analytics API Views for Charts
@login_required
@cache_page(CACHE_TIMEOUT_ANALYTICS)  # Cache for 5 minutes
def dashboard_analytics_api(request):
    """API endpoint for dashboard analytics data"""
    if not is_hr_or_admin(request.user):
        return JsonResponse({'error': ERROR_MESSAGES['permission_denied']}, status=403)

    try:
        # Time periods
        now = timezone.now()
        thirty_days_ago = now - timedelta(days=30)
        six_months_ago = now - timedelta(days=180)

        # Employee status distribution
        status_data = list(UserDetails.objects.values('employment_status').annotate(
            count=Count('id')
        ).order_by('-count'))

        # Location distribution
        location_data = list(UserDetails.objects.filter(
            office_location__isnull=False
        ).values('office_location__name').annotate(
            count=Count('id')
        ).order_by('-count'))

        # Employee type distribution
        type_data = list(UserDetails.objects.values('employee_type').annotate(
            count=Count('id')
        ).order_by('-count'))

        # Monthly hiring trends (last 6 months)
        monthly_hires = []
        for i in range(6):
            month_start = (now - timedelta(days=30*i)).replace(day=1)
            month_end = (month_start.replace(month=month_start.month+1) - timedelta(days=1)) if month_start.month < 12 else month_start.replace(year=month_start.year+1, month=1) - timedelta(days=1)

            count = UserDetails.objects.filter(
                hire_date__gte=month_start,
                hire_date__lte=month_end
            ).count()

            monthly_hires.append({
                'month': month_start.strftime('%B %Y'),
                'count': count
            })

        monthly_hires.reverse()

        # User session analytics (if available)
        session_analytics = {}
        try:
            # Active sessions today
            today = now.date()
            session_analytics['active_sessions_today'] = UserSession.objects.filter(
                created_at__date=today,
                is_active=True
            ).count()

            # Average session duration
            avg_session_duration = UserSession.objects.filter(
                created_at__gte=thirty_days_ago,
                session_duration__isnull=False
            ).aggregate(avg_duration=Avg('session_duration'))['avg_duration']

            session_analytics['avg_session_duration'] = round(avg_session_duration or 0, 2)

            # Top active users (by session count)
            top_users = list(UserSession.objects.filter(
                created_at__gte=thirty_days_ago
            ).values('user__username', 'user__first_name', 'user__last_name').annotate(
                session_count=Count('id')
            ).order_by('-session_count')[:5])

            session_analytics['top_users'] = top_users

        except Exception as e:
            # If UserSession model is not available or has issues
            session_analytics = {
                'active_sessions_today': 0,
                'avg_session_duration': 0,
                'top_users': []
            }

        # Recent activities summary
        recent_activities = list(UserActionLog.objects.filter(
            timestamp__gte=thirty_days_ago
        ).values('action_type').annotate(
            count=Count('id')
        ).order_by('-count'))

        return JsonResponse({
            'status_distribution': status_data,
            'location_distribution': location_data,
            'type_distribution': type_data,
            'monthly_hiring_trend': monthly_hires,
            'session_analytics': session_analytics,
            'recent_activities': recent_activities
        })
    
    except Exception as e:
        logger.exception(f"Error in dashboard analytics API: {str(e)}")
        return JsonResponse({'error': 'An error occurred while fetching analytics data'}, status=500)


@login_required
def user_activity_analytics_api(request, user_id):
    """API endpoint for individual user activity analytics"""
    if not is_hr_or_admin(request.user) and request.user.id != user_id:
        return JsonResponse({'error': 'Permission denied'}, status=403)

    try:
        user = get_object_or_404(User, id=user_id)
        user_profile = get_object_or_404(UserDetails, user=user)

        # Time periods
        now = timezone.now()
        thirty_days_ago = now - timedelta(days=30)

        # User sessions data
        user_sessions = UserSession.objects.filter(
            user=user,
            created_at__gte=thirty_days_ago
        ).order_by('created_at')

        # Daily activity data
        daily_activity = []
        for i in range(30):
            day = (now - timedelta(days=i)).date()
            sessions_count = user_sessions.filter(created_at__date=day).count()

            avg_duration = user_sessions.filter(
                created_at__date=day,
                session_duration__isnull=False
            ).aggregate(avg_duration=Avg('session_duration'))['avg_duration']

            daily_activity.append({
                'date': day.strftime('%Y-%m-%d'),
                'sessions': sessions_count,
                'avg_duration': round(avg_duration or 0, 2)
            })

        daily_activity.reverse()

        # Activity breakdown
        activity_breakdown = list(SessionActivity.objects.filter(
            user=user,
            created_at__gte=thirty_days_ago
        ).values('activity_type').annotate(
            count=Count('id')
        ).order_by('-count'))

        # Productivity metrics
        productivity_data = user_sessions.filter(
            productivity_score__isnull=False
        ).aggregate(
            avg_productivity=Avg('productivity_score'),
            avg_engagement=Avg('engagement_score')
        )

        return JsonResponse({
            'user_info': {
                'username': user.username,
                'full_name': user.get_full_name(),
                'employee_type': user_profile.get_employee_type_display() if user_profile.employee_type else 'N/A'
            },
            'daily_activity': daily_activity,
            'activity_breakdown': activity_breakdown,
            'productivity_metrics': {
                'avg_productivity': round(productivity_data['avg_productivity'] or 0, 2),
                'avg_engagement': round(productivity_data['avg_engagement'] or 0, 2)
            }
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@require_POST
def save_dashboard_layout(request):
    """Save user's dashboard layout preferences"""
    if not is_hr_or_admin(request.user):
        return JsonResponse({'error': 'Permission denied'}, status=403)

    try:
        import json
        data = json.loads(request.body)
        layout_data = data.get('layout', {})

    

        if not created:
            layout_preference.layout = layout_data
            layout_preference.save()

        return JsonResponse({'success': True, 'message': 'Layout saved successfully'})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def dashboard_stats_api(request):
    """API endpoint for real-time dashboard stats"""
    if not is_hr_or_admin(request.user):
        return JsonResponse({'error': 'Permission denied'}, status=403)

    try:
        from datetime import timedelta
        from django.utils import timezone

        # Get overall stats
        total_users = User.objects.filter(is_active=True).count()
        user_details_count = UserDetails.objects.count()

        if user_details_count > total_users:
            total_users = user_details_count

        # Get active users based on employment status
        active_users = UserDetails.objects.filter(employment_status='active').count()
        if active_users == 0:
            active_users = User.objects.filter(is_active=True).count()

        # Calculate inactive users
        inactive_users = total_users - active_users if total_users > active_users else 0

        # Get new users this month
        thirty_days_ago = timezone.now() - timedelta(days=30)
        new_hires_count = UserDetails.objects.filter(created_at__gte=thirty_days_ago).count()
        if new_hires_count == 0:
            new_hires_count = User.objects.filter(date_joined__gte=thirty_days_ago).count()

        return JsonResponse({
            'total_users': total_users,
            'active_users': active_users,
            'inactive_users': inactive_users,
            'new_hires_count': new_hires_count,
            'timestamp': timezone.now().isoformat()
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
