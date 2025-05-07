from django.shortcuts import render
from django.contrib.auth.models import User, Group
from .models import (UserSession, Attendance, SystemError, 
                    Support, FailedLoginAttempt, PasswordChange, 
                    RoleAssignmentAudit, FeatureUsage, SystemUsage, 
                    Timesheet,GlobalUpdate,
                     UserDetails,ProjectUpdate, Presence, PresenceStatus, 
                     Project,
                       ClientProfile, ShiftMaster,ShiftAssignment, Appraisal, AppraisalItem, AppraisalWorkflow )
from django.db.models import Q
from datetime import datetime, timedelta, date
from decimal import Decimal
from django.utils import timezone
from django.contrib import messages
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required, user_passes_test
from .helpers import is_user_in_group
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
import json
from django.utils.dateparse import parse_date
from django.views.decorators.csrf import csrf_exempt
import sys
import traceback
from django.db import transaction
from django.shortcuts import render
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from .models import Attendance

from django.http import HttpResponse
from django.template.loader import render_to_string
import csv
import openpyxl
from datetime import datetime, timedelta
from django.db.models import F, ExpressionWrapper, DurationField
# Commented out xlsxwriter import since it's not installed
# import xlsxwriter

'''------------------------------ TRACKING ------------------------'''

@login_required
@csrf_exempt
def update_last_activity(request):
    """
    View to handle activity updates from the client.
    Updates the user's last activity timestamp and tracks idle time.
    """
    if request.method == 'POST':
        try:
            from django.db import transaction
            from django.http import JsonResponse

            with transaction.atomic():
                # Parse request data
                try:
                    data = json.loads(request.body)
                except ValueError:
                    data = {}

                # Get client IP
                x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
                ip_address = x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')

                # Get or create user session using model logic
                user_session = UserSession.objects.filter(
                    user=request.user,
                    is_active=True
                ).select_for_update().first()

                current_time = UserSession.get_current_time_utc()

                if not user_session:
                    # Use model method to create session
                    user_session = UserSession.get_or_create_session(
                        user=request.user,
                        session_key=request.session.session_key,
                        ip_address=ip_address,
                        user_agent=request.META.get('HTTP_USER_AGENT', None)
                    )
                    return JsonResponse({
                        'status': 'success',
                        'message': 'New session created',
                        'session_id': user_session.id
                    })

                # Check for session timeout (5 minutes)
                if (current_time - user_session.last_activity) > timedelta(minutes=5):
                    user_session.end_session(current_time, is_idle=True)
                    new_session = UserSession.get_or_create_session(
                        user=request.user,
                        session_key=request.session.session_key,
                        ip_address=ip_address,
                        user_agent=request.META.get('HTTP_USER_AGENT', None)
                    )
                    return JsonResponse({
                        'status': 'success',
                        'sessionExpired': True,
                        'message': 'Previous session timed out, new session created',
                        'session_id': new_session.id
                    })

                # Update IP and location if changed
                if user_session.ip_address != ip_address:
                    user_session.ip_address = ip_address
                    user_session.location = user_session.determine_location()
                    user_session.save(update_fields=['ip_address', 'location'])

                # Handle client-reported idle state
                is_idle = data.get('isIdle', False)
                is_focused = data.get('isFocused', True)
                
                # Update activity with idle state
                user_session.update_activity(current_time, is_idle=is_idle)

                user_session.refresh_from_db()

                return JsonResponse({
                    'status': 'success',
                    'last_activity': user_session.get_last_activity_local().isoformat(),
                    'idle_time': str(user_session.idle_time),
                    'working_hours': str(user_session.working_hours) if user_session.working_hours else None,
                    'location': user_session.location
                })

        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error updating last activity: {str(e)}")
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=400)

    return JsonResponse({
        'status': 'error',
        'message': 'Invalid request method'
    }, status=405)

@login_required
def end_session(request):
    """
    View to handle session end/logout.
    Calculates final working hours and idle time.
    """
    if request.method != 'POST':
        return JsonResponse({
            'status': 'error',
            'message': 'Invalid request method'
        }, status=405)

    try:
        from django.db import transaction
        from django.http import JsonResponse

        with transaction.atomic():
            user_session = UserSession.objects.filter(
                user=request.user,
                is_active=True
            ).select_for_update().first()

            if not user_session:
                return JsonResponse({
                    'status': 'error',
                    'message': 'No active session found'
                }, status=404)

            # Use model method to end session
            user_session.end_session()
            user_session.refresh_from_db()

            return JsonResponse({
                'status': 'success',
                'message': 'Session ended successfully',
                'working_hours': user_session.get_total_working_hours_display(),
                'idle_time': str(user_session.idle_time)
            })

    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error ending session: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=400)

@login_required
def get_session_status(request):
    """Get the current session status"""
    try:
        from django.http import JsonResponse
        
        user_session = UserSession.objects.filter(
            user=request.user,
            is_active=True
        ).first()

        if not user_session:
            return JsonResponse({
                'status': 'error',
                'message': 'No active session found'
            }, status=404)

        current_time = UserSession.get_current_time_utc()
        total_duration = current_time - user_session.login_time

        return JsonResponse({
            'status': 'success',
            'session_id': user_session.id,
            'login_time': user_session.get_login_time_local().isoformat(),
            'last_activity': user_session.get_last_activity_local().isoformat(),
            'idle_time': str(user_session.idle_time),
            'location': user_session.location,
            'session_duration': user_session.get_session_duration_display()
        })

    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=400)

''' ------------------ ROLE-BASED CHECKS ------------------ '''

def is_admin(user):
    """Check if the user belongs to the 'Admin' group."""
    return user.groups.filter(name="Admin").exists()

def is_hr(user):
    """Check if the user belongs to the 'HR' group."""
    return user.groups.filter(name="HR").exists()

def is_manager(user):
    """Check if the user belongs to the 'Manager' group."""
    return user.groups.filter(name="Manager").exists()

def is_employee(user):
    """Check if the user belongs to the 'Employee' group."""
    return user.groups.filter(name="Employee").exists()
    
def is_management(user):
    """Check if the user belongs to the 'Employee' group."""
    return user.groups.filter(name="Management").exists()
    


''' ----------------- COMMON AREA ----------------- '''
@login_required
def reset_password(request):
    if request.method == 'POST':
        current_password = request.POST.get('current_pwd')
        new_password = request.POST.get('new_pwd')
        confirm_password = request.POST.get('confirm_pwd')

        # Validate new password and confirmation
        if new_password != confirm_password:
            messages.error(request, "New password and confirm password do not match.")
            return redirect('reset_password')

        # Authenticate the user with the current password
        user = authenticate(username=request.user.username, password=current_password)
        if user:
            # Update the user's password
            user.set_password(new_password)
            user.save()
            # Update session authentication hash to maintain user session
            update_session_auth_hash(request, user)

            messages.success(request, "Your password has been successfully updated.")
            return redirect('home')  # Redirect to the home page or any other page after reset
        else:
            messages.error(request, "Incorrect current password.")
            return redirect('reset_password')
    
    return render(request, 'basic/user_profile.html')

# Create your views here.

# Home View (Redirects to login page)
def home_view(request):
    return redirect('login')

from .utils import get_client_ip  # You can define this utility to fetch client IP address

def login_view(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')

        try:
            # Authenticate the user
            user = authenticate(request, username=username, password=password)

            if user is not None:
                login(request, user)

                # Check if the user is authenticated and create a session for them
                if request.user.is_authenticated:
                    session = UserSession.get_or_create_session(
                        user=request.user,
                        session_key=request.session.session_key,
                        ip_address=get_client_ip(request)  # Assuming you have a utility to get the user's IP
                    )
                return redirect('dashboard')
            else:
                # Show error if authentication fails
                error_message = 'Invalid username or password'
                return render(request, 'login.html', {'error': error_message})

        except Exception as e:
            # Handle any unexpected errors
            error_message = f'An error occurred: {str(e)}'
            return render(request, 'login.html', {'error': error_message})

    return render(request, 'login.html')

# # Login View
# def login_view(request):
#     if request.method == "POST":
#         username = request.POST.get('username')
#         password = request.POST.get('password')

#         try:
#             # Authenticate the user
#             user = authenticate(request, username=username, password=password)

#             if user is not None:
#                 login(request, user)

#                 # Check if the user is authenticated and create a session for them
#                 if request.user.is_authenticated:
#                     session = UserSession.get_or_create_session(
#                         user=request.user,
#                         session_key=request.session.session_key,
#                         ip_address=get_client_ip(request)  # Assuming you have a utility to get the user's IP
#                     )
#                 return redirect('dashboard')
#             else:
#                 # Show error if authentication fails
#                 error_message = 'Invalid username or password'
#                 return render(request, 'error.html', {'error': error_message})

#         except Exception as e:
#             # Handle any unexpected errors
#             error_message = f'An error occurred: {str(e)}'
#             return render(request, 'error.html', {'error': error_message})

#     return render(request, 'login.html')



# Logout View
from django.http import JsonResponse

def logout_view(request):
    if request.user.is_authenticated:
        try:
            # End any active sessions for this user
            active_session = UserSession.objects.filter(
                user=request.user,
                logout_time__isnull=True
            ).first()

            if active_session:
                active_session.end_session()  # Assume end_session() properly sets logout_time

            # Logout the user
            logout(request)

            return redirect('login')
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': f'An error occurred: {str(e)}'}, status=500)

    return redirect('login')

# Set Password View
def set_password_view(request, username):
    if request.method == "POST":
        try:
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')
            first_name = request.POST.get('first_name')
            last_name = request.POST.get('last_name')
            email = request.POST.get('email')

            if new_password != confirm_password:
                return render(
                    request,
                    'set_password.html',
                    {
                        'error': 'Passwords do not match',
                        'username': username,
                        'first_name': first_name,
                        'last_name': last_name,
                        'email': email
                    }
                )

            user = User.objects.get(username=username)
            user.set_password(new_password)
            user.first_name = first_name
            user.last_name = last_name
            user.email = email
            user.save()

            return redirect('login')

        except User.DoesNotExist:
            return render(request, 'set_password.html', {'error': 'User does not exist', 'username': username})
        except Exception as e:
            return render(request, 'set_password.html', {'error': f'An error occurred: {str(e)}'})

    return render(request, 'set_password.html', {'username': username})



'''---------------------------------   DASHBOARD VIEW ----------------------------------'''
from django.shortcuts import render
from .models import Attendance

from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from .models import Break
from django.utils.timezone import now
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required


def check_active_break(request):
    """
    Check if the authenticated user has an active break and remaining break count.
    """
    print(f"Checking active break for user: {request.user.username}")
    active_break = Break.objects.filter(user=request.user, end_time__isnull=True).first()
    
    # Get today's date
    today = timezone.now().date()
    
    # Get break counts for today
    break_counts = {}
    for break_type, _ in Break.BREAK_TYPES:
        total_allowed = Break.BREAK_LIMITS.get(break_type, 1)
        used_count = Break.objects.filter(
            user=request.user,
            break_type=break_type,
            start_time__date=today
        ).count()
        break_counts[break_type] = {
            'used': used_count,
            'remaining': total_allowed - used_count
        }

    if active_break and active_break.is_active:
        return JsonResponse({
            'status': 'success',
            'break_id': active_break.id,
            'break_type': active_break.break_type,
            'start_time': active_break.start_time,
            'is_active': active_break.is_active,
            'break_counts': break_counts
        })
    else:
        return JsonResponse({
            'status': 'error', 
            'message': 'No active break found',
            'break_counts': break_counts
        })

def take_break(request):
    if request.method == 'POST':
        break_type = request.POST.get('break_type')

        # Ensure valid break type
        if not break_type or break_type not in dict(Break.BREAK_TYPES).keys():
            messages.error(request, "Invalid break type.")
            return redirect('dashboard')

        # Create new break
        new_break = Break(user=request.user, break_type=break_type)
        try:
            # Run validation to check for active breaks and limits
            new_break.clean()  # This will run all validations from the `clean` method
            new_break.save()
            messages.success(request, f"Started {break_type}")
        except ValidationError as e:
            messages.error(request, str(e))
        
        return redirect('dashboard')

from django.urls import reverse

@login_required
def end_break(request, break_id):
    if request.method == 'POST':
        try:
            print(f"Ending break with ID: {break_id} for user: {request.user.username}")
            active_break = get_object_or_404(Break, id=break_id, user=request.user, end_time__isnull=True)
            
            max_duration = Break.BREAK_DURATIONS.get(active_break.break_type, timedelta(minutes=15))
            # Use timezone.now() for consistent timezone-aware datetime
            elapsed_time = timezone.now() - active_break.start_time
            
            if elapsed_time > max_duration and not request.POST.get('reason'):
                return JsonResponse({
                    'status': 'error',
                    'message': 'Please provide a reason for the extended break.'
                })
            
            reason = request.POST.get('reason', '')
            # Use timezone.now() when setting end_time
            active_break.end_time = timezone.now()
            active_break.reason_for_extension = reason
            active_break.save()
            print(f"Break ended with reason: {reason}")
            
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'status': 'success'})
            
            return redirect(f"{reverse('dashboard')}?success=Break ended successfully")
            
        except Exception as e:
            return redirect(f"{reverse('dashboard')}?error={str(e)}")
    
    return redirect(f"{reverse('dashboard')}?error=Invalid request method")


from django.utils.timezone import now  # Use timezone-aware datetime
from django.shortcuts import render
from django.db.models import Count

def get_attendance_stats(request):
    """Get attendance statistics for the current user."""
    user = request.user
    try:
        # Get current month and today's date
        current_time = now()  # Use timezone-aware datetime
        current_month = current_time.month
        current_year = current_time.year
        today_date = current_time.strftime('%B %d, %Y')  # Example: January 23, 2025
        print(f"Today's Date: {today_date}")

        # Get attendance records for the current month
        current_month = timezone.now().month
        current_year = timezone.now().year

        attendance_records = Attendance.objects.filter(
            user=request.user,
            date__month=current_month,
            date__year=current_year
        )
        print(f"Attendance Records for Current Month: {attendance_records.count()}")

        # Count present days (including WFH)
        present_days = attendance_records.filter(
            status__in=["Present", "Work From Home"]
        ).count()
        print(f"Total Present Days (including WFH): {present_days}")

        # Get leave requests for the current month
        leave_requests = Leave.objects.filter(
            user=user,
            start_date__month=current_month,
            start_date__year=current_year
        )
        print(f"Total Leave Requests (Current Month): {leave_requests.count()}")

        # Count pending and approved leaves
        leave_request_count = leave_requests.filter(status="Pending").count()
        approved_leave_count = leave_requests.filter(status="Approved").count()
        print(f"Pending Leave Requests: {leave_request_count}")
        print(f"Approved Leave Requests: {approved_leave_count}")

        # Format response data
        result = {
            'today_date': today_date,
            'current_month_name': current_time.strftime('%B'),  # Full month name, e.g., "January"
            'attendance': {
                'total_present': present_days,
                'leave_request_count': leave_request_count,
                'approved_leave_count': approved_leave_count,
            }
        }
        print(f"Formatted Attendance Data: {result}")
        return result

    except Exception as e:
        # Log the error
        print(f"Error generating attendance stats: {str(e)}")

        # Return empty data on error
        return {
            'today_date': '',
            'current_month_name': '',
            'attendance': {
                'total_present': 0,
                'leave_request_count': 0,
                'approved_leave_count': 0,
            }
        }


from django.utils import timezone

@login_required
def dashboard_view(request):
    # Get today's date
    time = timezone.now()
    print(f"time: {time}")
    today = timezone.now().date()
    
    user = request.user

    # Get user's current session status
    user_session = UserSession.objects.filter(
        user=user,
        session_key=request.session.session_key,
        logout_time__isnull=True
    ).last()
    
    # Calculate user status
    def format_timedelta(td):
        """Helper function to format timedelta into a readable string"""
        total_seconds = int(td.total_seconds())
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        
        if hours > 0:
            return f"{hours}h {minutes}m"
        return f"{minutes}m"

    # Calculate user status
    user_status = {
        'status': 'offline',
        'color': 'gray',
        'idle_time': None,
        'working_hours': None,
        'formatted_idle_time': None
    }
    
    if user_session:
        current_time = timezone.now()
        time_since_last_activity = current_time - user_session.last_activity
        
        # If last activity was less than 1 minute ago - user is active
        if time_since_last_activity < timedelta(minutes=1):
            user_status['status'] = 'active'
            user_status['color'] = 'green'
        # If last activity was between 1-5 minutes ago - user is idle
        elif time_since_last_activity < timedelta(minutes=5):
            user_status['status'] = 'idle'
            user_status['color'] = 'yellow'
        else:
            user_status['status'] = 'inactive'
            user_status['color'] = 'red'
        
        user_status['idle_time'] = user_session.idle_time
        user_status['working_hours'] = user_session.working_hours
        user_status['last_activity'] = user_session.last_activity if user_session.last_activity else None
        
        # Format idle time as a readable string
        if user_status['idle_time']:
            user_status['formatted_idle_time'] = format_timedelta(user_status['idle_time'])

    # Check if the user has the HR role
    is_hr = user.groups.filter(name='HR').exists()
    is_manager = user.groups.filter(name='Manager').exists()

    # Variables for attendance stats and active projects
    present_employees = absent_employees = active_projects = None

    # Get today's date using timezone-aware datetime
    today = timezone.now().date()

    # Get date range from request (default to today if not provided)
    start_date_str = request.GET.get('start_date', today)
    end_date_str = request.GET.get('end_date', today)

    # Convert string date inputs to date format
    try:
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date() if isinstance(start_date_str, str) else today
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date() if isinstance(end_date_str, str) else today
    except ValueError:
        return JsonResponse({'status': 'error', 'message': 'Invalid date format. Use YYYY-MM-DD.'})

    # Ensure the end date is inclusive
    end_date += timedelta(days=1)

    active_break = Break.objects.filter(user=user, end_time__isnull=True).first()
    break_data = None
    
    # Get today's date for break counts
    today = timezone.now().date()
    
    # Get break counts for today
    break_counts = {}
    for break_type, _ in Break.BREAK_TYPES:
        total_allowed = Break.DAILY_BREAK_LIMITS.get(break_type, 1)
        used_count = Break.objects.filter(
            user=user,
            break_type=break_type,
            start_time__date=today
        ).count()
        break_counts[break_type] = {
            'used': used_count,
            'remaining': total_allowed - used_count
        }
    
    # Always include break counts whether break is active or not
    break_data = {
        'break_counts': break_counts
    }
    
    if active_break and active_break.is_active:
        # Get break duration in minutes
        break_duration = Break.BREAK_DURATIONS.get(active_break.break_type, timedelta(minutes=15))
        
        # Ensure both times are timezone-aware
        now = timezone.now()
        elapsed_time = now - active_break.start_time
        remaining_time = max(timedelta(0), break_duration - elapsed_time)
        
        # Add active break info to break_data
        break_data.update({
            'break_id': active_break.id,
            'break_type': active_break.break_type,
            'start_time': active_break.start_time,
            'active_break': active_break.is_active,
            'remaining_minutes': int(remaining_time.total_seconds() / 60),
            'remaining_seconds': int(remaining_time.total_seconds() % 60)
        })
    

    if is_hr:
        # Get today's present employees
        present_employees = Attendance.objects.filter(
            status='Present',
            date=today
        ).count()

        # Get today's absent employees
        absent_employees = Attendance.objects.filter(
            status='Absent',
            date=today
        ).count()

        # Get active projects
        active_projects = Project.objects.filter(status='Active').count()

    # Retrieve assignments and projects for non-HR users
    assignments = ProjectAssignment.objects.filter(user=user)
    projects = [assignment.project for assignment in assignments]

    # Get project timelines for each project
    project_timelines = []
    for project in projects:
        timeline = project_timeline(request, project.id)  # Returns a dictionary with project info
        project_timelines.append(timeline['project']) 

    # Retrieve global updates
    updates = GlobalUpdate.objects.all().order_by('-created_at')

    # Retrieve project team updates
    project_team_updates = ProjectUpdate.objects.all()

    # Check if we are editing an update
    update = None
    if 'update_id' in request.GET:
        update = GlobalUpdate.objects.filter(id=request.GET['update_id']).first()

    """Manager's Dashboard view."""
    
    # Get the manager's assigned users' breaks
    project_assignments = ProjectAssignment.objects.filter(
        project__projectassignment__user=request.user,
        project__projectassignment__role_in_project='Manager',
        is_active=True
    ).values_list('user', flat=True).distinct()

    if project_assignments.exists():
        active_breaks = Break.objects.filter(user__in=project_assignments, end_time__isnull=True).count()
    else:
        active_breaks = 0

    # Initialize present employees count
    present_employees_count = None

    if is_manager:
        # Get today's date
        today = timezone.now().date()

        # Get the manager's assigned projects
        project_assignments = ProjectAssignment.objects.filter(
            project__projectassignment__user=request.user,
            project__projectassignment__role_in_project='Manager',
            is_active=True
        )

        # Get the users assigned to the manager's projects
        users_in_projects = project_assignments.values_list('user', flat=True)

        # Count present employees
        present_employees_count = Attendance.objects.filter(
            user__in=users_in_projects,
            date=today,
            status='Present'
        ).count()
    # Context for the dashboard view
    context = {
        'active_breaks': active_breaks,
        'attendance': get_attendance_stats(request),  # Direct assignment
        'projects': projects,
        'project_timelines': project_timelines,
        'updates': updates,
        'is_hr': is_hr,
        'is_manager': is_manager,
        'projectTeamUpdates': project_team_updates,
        'update': update,
        'present_employees': present_employees,
        'absent_employees': absent_employees,
        'active_projects': active_projects,
        'start_date': start_date,
        'end_date': end_date - timedelta(days=1),
        'show_employee_directory': is_hr,
        'break_data': break_data,
        'break_types': dict(Break.BREAK_TYPES),
        'break_durations': {k: int(v.total_seconds() / 60) for k, v in Break.BREAK_DURATIONS.items()},
        'user_status': user_status,
        'present_employees_count': present_employees_count,
        'time': time
    }

    return render(request, 'dashboard.html', context)


def project_timeline(request, project_id):
    project = Project.objects.get(id=project_id)
    current_date = timezone.now().date()
    
    # Calculate total project duration and remaining time
    total_duration = project.deadline - project.start_date
    remaining_duration = project.deadline - current_date
    
    # Check if remaining time is within the last 25% of the total duration
    is_deadline_close = remaining_duration <= total_duration * 0.25

    
    return {
        'project': {
            'name': project.name,
            'start_date': project.start_date,
            'deadline': project.deadline,  # No need to include 'deadline' twice
            'is_deadline_close': is_deadline_close,
        }
    }



from django.utils.timezone import now, timezone

@user_passes_test(is_hr)
@login_required
def employee_directory(request):
    # Check if the user has the HR role
    if not request.user.groups.filter(name='HR').exists():
        return JsonResponse({'error': 'Permission denied'}, status=403)

    # Fetch all employee details
    employees = UserDetails.objects.all().values(
        'id', 'user__username', 'user__first_name', 'user__last_name', 'contact_number_primary', 'personal_email'
    )
    
    # Convert queryset to list of dictionaries
    employee_data = list(employees)
    
    # Return the data as JSON
    return JsonResponse({'employees': employee_data})

# Create global update view
@login_required
@transaction.atomic
def hr_create_update(request):
    if not request.user.groups.filter(name='HR').exists():
        messages.error(request, "You do not have permission to manage global updates.")
        return redirect('dashboard')

    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        status = request.POST.get('status', 'upcoming')
        scheduled_date_str = request.POST.get('scheduled_date')

        if not title or not description:
            messages.error(request, "Title and description are required.")
            return redirect('dashboard')

        try:
            scheduled_date = None
            if scheduled_date_str:
                scheduled_date = datetime.strptime(scheduled_date_str, '%Y-%m-%dT%H:%M')
                scheduled_date = timezone.make_aware(scheduled_date)  # Make timezone-aware

            new_update = GlobalUpdate.objects.create(
                title=title,
                description=description,
                status=status,
                scheduled_date=scheduled_date,
                managed_by=request.user,
            )

            messages.success(request, "Global update created successfully.")
            return redirect('dashboard')
        except Exception as e:
            messages.error(request, "Error creating update. Please try again.")
            return redirect('dashboard')

    return redirect('dashboard')

# Get update data API for editing
@login_required
def get_update_data(request, update_id):
    """API endpoint to fetch update data for editing"""
    if not request.user.groups.filter(name='HR').exists():
        return JsonResponse({'error': 'Permission denied'}, status=403)

    try:
        update = get_object_or_404(GlobalUpdate, id=update_id)
        data = {
            'title': update.title,
            'description': update.description,
            'status': update.status,
            'scheduled_date': update.scheduled_date.isoformat() if update.scheduled_date else '',
        }
        return JsonResponse(data)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

# Edit global update view
@login_required
@transaction.atomic
def hr_edit_update(request, update_id):
    """View to handle update editing"""
    update = get_object_or_404(GlobalUpdate, id=update_id)
    
    # Check permissions
    if not request.user.groups.filter(name='HR').exists():
        messages.error(request, "You do not have permission to edit this update.")
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    if request.method == 'POST':
        try:
            # Get form data
            title = request.POST.get('title')
            description = request.POST.get('description')
            status = request.POST.get('status')
            scheduled_date_str = request.POST.get('scheduled_date')
            
            # Validate required fields
            if not title or not description:
                return JsonResponse({'error': 'Title and description are required'}, status=400)
            
            # Update fields
            update.title = title
            update.description = description
            update.status = status
            
            if scheduled_date_str:
                try:
                    scheduled_date = datetime.strptime(scheduled_date_str, '%Y-%m-%dT%H:%M')
                    update.scheduled_date = timezone.make_aware(scheduled_date)
                except ValueError:
                    return JsonResponse({'error': 'Invalid date format'}, status=400)
            else:
                update.scheduled_date = None
            
            update.save()
            messages.success(request, "Global update edited successfully.")
            return redirect('dashboard')  # Redirect to the dashboard after successful deletion
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

# Delete global update view
@login_required
@transaction.atomic
def hr_delete_update(request, update_id):
    """View to handle update deletion"""
    if not request.user.groups.filter(name='HR').exists():
        return JsonResponse({'error': 'Permission denied'}, status=403)

    try:
        update = get_object_or_404(GlobalUpdate, id=update_id)
        update.delete()
        messages.success(request, "Global update deleted successfully.")
        return redirect('dashboard')  # Redirect to the dashboard after successful deletion
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    
''' ------------------------------------------------------- BREAK AREA AREA --------------------------------------------------------- '''



''' ------------------------------------------------------- MANAGER TEAM PROJECT AREA --------------------------------------------------------- '''

@login_required
@user_passes_test(is_manager)
@transaction.atomic
def manager_create_project_update(request):
    """Manager creates an update for their project."""
    if request.method == 'POST':
        project_id = request.POST.get('project_id')
        title = request.POST.get('title')
        description = request.POST.get('description')
        status = request.POST.get('status', 'upcoming')
        scheduled_date_str = request.POST.get('scheduled_date')

        # Validate fields
        if not title or not description or not project_id:
            messages.error(request, "Title, description, and project are required.")
            return redirect('dashboard')

        try:
            # Fetch the project assigned to the manager
            project = get_object_or_404(Project, id=project_id)
            project_assignment = ProjectAssignment.objects.filter(project=project, user=request.user, is_active=True).first()
            if not project_assignment or project_assignment.role_in_project != 'Manager':
                messages.error(request, "You are not assigned as the manager for this project.")
                return redirect('dashboard')

            # Handle scheduled date
            scheduled_date = None
            if scheduled_date_str:
                scheduled_date = datetime.strptime(scheduled_date_str, '%Y-%m-%dT%H:%M')
                scheduled_date = timezone.make_aware(scheduled_date)

            # Create the project update
            new_update = ProjectUpdate.objects.create(
                project=project,
                created_by=request.user,
                title=title,
                description=description,
                status=status,
                scheduled_date=scheduled_date
            )

            messages.success(request, "Project update created successfully.")
            return redirect('dashboard')

        except Exception as e:
            messages.error(request, f"Error creating update: {str(e)}")
            return redirect('dashboard')

    return redirect('dashboard')

@login_required
@user_passes_test(is_manager)
@transaction.atomic
def manager_edit_project_update(request, update_id):
    """Manager edits an existing project update."""
    try:
        update = get_object_or_404(ProjectUpdate, id=update_id)
        if update.created_by != request.user:
            messages.error(request, "You do not have permission to edit this update.")
            return redirect('dashboard')

        if request.method == 'POST':
            title = request.POST.get('title')
            description = request.POST.get('description')
            status = request.POST.get('status', 'upcoming')
            scheduled_date_str = request.POST.get('scheduled_date')

            if not title or not description:
                return JsonResponse({'error': 'Title and description are required'}, status=400)

            scheduled_date = None
            if scheduled_date_str:
                try:
                    scheduled_date = datetime.strptime(scheduled_date_str, '%Y-%m-%dT%H:%M')
                    update.scheduled_date = timezone.make_aware(scheduled_date)
                except ValueError:
                    return JsonResponse({'error': 'Invalid date format'}, status=400)

            update.title = title
            update.description = description
            update.status = status
            update.save()

            messages.success(request, "Project update edited successfully.")
            return redirect('dashboard')  # Redirect to the dashboard after successful edit

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

@login_required
@user_passes_test(is_manager)
@transaction.atomic
def manager_delete_project_update(request, update_id):
    """Manager deletes a project update."""
    try:
        update = get_object_or_404(ProjectUpdate, id=update_id)
        if update.created_by != request.user:
            messages.error(request, "You do not have permission to delete this update.")
            return redirect('dashboard')

        update.delete()
        messages.success(request, "Project update deleted successfully.")
        return redirect('dashboard')

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

''' --------------------------------------------------------- USER DETAILS AREA --------------------------------------------------------- '''

# aps/views.py

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User, Group
from django.contrib import messages
from django.http import HttpResponseForbidden, HttpResponse, JsonResponse
from django.db import transaction
from django.db.models import Q, Count, Sum, Max, Avg
from django.core.paginator import Paginator
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.core.mail import EmailMessage, EmailMultiAlternatives
from django.utils import timezone
import logging
import re
import csv
import io
import random
import string
from datetime import date, datetime, timedelta
from .models import UserDetails, UserActionLog, UserSession, validate_pan, validate_aadhar

logger = logging.getLogger(__name__)

# Permission check functions
def is_hr(user):
    return user.groups.filter(name='HR').exists()

def is_manager(user):
    return user.groups.filter(name='Manager').exists()

def is_employee(user):
    return user.groups.filter(name='Employee').exists()

    
# Helper function to generate employee ID
def generate_employee_id(work_location=None, group_id=None):
    """
    Generate employee ID based on work location with role-based reserved ranges
    
    Reserved ranges for Management and Finance groups (IDs 7 and 8):
    - 1-15: First priority range
    - 301-400: Second priority range
    
    Regular employees use 101-300 and 401+ ranges
    """
    from django.db.models import Q
    from datetime import datetime
    import re
    
    # Check if user belongs to Finance or Management groups based on group_id
    is_reserved_role = False
    if group_id and group_id in ['7', '8']:  # Finance or Management
        is_reserved_role = True
    
    # Determine prefix based on location
    if work_location and work_location.lower() == 'betul':
        prefix = "ATS"
        separator = ""
        year_suffix = ""
    elif work_location and work_location.lower() == 'pune':
        prefix = "AT"
        separator = ""
        year_suffix = ""
    else:
        prefix = "EMP"
        current_year = str(datetime.now().year)[2:]
        year_suffix = current_year
        separator = "-"
    
    # Function to extract numeric ID from username
    def extract_id(username):
        # Extract numbers at the end of the string
        match = re.search(r'(\d+)$', username)
        if match:
            try:
                return int(match.group(1))
            except ValueError:
                return None
        return None
    
    # Set ID ranges based on role
    if is_reserved_role:
        # Check if there's a gap in priority range 1-15
        used_ids = []
        
        # Query all users with the prefix
        all_users = User.objects.filter(username__startswith=prefix)
        
        # Find all used IDs in the priority range
        for user in all_users:
            user_id = extract_id(user.username)
            if user_id and 1 <= user_id <= 15:
                used_ids.append(user_id)
        
        # Look for the first available ID in priority range
        for i in range(1, 16):
            if i not in used_ids:
                seq_num = i
                break
        else:
            # Priority range is full, check reserved range 301-400
            used_ids = []
            for user in all_users:
                user_id = extract_id(user.username)
                if user_id and 301 <= user_id <= 400:
                    used_ids.append(user_id)
            
            # Look for the first available ID in reserved range
            for i in range(301, 401):
                if i not in used_ids:
                    seq_num = i
                    break
            else:
                # Both ranges are full, generate fallback ID
                timestamp = int(datetime.now().timestamp())
                return f"{prefix}{separator}{timestamp}"
    else:
        # Regular employees use 101-300 and 401+
        all_users = User.objects.filter(username__startswith=prefix)
        highest_id = 100  # Start from 101
        
        # Find the highest used ID outside reserved ranges
        for user in all_users:
            user_id = extract_id(user.username)
            if user_id and user_id > highest_id and user_id not in range(1, 16) and user_id not in range(301, 401):
                highest_id = user_id
        
        # Start from highest + 1
        seq_num = highest_id + 1
        
        # Skip reserved ranges
        if 1 <= seq_num <= 15:
            seq_num = 101
        elif 301 <= seq_num <= 400:
            seq_num = 401
    
    # Format the sequence number and build the ID
    formatted_seq = f"{seq_num:04d}"
    if year_suffix:
        employee_id = f"{prefix}{year_suffix}{separator}{formatted_seq}"
    else:
        employee_id = f"{prefix}{formatted_seq}"
    
    # Final validation to ensure ID doesn't already exist
    if User.objects.filter(username=employee_id).exists():
        # If this ID is taken, recurse with a timestamp-based ID
        timestamp = int(datetime.now().timestamp())
        if year_suffix:
            return f"{prefix}{year_suffix}{separator}{timestamp}"
        else:
            return f"{prefix}{separator}{timestamp}"
    
    return employee_id

# Helper function to send welcome email
def send_welcome_email(user, password):
    """Send welcome email with login credentials"""
    from django.core.mail import EmailMessage, EmailMultiAlternatives
    from django.template.loader import render_to_string

    subject = "Welcome to Ardur Company Portal"
    
    # Plain text email body
    email_body = f"""
    Hello {user.first_name} {user.last_name},
    
    Welcome to Our Company! Your account has been created successfully.
    
    Here are your login details:
    Username: {user.username}
    Password: {password}
    
    Please log in at: https://home.ardurtechnology.com/login/
    
    For security reasons, we recommend changing your password after first login.
    
    Regards,
    HR Department
    """
    
    # Try to render HTML template, fall back to plain text if it fails
    try:
        html_message = render_to_string('components/hr/emails/welcome_email.html', {
            'user': user,
            'password': password,
            'login_url': 'https://home.ardurtechnology.com/login/'
        })
        
        # Send email with both HTML and plain text
        email = EmailMultiAlternatives(
            subject=subject,
            body=email_body,
            to=[user.email]
        )
        email.attach_alternative(html_message, "text/html")
    except Exception as e:
        logger.error(f"Error rendering HTML template: {str(e)}")
        # Fall back to plain text email
        email = EmailMessage(
            subject=subject,
            body=email_body,
            to=[user.email]
        )
    
    # Add logging before sending
    logger.info(f"Attempting to send welcome email to {user.email}")
    
    # Send the email
    email.send()
    logger.info(f"Welcome email sent successfully to {user.email}")
    
    return True

# HR Dashboard with enhanced features
@login_required
@user_passes_test(is_hr)
def hr_dashboard(request):
    """HR Dashboard with improved filtering, query optimization, and pagination"""
    # Get filter parameters with defaults
    filters = {
        'search': request.GET.get('search', ''),
        'department': request.GET.get('department', ''),
        'status': request.GET.get('status', ''),
        'work_location': request.GET.get('work_location', ''),
        'role': request.GET.get('role', ''),
        'employee_type': request.GET.get('employee_type', '')
    }

    # Start with optimized base queryset
    users = User.objects.select_related('profile').prefetch_related(
        'groups',
        Prefetch(
            'usersession_set',
            queryset=UserSession.objects.filter(
                login_time__date=datetime.now().date()
            ).order_by('-login_time'),
            to_attr='today_sessions'
        )
    )

    # Apply search filter
    if filters['search']:
        users = users.filter(
            Q(first_name__icontains=filters['search']) |
            Q(last_name__icontains=filters['search']) |
            Q(username__icontains=filters['search']) |
            Q(email__icontains=filters['search']) |
            Q(profile__job_description__icontains=filters['search']) |
            Q(profile__current_city__icontains=filters['search']) |
            Q(profile__current_state__icontains=filters['search'])
        ).distinct()

    # Apply other filters
    if filters['status']:
        users = users.filter(profile__employment_status=filters['status'])
    if filters['work_location']:
        users = users.filter(profile__work_location=filters['work_location'])
    if filters['role']:
        users = users.filter(groups__name=filters['role'])
    if filters['employee_type']:
        users = users.filter(profile__employee_type=filters['employee_type'])

    # Create missing profiles
    for user in users:
        if not hasattr(user, 'profile'):
            UserDetails.objects.create(user=user)

    # Get dashboard statistics using aggregation
    stats = {
        'total_users': users.count(),
        'active_users': users.filter(is_active=True).count(),
        'inactive_users': users.filter(is_active=False).count(),
        'status_counts': UserDetails.objects.values('employment_status').annotate(
            count=Count('id'),
            active_count=Count('user', filter=Q(user__is_active=True))
        ),
        'location_counts': UserDetails.objects.exclude(
            Q(work_location__isnull=True) | Q(work_location='')
        ).values('work_location').annotate(
            count=Count('id'),
            active_count=Count('user', filter=Q(user__is_active=True))
        ).order_by('-count'),
        'employee_type_counts': UserDetails.objects.values('employee_type').annotate(
            count=Count('id'),
            active_count=Count('user', filter=Q(user__is_active=True))
        ),
        'recent_users': User.objects.select_related('profile').filter(
            date_joined__gte=datetime.now().date() - timedelta(days=7)
        ).order_by('-date_joined')[:5]
    }

    # Handle pagination with remembered page size
    page_size = request.session.get('hr_dashboard_page_size', 20)
    if 'page_size' in request.GET:
        page_size = int(request.GET['page_size'])
        request.session['hr_dashboard_page_size'] = page_size

    paginator = Paginator(users, page_size)
    page_obj = paginator.get_page(request.GET.get('page'))

    # Get filter options from model
    filter_options = {
        'employment_status_choices': UserDetails.EMPLOYMENT_STATUS_CHOICES,
        'employee_type_choices': UserDetails.EMPLOYEE_TYPE_CHOICES,
        'work_locations': UserDetails.objects.exclude(
            Q(work_location__isnull=True) | Q(work_location='')
        ).values_list('work_location', flat=True).distinct(),
        'roles': Group.objects.all()
    }

    context = {
        'page_obj': page_obj,
        'page_range': paginator.get_elided_page_range(
            page_obj.number,
            on_each_side=2,
            on_ends=1
        ),
        'page_size': page_size,
        'filters': filters,
        'filter_options': filter_options,
        'stats': stats,
        'role': 'HR'
    }

    return render(request, 'components/hr/hr_dashboard.html', context)
@login_required
@user_passes_test(is_hr)
def hr_user_detail(request, user_id):
    """Enhanced view for HR to view and edit comprehensive user details"""
    import re
    from datetime import date, datetime
    
    # Log the requested user_id to help diagnose issues
    logger.info(f"Accessing user detail for user_id: {user_id}")
    
    user = get_object_or_404(User, id=user_id)
    user_detail, created = UserDetails.objects.get_or_create(user=user)
    
    # Log the retrieved user information
    logger.info(f"Retrieved user: {user.username} ({user.first_name} {user.last_name}), user_id: {user.id}")
    
    # Get user action logs
    action_logs = UserActionLog.objects.filter(user=user).order_by('-timestamp')[:10]
    
    # Get recent sessions
    recent_sessions = UserSession.objects.filter(user=user).order_by('-login_time')[:5]

    if request.method == 'POST':
        try:
            logger.info(f"Processing POST request for user_id: {user_id}")

            # Extract and clean data
            data = request.POST.copy()

            # Validate date of birth
            dob = data.get('dob')
            if dob:
                dob_date = datetime.strptime(dob, '%Y-%m-%d').date()
                today = date.today()
                age = today.year - dob_date.year - ((today.month, today.day) < (dob_date.month, dob_date.day))
                if age < 18:
                    raise ValueError('Employee must be at least 18 years old.')

            # Validate contact numbers
            def validate_contact(number, field_name):
                if not number:
                    return None
                    
                # Remove any non-digit characters for validation
                cleaned_number = ''.join(c for c in number if c.isdigit())
                
                # Check if the number is valid (allowing for international format)
                if len(cleaned_number) < 10 or len(cleaned_number) > 15:
                    raise ValueError(f'{field_name} must be between 10 and 15 digits.')
                    
                return number

            # Primary contact validation
            primary_number = data.get('contact_number_primary', '').strip()
            primary_contact = validate_contact(primary_number, 'Primary contact number')

            # Emergency contact validation  
            emergency_number = data.get('emergency_contact_number', '').strip()
            emergency_contact = validate_contact(emergency_number, 'Emergency contact number')
            
            # Secondary emergency contact validation
            secondary_emergency_number = data.get('secondary_emergency_contact_number', '').strip()
            secondary_emergency_contact = validate_contact(secondary_emergency_number, 'Secondary emergency contact number')

            # Validate PAN using model validator
            pan = data.get('pan_number')
            if pan:
                validate_pan(pan)

            # Validate Aadhar using model validator  
            aadhar = data.get('aadhar_number', '').replace(' ', '')
            if aadhar:
                validate_aadhar(aadhar)

            # Validate email
            email = data.get('personal_email')
            if email and not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                raise ValueError('Invalid email format')
                
            company_email = data.get('company_email')
            if company_email and not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', company_email):
                raise ValueError('Invalid company email format')

            # Dictionary of fields to update based on UserDetails model fields
            fields_to_update = {
                # Personal Information
                'dob': dob or None,
                'blood_group': data.get('blood_group') or None,
                'gender': data.get('gender') or None,
                'marital_status': data.get('marital_status') or None,
                
                # Contact Information
                'contact_number_primary': primary_contact,
                'personal_email': email or None,
                'company_email': company_email or None,
                
                # Current Address
                'current_address_line1': data.get('current_address_line1') or None,
                'current_address_line2': data.get('current_address_line2') or None,
                'current_city': data.get('current_city') or None,
                'current_state': data.get('current_state') or None,
                'current_postal_code': data.get('current_postal_code') or None,
                'current_country': data.get('current_country') or None,
                
                # Permanent Address
                'permanent_address_line1': data.get('permanent_address_line1') or None,
                'permanent_address_line2': data.get('permanent_address_line2') or None,
                'permanent_city': data.get('permanent_city') or None,
                'permanent_state': data.get('permanent_state') or None,
                'permanent_postal_code': data.get('permanent_postal_code') or None,
                'permanent_country': data.get('permanent_country') or None,
                'is_current_same_as_permanent': data.get('is_current_same_as_permanent') == 'on',
                
                # Emergency Contact
                'emergency_contact_name': data.get('emergency_contact_name') or None,
                'emergency_contact_number': emergency_contact,
                'emergency_contact_relationship': data.get('emergency_contact_relationship') or None,
                
                # Secondary Emergency Contact
                'secondary_emergency_contact_name': data.get('secondary_emergency_contact_name') or None,
                'secondary_emergency_contact_number': secondary_emergency_contact,
                'secondary_emergency_contact_relationship': data.get('secondary_emergency_contact_relationship') or None,
                
                # Employment Information
                'employee_type': data.get('employee_type') or None,
                'reporting_manager_id': data.get('reporting_manager') or None,
                'hire_date': data.get('hire_date') or None,
                'start_date': data.get('start_date') or None,
                'probation_end_date': data.get('probation_end_date') or None,
                'notice_period_days': data.get('notice_period_days') or 30,
                'job_description': data.get('job_description') or None,
                'work_location': data.get('work_location') or None,
                'employment_status': data.get('employment_status') or None,
                'exit_date': data.get('exit_date') or None,
                'exit_reason': data.get('exit_reason') or None,
                'rehire_eligibility': data.get('rehire_eligibility') == 'on',
                
                # Compensation Details
                'salary_currency': data.get('salary_currency') or 'INR',
                'base_salary': data.get('base_salary') or None,
                'salary_frequency': data.get('salary_frequency') or 'monthly',
                
                # Government IDs
                'pan_number': pan or None,
                'aadhar_number': aadhar or None,
                'passport_number': data.get('passport_number') or None,
                'passport_expiry': data.get('passport_expiry') or None,
                
                # Banking Details
                'bank_name': data.get('bank_name') or None,
                'bank_account_number': data.get('bank_account_number') or None,
                'bank_ifsc': data.get('bank_ifsc') or None,
                
                # Previous Employment
                'previous_company': data.get('previous_company') or None,
                'previous_position': data.get('previous_position') or None,
                'previous_experience_years': data.get('previous_experience_years') or None,
                
                # Skills and Competencies
                'skills': data.get('skills') or None,
                
                # Additional HR Notes
                'confidential_notes': data.get('confidential_notes') if request.user.has_perm('view_confidential_notes') else user_detail.confidential_notes
            }

            # Check if role/group is being updated
            old_group = user.groups.first()
            new_group_id = data.get('group')
            if new_group_id:
                new_group = Group.objects.get(id=new_group_id)
                
                if not old_group or old_group.id != new_group.id:
                    user.groups.clear()
                    user.groups.add(new_group)
                    
                    UserActionLog.objects.create(
                        user=user,
                        action_type='role_change',
                        action_by=request.user,
                        details=f"Role changed from {old_group.name if old_group else 'None'} to {new_group.name}"
                    )

            # Handle employment status changes based on model choices
            old_status = user_detail.employment_status
            new_status = data.get('employment_status')
            
            if old_status != new_status and new_status:
                if new_status in ['inactive', 'terminated', 'resigned', 'suspended', 'absconding']:
                    if user.is_active:
                        user.is_active = False
                        user.save()
                        
                        UserActionLog.objects.create(
                            user=user,
                            action_type='deactivate',
                            action_by=request.user,
                            details=f"User account deactivated due to status change to {new_status}"
                        )
                elif new_status == 'active' and not user.is_active:
                    user.is_active = True
                    user.save()
                    
                    UserActionLog.objects.create(
                        user=user,
                        action_type='activate',
                        action_by=request.user,
                        details="User account activated due to status change to active"
                    )

            # Remove empty values
            fields_to_update = {k: v for k, v in fields_to_update.items() if v is not None}

            # Validate against model choices
            model_fields = UserDetails._meta.get_fields()
            for field_name, value in fields_to_update.items():
                field = next((f for f in model_fields if f.name == field_name), None)
                if hasattr(field, 'choices') and field.choices and value:
                    valid_choices = dict(field.choices)
                    if value not in valid_choices:
                        raise ValueError(f'Invalid value for {field_name}')

            # Update basic user details if provided
            first_name = data.get('first_name')
            last_name = data.get('last_name')
            email = data.get('email')
            
            if first_name or last_name or email:
                user.first_name = first_name or user.first_name
                user.last_name = last_name or user.last_name
                user.email = email or user.email
                user.save()
                
                UserActionLog.objects.create(
                    user=user,
                    action_type='update',
                    action_by=request.user,
                    details="Basic user information updated"
                )

            # Perform atomic update
            with transaction.atomic():
                for field, value in fields_to_update.items():
                    setattr(user_detail, field, value)
                user_detail.save()
                
                UserActionLog.objects.create(
                    user=user,
                    action_type='update',
                    action_by=request.user,
                    details="User details updated"
                )

            messages.success(request, 'User details updated successfully.')
            return redirect('aps_hr:hr_user_detail', user_id=user.id)

        except ValueError as e:
            logger.warning(f"Validation Error for user {user_id}: {str(e)}")
            messages.error(request, str(e))
        except Exception as e:
            logger.error(f"Unexpected error for user {user_id}: {str(e)}", exc_info=True)
            messages.error(request, 'An unexpected error occurred while updating user details.')

    # Prepare context with user details and metadata
    context = {
        'user_obj': user,
        'user_detail': user_detail,
        'action_logs': action_logs,
        'recent_sessions': recent_sessions,
        'today': date.today(),
        'blood_group_choices': UserDetails.BLOOD_GROUP_CHOICES,
        'gender_choices': UserDetails.GENDER_CHOICES,
        'marital_status_choices': UserDetails.MARITAL_STATUS_CHOICES,
        'employment_status_choices': UserDetails.EMPLOYMENT_STATUS_CHOICES,
        'employee_type_choices': UserDetails.EMPLOYEE_TYPE_CHOICES,
        'groups': Group.objects.all(),
        'employment_duration': user_detail.employment_duration,
        'status_display': user_detail.status_display,
        'reporting_chain': user_detail.get_reporting_chain,
        'salary_frequencies': [('monthly', 'Monthly'), ('bi_weekly', 'Bi-Weekly'), ('weekly', 'Weekly')],
        'remaining_notice_period': user_detail.remaining_notice_period if user_detail.is_on_notice else None,
        'age': user_detail.age,
        'managers': User.objects.filter(groups__name='Manager').order_by('first_name', 'last_name')
    }

    return render(request, 'components/hr/hr_user_detail.html', context)

@login_required
@user_passes_test(is_hr)
def add_user(request):
    """Enhanced view to add a new user to the system with auto ID generation"""
    if request.method == 'POST':
        try:
            with transaction.atomic():
                # Extract basic user information
                email = request.POST.get('email', '').strip()
                first_name = request.POST.get('first_name')
                last_name = request.POST.get('last_name')
                group_id = request.POST.get('group')
                work_location = request.POST.get('work_location')
                
                # Validate required fields
                if not (first_name and last_name and group_id):
                    raise ValueError("First name, last name, and group are required fields")
                
                # Check if email already exists (only if provided)
                if email and User.objects.filter(email=email).exists():
                    raise ValueError(f"Email '{email}' already exists")
                
                # Generate employee ID for username
                employee_id = generate_employee_id(work_location, group_id)

                # Generate a random password
                password = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=12))
                
                # Create new user
                user = User.objects.create_user(
                    username=employee_id,
                    email=email if email else None,
                    password=password,
                    first_name=first_name,
                    last_name=last_name
                )
                
                # Add user to group
                try:
                    group = Group.objects.get(id=int(group_id))
                    user.groups.add(group)
                except (ValueError, Group.DoesNotExist):
                    raise ValueError("Invalid group selected")
                
                # Create UserDetails with comprehensive information
                user_details = UserDetails.objects.create(
                    user=user,
                    hire_date=request.POST.get('hire_date') or datetime.now().date(),
                    start_date=request.POST.get('start_date') or datetime.now().date(),
                    employment_status='active',
                    work_location=work_location,
                    job_description=request.POST.get('job_description') or None,
                    dob=request.POST.get('dob') or None,
                    gender=request.POST.get('gender') or None,
                    blood_group=request.POST.get('blood_group') or None,
                    contact_number_primary=request.POST.get('contact_number_primary') or None,
                    personal_email=request.POST.get('personal_email') or None,
                    emergency_contact_name=request.POST.get('emergency_contact_name') or None,
                    emergency_contact_number=request.POST.get('emergency_contact_primary') or None,
                    emergency_contact_relationship=request.POST.get('emergency_contact_relationship') or None,
                    onboarded_by=request.user,
                    onboarding_date=timezone.now(),
                    employee_type=request.POST.get('employee_type') or None,
                    current_address_line1=request.POST.get('address_line1') or None,
                    current_address_line2=request.POST.get('address_line2') or None,
                    current_city=request.POST.get('city') or None,
                    current_state=request.POST.get('state') or None,
                    current_postal_code=request.POST.get('postal_code') or None,
                    current_country=request.POST.get('country') or None
                )
                
                # Log user creation
                UserActionLog.objects.create(
                    user=user,
                    action_type='create',
                    action_by=request.user,
                    details=f"User created with ID: {employee_id}, role: {group.name}"
                )
                
                # Send welcome email with better exception handling (only if email is provided)
                if email:
                    try:
                        send_welcome_email(user, password)
                        messages.success(request, f"Welcome email sent to {email} with login credentials.")
                    except ConnectionRefusedError:
                        logger.error("Email server connection refused. Check email server settings.", exc_info=True)
                        messages.warning(request, f"User created successfully, but welcome email could not be sent due to email server connection issues.")
                    except Exception as e:
                        logger.error(f"Error sending welcome email: {str(e)}", exc_info=True)
                        messages.warning(request, f"User created successfully, but welcome email could not be sent: {str(e)}")
                
                messages.success(request, f"User {employee_id} ({first_name} {last_name}) created successfully.")
                # Fix the URL name to include the namespace
                return redirect('aps_hr:hr_user_detail', user_id=user.id)
                
        except ValueError as e:
            messages.error(request, str(e))
        except Exception as e:
            logger.error(f"Error creating user: {str(e)}", exc_info=True)
            messages.error(request, f"Error creating user: {str(e)}")
    
    return render(request, 'components/hr/add_user.html', {
        'groups': Group.objects.all(),
        'today': date.today(),
        'blood_group_choices': UserDetails.BLOOD_GROUP_CHOICES,
        'gender_choices': UserDetails.GENDER_CHOICES,
        'employment_status_choices': UserDetails.EMPLOYMENT_STATUS_CHOICES,
        'employee_type_choices': UserDetails.EMPLOYEE_TYPE_CHOICES,
    })
@login_required
@user_passes_test(is_hr)
def bulk_add_users(request):
    """View to add multiple users to the system at once from a text file or pasted content"""
    
    if request.method == 'POST':
        user_data = request.POST.get('user_data', '').strip()
        selected_group_id = request.POST.get('group')
        work_location = request.POST.get('work_location')
        
        if not user_data:
            messages.error(request, "No user data provided. Please enter user data in the text area.")
            return redirect('aps_hr:bulk_add_users')
        
        if not selected_group_id:
            messages.error(request, "Please select a role/group for the users from the dropdown menu.")
            return redirect('aps_hr:bulk_add_users')
            
        try:
            group = Group.objects.get(id=int(selected_group_id))
        except (ValueError, Group.DoesNotExist):
            messages.error(request, "Invalid group selected. Please select a valid group from the dropdown.")
            return redirect('aps_hr:bulk_add_users')
        
        # Process the user data
        lines = user_data.strip().split('\n')
        success_count = 0
        skipped_count = 0
        error_messages = []
        
        with transaction.atomic():
            for line_number, line in enumerate(lines, 1):
                line = line.strip()
                if not line:
                    continue
                    
                # Split by tab or space if tab not found
                parts = line.split('\t') if '\t' in line else line.split(maxsplit=1)
                
                if len(parts) < 2:
                    error_messages.append(f"Line {line_number}: Invalid format - '{line}'. Expected format: 'Username FirstName LastName'")
                    continue
                
                username = parts[0].strip()
                full_name = parts[1].strip()
                
                # Skip empty entries
                if not username or not full_name:
                    error_messages.append(f"Line {line_number}: Empty username or name - '{line}'")
                    skipped_count += 1
                    continue
                
                # Split full name into first and last name
                name_parts = full_name.split()
                if len(name_parts) > 1:
                    first_name = name_parts[0]
                    last_name = ' '.join(name_parts[1:])
                else:
                    first_name = full_name
                    last_name = ""
                
                # Check if user already exists
                if User.objects.filter(username=username).exists():
                    error_messages.append(f"Line {line_number}: Username '{username}' already exists in the system")
                    skipped_count += 1
                    continue
                
                try:
                    # Create user with standard password
                    user = User.objects.create_user(
                        username=username,
                        password="number@123",
                        first_name=first_name,
                        last_name=last_name
                    )
                    
                    # Add user to the selected group
                    user.groups.add(group)
                    
                    # Create UserDetails
                    UserDetails.objects.create(
                        user=user,
                        hire_date=datetime.now().date(),
                        start_date=datetime.now().date(),
                        employment_status='active',
                        work_location=work_location,
                        onboarded_by=request.user,
                        onboarding_date=timezone.now()
                    )
                    
                    # Log user creation
                    UserActionLog.objects.create(
                        user=user,
                        action_type='create',
                        action_by=request.user,
                        details=f"User created in bulk import with ID: {username}, role: {group.name}"
                    )
                    
                    success_count += 1
                    
                except Exception as e:
                    error_messages.append(f"Line {line_number}: Error creating user '{username}' - {str(e)}")
        
        if success_count > 0:
            messages.success(request, f"Successfully added {success_count} users to the system.")
        
        if skipped_count > 0:
            messages.warning(request, f"Skipped {skipped_count} entries due to duplicates or invalid data.")
            
        if error_messages:
            messages.error(request, "The following errors occurred during import:")
            for msg in error_messages[:10]:  # Show first 10 errors
                messages.error(request, msg)
            
            if len(error_messages) > 10:
                messages.error(request, f"...and {len(error_messages) - 10} more errors. Please check your input data and try again.")
        
        return redirect('aps_hr:hr_dashboard')
    
    # For GET request, show the upload form
    return render(request, 'components/hr/bulk_add_users.html', {
        'groups': Group.objects.all(),
    })

@login_required
@user_passes_test(is_hr)
def import_errors(request):
    """View to display errors from bulk import"""
    errors = request.session.get('import_errors', [])
    if not errors:
        messages.info(request, "No import errors to display")
        return redirect('hr_dashboard')
    
    return render(request, 'components/hr/import_errors.html', {
        'errors': errors
    })


@login_required
@user_passes_test(is_hr)
def user_action_logs(request, user_id=None):
    """View all action logs or filtered by user"""
    if user_id:
        user = get_object_or_404(User, id=user_id)
        logs = UserActionLog.objects.filter(user=user).order_by('-timestamp')
        context = {
            'logs': logs,
            'user': user,
        }
        return render(request, 'components/hr/user_action_logs.html', context)
    else:
        # Get filter parameters
        action_type = request.GET.get('action_type', '')
        start_date = request.GET.get('start_date', '')
        end_date = request.GET.get('end_date', '')
        user_filter = request.GET.get('user', '')
        
        logs = UserActionLog.objects.all().order_by('-timestamp')
        
        # Apply filters
        if action_type:
            logs = logs.filter(action_type=action_type)
        
        if start_date:
            try:
                start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
                logs = logs.filter(timestamp__date__gte=start_date)
            except ValueError:
                messages.error(request, 'Invalid start date format')
        
        if end_date:
            try:
                end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
                logs = logs.filter(timestamp__date__lte=end_date)
            except ValueError:
                messages.error(request, 'Invalid end date format')
        
        if user_filter:
            logs = logs.filter(
                Q(user__username__icontains=user_filter) |
                Q(user__first_name__icontains=user_filter) |
                Q(user__last_name__icontains=user_filter)
            )
        
        # Pagination
        paginator = Paginator(logs, 20)  # Show 20 logs per page
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)
        
        context = {
            'page_obj': page_obj,
            'action_types': UserActionLog.ACTION_TYPES,
            'filter_action_type': action_type,
            'filter_start_date': start_date,
            'filter_end_date': end_date,
            'filter_user': user_filter,
        }
        return render(request, 'components/hr/all_action_logs.html', context)

@login_required
@user_passes_test(is_hr)
def session_logs(request, user_id=None):
    """View session logs for a specific user or all users"""
    if user_id:
        user = get_object_or_404(User, id=user_id)
        sessions = UserSession.objects.filter(user=user).order_by('-login_time')
        context = {
            'sessions': sessions,
            'user': user,
        }
        return render(request, 'components/hr/user_session_logs.html', context)
    else:
        # Get filter parameters
        start_date = request.GET.get('start_date', '')
        end_date = request.GET.get('end_date', '')
        user_filter = request.GET.get('user', '')
        location_filter = request.GET.get('location', '')
        
        sessions = UserSession.objects.all().order_by('-login_time')
        
        # Apply filters
        if start_date:
            try:
                start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
                sessions = sessions.filter(login_time__date__gte=start_date)
            except ValueError:
                messages.error(request, 'Invalid start date format')
        
        if end_date:
            try:
                end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
                sessions = sessions.filter(login_time__date__lte=end_date)
            except ValueError:
                messages.error(request, 'Invalid end date format')
        
        if user_filter:
            sessions = sessions.filter(
                Q(user__username__icontains=user_filter) |
                Q(user__first_name__icontains=user_filter) |
                Q(user__last_name__icontains=user_filter)
            )
        
        if location_filter:
            sessions = sessions.filter(location=location_filter)
        
        # Pagination
        paginator = Paginator(sessions, 20)  # Show 20 sessions per page
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)
        
        # Get unique locations for filter dropdown
        locations = UserSession.objects.values_list('location', flat=True).distinct()
        
        context = {
            'page_obj': page_obj,
            'locations': locations,
            'filter_start_date': start_date,
            'filter_end_date': end_date,
            'filter_user': user_filter,
            'filter_location': location_filter,
        }
        return render(request, 'components/hr/all_session_logs.html', context)

@login_required
@user_passes_test(is_hr)
def user_reports(request):
    """View to generate reports on user data"""
    report_type = request.GET.get('report_type', 'active_users')
    export_format = request.GET.get('export_format', '')
    
    if report_type == 'active_users':
        # Report on active vs inactive users
        active_count = User.objects.filter(is_active=True).count()
        inactive_count = User.objects.filter(is_active=False).count()
        
        # Users by employment status
        status_counts = UserDetails.objects.exclude(employment_status__isnull=True).values('employment_status').annotate(count=Count('employment_status'))
        
        # Convert to dict with display names
        status_choices = dict(UserDetails._meta.get_field('employment_status').choices)
        status_data = {status_choices.get(item['employment_status'], item['employment_status']): item['count'] for item in status_counts}
        
        context = {
            'report_type': 'active_users',
            'active_count': active_count,
            'inactive_count': inactive_count,
            'status_data': status_data,
        }
    
    elif report_type == 'location_distribution':
        # Report on work location distribution
        location_counts = UserDetails.objects.exclude(work_location__isnull=True).exclude(work_location='').values('work_location').annotate(count=Count('work_location')).order_by('-count')
        
        context = {
            'report_type': 'location_distribution',
            'location_counts': location_counts,
        }
    
    elif report_type == 'session_activity':
        # Report on session activity
        # Today's active users
        today = datetime.now().date()
        active_today = UserSession.objects.filter(login_time__date=today).values('user').distinct().count()
        
        # Last 7 days active users
        week_ago = today - timedelta(days=7)
        active_week = UserSession.objects.filter(login_time__date__gte=week_ago).values('user').distinct().count()
        
        # Average session duration
        avg_duration = UserSession.objects.filter(
            working_hours__isnull=False
        ).values('user').annotate(
            avg_duration=Avg('working_hours')
        )
        
        # Location breakdown
        location_sessions = UserSession.objects.filter(
            login_time__date__gte=week_ago
        ).values('location').annotate(
            count=Count('id')
        ).order_by('-count')
        
        context = {
            'report_type': 'session_activity',
            'active_today': active_today,
            'active_week': active_week,
            'avg_duration': avg_duration,
            'location_sessions': location_sessions,
        }
    
    elif report_type == 'role_distribution':
        # Report on role distribution
        role_counts = Group.objects.annotate(
            user_count=Count('user')
        ).values('name', 'user_count').order_by('-user_count')
        
        context = {
            'report_type': 'role_distribution',
            'role_counts': role_counts,
        }
    
    # Handle export if requested
    if export_format:
        if export_format == 'csv':
            return export_as_csv(request, report_type, context)
        # Comment out or remove undefined functions until they're implemented
        # elif export_format == 'excel':
        #     return export_as_excel(request, report_type, context)
        # elif export_format == 'pdf':
        #     return export_as_pdf(request, report_type, context)
    
    return render(request, 'components/hr/user_reports.html', context)

@login_required
@user_passes_test(is_hr)
def export_as_csv(request, report_type, context):
    """Export report data as CSV"""
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{report_type}_report.csv"'
    
    writer = csv.writer(response)
    
    if report_type == 'active_users':
        writer.writerow(['Status', 'Count'])
        writer.writerow(['Active', context['active_count']])
        writer.writerow(['Inactive', context['inactive_count']])
        
        writer.writerow([])  # Empty row as separator
        writer.writerow(['Employment Status', 'Count'])
        for status, count in context['status_data'].items():
            writer.writerow([status, count])
    
    elif report_type == 'location_distribution':
        writer.writerow(['Location', 'User Count'])
        for item in context['location_counts']:
            writer.writerow([item['work_location'], item['count']])
    
    elif report_type == 'session_activity':
        writer.writerow(['Metric', 'Value'])
        writer.writerow(['Active Users Today', context['active_today']])
        writer.writerow(['Active Users Last 7 Days', context['active_week']])
        
        writer.writerow([])  # Empty row as separator
        writer.writerow(['Location', 'Session Count'])
        for item in context['location_sessions']:
            writer.writerow([item['location'], item['count']])
    
    elif report_type == 'role_distribution':
        writer.writerow(['Role', 'User Count'])
        for item in context['role_counts']:
            writer.writerow([item['name'], item['user_count']])
    
    return response


@login_required
@user_passes_test(is_hr)
def reset_user_password(request, user_id):
    """Reset a user's password"""
    user = get_object_or_404(User, id=user_id)
    
    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        reason = request.POST.get('reason')
        
        if not reason:
            messages.error(request, "Please provide a reason for password reset")
            return redirect('aps_hr:hr_user_detail', user_id=user_id)
        
        if not new_password or len(new_password) < 8:
            messages.error(request, "Password must be at least 8 characters")
            return redirect('aps_hr:hr_user_detail', user_id=user_id)
            
        if new_password != confirm_password:
            messages.error(request, "Passwords do not match")
            return redirect('aps_hr:hr_user_detail', user_id=user_id)
        
        try:
            # Set new password
            user.set_password(new_password)
            user.save()
            
            # Log password reset with reason
            UserActionLog.objects.create(
                user=user,
                action_type='password_reset',
                action_by=request.user,
                details=f"Password reset by HR. Reason: {reason}"
            )
            
            # Send email notification to user
            try:
                subject = "Your Password Has Been Reset"
                message = f"""
                Hello {user.first_name} {user.last_name},
                
                Your password has been reset by HR. Your new password is:
                
                {new_password}
                
                Please log in at http://yourcompanyportal.com/login/ and change your password immediately.
                
                Reason for reset: {reason}
                
                Regards,
                HR Department
                """
                
                user.email_user(subject, message, fail_silently=True)
                messages.success(request, f"Password for {user.username} has been reset and email sent to the user.")
            except Exception as e:
                logger.error(f"Error sending email: {str(e)}", exc_info=True)
                messages.warning(request, f"Password for {user.username} has been reset but email could not be sent.")
            
            return redirect('aps_hr:hr_user_detail', user_id=user.id)
        
        except Exception as e:
            logger.error(f"Error resetting password: {str(e)}", exc_info=True)
            messages.error(request, f"Error resetting password: {str(e)}")
            return redirect('aps_hr:hr_user_detail', user_id=user_id)
    
    # This fallback should also redirect to the user detail page
    messages.error(request, "Invalid request")
    return redirect('aps_hr:hr_user_detail', user_id=user_id)

@login_required
@user_passes_test(is_hr)
def change_user_status(request, user_id):
    """Change a user's status (activate/deactivate)"""
    # Debug information
    logger.info(f"change_user_status called with user_id={user_id}")
    logger.info(f"POST data: {request.POST}")
    
    # Get the user from the URL parameter
    user = get_object_or_404(User, id=user_id)
    user_detail, created = UserDetails.objects.get_or_create(user=user)
    
    if request.method == 'POST':
        # Extra safety check - verify the user_id in POST matches the URL
        form_user_id = request.POST.get('user_id')
        if form_user_id and int(form_user_id) != int(user_id):
            messages.error(request, "User ID mismatch detected. Operation aborted for security.")
            return redirect('aps_hr:hr_user_detail', user_id=user_id)
            
        new_status = request.POST.get('status')
        reason = request.POST.get('reason', '')
        
        if not new_status or new_status not in dict(UserDetails._meta.get_field('employment_status').choices):
            messages.error(request, "Invalid status provided")
            return redirect('aps_hr:hr_user_detail', user_id=user.id)
        
        try:
            with transaction.atomic():
                # Update UserDetails status
                old_status = user_detail.employment_status
                user_detail.employment_status = new_status
                user_detail.last_status_change = timezone.now()
                user_detail.save()
                
                # Update User.is_active based on status
                if new_status in ['inactive', 'terminated', 'resigned', 'suspended', 'absconding']:
                    user.is_active = False
                elif new_status == 'active':
                    user.is_active = True
                user.save()
                
                # Log status change
                UserActionLog.objects.create(
                    user=user,
                    action_type='status_change',
                    action_by=request.user,
                    details=f"Status changed from '{old_status or 'None'}' to '{new_status}'. Reason: {reason}"
                )
                
                messages.success(request, f"Status for {user.username} changed to {new_status}")
        except Exception as e:
            logger.error(f"Error changing user status: {str(e)}", exc_info=True)
            messages.error(request, f"Error changing user status: {str(e)}")
    
    return redirect('aps_hr:hr_user_detail', user_id=user.id)

@login_required
@user_passes_test(is_hr)
def change_user_role(request, user_id):
    """Change a user's role/group"""
    # Get the user from the URL parameter
    user = get_object_or_404(User, id=user_id)
    user_detail, created = UserDetails.objects.get_or_create(user=user)
    
    if request.method == 'POST':
        # Extra safety check - verify the user_id in POST matches the URL
        form_user_id = request.POST.get('user_id')
        if form_user_id and int(form_user_id) != int(user_id):
            messages.error(request, "User ID mismatch detected. Operation aborted for security.")
            return redirect('aps_hr:hr_user_detail', user_id=user_id)
            
        new_group_id = request.POST.get('group')
        reason = request.POST.get('reason', '')
        
        if not new_group_id:
            messages.error(request, "No role selected")
            return redirect('aps_hr:hr_user_detail', user_id=user.id)
        
        try:
            new_group = Group.objects.get(id=new_group_id)
            old_groups = list(user.groups.all())
            old_group_names = ', '.join([group.name for group in old_groups]) if old_groups else 'None'
            
            with transaction.atomic():
                # Remove from all current groups
                user.groups.clear()
                
                # Add to new group
                user.groups.add(new_group)
                
                # Update UserDetails
                user_detail.group = new_group
                user_detail.save()
                
                # Log role change
                UserActionLog.objects.create(
                    user=user,
                    action_type='role_change',
                    action_by=request.user,
                    details=f"Role changed from '{old_group_names}' to '{new_group.name}'. Reason: {reason}"
                )
                
                messages.success(request, f"Role for {user.username} changed to {new_group.name}")
        except Group.DoesNotExist:
            messages.error(request, "Invalid role selected")
        except Exception as e:
            logger.error(f"Error changing user role: {str(e)}", exc_info=True)
            messages.error(request, f"Error changing user role: {str(e)}")
    
    return redirect('aps_hr:hr_user_detail', user_id=user.id)

# Manager Views
@login_required
@user_passes_test(is_manager)
def manager_employee_profile(request):
    """Manager Dashboard to view team members"""
    manager_group = request.user.groups.first()
    team_members = UserDetails.objects.filter(group=manager_group).exclude(user=request.user)
    
    return render(request, 'components/manager/manager_dashboard.html', {
        'team_members': team_members,
        'role': 'Manager',
        'user_detail': request.user.userdetails,
    })

@login_required
@user_passes_test(is_manager)
def manager_user_detail(request, user_id):
    """Manager view to see (but not edit) user details"""
    user_detail = get_object_or_404(UserDetails, id=user_id)
    
    # Managers should only see users in their group
    if request.user.groups.first() != user_detail.group:
        return HttpResponseForbidden("You don't have permission to view this user's details")
    
    # Get recent sessions
    recent_sessions = UserSession.objects.filter(user=user_detail.user).order_by('-login_time')[:5]
    
    return render(request, 'components/manager/manager_user_detail.html', {
        'user_detail': user_detail,
        'recent_sessions': recent_sessions,
        'role': 'Manager'
    })

# Employee Views
@login_required
@user_passes_test(is_employee)
def employee_profile(request):
    """Employee Profile to view their own details"""
    try:
        user_detail = UserDetails.objects.get(user=request.user)
    except UserDetails.DoesNotExist:
        messages.error(request, 'Profile not found.')
        return redirect('home')
    
    # Get recent sessions
    recent_sessions = UserSession.objects.filter(
        user=request.user
    ).order_by('-login_time')[:5]
    
    return render(request, 'components/employee/employee_profile.html', {
        'user_detail': user_detail,
        'recent_sessions': recent_sessions,
        'role': 'Employee',
        'username': request.user.username
    })

@login_required
def user_profile(request, user_id):
    """View to display user profile accessible to all logged-in users"""
    user_detail = get_object_or_404(UserDetails, user__id=user_id)
    
    return render(request, 'basic/user_profile.html', {
        'user_detail': user_detail,
        'role': user_detail.user.groups.first().name if user_detail.user.groups.exists() else 'User',
        'username': user_detail.user.username
    })

# Alias for reset_user_password to maintain URL compatibility
# @login_required
# @user_passes_test(is_hr)
# def hr_reset_user_password(request, user_id):
#     """Alias for reset_user_password to maintain URL compatibility"""
#     return reset_user_password(request, user_id)
''' --------------------------------------------------------- ADMIN AREA --------------------------------------------------------- '''
# Helper function to check if the user belongs to the Admin group
def is_admin(user):
    """Check if the user belongs to the Admin group using Group model."""
    admin_group_id = 1  # Admin group ID from auth_group table
    return user.groups.filter(id=admin_group_id).exists()


from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.db.models import Q
from django.utils import timezone
from django.contrib import messages
from datetime import datetime, timedelta

# Helper function to check if the user is an admin
def is_admin(user):
    return user.is_authenticated and user.is_staff

from django.contrib.auth.decorators import login_required, user_passes_test
from django.shortcuts import render

def is_admin(user):
    """Check if the user has admin privileges."""
    return user.groups.filter(name='Admin').exists()



@login_required
@user_passes_test(is_manager)
def manager_report_view(request):
    """Manager report dashboard view."""
    
    # Navigation items for the manager dashboard
    nav_items = [
        {
            'id': 'team_breaks',
            'name': 'Team Breaks',
            'icon': 'fas fa-coffee',
            'description': 'Monitor team break patterns and durations.',
            'url': reverse('aps_manager:break_report_view_manager')
        },
        {
            'id': 'team_attendance',
            'name': 'Team Attendance',
            'icon': 'fas fa-calendar-check',
            'description': 'Track team attendance and working hours.',
            'url': reverse('aps_manager:attendance_report_view_manager')
        },
        {
            'id': 'project_progress',
            'name': 'Project Progress',
            'icon': 'fas fa-tasks',
            'description': 'View progress of your team\'s projects.',
            # 'url': reverse('manager:project_progress_report')
        },
        {
            'id': 'leave_management',
            'name': 'Leave Management',
            'icon': 'fas fa-user-clock',
            'description': 'Manage team leave requests and schedules.',
            # 'url': reverse('manager:leave_management')
        }
    ]
    
    # Detailed sections for the manager dashboard
    sections = [
        {
            "title": "Team Break Analysis",
            "description": "Monitor and analyze your team's break patterns",
            "content": "View break statistics, patterns, and ensure policy compliance.",
            # "link": reverse('manager:team_breaks_report'),
            "metrics": [
                {"label": "Active Breaks", "value": "get_active_breaks_count()"},
                {"label": "Today's Total Breaks", "value": "get_today_breaks_count()"}
            ]
        },
        {
            "title": "Team Attendance Overview",
            "description": "Track your team's attendance and working hours",
            "content": "Monitor check-ins, working hours, and attendance patterns.",
            # "link": reverse('manager:team_attendance_report'),
            "metrics": [
                {"label": "Team Present", "value": "get_present_count()"},
                {"label": "On Leave", "value": "get_on_leave_count()"}
            ]
        },
        {
            "title": "Project Status",
            "description": "Current status of all projects under your management",
            "content": "Track project progress, deadlines, and resource allocation.",
            # "link": reverse('manager:project_progress_report'),
            "metrics": [
                {"label": "Active Projects", "value": "get_active_projects_count()"},
                {"label": "Upcoming Deadlines", "value": "get_upcoming_deadlines_count()"}
            ]
        },
        {
            "title": "Leave Management",
            "description": "Manage team leave requests and schedules",
            "content": "Review and approve leave requests, plan team availability.",
            # "link": reverse('manager:leave_management'),
            "metrics": [
                {"label": "Pending Requests", "value": "get_pending_leaves_count()"},
                {"label": "Approved Leaves", "value": "get_approved_leaves_count()"}
            ]
        }
    ]
    
    context = {
        'nav_items': nav_items,
        'sections': sections,
        'page_title': 'Manager Dashboard',
        'manager_name': request.user.get_full_name() or request.user.username
    }
    
    return render(request, 'components/manager/report.html', context)

from django.db.models import F, ExpressionWrapper, DurationField
from django.db.models.functions import Coalesce
from django.utils import timezone

@login_required
@user_passes_test(is_manager)
def break_report_view_manager(request):
    """View for managers to see breaks taken by users assigned to their projects."""

    # Get filter parameters
    group_name = request.GET.get('group', '')
    break_type = request.GET.get('break_type', '')
    date_str = request.GET.get('date', '')

    # Start with base query
    breaks_query = Break.objects.select_related('user').all()

    # Filter based on the manager's team (users assigned to projects managed by the manager)
    project_assignments = ProjectAssignment.objects.filter(
        project__projectassignment__user=request.user,
        project__projectassignment__role_in_project='Manager',
        is_active=True
    ).values_list('user', flat=True).distinct()

    # Ensure only breaks from users assigned to the manager's projects are visible
    if project_assignments.exists():
        breaks_query = breaks_query.filter(user__in=project_assignments)
    else:
        # No assigned users for the manager
        breaks_query = Break.objects.none()

    # Apply additional filters
    if group_name:
        breaks_query = breaks_query.filter(user__groups__name=group_name)

    if break_type:
        breaks_query = breaks_query.filter(break_type=break_type)

    if date_str:
        try:
            filter_date = timezone.datetime.strptime(date_str, '%Y-%m-%d').date()
            breaks_query = breaks_query.filter(start_time__date=filter_date)
        except ValueError:
            pass

    # Calculate duration for each break (in minutes), accounting for ongoing breaks
    breaks_query = breaks_query.annotate(
        duration=ExpressionWrapper(
            Coalesce(F('end_time'), timezone.now()) - F('start_time'),
            output_field=DurationField()
        )
    )

    # Convert the duration to minutes after the query
    for break_obj in breaks_query:
        if break_obj.duration:
            break_obj.duration_minutes = break_obj.duration.total_seconds() / 60
        else:
            break_obj.duration_minutes = None

    # Order breaks by start time (most recent first)
    breaks_query = breaks_query.order_by('-start_time')

    # Get available groups based on the manager's team
    groups = Group.objects.filter(user__in=project_assignments).distinct()

    # Pagination
    paginator = Paginator(breaks_query, 10)  # 10 breaks per page
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)

    # Add pagination info
    page_obj.start = (page_obj.number - 1) * paginator.per_page + 1
    page_obj.end = min(page_obj.start + paginator.per_page - 1, paginator.count)
    page_obj.total = paginator.count

    # Define break types
    break_types = [
        'Tea Break (10 mins)',
        'Lunch/Dinner Break (30 mins)',
        'Tea Break (15 mins)'
    ]

    # Add role-specific data for managers
    context = {
        'breaks': page_obj,
        'groups': groups,
        'break_types': break_types,
        'selected_group': group_name,
        'selected_break_type': break_type,
        'selected_date': date_str,
        'total_breaks': breaks_query.count(),
        'active_breaks': breaks_query.filter(end_time__isnull=True).count(),
    }

    return render(request, 'components/manager/break_report.html', context)


@login_required
@user_passes_test(is_manager)
def attendance_report_view_manager(request):
    """View for managers to see attendance of users assigned to their projects."""
    

    # Get the manager's assigned projects
    project_assignments = ProjectAssignment.objects.filter(
        project__projectassignment__user=request.user,
        project__projectassignment__role_in_project='Manager',
        is_active=True
    )
    
    # Get the users assigned to the manager's projects
    users_in_projects = project_assignments.values_list('user', flat=True)
    
    # Get filter parameters (optional, for filtering attendance records)
    user_filter = request.GET.get('user', '')  # Optionally filter by specific user
    date_filter = request.GET.get('date', '')  # Optionally filter by specific date

    # Start with base query for attendance
    attendance_query = Attendance.objects.filter(user__in=users_in_projects)

    # Apply filtering based on user
    if user_filter:
        attendance_query = attendance_query.filter(user__username=user_filter)

    # Apply filtering based on date
    if date_filter:
        try:
            filter_date = timezone.datetime.strptime(date_filter, '%Y-%m-%d').date()
            attendance_query = attendance_query.filter(date=filter_date)
        except ValueError:
            pass  # If date is invalid, no filtering will occur

    # Pagination for better performance
    paginator = Paginator(attendance_query, 10)  # 10 records per page
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)

    # Add pagination info
    page_obj.start = (page_obj.number - 1) * paginator.per_page + 1
    page_obj.end = min(page_obj.start + paginator.per_page - 1, paginator.count)
    page_obj.total = paginator.count

    # Add context data
    context = {
        'attendance': page_obj,
        'project_assignments': project_assignments,
        'users_in_projects': users_in_projects,
        'selected_user': user_filter,
        'selected_date': date_filter,
    }

    return render(request, 'components/manager/attendance_report.html', context)




@login_required  # Ensure the user is logged in
@user_passes_test(is_admin)  # Ensure the user is an admin
def report_view(request):
    """Main report navigation view."""
    
    # Navigation items for the report dashboard
    nav_items = [
        {
            'id': 'breaks', 
            'name': 'Break Report', 
            'icon': 'fas fa-clock',
            'description': 'View breaks taken by all users.',
            'url': reverse('aps_admin:break_report_view')  # Add URL to the nav item
        },
        {
            'id': 'attendance', 
            'name': 'Attendace Report', 
            'icon': 'fas fa-clock',
            'description': 'View attendance taken by all users.',
            'url': reverse('aps_admin:attendance')  # Add URL to the nav item
        },
        {
            'id': 'projects', 
            'name': 'Projects', 
            'icon': 'fas fa-project-diagram',
            'description': 'Detailed overview of ongoing and completed projects.',
        },
        {
            'id': 'systemerrors', 
            'name': 'System Errors', 
            'icon': 'fas fa-exclamation-triangle',
            'description': 'Log and analyze system errors.',
        },
        {
            'id': 'systemusage', 
            'name': 'System Usage', 
            'icon': 'fas fa-desktop',
            'description': 'Track system performance metrics and user activity.',
        },
    ]
    
    # Additional sections for the report dashboard
    sections = [
        {
            "title": "Break Report",
            "description": "This section allows you to view all the breaks taken by users.",
            "content": "You can filter the breaks by group, break type, and date.",
            "link": "/aps/reports/breaks/",  # Link to the break report page
        },
        {
            "title": "Attendace Report",
            "description": "This section provides insights into how features are being used within the platform.",
            "content": "Coming soon...",
        },
        {
            "title": "Projects Report",
            "description": "Detailed overview of all ongoing and completed projects.",
            "content": "Coming soon...",
        },
        {
            "title": "System Errors",
            "description": "Log and analyze system errors to ensure smooth platform performance.",
            "content": "Coming soon...",
        },
        {
            "title": "System Usage",
            "description": "Track overall system usage, including performance metrics and user activity.",
            "content": "Coming soon...",
        },
    ]
    
    return render(request, 'components/admin/report.html', {'nav_items': nav_items, 'sections': sections})

# View for Feature Usage Information

from django.utils import timezone

@login_required
@user_passes_test(is_admin)
def admin_attendance_view(request):
    # Filter parameters
    username_filter = request.GET.get('username', '')
    status_filter = request.GET.get('status', '')
    date_filter = request.GET.get('date', '')
    date_range_start = request.GET.get('start_date', '')
    date_range_end = request.GET.get('end_date', '')

    # Query attendance records
    attendance_summary = Attendance.objects.all()

    if username_filter:
        attendance_summary = attendance_summary.filter(user__username__icontains=username_filter)
    if status_filter:
        attendance_summary = attendance_summary.filter(status=status_filter)
    if date_filter:
        try:
            date_obj = timezone.datetime.strptime(date_filter, '%Y-%m-%d').date()
            attendance_summary = attendance_summary.filter(date=date_obj)
        except ValueError:
            pass
    if date_range_start and date_range_end:
        try:
            start_date = timezone.datetime.strptime(date_range_start, '%Y-%m-%d').date()
            end_date = timezone.datetime.strptime(date_range_end, '%Y-%m-%d').date()
            attendance_summary = attendance_summary.filter(date__range=[start_date, end_date])
        except ValueError:
            pass

    # Fetch necessary fields and apply timezone conversion for clock-in/out times
    attendance_summary = attendance_summary.values(
        'user', 'user__first_name', 'user__last_name', 'user__username', 'status', 'date', 'total_hours', 
        'clock_in_time', 'clock_out_time'
    ).order_by('-date')

    # Applying timezone conversion
    for record in attendance_summary:
        if record['clock_in_time']:
            # Convert clock_in_time to local time zone
            record['clock_in_time'] = timezone.localtime(record['clock_in_time'])
        if record['clock_out_time']:
            # Convert clock_out_time to local time zone
            record['clock_out_time'] = timezone.localtime(record['clock_out_time'])

    # Pagination
    paginator = Paginator(attendance_summary, 10)
    page = request.GET.get('page', 1)

    try:
        summary_records = paginator.get_page(page)
    except EmptyPage:
        summary_records = paginator.page(paginator.num_pages)
    except PageNotAnInteger:
        summary_records = paginator.page(1)

    return render(request, 'components/admin/attendance_report.html', {
        'summary': summary_records,
        'username_filter': username_filter,
        'status_filter': status_filter,
        'date_filter': date_filter,
        'date_range_start': date_range_start,
        'date_range_end': date_range_end,
    })


@login_required
@user_passes_test(is_admin)
def feature_usage_view(request):
    """View to display feature usage details."""
    try:
        feature_usages = FeatureUsage.objects.all().order_by('-usage_count')
        return render(request, 'components/admin/reports/feature_usage.html', {'feature_usages': feature_usages})

    except Exception as e:
        messages.error(request, f"An error occurred while fetching feature usage data: {str(e)}")
        return redirect('dashboard')


@login_required
@user_passes_test(is_admin)
def projects_report_view(request):
    """View to display projects report."""
    return render(request, 'components/admin/reports/projects_report.html')

@login_required
@user_passes_test(is_admin)
def break_report_view(request):
    """View for admin to see all breaks taken by all users."""
    
    # Get filter parameters
    group_name = request.GET.get('group', '')
    break_type = request.GET.get('break_type', '')
    date_str = request.GET.get('date', '')

    # Start with all breaks - no initial filter
    breaks_query = Break.objects.select_related('user').all()

    # Apply filters only if they're provided
    if group_name:
        breaks_query = breaks_query.filter(user__groups__name=group_name)
    
    if break_type:
        breaks_query = breaks_query.filter(break_type=break_type)
    
    if date_str:
        try:
            filter_date = timezone.datetime.strptime(date_str, '%Y-%m-%d').date()
            breaks_query = breaks_query.filter(start_time__date=filter_date)
        except ValueError:
            pass

    # Calculate duration for each break
    for break_obj in breaks_query:
        if break_obj.end_time:
            duration = (break_obj.end_time - break_obj.start_time).total_seconds() / 60
            break_obj.duration = int(duration)  # Duration in minutes
        else:
            break_obj.duration = None  # If break is ongoing

    # Order breaks by start time (most recent first)
    breaks_query = breaks_query.order_by('-start_time')

    # Debug print
    print(f"Total breaks found: {breaks_query.count()}")
    for break_obj in breaks_query:
        print(f"Break: {break_obj.id}, User: {break_obj.user}, Type: {break_obj.break_type}")

    # Pagination
    paginator = Paginator(breaks_query, 10)  # 10 breaks per page
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)

    # Add pagination info
    page_obj.start = (page_obj.number - 1) * paginator.per_page + 1
    page_obj.end = min(page_obj.start + paginator.per_page - 1, paginator.count)
    page_obj.total = paginator.count

    # Get all groups for the filter dropdown
    groups = Group.objects.all()
    
    # Debug print groups
    print(f"Available groups: {[group.name for group in groups]}")

    # Define break types
    break_types = [
        'Tea Break (10 mins)',
        'Lunch/Dinner Break (30 mins)',
        'Tea Break (15 mins)'
    ]

    context = {
        'breaks': page_obj,
        'groups': groups,
        'break_types': break_types,
        'selected_group': group_name,
        'selected_break_type': break_type,
        'selected_date': date_str,
    }

    return render(request, 'components/admin/break_report.html', context)

@login_required
@user_passes_test(is_admin)
def system_error_view(request):
    """View to display system errors."""
    try:
        system_errors = SystemError.objects.all().order_by('-error_time')
        return render(request, 'components/admin/reports/system_error.html', {'system_errors': system_errors})

    except Exception as e:
        messages.error(request, f"An error occurred while fetching system errors: {str(e)}")
        return redirect('dashboard')


@login_required
@user_passes_test(is_admin)
def system_usage_view(request):
    """View to display system usage details."""
    try:
        system_usages = SystemUsage.objects.all().order_by('-peak_time_start')
        return render(request, 'components/admin/reports/system_usage.html', {'system_usages': system_usages})

    except Exception as e:
        messages.error(request, f"An error occurred while fetching system usage data: {str(e)}")
        return redirect('dashboard')
    
    
''' -------------- usersession ---------------'''
from django.db.models import Count, Min, Max, Sum, Case, When, BooleanField, Avg, F, Q
from django.db.models.functions import Coalesce, ExtractHour
from datetime import datetime, date, timedelta
from django.utils import timezone
from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from .models import UserSession, User
from django.core.paginator import Paginator
import logging
import json

logger = logging.getLogger(__name__)
@login_required
@user_passes_test(is_admin)
def user_sessions_view(request):
    """
    Enhanced view to display user sessions with advanced filtering, analytics and insights
    for tracking employee productivity.
    """
    try:
        # Advanced filtering parameters with defaults
        filters = {
            'username': request.GET.get('username', ''),
            'date_from': request.GET.get('date_from', ''),
            'date_to': request.GET.get('date_to', ''),
            'location': request.GET.get('location', ''),
            'status': request.GET.get('status', ''),
            'min_hours': request.GET.get('min_hours', ''),
            'max_hours': request.GET.get('max_hours', ''),
            'idle_threshold': request.GET.get('idle_threshold', ''),
            'ip_address': request.GET.get('ip_address', '')
        }

        # Base queryset with select_related for performance
        sessions = UserSession.objects.select_related('user').all()

        # Build complex filter conditions
        filter_conditions = Q()
        
        # Advanced username/user filtering
        if filters['username']:
            filter_conditions &= (
                Q(user__username__icontains=filters['username']) | 
                Q(user__first_name__icontains=filters['username']) | 
                Q(user__last_name__icontains=filters['username']) |
                Q(user__email__icontains=filters['username'])
            )

        # Date range filtering
        if filters['date_from'] or filters['date_to']:
            try:
                date_from = None
                date_to = None
                
                if filters['date_from']:
                    date_from = datetime.strptime(filters['date_from'], "%Y-%m-%d")
                if filters['date_to']:
                    date_to = datetime.strptime(filters['date_to'], "%Y-%m-%d") + timedelta(days=1)
                
                if date_from and date_to:
                    filter_conditions &= (
                        Q(login_time__range=[date_from, date_to]) |
                        Q(logout_time__range=[date_from, date_to])
                    )
                elif date_from:
                    filter_conditions &= Q(login_time__gte=date_from)
                elif date_to:
                    filter_conditions &= Q(login_time__lt=date_to)
                    
            except ValueError:
                messages.error(request, "Invalid date format. Use YYYY-MM-DD.")

        # Location filtering
        if filters['location']:
            filter_conditions &= Q(location=filters['location'])

        # Enhanced status filtering
        if filters['status']:
            if filters['status'] == 'active':
                filter_conditions &= Q(is_active=True)
            elif filters['status'] == 'inactive':
                filter_conditions &= Q(is_active=False)
            elif filters['status'] == 'idle':
                idle_threshold = timedelta(minutes=UserSession.IDLE_THRESHOLD_MINUTES)
                filter_conditions &= Q(idle_time__gt=idle_threshold)

        # Working hours range filtering
        if filters['min_hours']:
            try:
                min_hours = float(filters['min_hours'])
                min_duration = timedelta(hours=min_hours)
                filter_conditions &= Q(working_hours__gte=min_duration)
            except ValueError:
                messages.warning(request, "Invalid minimum hours value")

        if filters['max_hours']:
            try:
                max_hours = float(filters['max_hours'])
                max_duration = timedelta(hours=max_hours)
                filter_conditions &= Q(working_hours__lte=max_duration)
            except ValueError:
                messages.warning(request, "Invalid maximum hours value")

        # Idle time threshold filtering
        if filters['idle_threshold']:
            try:
                idle_mins = float(filters['idle_threshold'])
                idle_duration = timedelta(minutes=idle_mins)
                filter_conditions &= Q(idle_time__gte=idle_duration)
            except ValueError:
                messages.warning(request, "Invalid idle threshold value")

        # IP address filtering
        if filters['ip_address']:
            filter_conditions &= Q(ip_address__icontains=filters['ip_address'])

        # Apply all filters
        sessions = sessions.filter(filter_conditions).order_by('-login_time')
        
        # Pagination
        paginator = Paginator(sessions, 20)  # Show 20 sessions per page
        page_number = request.GET.get('page', 1)
        page_obj = paginator.get_page(page_number)
        
        # Calculate analytics for all matching sessions
        total_sessions = sessions.count()
        
        # Location distribution
        location_distribution = dict(sessions.values('location')
                                    .annotate(count=Count('id'))
                                    .values_list('location', 'count'))
        
        # Calculate average working hours and idle time
        avg_working_hours = sessions.exclude(working_hours=None).aggregate(
            avg=Coalesce(Avg('working_hours'), timedelta())
        )['avg']
        
        avg_idle_time = sessions.aggregate(
            avg=Coalesce(Avg('idle_time'), timedelta())
        )['avg']
        
        # Get peak activity hours
        peak_hours = sessions.annotate(
            hour=ExtractHour('login_time')
        ).values('hour').annotate(count=Count('id')).order_by('-count')[:3]
        
        # Get most productive users
        productive_users = sessions.values('user__username').annotate(
            total_working_hours=Sum('working_hours'),
            avg_idle_time=Avg('idle_time')
        ).order_by('-total_working_hours')[:5]
        
        # Consolidate sessions by user and date
        daily_user_sessions = consolidate_daily_sessions(page_obj)

        # Prepare context with enhanced options
        context = {
            'sessions': page_obj,
            'daily_sessions': daily_user_sessions,
            'filters': filters,
            'analytics': {
                'total_sessions': total_sessions,
                'active_sessions': sessions.filter(is_active=True).count(),
                'avg_working_hours': avg_working_hours.total_seconds() / 3600 if avg_working_hours else 0,
                'avg_idle_time': avg_idle_time.total_seconds() / 3600 if avg_idle_time else 0,
                'location_distribution': location_distribution,
                'peak_hours': peak_hours,
                'productive_users': productive_users
            },
            'location_choices': UserSession.OFFICE_IPS + ['Home', 'Unknown'],
            'status_choices': [
                ('active', 'Active'), 
                ('inactive', 'Inactive'),
                ('idle', 'Idle')
            ],
            'idle_thresholds': [
                (UserSession.IDLE_THRESHOLD_MINUTES, f'{UserSession.IDLE_THRESHOLD_MINUTES} minutes'),
                (UserSession.SESSION_TIMEOUT_MINUTES, f'{UserSession.SESSION_TIMEOUT_MINUTES} minutes'),
                (60, '1 hour')
            ]
        }

        return render(request, 'components/admin/user_sessions.html', context)

    except Exception as e:
        logger.error(f"Error in user_sessions_view: {str(e)}", exc_info=True)
        messages.error(request, f"An error occurred while processing your request: {str(e)}")
        return redirect('dashboard')

def consolidate_daily_sessions(sessions):
    """
    Consolidate user sessions by user and date to provide a comprehensive view
    of daily productivity metrics.
    """
    daily_sessions = {}
    
    for session in sessions:
        # Use login date as the key date
        if not session.login_time:
            continue
            
        session_date = session.get_login_time_local().date()
        user_key = (session.user.id, session_date)

        if user_key not in daily_sessions:
            daily_sessions[user_key] = {
                'user': session.user,
                'date': session_date,
                'sessions': [],
                'first_login': None,
                'last_logout': None,
                'total_working_hours': timedelta(),
                'total_idle_time': timedelta(),
                'locations': set(),
                'ip_addresses': set(),
                'session_count': 0,
                'is_active': False
            }

        # Add session data
        daily_sessions[user_key]['sessions'].append(session)
        daily_sessions[user_key]['session_count'] += 1
        
        # Update first login time using local time
        login_time_local = session.get_login_time_local()
        if login_time_local and (daily_sessions[user_key]['first_login'] is None or 
                                login_time_local < daily_sessions[user_key]['first_login']):
            daily_sessions[user_key]['first_login'] = login_time_local
        
        # Update last logout time using local time
        logout_time_local = session.get_logout_time_local()
        if logout_time_local and (daily_sessions[user_key]['last_logout'] is None or 
                                 logout_time_local > daily_sessions[user_key]['last_logout']):
            daily_sessions[user_key]['last_logout'] = logout_time_local
        
        # Add working hours and idle time
        if session.working_hours:
            daily_sessions[user_key]['total_working_hours'] += session.working_hours
        
        if session.idle_time:
            daily_sessions[user_key]['total_idle_time'] += session.idle_time
        
        # Add location and IP
        if session.location:
            daily_sessions[user_key]['locations'].add(session.location)
        
        if session.ip_address:
            daily_sessions[user_key]['ip_addresses'].add(session.ip_address)
        
        # Check if any session is active
        if session.is_active:
            daily_sessions[user_key]['is_active'] = True

    # Process the consolidated data for display
    result = []
    for data in daily_sessions.values():
        # Calculate productivity score
        total_duration = data['total_working_hours'] + data['total_idle_time']
        if total_duration > timedelta():
            productivity_score = (data['total_working_hours'].total_seconds() / total_duration.total_seconds()) * 100
        else:
            productivity_score = 0
            
        # Calculate total duration in hours
        if data['first_login']:
            end_time = data['last_logout'] or timezone.localtime(timezone.now())
            total_duration = (end_time - data['first_login']).total_seconds() / 3600
        else:
            total_duration = 0
            
        # Format data for template with hours
        result.append({
            'user': data['user'],
            'date': data['date'],
            'first_login': data['first_login'],
            'last_logout': data['last_logout'] or timezone.localtime(timezone.now()) if data['is_active'] else data['last_logout'],
            'total_working_hours': data['total_working_hours'].total_seconds() / 3600,
            'total_idle_time': data['total_idle_time'].total_seconds() / 3600,
            'locations': list(data['locations']),
            'ip_addresses': list(data['ip_addresses']),
            'session_count': data['session_count'],
            'is_active': data['is_active'],
            'productivity_score': round(productivity_score, 1),
            'total_duration': round(total_duration, 1)
        })
    
    # Sort by date (newest first) and then by username
    return sorted(result, key=lambda x: (x['date'], x['user'].username), reverse=True)

@login_required
@user_passes_test(is_admin)
def user_session_detail_view(request, user_id, date_str):
    """
    Detailed view of a user's sessions for a specific date.
    Shows session timeline and productivity metrics.
    """
    try:
        # Parse date and get user, with validation
        try:
            date_obj = datetime.strptime(date_str, "%Y-%m-%d").date()
            user = User.objects.get(id=user_id)
            print(f"User: {user.username} (ID: {user_id})")
            print(f"Date: {date_str}")
            logger.debug(f"Looking for sessions for user ID {user_id} ({user.username}) on {date_str}")
        except (ValueError, User.DoesNotExist) as e:
            logger.error(f"Invalid date format or user not found: {str(e)}")
            messages.error(request, "Invalid date format or user not found")
            return redirect('aps_admin:user_sessions')

        # Debug: Check all sessions for this user
        debug_sessions = UserSession.objects.filter(user=user)
        print(f"Total sessions for user: {debug_sessions.count()}")
        logger.debug(f"All sessions for user {user.username}: {debug_sessions.count()}")
        if debug_sessions.exists():
            recent = debug_sessions.order_by('-login_time').first()
            print(f"Most recent session: {recent.get_login_time_local()}")
            print(f"Working hours: {recent.get_total_working_hours_display()}")
            print(f"Idle time: {recent.idle_time}")
            logger.debug(f"Most recent session: {recent.get_login_time_local()} - Working: {recent.get_total_working_hours_display()}, Idle: {recent.idle_time}")

        # Get timezone-aware date range for the specific date
        tz = timezone.get_current_timezone()
        start_date = datetime.combine(date_obj, datetime.min.time(), tzinfo=tz)
        end_date = datetime.combine(date_obj + timedelta(days=1), datetime.min.time(), tzinfo=tz)

        # Get all sessions for this user on this date
        sessions = UserSession.objects.filter(
            user=user,
            login_time__gte=start_date,
            login_time__lt=end_date
        ).order_by('login_time')

        print(f"Sessions found for date {date_str}: {sessions.count()}")
        logger.debug(f"Found {sessions.count()} sessions for date {date_str}")
        
        if sessions.count() == 0:
            all_user_sessions = UserSession.objects.filter(user=user).count()
            print(f"Total sessions across all dates: {all_user_sessions}")
            logger.debug(f"User has {all_user_sessions} total sessions across all dates")

        # Initialize totals
        total_working_hours = timedelta()
        total_idle_time = timedelta()
        current_time = timezone.now()
        processed_sessions = []

        # Process each session
        for session in sessions:
            # Get working and idle hours, defaulting to 0 if None
            working_hours = session.working_hours or timedelta()
            idle_time = session.idle_time or timedelta()

            print(f"\nSession details:")
            print(f"Login time: {session.get_login_time_local()}")
            print(f"Logout time: {session.get_logout_time_local()}")
            print(f"Working hours: {session.get_total_working_hours_display()}")
            print(f"Idle time: {idle_time}")
            print(f"Location: {session.location or 'Unknown'}")
            print(f"IP Address: {session.ip_address or 'Unknown'}")
            print(f"Active: {session.is_active}")

            # For active sessions, calculate current working/idle time
            if session.is_active:
                # Calculate time since last activity
                time_since_last = current_time - session.last_activity
                print(f"Time since last activity: {time_since_last}")
                
                # Calculate session duration so far
                current_duration = current_time - session.login_time
                
                # Add to idle time if exceeds threshold
                current_idle = idle_time
                if time_since_last > timedelta(minutes=session.IDLE_THRESHOLD_MINUTES):
                    current_idle = idle_time + time_since_last
                    print(f"Additional idle time: {time_since_last}")
                
                # Calculate current working hours
                current_working = current_duration - current_idle
                
                # Use these calculated values
                working_hours = current_working
                idle_time = current_idle
                
                print(f"Current duration: {current_duration}")
                print(f"Current working hours: {working_hours}")
                print(f"Current idle time: {idle_time}")

            # Add to running totals
            total_working_hours += working_hours
            total_idle_time += idle_time

            # Create session object with all required fields
            processed_session = {
                'login_time': session.get_login_time_local(),
                'logout_time': session.get_logout_time_local() or timezone.localtime(current_time),  # Use current time for active sessions
                'working_hours': working_hours,
                'idle_time': idle_time,
                'location': session.location or 'Unknown',
                'ip_address': session.ip_address or 'Unknown',
                'is_active': session.is_active,
                # Add formatted display versions
                'working_hours_display': format_timedelta(working_hours),
                'idle_time_display': format_timedelta(idle_time),
            }
            processed_sessions.append(processed_session)

        # Debug processed sessions
        print(f"\nProcessed sessions summary:")
        print(f"Total sessions processed: {len(processed_sessions)}")
        logger.debug(f"Sessions being sent to template: {len(processed_sessions)}")
        for i, s in enumerate(processed_sessions):
            print(f"\nSession {i+1}:")
            print(f"Login: {s['login_time']}")
            print(f"Working hours: {s['working_hours']}")
            print(f"Idle time: {s['idle_time']}")
            print(f"Location: {s['location']}")
            print(f"IP Address: {s['ip_address']}")
            print(f"Active: {s['is_active']}")
            logger.debug(f"Session {i+1}: Login {s['login_time']}, Working: {s['working_hours']}")

        # Calculate productivity score
        total_duration = total_working_hours + total_idle_time
        if total_duration > timedelta():
            productivity_score = (total_working_hours.total_seconds() / total_duration.total_seconds()) * 100
        else:
            productivity_score = 0

        print(f"\nFinal Summary:")
        print(f"Total working hours: {total_working_hours.total_seconds() / 3600:.2f} hours")
        print(f"Total idle time: {total_idle_time.total_seconds() / 3600:.2f} hours") 
        print(f"Productivity score: {round(productivity_score, 1)}%")

        context = {
            'user': user,
            'date': date_obj,
            'sessions': processed_sessions,
            'total_working_hours': total_working_hours.total_seconds() / 3600,
            'total_idle_time': total_idle_time.total_seconds() / 3600,
            'total_working_hours_display': format_timedelta(total_working_hours),
            'total_idle_time_display': format_timedelta(total_idle_time),
            'productivity_score': round(productivity_score, 1)
        }

        print("\nContext data being sent to template:")
        print(context)

        return render(request, 'components/admin/user_session_detail.html', context)

    except Exception as e:
        logger.error(f"Error in user_session_detail_view: {str(e)}", exc_info=True)
        messages.error(request, "An error occurred while processing the request")
        return redirect('aps_admin:user_sessions')


def format_timedelta(td):
    """Format a timedelta into a human-friendly string (e.g., '2h 45m')"""
    total_seconds = td.total_seconds()
    hours = int(total_seconds // 3600)
    minutes = int((total_seconds % 3600) // 60)
    
    if hours > 0:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"

def calculate_productivity_score(working_hours, idle_time):
    """Calculate productivity score based on working hours and idle time"""
    total_duration = working_hours + idle_time
    if total_duration <= timedelta():
        return 0
        
    productivity = (working_hours.total_seconds() / total_duration.total_seconds()) * 100
    return min(round(productivity, 1), 100)





''' ---------------------------------------- TIMESHEET AREA ---------------------------------------- '''
@login_required
@user_passes_test(is_employee)  # Only allow employees to access this view
def timesheet_view(request):
    if request.method == "POST":
        try:
            # Get the submitted data from the form
            week_start_date = request.POST.get('week_start_date')
            project_ids = request.POST.getlist('project_id[]')
            task_names = request.POST.getlist('task_name[]')
            task_descriptions = request.POST.getlist('task_description[]')
            hours = request.POST.getlist('hours[]')

            # Validate that all lists are the same length
            if len(project_ids) != len(task_names) or len(task_names) != len(hours) or len(task_descriptions) != len(hours):
                messages.error(request, "All form fields should have the same number of entries.")
                return redirect('aps_employee:timesheet')

            # Create the Timesheet objects and save them to the database
            for project_id, task_name, task_description, hour in zip(project_ids, task_names, task_descriptions, hours):
                try:
                    # Convert hours to float and validate
                    hours_float = float(hour)
                    
                    # Get the project
                    project = Project.objects.get(id=project_id)
                    
                    # Create new timesheet entry
                    timesheet = Timesheet(
                        user=request.user,
                        week_start_date=week_start_date,
                        project=project,
                        task_name=task_name,
                        task_description=task_description,
                        hours=hours_float
                    )
                    
                    # This will run the clean method which validates hours limits
                    timesheet.save()
                    
                except ValidationError as ve:
                    messages.error(request, f"Validation error: {str(ve)}")
                    return redirect('aps_employee:timesheet')
                except Project.DoesNotExist:
                    messages.error(request, f"Project with ID {project_id} does not exist.")
                    return redirect('aps_employee:timesheet')

            # Display success message
            messages.success(request, "Timesheet submitted successfully!")
            return redirect('aps_employee:timesheet')

        except Exception as e:
            # If an error occurs, show an error message
            messages.error(request, f"An error occurred: {str(e)}")
            return redirect('aps_employee:timesheet')

    else:
        # If it's a GET request, show the current timesheet history
        today = timezone.now().date()
        
        # Calculate the start of the current week (Monday)
        current_week_start = today - timedelta(days=today.weekday())

        # Fetch the timesheet history for the logged-in employee, ordered by week start date and version
        timesheet_history = Timesheet.objects.filter(user=request.user).order_by('-week_start_date', '-version')

        # Fetch the list of projects the user is assigned to using the ProjectAssignment model
        assigned_projects = Project.objects.filter(projectassignment__user=request.user, projectassignment__is_active=True)

        # Get weekly hours summary
        week_end_date = current_week_start + timedelta(days=6)
        weekly_hours = Timesheet.objects.filter(
            user=request.user,
            week_start_date__gte=current_week_start,
            week_start_date__lte=week_end_date
        ).aggregate(total_hours=Sum('hours'))['total_hours'] or 0
        
        remaining_hours = 45 - weekly_hours  # Updated to 45 hours weekly limit

        # Render the timesheet page with the data
        return render(request, 'components/employee/timesheet.html', {
            'today': today,
            'current_week_start': current_week_start,
            'timesheet_history': timesheet_history,
            'assigned_projects': assigned_projects,
            'weekly_hours': weekly_hours,
            'remaining_hours': remaining_hours
        })

@login_required
@user_passes_test(is_employee)
def get_timesheet_details(request, week_start_date):
    """
    View to get detailed timesheet information for a specific week.
    Returns JSON data for AJAX requests to populate the timesheet modal.
    """
    try:
        # Try to parse the date with multiple possible formats
        start_date = None
        date_formats = ['%Y-%m-%d', '%B %d, %Y', '%m/%d/%Y', '%d-%m-%Y']
        
        for date_format in date_formats:
            try:
                start_date = timezone.datetime.strptime(week_start_date, date_format).date()
                break
            except ValueError:
                continue
        
        if start_date is None:
            raise ValueError(f"Could not parse date '{week_start_date}' with any supported format")
        
        # Get all timesheet entries for the specified week
        timesheet_entries = Timesheet.objects.filter(
            user=request.user,
            week_start_date=start_date
        ).select_related('project')
        
        if not timesheet_entries.exists():
            return JsonResponse({
                'success': False,
                'message': 'No timesheet entries found for this week.'
            })
        
        # Format the data for the response
        entries_data = []
        total_hours = 0
        
        for entry in timesheet_entries:
            entries_data.append({
                'id': entry.id,
                'project_name': entry.project.name,
                'project_id': entry.project.id,
                'task_name': entry.task_name,
                'task_description': entry.task_description,
                'hours': entry.hours,
                'approval_status': entry.approval_status,
                'comments': entry.manager_comments or '',
                'submitted_at': entry.submitted_at.isoformat() if hasattr(entry, 'submitted_at') else None,
                'last_modified': entry.reviewed_at.isoformat() if hasattr(entry, 'reviewed_at') else None
            })
            total_hours += entry.hours
        
        # Return the formatted data
        return JsonResponse({
            'success': True,
            'week_start': start_date.strftime('%Y-%m-%d'),
            'week_end': (start_date + timedelta(days=6)).strftime('%Y-%m-%d'),
            'total_hours': total_hours,
            'entries': entries_data
        })
        
    except Exception as e:
        logger.error(f"Error retrieving timesheet details: {str(e)}")
        return JsonResponse({
            'success': False,
            'message': f"An error occurred: {str(e)}"
        })

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from .models import Timesheet, Project, ProjectAssignment
from django.db.models import Sum, Count, Q
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from datetime import timedelta
from django.http import JsonResponse
import logging
logger = logging.getLogger(__name__)

@login_required
@user_passes_test(is_manager)
def manager_view_timesheets(request):
    """
    View for managers to review and manage timesheets for their projects.
    Includes filtering, search, and pagination functionality.
    """
    # Get filter parameters from request
    time_filter = request.GET.get('time-filter', '7')
    search_query = request.GET.get('search', '')
    
    # Default to 7 days if custom filter not specified
    if time_filter != 'custom':
        filter_days = int(time_filter)
        start_date = timezone.now().date() - timedelta(days=filter_days)
    else:
        # Handle custom date range if implemented
        start_date_str = request.GET.get('start_date')
        end_date_str = request.GET.get('end_date')
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        except (ValueError, TypeError):
            start_date = timezone.now().date() - timedelta(days=30)  # Default fallback

    # Get projects managed by the current user
    managed_projects = Project.objects.filter(
        projectassignment__user=request.user, 
        projectassignment__role_in_project='Manager', 
        projectassignment__is_active=True
    ).distinct()
    
    managed_project_ids = managed_projects.values_list('id', flat=True)

    # Base queryset with prefetching for optimization
    timesheets = Timesheet.objects.select_related('project', 'user').filter(
        project_id__in=managed_project_ids
    )
    
    # Apply date filter
    timesheets = timesheets.filter(week_start_date__gte=start_date)

    # Apply search filter if provided
    if search_query:
        timesheets = timesheets.filter(
            Q(user__first_name__icontains=search_query) |
            Q(user__last_name__icontains=search_query) |
            Q(project__name__icontains=search_query) |
            Q(task_name__icontains=search_query) |
            Q(task_description__icontains=search_query)
        )

    # Calculate dashboard statistics
    total_hours = timesheets.aggregate(Sum('hours'))['hours__sum'] or 0
    active_projects = timesheets.values('project').distinct().count()
    pending_approvals = timesheets.filter(approval_status='Pending').count()
    completion_rate = calculate_completion_rate(timesheets)

    # Group timesheets by status for easier filtering in the template
    status_counts = {
        'pending': timesheets.filter(approval_status='Pending').count(),
        'approved': timesheets.filter(approval_status='Approved').count(),
        'rejected': timesheets.filter(approval_status='Rejected').count(),
        'clarification': timesheets.filter(approval_status='Clarification_Requested').count()
    }

    # Order by most recent first, then by employee name
    timesheets = timesheets.order_by('-week_start_date', 'user__first_name')
    
    # Paginate results
    paginator = Paginator(timesheets, 20)  # 20 items per page
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)

    # Prepare context for template
    context = {
        'page_obj': page_obj,
        'total_hours': total_hours,
        'active_projects': active_projects,
        'completion_rate': completion_rate,
        'pending_approvals': pending_approvals,
        'time_filter': time_filter,
        'search_query': search_query,
        'status_counts': status_counts,
        'managed_projects': managed_projects,
    }

    return render(request, 'components/manager/view_timesheets.html', context)


@login_required
@user_passes_test(is_manager)
def bulk_update_timesheet(request):
    """
    Handle bulk actions on timesheets (approve, reject, request clarification).
    Only allows managers to update timesheets for projects they manage.
    """
    if request.method != 'POST':
        messages.error(request, 'Invalid request method')
        return redirect('aps_manager:view_timesheets')

    # Get parameters from request
    timesheet_ids = request.POST.getlist('selected_timesheets[]')
    action = request.POST.get('action')
    rejection_reason = request.POST.get('rejection_reason')
    manager_comments = request.POST.get('manager_comments', '')

    # Validate input
    if not timesheet_ids:
        messages.error(request, 'No timesheets selected')
        return redirect('aps_manager:view_timesheets')

    if action not in ['approve', 'reject', 'request_clarification']:
        messages.error(request, 'Invalid action')
        return redirect('aps_manager:view_timesheets')

    # Map action to status
    status_map = {
        'approve': 'Approved',
        'reject': 'Rejected',
        'request_clarification': 'Clarification_Requested'
    }

    try:
        # Get projects managed by the current user
        managed_projects = Project.objects.filter(
            projectassignment__user=request.user, 
            projectassignment__role_in_project='Manager', 
            projectassignment__is_active=True
        ).values_list('id', flat=True)

        # Restrict timesheets to manager's projects
        timesheets = Timesheet.objects.filter(
            id__in=timesheet_ids,
            project_id__in=managed_projects
        )

        if not timesheets.exists():
            messages.error(request, 'You are not authorized to update the selected timesheets')
            return redirect('aps_manager:view_timesheets')

        # Validate rejection reason if rejecting
        if action == 'reject' and not rejection_reason:
            messages.error(request, 'Rejection reason is required')
            return redirect('aps_manager:view_timesheets')

        # Update timesheets
        update_count = 0
        for timesheet in timesheets:
            timesheet.approval_status = status_map[action]
            
            if action == 'reject':
                timesheet.rejection_reason = rejection_reason
            
            if manager_comments:
                timesheet.manager_comments = manager_comments
                
            # reviewed_at will be updated by the signal
            timesheet.save()
            update_count += 1

        # Create success message based on action
        action_display = 'approved' if action == 'approve' else 'rejected' if action == 'reject' else 'requested clarification for'
        messages.success(request, f'Successfully {action_display} {update_count} timesheet{"s" if update_count != 1 else ""}.')
        
        return redirect('aps_manager:view_timesheets')
    except Exception as e:
        logger.error(f"Error processing timesheets: {e}", exc_info=True)
        messages.error(request, f"An error occurred: {str(e)}")
        return redirect('aps_manager:view_timesheets')


@login_required
@user_passes_test(is_manager)
def timesheet_detail(request, timesheet_id):
    """
    View a single timesheet in detail, with history of previous versions.
    Only accessible to managers of the project.
    """
    try:
        # Get the timesheet with related data
        timesheet = Timesheet.objects.select_related('user', 'project').get(id=timesheet_id)
        
        # Check if user is manager of this project
        is_project_manager = ProjectAssignment.objects.filter(
            user=request.user,
            project=timesheet.project,
            role_in_project='Manager',
            is_active=True
        ).exists()
        
        if not is_project_manager:
            messages.error(request, "You don't have permission to view this timesheet.")
            return redirect('aps_manager:view_timesheets')
        
        # Get version history if this is a resubmission
        version_history = []
        if timesheet.original_submission_id:
            version_history = Timesheet.objects.filter(
                Q(id=timesheet.original_submission_id) | 
                Q(original_submission_id=timesheet.original_submission_id)
            ).order_by('version')
        
        context = {
            'timesheet': timesheet,
            'version_history': version_history
        }
        
        return render(request, 'components/manager/timesheet_detail.html', context)
        
    except Timesheet.DoesNotExist:
        messages.error(request, "Timesheet not found.")
        return redirect('aps_manager:view_timesheets')


def calculate_completion_rate(timesheets):
    """Calculate the percentage of approved timesheets."""
    total_count = timesheets.count()
    if total_count == 0:
        return 0

    approved_count = timesheets.filter(approval_status='Approved').count()
    completion_rate = (approved_count / total_count) * 100
    return round(completion_rate, 1)


''' ---------------------------------------- LEAVE AREA ---------------------------------------- '''
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import Http404
from .models import Leave
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Leave
from django.contrib.auth.decorators import login_required, user_passes_test
from datetime import datetime
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Leave
from django.contrib.auth.decorators import login_required, user_passes_test
from datetime import datetime

@login_required
@user_passes_test(lambda u: is_employee(u) or is_hr(u))  # Allow both employees and HR
def leave_view(request):
    """Handle multiple leave functionalities on one page."""
    # Get current year for filtering
    year = timezone.now().year
    
    try:
        # Get detailed leave balance info
        leave_balance = Leave.get_leave_balance(request.user)
        
        # Get all leave requests for the current user
        leave_requests = Leave.objects.filter(user=request.user).order_by('-created_at')

    except Exception as e:
        logger.error(f"Error calculating leave balance for user {request.user.username}: {str(e)}")
        logger.error(f"Full exception traceback:", exc_info=True)
        
        # Set default values if error occurs
        leave_balance = {
            'total_leaves': 0,
            'used_leaves': 0,
            'comp_off': 0,
            'loss_of_pay': 0
        }
        leave_requests = Leave.objects.none()
        messages.error(request, "Unable to calculate leave balance. Please contact HR.")

    # Handle leave request submission
    if request.method == 'POST' and 'request_leave' in request.POST:
        try:
            # Parse dates
            start_date = datetime.strptime(request.POST.get('start_date'), '%Y-%m-%d').date()
            end_date = datetime.strptime(request.POST.get('end_date'), '%Y-%m-%d').date()

            # Get half_day value properly from form
            half_day = request.POST.get('half_day') == 'true'

            # Get leave type with default
            leave_type = request.POST.get('leave_type')
            if not leave_type:
                messages.error(request, "Leave type is required")
                return redirect('aps_employee:leave_view')

            # Create new leave request
            leave = Leave(
                user=request.user,
                leave_type=leave_type,
                start_date=start_date,
                end_date=end_date,
                reason=request.POST.get('reason'),
                half_day=half_day,
                documentation=request.FILES.get('documentation')
            )

            # Auto convert leave type based on balance
            try:
                leave.auto_convert_leave_type()
            except Exception as e:
                messages.error(request, f"Error converting leave type: {str(e)}")
                return redirect('aps_employee:leave_view')

            # Run validations and save
            leave.full_clean()
            leave.save()

            messages.success(request, "Leave request submitted successfully.")
            return redirect('aps_employee:leave_view')

        except ValidationError as e:
            messages.error(request, str(e))
        except ValueError as e:
            messages.error(request, "Invalid date format")
        except Exception as e:
            messages.error(request, f"Error submitting leave request: {str(e)}")
        return redirect('aps_employee:leave_view')

    # Handle leave request updates
    if request.method == 'POST' and 'edit_leave' in request.POST:
        try:
            leave = Leave.objects.get(id=request.POST.get('leave_id'), user=request.user)
            
            if leave.status != 'Pending':
                messages.error(request, "Only pending leave requests can be edited.")
                return redirect('aps_employee:leave_view')

            # Update leave details
            leave.start_date = datetime.strptime(request.POST.get('start_date'), '%Y-%m-%d').date()
            leave.end_date = datetime.strptime(request.POST.get('end_date'), '%Y-%m-%d').date()
            leave.reason = request.POST.get('reason')
            leave.half_day = request.POST.get('half_day') == 'true'
            
            if 'documentation' in request.FILES:
                leave.documentation = request.FILES['documentation']

            # Auto convert leave type based on updated dates
            leave.auto_convert_leave_type()

            # Validate and save
            leave.full_clean()
            leave.save()
            
            messages.success(request, "Leave request updated successfully.")
            return redirect('aps_employee:leave_view')

        except (ValidationError, Leave.DoesNotExist) as e:
            messages.error(request, str(e))
        except Exception as e:
            messages.error(request, f"Error updating leave request: {str(e)}")
        return redirect('aps_employee:leave_view')

    # Handle leave cancellation
    if request.method == 'POST' and 'delete_leave' in request.POST:
        try:
            leave = Leave.objects.get(id=request.POST.get('leave_id'), user=request.user)
            
            if leave.status not in ['Pending', 'Approved']:
                messages.error(request, "This leave request cannot be cancelled.")
                return redirect('aps_employee:leave_view')

            leave.status = 'Cancelled'
            leave.save()
            
            messages.success(request, "Leave request cancelled successfully.")
            return redirect('aps_employee:leave_view')

        except Leave.DoesNotExist:
            messages.error(request, "Leave request not found.")
        except Exception as e:
            messages.error(request, f"Error cancelling leave request: {str(e)}")
        return redirect('aps_employee:leave_view')

    # Constants for display
    TOTAL_ANNUAL_LEAVES = 18.0
    
    return render(request, 'basic/leave.html', {
        'leave_balance': leave_balance,
        'leave_requests': leave_requests,
        'leave_types': Leave.LEAVE_TYPES,
        'total_annual_leaves': TOTAL_ANNUAL_LEAVES,
        'leaves_taken': leave_balance.get('used_leaves', 0.0),
        'remaining_leaves': leave_balance.get('total_leaves', TOTAL_ANNUAL_LEAVES),
        'loss_of_pay': leave_balance.get('loss_of_pay', 0.0)
    })


@login_required
@user_passes_test(is_hr)
def view_leave_requests_hr(request):
    """HR views all leave requests with comprehensive filtering and organizational hierarchy."""
    # Apply filters
    employee_filter = request.GET.get('employee', '')
    leave_type_filter = request.GET.get('leave_type', '')
    status_filter = request.GET.get('status', '')
    date_range = request.GET.get('date_range', '')
    
    # HR can see all leave requests except admin
    leave_requests = Leave.objects.all().select_related('user', 'approver').order_by('-created_at')
    
    # Apply filters
    if employee_filter:
        leave_requests = leave_requests.filter(
            Q(user__username__icontains=employee_filter) | 
            Q(user__first_name__icontains=employee_filter) | 
            Q(user__last_name__icontains=employee_filter)
        )
    
    if leave_type_filter:
        leave_requests = leave_requests.filter(leave_type=leave_type_filter)
    
    if status_filter:
        leave_requests = leave_requests.filter(status=status_filter)
    
    if date_range:
        try:
            date_parts = date_range.split(' - ')
            start_date = datetime.strptime(date_parts[0], '%Y-%m-%d').date()
            end_date = datetime.strptime(date_parts[1], '%Y-%m-%d').date()
            leave_requests = leave_requests.filter(
                Q(start_date__range=[start_date, end_date]) | 
                Q(end_date__range=[start_date, end_date])
            )
        except (ValueError, IndexError):
            messages.error(request, "Invalid date range format")
    
    # Separate employee and manager requests that need HR approval
    employee_manager_requests = leave_requests.filter(
        Q(user__groups__name='Employee') | 
        Q(user__groups__name='Manager'),
        status='Pending'
    )
    
    # Other requests for reference
    other_requests = leave_requests.exclude(
        Q(user__groups__name='Employee') | 
        Q(user__groups__name='Manager'),
        status='Pending'
    )
    
    # Get organizational hierarchy data
    org_hierarchy = {
        'hr': User.objects.filter(groups__name='HR').count(),
        'managers': User.objects.filter(groups__name='Manager').count(),
        'employees': User.objects.filter(groups__name='Employee').count(),
    }
    
    # Get approval history for audit trail
    approval_history = Leave.objects.exclude(approver=None).values(
        'user__username', 'user__first_name', 'user__last_name',
        'approver__username', 'approver__first_name', 'approver__last_name',
        'status', 'created_at', 'updated_at', 'leave_type'
    ).order_by('-updated_at')[:100]  # Last 100 approvals
    
    return render(request, 'components/hr/view_leave_requests.html', {
        'employee_manager_requests': employee_manager_requests,
        'other_requests': other_requests,
        'leave_types': Leave.LEAVE_TYPES,
        'status_choices': Leave.STATUS_CHOICES,
        'org_hierarchy': org_hierarchy,
        'approval_history': approval_history,
        'filters': {
            'employee': employee_filter,
            'leave_type': leave_type_filter,
            'status': status_filter,
            'date_range': date_range
        }
    })

@login_required
@user_passes_test(is_hr)
def manage_leave_request_hr(request, leave_id, action):
    """HR approves or rejects employee and manager leave requests with comprehensive validation."""
    leave_request = get_object_or_404(Leave.objects.select_related('user', 'approver'), id=leave_id)
    
    # HR should only approve/reject employee and manager requests
    if not (is_employee(leave_request.user) or is_manager(leave_request.user)):
        messages.error(request, "HR should only approve employee and manager leave requests.")
        return redirect('aps_hr:view_leave_requests_hr')
    
    # Check if leave request is already processed
    if leave_request.status != 'Pending':
        messages.error(request, f"This leave request is already {leave_request.status.lower()}.")
        return redirect('aps_hr:view_leave_requests_hr')

    if request.method == 'POST':
        try:
            with transaction.atomic():
                if action == 'approve':
                    # For managers, check team coverage
                    if is_manager(leave_request.user):
                        # Check if team has coverage during this period
                        team_size = User.objects.filter(employee__reporting_manager=leave_request.user).count()
                        if team_size > 0:
                            messages.info(request, f"Note: This manager has {team_size} direct reports.")
                    
                    leave_request.status = 'Approved'
                    leave_request.approver = request.user
                    leave_request.approval_date = timezone.now()
                    leave_request.save()
                    
                    # Log the approval
                    logger.info(f"Leave ID {leave_id} for {leave_request.user.username} approved by HR {request.user.username}")
                    
                    messages.success(request, f"Leave for {leave_request.user.get_full_name() or leave_request.user.username} approved.")
                
                elif action == 'reject':
                    rejection_reason = request.POST.get('rejection_reason')
                    if not rejection_reason:
                        messages.error(request, "Rejection reason is required.")
                        return render(request, 'components/hr/manage_leave.html', {
                            'leave_request': leave_request,
                            'action': action.capitalize(),
                            'leave_balance': Leave.get_leave_balance(leave_request.user)
                        })
                    
                    leave_request.status = 'Rejected'
                    leave_request.approver = request.user
                    leave_request.rejection_reason = rejection_reason
                    leave_request.approval_date = timezone.now()
                    leave_request.save()
                    
                    # Log the rejection
                    logger.info(f"Leave ID {leave_id} for {leave_request.user.username} rejected by HR {request.user.username}")
                    
                    messages.warning(request, f"Leave for {leave_request.user.get_full_name() or leave_request.user.username} rejected.")
                
                return redirect('aps_hr:view_leave_requests_hr')
        
        except Exception as e:
            logger.error(f"Error processing leave request: {str(e)}")
            messages.error(request, f"Error processing leave request: {str(e)}")
            return redirect('aps_hr:view_leave_requests_hr')

    # Get organizational context
    org_context = {}
    
    if is_manager(leave_request.user):
        org_context['role'] = 'Manager'
        org_context['team_size'] = User.objects.filter(employee__reporting_manager=leave_request.user).count()
        org_context['team_on_leave'] = Leave.objects.filter(
            user__employee__reporting_manager=leave_request.user,
            status='Approved',
            start_date__lte=leave_request.end_date,
            end_date__gte=leave_request.start_date
        ).count()

    # Get leave history for context
    leave_history = Leave.objects.filter(user=leave_request.user).exclude(id=leave_id).order_by('-created_at')[:10]
    
    return render(request, 'components/hr/manage_leave.html', {
        'leave_request': leave_request,
        'action': action.capitalize(),
        'leave_balance': Leave.get_leave_balance(leave_request.user),
        'leave_history': leave_history,
        'org_context': org_context
    })

@login_required
@user_passes_test(is_manager)
def view_leave_requests_manager(request):
    """Manager views team leave requests with comprehensive filtering."""
    # Apply filters
    employee_filter = request.GET.get('employee', '')
    leave_type_filter = request.GET.get('leave_type', '')
    status_filter = request.GET.get('status', '')
    date_range = request.GET.get('date_range', '')
    
    # Manager can only see their team's leave requests
    leave_requests = Leave.objects.filter(
        user__employee__reporting_manager=request.user
    ).select_related('user', 'approver').order_by('-created_at')
    
    # Apply filters
    if employee_filter:
        leave_requests = leave_requests.filter(
            Q(user__username__icontains=employee_filter) | 
            Q(user__first_name__icontains=employee_filter) | 
            Q(user__last_name__icontains=employee_filter)
        )
    
    if leave_type_filter:
        leave_requests = leave_requests.filter(leave_type=leave_type_filter)
    
    if status_filter:
        leave_requests = leave_requests.filter(status=status_filter)
    
    if date_range:
        try:
            date_parts = date_range.split(' - ')
            start_date = datetime.strptime(date_parts[0], '%Y-%m-%d').date()
            end_date = datetime.strptime(date_parts[1], '%Y-%m-%d').date()
            leave_requests = leave_requests.filter(
                Q(start_date__range=[start_date, end_date]) | 
                Q(end_date__range=[start_date, end_date])
            )
        except (ValueError, IndexError):
            messages.error(request, "Invalid date range format")
    
    # Get team hierarchy data
    team_hierarchy = {
        'total_team': User.objects.filter(employee__reporting_manager=request.user).count(),
        'on_leave': Leave.objects.filter(
            user__employee__reporting_manager=request.user,
            status='Approved'
        ).count()
    }
    
    # Get approval history for audit trail
    approval_history = Leave.objects.filter(
        user__employee__reporting_manager=request.user
    ).exclude(approver=None).values(
        'user__username', 'user__first_name', 'user__last_name',
        'approver__username', 'approver__first_name', 'approver__last_name',
        'status', 'created_at', 'updated_at', 'leave_type'
    ).order_by('-updated_at')[:50]  # Last 50 approvals
    
    return render(request, 'components/manager/view_leave_requests.html', {
        'leave_requests': leave_requests,
        'leave_types': Leave.LEAVE_TYPES,
        'status_choices': Leave.STATUS_CHOICES,
        'team_hierarchy': team_hierarchy,
        'approval_history': approval_history,
        'filters': {
            'employee': employee_filter,
            'leave_type': leave_type_filter,
            'status': status_filter,
            'date_range': date_range
        }
    })

@login_required
@user_passes_test(is_manager)
def manage_leave_request_manager(request, leave_id, action):
    """Manager approves or rejects team leave requests with comprehensive validation."""
    leave_request = get_object_or_404(
        Leave.objects.select_related('user', 'approver'),
        id=leave_id,
        user__employee__reporting_manager=request.user
    )
    
    # Check if leave request is already processed
    if leave_request.status != 'Pending':
        messages.error(request, f"This leave request is already {leave_request.status.lower()}.")
        return redirect('aps_manager:view_leave_requests_manager')

    if request.method == 'POST':
        try:
            with transaction.atomic():
                if action == 'approve':
                    # Check team coverage during leave period
                    team_on_leave = Leave.objects.filter(
                        user__employee__reporting_manager=request.user,
                        status='Approved',
                        start_date__lte=leave_request.end_date,
                        end_date__gte=leave_request.start_date
                    ).exclude(id=leave_id).count()
                    
                    team_size = User.objects.filter(
                        employee__reporting_manager=request.user
                    ).count()
                    
                    if team_on_leave >= (team_size / 2):
                        messages.warning(request, f"Warning: {team_on_leave} out of {team_size} team members will be on leave during this period.")
                    
                    leave_request.status = 'Approved'
                    leave_request.approver = request.user
                    leave_request.approval_date = timezone.now()
                    leave_request.save()
                    
                    # Log the approval
                    logger.info(f"Leave ID {leave_id} for {leave_request.user.username} approved by manager {request.user.username}")
                    
                    messages.success(request, f"Leave for {leave_request.user.get_full_name() or leave_request.user.username} approved.")
                
                elif action == 'reject':
                    rejection_reason = request.POST.get('rejection_reason')
                    if not rejection_reason:
                        messages.error(request, "Rejection reason is required.")
                        return render(request, 'components/manager/manage_leave.html', {
                            'leave_request': leave_request,
                            'action': action.capitalize(),
                            'leave_balance': Leave.get_leave_balance(leave_request.user)
                        })
                    
                    leave_request.status = 'Rejected'
                    leave_request.approver = request.user
                    leave_request.rejection_reason = rejection_reason
                    leave_request.approval_date = timezone.now()
                    leave_request.save()
                    
                    # Log the rejection
                    logger.info(f"Leave ID {leave_id} for {leave_request.user.username} rejected by manager {request.user.username}")
                    
                    messages.warning(request, f"Leave for {leave_request.user.get_full_name() or leave_request.user.username} rejected.")
                
                return redirect('aps_manager:view_leave_requests_manager')
        
        except Exception as e:
            logger.error(f"Error processing leave request: {str(e)}")
            messages.error(request, f"Error processing leave request: {str(e)}")
            return redirect('aps_manager:view_leave_requests_manager')

    # Get leave history for context
    leave_history = Leave.objects.filter(user=leave_request.user).exclude(id=leave_id).order_by('-created_at')[:10]
    
    return render(request, 'components/manager/manage_leave.html', {
        'leave_request': leave_request,
        'action': action.capitalize(),
        'leave_balance': Leave.get_leave_balance(leave_request.user),
        'leave_history': leave_history,
        'team_on_leave': Leave.objects.filter(
            user__employee__reporting_manager=request.user,
            status='Approved',
            start_date__lte=leave_request.end_date,
            end_date__gte=leave_request.start_date
        ).exclude(id=leave_id).count()
    })

@login_required
@user_passes_test(is_admin)
def view_leave_requests_admin(request):
    """Admin views all leave requests with comprehensive filtering and organizational hierarchy."""
    # Apply filters
    employee_filter = request.GET.get('employee', '')
    leave_type_filter = request.GET.get('leave_type', '')
    status_filter = request.GET.get('status', '')
    date_range = request.GET.get('date_range', '')
    
    # Admin can see all leave requests
    leave_requests = Leave.objects.all().select_related('user', 'approver').order_by('-created_at')
    
    # Apply filters
    if employee_filter:
        leave_requests = leave_requests.filter(
            Q(user__username__icontains=employee_filter) | 
            Q(user__first_name__icontains=employee_filter) | 
            Q(user__last_name__icontains=employee_filter)
        )
    
    if leave_type_filter:
        leave_requests = leave_requests.filter(leave_type=leave_type_filter)
    
    if status_filter:
        leave_requests = leave_requests.filter(status=status_filter)
    
    if date_range:
        try:
            date_parts = date_range.split(' - ')
            start_date = datetime.strptime(date_parts[0], '%Y-%m-%d').date()
            end_date = datetime.strptime(date_parts[1], '%Y-%m-%d').date()
            leave_requests = leave_requests.filter(
                Q(start_date__range=[start_date, end_date]) | 
                Q(end_date__range=[start_date, end_date])
            )
        except (ValueError, IndexError):
            messages.error(request, "Invalid date range format")
    
    # Separate HR and manager requests that need admin approval
    hr_manager_requests = leave_requests.filter(
        Q(user__groups__name='HR') | 
        Q(user__groups__name='Manager'),
        status='Pending'
    )
    
    # Other requests for reference
    other_requests = leave_requests.exclude(
        Q(user__groups__name='HR') | 
        Q(user__groups__name='Manager'),
        status='Pending'
    )
    
    # Get organizational hierarchy data
    org_hierarchy = {
        'admin': User.objects.filter(groups__name='Admin').count(),
        'hr': User.objects.filter(groups__name='HR').count(),
        'managers': User.objects.filter(groups__name='Manager').count(),
        'employees': User.objects.filter(groups__name='Employee').count(),
    }
    
    # Get approval history for audit trail
    approval_history = Leave.objects.exclude(approver=None).values(
        'user__username', 'user__first_name', 'user__last_name',
        'approver__username', 'approver__first_name', 'approver__last_name',
        'status', 'created_at', 'updated_at', 'leave_type'
    ).order_by('-updated_at')[:100]  # Last 100 approvals
    
    return render(request, 'components/admin/view_leave_requests.html', {
        'hr_manager_requests': hr_manager_requests,
        'other_requests': other_requests,
        'leave_types': Leave.LEAVE_TYPES,
        'status_choices': Leave.STATUS_CHOICES,
        'org_hierarchy': org_hierarchy,
        'approval_history': approval_history,
        'filters': {
            'employee': employee_filter,
            'leave_type': leave_type_filter,
            'status': status_filter,
            'date_range': date_range
        }
    })

@login_required
@user_passes_test(is_admin)
def manage_leave_request_admin(request, leave_id, action):
    """Admin approves or rejects HR and manager leave requests with comprehensive validation."""
    leave_request = get_object_or_404(Leave.objects.select_related('user', 'approver'), id=leave_id)
    
    # Admin should only approve/reject HR and manager requests
    if not (is_hr(leave_request.user) or is_manager(leave_request.user)):
        messages.error(request, "Admin should only approve HR and Manager leave requests.")
        return redirect('aps_admin:view_leave_requests_admin')
    
    # Check if leave request is already processed
    if leave_request.status != 'Pending':
        messages.error(request, f"This leave request is already {leave_request.status.lower()}.")
        return redirect('aps_admin:view_leave_requests_admin')

    if request.method == 'POST':
        try:
            with transaction.atomic():
                if action == 'approve':
                    # For HR and managers, check organizational impact
                    if is_hr(leave_request.user):
                        # Check if other HR personnel are available during this period
                        other_hr_on_leave = Leave.objects.filter(
                            user__groups__name='HR',
                            status='Approved',
                            start_date__lte=leave_request.end_date,
                            end_date__gte=leave_request.start_date
                        ).exclude(id=leave_id).count()
                        
                        total_hr = User.objects.filter(groups__name='HR').count()
                        
                        if other_hr_on_leave >= (total_hr / 2):
                            messages.warning(request, f"Warning: {other_hr_on_leave} out of {total_hr} HR personnel will be on leave during this period.")
                    
                    elif is_manager(leave_request.user):
                        # Check team coverage for manager's absence
                        team_size = User.objects.filter(employee__reporting_manager=leave_request.user).count()
                        if team_size > 0:
                            messages.info(request, f"Note: This manager has {team_size} direct reports.")
                    
                    leave_request.status = 'Approved'
                    leave_request.approver = request.user
                    leave_request.approval_date = timezone.now()
                    leave_request.save()
                    
                    # Log the approval
                    logger.info(f"Leave ID {leave_id} for {leave_request.user.username} approved by admin {request.user.username}")
                    
                    messages.success(request, f"Leave for {leave_request.user.get_full_name() or leave_request.user.username} approved.")
                
                elif action == 'reject':
                    rejection_reason = request.POST.get('rejection_reason')
                    if not rejection_reason:
                        messages.error(request, "Rejection reason is required.")
                        return render(request, 'components/admin/manage_leave.html', {
                            'leave_request': leave_request,
                            'action': action.capitalize(),
                            'leave_balance': Leave.get_leave_balance(leave_request.user)
                        })
                    
                    leave_request.status = 'Rejected'
                    leave_request.approver = request.user
                    leave_request.rejection_reason = rejection_reason
                    leave_request.approval_date = timezone.now()
                    leave_request.save()
                    
                    # Log the rejection
                    logger.info(f"Leave ID {leave_id} for {leave_request.user.username} rejected by admin {request.user.username}")
                    
                    messages.warning(request, f"Leave for {leave_request.user.get_full_name() or leave_request.user.username} rejected.")
                
                return redirect('aps_admin:view_leave_requests_admin')
        
        except Exception as e:
            logger.error(f"Error processing leave request: {str(e)}")
            messages.error(request, f"Error processing leave request: {str(e)}")
            return redirect('aps_admin:view_leave_requests_admin')

    # Get organizational context
    org_context = {}
    
    if is_hr(leave_request.user):
        org_context['role'] = 'HR'
        org_context['other_hr'] = User.objects.filter(groups__name='HR').exclude(id=leave_request.user.id).count()
        org_context['hr_on_leave'] = Leave.objects.filter(
            user__groups__name='HR',
            status='Approved',
            start_date__lte=leave_request.end_date,
            end_date__gte=leave_request.start_date
        ).exclude(user=leave_request.user).count()
    
    elif is_manager(leave_request.user):
        org_context['role'] = 'Manager'
        org_context['team_size'] = User.objects.filter(employee__reporting_manager=leave_request.user).count()
        org_context['team_on_leave'] = Leave.objects.filter(
            user__employee__reporting_manager=leave_request.user,
            status='Approved',
            start_date__lte=leave_request.end_date,
            end_date__gte=leave_request.start_date
        ).count()

    # Get leave history for context
    leave_history = Leave.objects.filter(user=leave_request.user).exclude(id=leave_id).order_by('-created_at')[:10]
    
    return render(request, 'components/admin/manage_leave.html', {
        'leave_request': leave_request,
        'action': action.capitalize(),
        'leave_balance': Leave.get_leave_balance(leave_request.user),
        'leave_history': leave_history,
        'org_context': org_context
    })



''' ------------------------------------------- PROJECT AREA ------------------------------------------- '''
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.contrib import messages
from django.utils import timezone
from django.db.models import Q, Sum
from django.core.exceptions import ValidationError
from .models import Project, ProjectAssignment, ClientParticipation, User
from django.views.decorators.http import require_http_methods
from django.db import transaction
from django.urls import reverse
import json
import logging
from django.contrib.auth.models import Group
from datetime import datetime

# Set up logging
logger = logging.getLogger(__name__)

class ProjectError(Exception):
    """Custom exception for project-related errors"""
    pass

def parse_request_data(request):
    """Helper method to parse request data consistently"""
    try:
        if request.content_type == 'application/json':
            return json.loads(request.body)
        return request.POST
    except json.JSONDecodeError as e:
        logger.error(f"JSON parsing error: {str(e)}")
        raise ProjectError("Invalid JSON data provided")

def validate_project_dates(start_date, deadline):
    """Validate project dates"""
    if start_date > deadline:
        raise ValidationError("Start date cannot be after deadline")
    if deadline < timezone.now().date():
        raise ValidationError("Deadline cannot be in the past")

def handle_assignment_changes(project, assignment, action='assign', role='Employee'):
    """Helper method to handle employee assignment changes"""
    try:
        if action == 'assign':
            if assignment:
                # Reactivate if previously deactivated
                assignment.is_active = True
                assignment.end_date = None
                assignment.role_in_project = role
                assignment.save()
                return False  # Not created, but updated
            return True  # New assignment created
        else:  # remove
            assignment.deactivate()
            return True
    except Exception as e:
        logger.error(f"Assignment change error: {str(e)}")
        raise ProjectError(f"Error {action}ing employee")

def get_users_from_group(group_name):
    """Fetch users dynamically from a given group."""
    try:
        group = Group.objects.get(name=group_name)
        return group.user_set.all()
    except Group.DoesNotExist:
        return User.objects.none()


# Assuming logger is set up
logger = logging.getLogger(__name__)

@login_required
def project_dashboard(request):
    try:
        today = date.today()

        # Get all active projects with related data
        projects = Project.objects.prefetch_related(
            'users', 
            'clients', 
            'projectassignment_set__user',
            'client_participations'
        ).all()

        # Print the project objects (you can adjust this as needed)
        print("Projects data:")
        for project in projects:
            print(f"Project ID: {project.id}, Project Name: {project.name}, Deadline: {project.deadline}")

            # Print the users related to the project (through projectassignment_set)
            print(f"Assigned Users for Project {project.name}:")
            for assignment in project.projectassignment_set.all():
                user = assignment.user
                print(f"  - User: {user.get_full_name()} (ID: {user.id}, Role: {assignment.get_role_in_project_display()})")

        for project in projects:
            # Calculate project duration and remaining days
            project_duration = (project.deadline - project.start_date).days
            remaining_days = (project.deadline - today).days
            
            remaining_percentage = max((remaining_days / project_duration) * 100, 0) if project_duration > 0 else 0

            # Set deadline status
            project.is_deadline_close = 0 <= remaining_percentage <= 10

            # Fetch active and removed assignments
            project.active_assignments = project.projectassignment_set.filter(is_active=True)
            project.removed_assignments = project.projectassignment_set.filter(is_active=False)

            # Print active assignments
            print(f"Project: {project.name} (Active Assignments)")
            for assignment in project.active_assignments:
                assignment.user.full_name = assignment.user.get_full_name()
                print(f"  - {assignment.user.full_name} (ID: {assignment.user.id}, Role: {assignment.get_role_in_project_display()})")
            
            # Print removed assignments
            print(f"Project: {project.name} (Removed Assignments)")
            for assignment in project.removed_assignments:
                assignment.user.full_name = assignment.user.get_full_name()
                print(f"  - {assignment.user.full_name} (ID: {assignment.user.id}, Ended: {assignment.end_date})")

        # Fetch users by group
        employees = get_users_from_group('Employee')
        managers = get_users_from_group('Manager')
        clients = get_users_from_group('Client')
                
        # Fetch role choices
        role_choices = dict(ProjectAssignment._meta.get_field('role_in_project').choices)

        # Context for rendering the template
        context = {
            'projects': projects,
            'employees': employees,
            'clients': clients,
            'managers': managers,
            'project_statuses': dict(Project._meta.get_field('status').choices),
            'role_choices': role_choices,
            
        }

        return render(request, 'components/admin/project_view.html', context)

    except Exception as e:
        # Capture exception details
        exc_type, exc_value, exc_tb = sys.exc_info()
        error_details = traceback.format_exception(exc_type, exc_value, exc_tb)

        # Log error and display error message
        logger.error(f"Dashboard error: {str(e)}")
        messages.error(request, "Error loading dashboard")

        # Provide detailed error information in the context for debugging
        context = {
            'error': str(e),
            'error_details': error_details,
        }
        return render(request, 'error.html', context)


@login_required
@require_http_methods(["POST"])
def project_create(request):
    """Handle project creation"""
    try:
        data = request.POST
        start_date_str = data.get('start_date')
        deadline_str = data.get('deadline')
        
        try:
            start_date = parse_date(start_date_str)
            deadline = parse_date(deadline_str)
            if not start_date or not deadline:
                raise ValidationError("Invalid date format. Expected 'YYYY-MM-DD'.")
        except ValueError:
            raise ValidationError("Invalid date format. Expected 'YYYY-MM-DD'.")

        validate_project_dates(start_date, deadline)
        
        with transaction.atomic():
            project = Project.objects.create(
                name=data.get('name'),
                description=data.get('description'),
                start_date=start_date,
                deadline=deadline,
                status='Pending'
            )
            
            client_ids = data.getlist('clients') if hasattr(data, 'getlist') else []
            if client_ids:
                project.clients.set(client_ids)
                for client_id in client_ids:
                    ClientParticipation.objects.create(project=project, client_id=client_id)
            
            manager_id = data.get('manager')
            if manager_id:
                ProjectAssignment.objects.create(project=project, user_id=manager_id, role_in_project='Manager')
            
            employee_ids = data.getlist('employees') if hasattr(data, 'getlist') else []
            for emp_id in employee_ids:
                ProjectAssignment.objects.create(project=project, user_id=emp_id, role_in_project='Employee')

        logger.info(f"Project created successfully: {project.name}")
        return redirect(reverse('aps_admin:project_dashboard'))
        
    except ValidationError as e:
        logger.warning(f"Validation error in project creation: {str(e)}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    except Exception as e:
        logger.error(f"Error creating project: {str(e)}")
        return JsonResponse({'status': 'error', 'message': 'Internal server error'}, status=500)
    
def update_project_status(project):
    """Automatically update project status based on dates"""
    today = datetime.now().date()

    # If the project is completed (Deadline passed)
    if project.deadline and today > project.deadline and project.status != 'Completed':
        project.status = 'Completed'
    
    # If the project is in progress (Start date has passed but deadline hasn't passed)
    elif project.start_date and today >= project.start_date and (not project.deadline or today <= project.deadline):
        project.status = 'In Progress'
    
    # If the project is on hold or any other condition you may define
    elif project.status != 'On Hold':  # Example condition
        project.status = 'On Hold'
    
    project.save()
  
@login_required
@user_passes_test(is_admin)
@require_http_methods(["POST"])
def project_update(request, project_id):
    """Handle project updates"""
    print(f"Updating project with ID: {project_id}")  # Debug line

    try:
        project = get_object_or_404(Project, id=project_id)
        data = parse_request_data(request)
        
        # Validate status from the form (if provided)
        new_status = data.get('status')
        if new_status and new_status not in ['Completed', 'In Progress', 'Pending', 'On Hold']:
            raise ValidationError("Invalid project status")
        
        # Update project status explicitly
        if new_status:
            project.status = new_status
        
        # Convert deadline to a date object if provided and ensure it's a string
        # Handle deadline field
        if 'deadline' in data and data['deadline']:
            deadline = data.get('deadline')
            try:
                # Convert deadline to a date object only if it's not empty
                if deadline:
                    deadline = datetime.strptime(deadline, '%Y-%m-%d').date()

                    # Validate that deadline is not in the past and that it is later than start_date
                    if deadline < datetime.now().date():
                        raise ValidationError("Deadline cannot be in the past.")
                    if project.start_date and deadline < project.start_date:
                        raise ValidationError("Deadline cannot be earlier than the start date.")

                    project.deadline = deadline
            except ValueError:
                raise ValidationError("Invalid date format for deadline. Please use YYYY-MM-DD.")

            project.deadline = deadline
        
        with transaction.atomic():
            # Update project basic info
            project.name = data.get('name', project.name)
            project.description = data.get('description', project.description)
            
            project.save()
        
        return redirect(reverse('aps_admin:project_dashboard'))  # Adjust the name of the URL pattern if needed

    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


def parse_request_data(request):
    """Helper function to parse data from the request"""
    return {
        'name': request.POST.get('name'),
        'description': request.POST.get('description'),
        'start_date': request.POST.get('start_date'),
        'deadline': request.POST.get('deadline'),
        'status': request.POST.get('status'),
    }


@login_required
@user_passes_test(is_admin)
@require_http_methods(["POST"])
def project_delete(request, project_id):
    """Handle project deletion"""
    try:
        project = get_object_or_404(Project, id=project_id)

        with transaction.atomic():
            # Soft delete all assignments
            ProjectAssignment.objects.filter(project=project).update(
                is_active=False,
                end_date=timezone.now().date()
            )

            # Soft delete all client participations
            ClientParticipation.objects.filter(project=project).update(is_active=False)

            # Delete the project
            project.delete()

        logger.info(f"Project deleted successfully: {project.name}")
        return redirect(reverse('aps_admin:project_dashboard'))  # This is fine after defining the URL

    except Exception as e:
        logger.error(f"Error deleting project: {str(e)}")
        return JsonResponse({'status': 'error', 'message': 'Internal server error'}, status=500)


@csrf_exempt
@login_required
@require_http_methods(["POST"])
def assign_employee(request, project_id):
    """Handle employee assignment to project dynamically, including deactivation"""
    try:
        with transaction.atomic():
            print(f"Transaction started for project_id: {project_id}")
            project = get_object_or_404(Project, id=project_id)
            print(f"Project found: {project.name} (ID: {project.id})")

            user_id = request.POST.get('user_id')
            role = request.POST.get('role', 'Employee')
            action = request.POST.get('action', 'assign')  # Action for remove or assign
            print(f"Received data - user_id: {user_id}, role: {role}, action: {action}")

            if not user_id:
                return JsonResponse({
                    'status': 'error',
                    'message': 'User ID is required'
                }, status=400)

            # Ensure role is valid
            role_choices = dict(ProjectAssignment._meta.get_field('role_in_project').choices)
            if role not in role_choices:
                return JsonResponse({
                    'status': 'error',
                    'message': f'Invalid role. Available roles are {", ".join(role_choices.keys())}'
                }, status=400)

            user = get_object_or_404(User, id=user_id)
            print(f"User found: {user.username} (ID: {user.id})")

            if action == 'remove':
                assignment = project.projectassignment_set.filter(user=user, is_active=True).first()

                if not assignment:
                    return JsonResponse({
                        'status': 'error',
                        'message': f'No active assignment found for employee {user.username} in this project'
                    }, status=404)

                # Soft delete by marking inactive
                assignment.is_active = False
                assignment.end_date = timezone.now().date()
                assignment.save()
                return JsonResponse({
                    'status': 'success',
                    'message': f'Employee {user.username} removed from the project'
                })

            # Check if the employee has been previously removed (soft deleted)
            assignment = project.projectassignment_set.filter(user=user, is_active=False).first()

            if assignment:
                # Reactivate the assignment if it was previously removed
                assignment.is_active = True
                assignment.role_in_project = role
                assignment.end_date = None  # Clear end_date if reactivating
                assignment.save()
                return JsonResponse({
                    'status': 'success',
                    'message': f'Employee {user.username} reactivated in the project'
                })
            else:
                # Handle assigning or updating an employee's role if not previously removed
                assignment, created = ProjectAssignment.objects.get_or_create(
                    project=project,
                    user=user
                )

                assignment.role_in_project = role
                assignment.is_active = True
                assignment.save()

                return JsonResponse({
                    'status': 'success',
                    'message': f'Employee {user.username} assigned to the project with role {role}'
                })

    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@csrf_exempt
@login_required
@require_http_methods(["POST"])
def change_role(request, project_id):
    """Handle changing the role of an assigned employee"""
    try:
        with transaction.atomic():
            project = get_object_or_404(Project, id=project_id)
            user_id = request.POST.get('user_id')
            new_role = request.POST.get('role', 'Employee')

            if not user_id:
                return JsonResponse({'status': 'error', 'message': 'User ID is required'}, status=400)

            # Ensure role is valid
            role_choices = dict(ProjectAssignment._meta.get_field('role_in_project').choices)
            if new_role not in role_choices:
                return JsonResponse({
                    'status': 'error',
                    'message': f'Invalid role. Available roles are {", ".join(role_choices.keys())}'
                }, status=400)

            user = get_object_or_404(User, id=user_id)
            assignment = project.projectassignment_set.filter(user=user, is_active=True).first()

            if not assignment:
                return JsonResponse({'status': 'error', 'message': 'No active assignment found for this user'}, status=404)

            assignment.role_in_project = new_role
            assignment.save()

            return JsonResponse({'status': 'success', 'message': 'Employee role updated successfully'})

    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@csrf_exempt
@login_required
@require_http_methods(["POST"])
def reactivate_employee(request, project_id):
    """Handle reactivating a previously removed employee"""
    try:
        with transaction.atomic():
            project = get_object_or_404(Project, id=project_id)
            user_id = request.POST.get('user_id')

            if not user_id:
                return JsonResponse({'status': 'error', 'message': 'User ID is required'}, status=400)

            user = get_object_or_404(User, id=user_id)
            
            # Find the most recent inactive assignment for this user in this project
            assignment = ProjectAssignment.objects.filter(
                project=project,
                user=user,
                is_active=False
            ).order_by('-end_date').first()

            if not assignment:
                return JsonResponse({'status': 'error', 'message': 'No removed assignment found for this user'}, status=404)

            # Reactivate the assignment
            assignment.is_active = True
            assignment.end_date = None  # Clear end date
            assignment.save()
            
            # Log the reactivation
            UserActionLog.objects.create(
                user=user,
                action_type='update',
                action_by=request.user,
                details=f"Reactivated in project: {project.name}"
            )

            return JsonResponse({
                'status': 'success', 
                'message': 'Employee reactivated successfully',
                'user_name': user.get_full_name() or user.username,
                'role': assignment.role_in_project
            })

    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
@require_http_methods(["POST"])
def update_hours(request, project_id):
    """Handle updating worked hours for an assignment"""
    try:
        project = get_object_or_404(Project, id=project_id)
        data = parse_request_data(request)
        
        user_id = data.get('user_id')
        hours = data.get('hours')
        
        if not user_id or hours is None:
            raise ValidationError("User ID and hours are required")
        
        try:
            hours = float(hours)
            if hours < 0:
                raise ValidationError("Hours cannot be negative")
        except ValueError:
            raise ValidationError("Invalid hours value")
        
        assignment = get_object_or_404(
            ProjectAssignment,
            project=project,
            user_id=user_id,
            is_active=True
        )
        
        assignment.update_hours(hours)
        
        logger.info(f"Hours updated successfully: {hours} hours for {user_id} in {project.name}")
        return JsonResponse({
            'status': 'success',
            'message': 'Hours updated successfully',
            'total_hours': assignment.get_total_hours()
        })
        
    except ValidationError as e:
        logger.warning(f"Validation error in hours update: {str(e)}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    except Exception as e:
        logger.error(f"Error updating hours: {str(e)}")
        return JsonResponse({'status': 'error', 'message': 'Internal server error'}, status=500)



def create_project(request):
    """Helper function to create a project."""
    name = request.POST.get('name')
    description = request.POST.get('description')
    start_date = request.POST.get('start_date')
    due_date = request.POST.get('due_date')
    client_ids = request.POST.getlist('clients')  # Ensure client_ids are being captured here
    print("Client IDs:", client_ids)  # Add this line for debugging
    
    project = Project.objects.create(
        name=name,
        description=description,
        start_date=start_date,
        deadline=due_date,
        status='Not Started'
    )
    
    assign_users_to_project(request, project, client_ids)  # Pass client_ids to the assign function
    return project


def update_project(request, project):
    """Helper function to update a project."""
    project.name = request.POST.get('name', project.name)
    project.description = request.POST.get('description', project.description)
    project.status = request.POST.get('status', project.status)
    project.start_date = request.POST.get('start_date', project.start_date)
    project.deadline = request.POST.get('deadline', project.deadline)
    project.save()

    # Reassign clients based on selected client_ids (Handle soft deletes if necessary)
    client_ids = request.POST.getlist('clients')
    # Clear current clients and reassign based on new client_ids
    project.clients.clear()  
    for client_id in client_ids:
        client = User.objects.get(id=client_id)
        project.clients.add(client)

    return project


def assign_users_to_project(request, project, client_ids=None):
    """Helper function to assign users to a project."""
    # Assign manager
    manager_id = request.POST.get('manager')
    if manager_id:
        manager = User.objects.get(id=manager_id)
        ProjectAssignment.objects.update_or_create(
            project=project,
            user=manager,
            defaults={'role_in_project': 'Manager', 'hours_worked': 0.0}
        )
    
    # Assign employees
    employee_ids = request.POST.getlist('employees')
    for employee_id in employee_ids:
        employee = User.objects.get(id=employee_id)
        ProjectAssignment.objects.get_or_create(
            project=project,
            user=employee,
            defaults={'role_in_project': 'Employee', 'hours_worked': 0.0}
        )
    
    # Assign clients if client_ids are passed
    if client_ids:
        for client_id in client_ids:  # Iterate through the passed client_ids
            client = User.objects.get(id=client_id)
            ClientParticipation.objects.get_or_create(
                project=project,
                client=client,
                defaults={'feedback': '', 'approved': False}
            )

            
@login_required
@user_passes_test(is_manager)
def manager_project_view(request, action=None, project_id=None):
    """Manager view for managing projects."""
    
    # Get all managers and employees
    managers = User.objects.filter(groups__name='Manager')
    employees = User.objects.filter(groups__name='Employee')
    clients = User.objects.filter(groups__name='Client')

    # Action to list all projects
    if action == "list":
        # Get the current manager's projects
        assignments = ProjectAssignment.objects.filter(user=request.user, role_in_project='Manager', is_active=True)
        projects = [assignment.project for assignment in assignments]
        
        return render(request, 'components/manager/project_view.html', {
            'projects': projects,
            'managers': managers,
            'employees': employees,
            'clients': clients,
            'action': 'list'
        })

    # Action to view project details
    elif action == "detail" and project_id:
        project = get_object_or_404(Project, id=project_id)
        active_assignments = project.projectassignment_set.filter(is_active=True)
        # Get all inactive assignments, not just the most recent ones
        removed_assignments = project.projectassignment_set.filter(is_active=False).order_by('-end_date')
        client_participations = project.client_participations.all()
        
        context = {
            'project': project,
            'active_assignments': active_assignments,
            'removed_assignments': removed_assignments,
            'employees': employees,
            'clients': clients,
            'client_participations': client_participations,
            'role_choices': dict(ProjectAssignment._meta.get_field('role_in_project').choices),
            'action': 'detail'
        }
        return render(request, 'components/manager/project_view.html', context)

    # Action to create a new project
    elif action == "create":
        if request.method == 'POST':
            try:
                with transaction.atomic():
                    # Create the project
                    project = create_project(request)
                    
                    # Log the action - removed log_user_action call
                    
                    messages.success(request, "Project created successfully!")
                    return redirect('aps_manager:project_detail', project_id=project.id)
            
            except ValidationError as e:
                messages.error(request, str(e))
            except Exception as e:
                messages.error(request, f"Error creating project: {str(e)}")
                logger.error(f"Project creation error: {str(e)}")

        return render(request, 'components/manager/project_view.html', {
            'employees': employees,
            'managers': managers,
            'clients': clients,
            'action': 'create'
        })

    # Action to update an existing project
    elif action == "update" and project_id:
        project = get_object_or_404(Project, id=project_id)
        
        # Verify manager has permission
        if not project.projectassignment_set.filter(user=request.user, role_in_project='Manager', is_active=True).exists():
            messages.error(request, "You don't have permission to update this project")
            return redirect('aps_manager:project_list')

        if request.method == 'POST':
            try:
                with transaction.atomic():
                    # Update the project
                    updated_project = update_project(request, project)
                    
                    # Handle employee assignments
                    assign_users_to_project(request, updated_project)
                    
                    # Log the action - removed log_user_action call
                    
                    messages.success(request, "Project updated successfully!")
                    return redirect('aps_manager:project_detail', project_id=project.id)

            except ValidationError as e:
                messages.error(request, str(e))
            except Exception as e:
                messages.error(request, f"Error updating project: {str(e)}")
                logger.error(f"Project update error: {str(e)}")

        # Get current project data for the form
        active_assignments = project.projectassignment_set.filter(is_active=True)
        # Include removed assignments for the update view as well
        removed_assignments = project.projectassignment_set.filter(is_active=False).order_by('-end_date')
        client_participations = project.client_participations.all()
        
        return render(request, 'components/manager/project_view.html', {
            'project': project,
            'employees': employees,
            'managers': managers,
            'clients': clients,
            'active_assignments': active_assignments,
            'removed_assignments': removed_assignments,
            'client_participations': client_participations,
            'action': 'update'
        })

    # Action to manage employees (assign/remove/change role)
    elif action == "manage_employees" and project_id:
        project = get_object_or_404(Project, id=project_id)
        
        # Verify manager has permission
        if not project.projectassignment_set.filter(user=request.user, role_in_project='Manager', is_active=True).exists():
            messages.error(request, "You don't have permission to manage employees for this project")
            return redirect('aps_manager:project_list')
        
        if request.method == 'POST':
            try:
                user_id = request.POST.get('user_id')
                role = request.POST.get('role', 'Employee')
                action_type = request.POST.get('action')
                hours = request.POST.get('hours')
                
                user = get_object_or_404(User, id=user_id)
                
                with transaction.atomic():
                    if action_type == 'assign':
                        # Check if there's an inactive assignment first
                        inactive_assignment = project.projectassignment_set.filter(
                            user=user, 
                            is_active=False
                        ).order_by('-end_date').first()
                        
                        if inactive_assignment:
                            # Reactivate the existing assignment
                            inactive_assignment.is_active = True
                            inactive_assignment.end_date = None
                            inactive_assignment.role_in_project = role
                            inactive_assignment.save()
                            
                            # Log the reactivation
                            UserActionLog.objects.create(
                                user=user,
                                action_type='update',
                                action_by=request.user,
                                details=f"Reactivated in project: {project.name}"
                            )
                        else:
                            # Create new assignment
                            ProjectAssignment.objects.create(
                                project=project,
                                user=user,
                                role_in_project=role,
                                is_active=True
                            )
                        
                    elif action_type == 'remove':
                        # Soft delete by marking inactive
                        assignment = project.projectassignment_set.filter(user=user, is_active=True).first()
                        if assignment:
                            assignment.is_active = False
                            assignment.end_date = timezone.now().date()
                            assignment.save()
                            # Removed log_user_action call
                    
                    elif action_type == 'change_role':
                        # Update role
                        assignment = project.projectassignment_set.filter(user=user, is_active=True).first()
                        if assignment:
                            assignment.role_in_project = role
                            assignment.save()
                            # Removed log_user_action call
                    
                    elif action_type == 'update_hours' and hours:
                        # Update worked hours
                        assignment = project.projectassignment_set.filter(user=user, is_active=True).first()
                        if assignment:
                            try:
                                hours_float = float(hours)
                                assignment.hours_worked = hours_float
                                assignment.save()
                                # Removed log_user_action call
                            except ValueError:
                                raise ValidationError("Invalid hours value")
                    
                    elif action_type == 'reactivate':
                        # Find the most recent inactive assignment for this user
                        inactive_assignment = project.projectassignment_set.filter(
                            user=user, 
                            is_active=False
                        ).order_by('-end_date').first()
                        
                        if inactive_assignment:
                            # Reactivate the assignment
                            inactive_assignment.is_active = True
                            inactive_assignment.end_date = None
                            inactive_assignment.save()
                            
                            # Log the reactivation
                            UserActionLog.objects.create(
                                user=user,
                                action_type='update',
                                action_by=request.user,
                                details=f"Reactivated in project: {project.name}"
                            )
                        else:
                            raise ValidationError("No inactive assignment found for this user")
                
                messages.success(request, "Employee assignment updated successfully!")
                
            except ValidationError as e:
                messages.error(request, str(e))
            except Exception as e:
                messages.error(request, f"Error managing employees: {str(e)}")
                logger.error(f"Employee management error: {str(e)}")
                
        return redirect('aps_manager:project_detail', project_id=project.id)

    return redirect('aps_manager:project_list')

''' ------------------------------------------- ATTENDACE AREA ------------------------------------------- '''

import calendar
from datetime import datetime, timedelta
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.shortcuts import render
from django.utils.timezone import now, localtime, make_aware
from django.db.models import Avg
from .models import Attendance, Leave
from datetime import time, timedelta

import calendar
from datetime import datetime, timedelta, time
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.shortcuts import render
from django.utils.timezone import now, localtime, make_aware
from django.db.models import Avg
from .models import Attendance, Leave

@login_required
def employee_attendance_view(request):
    # Current date in the local timezone
    current_date = localtime(now())
    print(f"Current date: {current_date}")
    
    # Get current month and year from query parameters or fallback to the current date
    current_month = int(request.GET.get('month', current_date.month))
    current_year = int(request.GET.get('year', current_date.year))
    current_month_name = calendar.month_name[current_month]
    print(f"Current month: {current_month}, Current year: {current_year}")

    # Calculate previous and next month and year
    prev_month = current_month - 1 if current_month > 1 else 12
    next_month = current_month + 1 if current_month < 12 else 1
    prev_year = current_year if current_month > 1 else current_year - 1
    next_year = current_year if current_month < 12 else current_year + 1
    print(f"Previous month: {prev_month}, Next month: {next_month}, Previous year: {prev_year}, Next year: {next_year}")

    # Generate the calendar for the current month
    cal = calendar.Calendar(firstweekday=6)  # Week starts on Sunday
    days_in_month = cal.monthdayscalendar(current_year, current_month)
    print(f"Days in month: {days_in_month}")

    # Query attendance and leave data for the current user
    user_attendance = Attendance.objects.filter(
        user=request.user, 
        date__month=current_month, 
        date__year=current_year
    ).select_related('user')
    print(f"User attendance records: {user_attendance.count()} found")
    
    # Get daily attendance aggregates (earliest clock in and latest clock out)
    daily_attendance = {}
    for attendance in user_attendance:
        date = attendance.date
        if date not in daily_attendance:
            daily_attendance[date] = {
                'first_clock_in': attendance.clock_in_time,
                'last_clock_out': attendance.clock_out_time,
                'total_hours': attendance.total_hours,
                'status': attendance.status,
                'location': attendance.location,
                'is_half_day': attendance.is_half_day,
                'regularization_status': attendance.regularization_status,
                'regularization_reason': attendance.regularization_reason,
                'breaks': attendance.breaks
            }
        else:
            # Update earliest clock in
            if attendance.clock_in_time and (not daily_attendance[date]['first_clock_in'] or 
                attendance.clock_in_time < daily_attendance[date]['first_clock_in']):
                daily_attendance[date]['first_clock_in'] = attendance.clock_in_time
            
            # Update latest clock out
            if attendance.clock_out_time and (not daily_attendance[date]['last_clock_out'] or
                attendance.clock_out_time > daily_attendance[date]['last_clock_out']):
                daily_attendance[date]['last_clock_out'] = attendance.clock_out_time
                
            # Accumulate total hours
            if attendance.total_hours:
                daily_attendance[date]['total_hours'] = (daily_attendance[date]['total_hours'] or 0) + attendance.total_hours
    
    leaves = Leave.objects.filter(
        user=request.user,
        status='Approved',
        start_date__lte=datetime(current_year, current_month, calendar.monthrange(current_year, current_month)[1]),
        end_date__gte=datetime(current_year, current_month, 1)
    )
    print(f"Approved leaves: {leaves.count()} found")

    # Aggregate statistics including weekend work
    total_present = user_attendance.filter(status='Present').count()
    total_absent = user_attendance.filter(status='Absent').count()
    total_late = user_attendance.filter(status='Late').count()
    total_leave = user_attendance.filter(status='On Leave').count()
    total_wfh = user_attendance.filter(status='Work From Home').count()
    weekend_work = user_attendance.filter(is_weekend=True, status='Present').count()
    total_half_days = user_attendance.filter(is_half_day=True).count()
    print(f"Attendance stats - Present: {total_present}, Absent: {total_absent}, Late: {total_late}, Leave: {total_leave}, WFH: {total_wfh}, Weekend Work: {weekend_work}, Half Days: {total_half_days}")

    # Get average working hours
    avg_hours = user_attendance.exclude(total_hours__isnull=True).aggregate(
        avg_hours=Avg('total_hours')
    )['avg_hours'] or 0
    print(f"Average working hours: {avg_hours}")

    # Prepare calendar data with attendance and leave details
    calendar_data = []
    for week in days_in_month:
        week_data = []
        for day in week:
            if day == 0:
                week_data.append({'empty': True})
                print(f"Day {day} is empty")
            else:
                date = make_aware(datetime(current_year, current_month, day))
                leave_status = None
                leave_type = None
                
                # Check if leave exists for the day
                leave_on_day = leaves.filter(start_date__lte=date, end_date__gte=date).first()
                if leave_on_day:
                    leave_status = 'On Leave'
                    leave_type = leave_on_day.leave_type
                    print(f"Leave on day {day}: {leave_status}, Type: {leave_type}")

                # Get aggregated attendance data for the day
                attendance_date = date.date()
                attendance_data = daily_attendance.get(attendance_date, {})

                week_data.append({
                    'date': day,
                    'is_today': date.date() == current_date.date(),
                    'status': leave_status or attendance_data.get('status'),
                    'leave_type': leave_type,
                    'clock_in_time': attendance_data.get('first_clock_in'),
                    'clock_out_time': attendance_data.get('last_clock_out'),
                    'total_hours': attendance_data.get('total_hours'),
                    'breaks': attendance_data.get('breaks'),
                    'location': attendance_data.get('location'),
                    'is_half_day': attendance_data.get('is_half_day', False),
                    'is_sunday': date.weekday() == 6,
                    'is_weekend': date.weekday() >= 5,  # Saturday and Sunday
                    'regularization_status': attendance_data.get('regularization_status'),
                    'regularization_reason': attendance_data.get('regularization_reason'),
                    'empty': False
                })
        calendar_data.append(week_data)

    # Paginate the attendance records
    paginator = Paginator(user_attendance.order_by('-date'), 10)
    page = request.GET.get('page')
    print(f"Pagination page: {page}")
    try:
        records = paginator.get_page(page)
        print(f"Records on page: {len(records)}")
    except (EmptyPage, PageNotAnInteger):
        records = paginator.page(1)
        print("No valid page number provided, defaulting to page 1")

    return render(request, 'components/employee/calander.html', {
        'current_month': current_month_name,
        'current_year': current_year,
        'prev_month': prev_month,
        'next_month': next_month,
        'prev_year': prev_year,
        'next_year': next_year,
        'calendar_data': calendar_data,
        'total_present': total_present,
        'total_absent': total_absent,
        'total_late': total_late,
        'total_leave': total_leave,
        'total_wfh': total_wfh,
        'total_half_days': total_half_days,
        'weekend_work': weekend_work,
        'avg_hours': round(avg_hours, 2),
        'records': records,
    })

@login_required
@user_passes_test(is_manager)
def manager_attendance_view(request):
    # Prefetching related user manager data for efficiency
    team_attendance = Attendance.objects.filter(
        user__manager=request.user
    ).select_related('user').order_by('-date')
    
    # Pagination setup
    paginator = Paginator(team_attendance, 10)
    page = request.GET.get('page')
    
    try:
        team_records = paginator.get_page(page)
    except EmptyPage:
        team_records = paginator.page(paginator.num_pages)
    except PageNotAnInteger:
        team_records = paginator.page(1)

    return render(request, 'components/manager/manager_attendance.html', {
        'team_attendance': team_records
    })
@login_required
@user_passes_test(is_hr)
def hr_attendance_view(request):
    # Get the month and year from request params, default to current month
    today = timezone.now().date()
    month = int(request.GET.get('month', today.month))
    year = int(request.GET.get('year', today.year))

    # Get first and last day of selected month
    first_day = datetime(year, month, 1).date()
    last_day = datetime(year, month, calendar.monthrange(year, month)[1]).date()

    # Get all users with their details - FIXED: changed userdetails to profile
    users = User.objects.select_related('profile').all().order_by('username')

    # Get all attendance records for the month with related data
    attendance_records = Attendance.objects.filter(
        date__range=[first_day, last_day]
    ).select_related('user', 'shift', 'user_session').prefetch_related('modified_by')

    # Get leave records for the month
    leave_records = Leave.objects.filter(
        start_date__lte=last_day,
        end_date__gte=first_day,
        status='Approved'
    ).select_related('user', 'approver')

    # Create attendance matrix
    attendance_matrix = []
    days_in_month = calendar.monthrange(year, month)[1]

    for user in users:
        user_row = {
            'employee': user,
            # FIXED: changed userdetails to profile
            'work_location': getattr(user.profile, 'work_location', 'Not set'),
            'attendance': {}
        }

        # Initialize all days
        for day in range(1, days_in_month + 1):
            current_date = datetime(year, month, day).date()
            day_name = current_date.strftime('%a')
            is_weekend = current_date.weekday() >= 5  # Saturday or Sunday
            
            user_row['attendance'][current_date] = {
                'status': 'Weekend' if is_weekend else 'Absent',
                'working_hours': None,
                'day_name': day_name,
                'is_weekend': is_weekend,
                'is_holiday': False,
                'overtime_hours': 0,
                'late_minutes': 0,
                'breaks': [],
                'location': None,
                'regularization_status': None,
                'regularization_reason': None,
                'shift': None,
                'modified_by': None,
                'remarks': None
            }

        # Fill in actual attendance records
        user_records = attendance_records.filter(user=user)
        for record in user_records:
            day_name = record.date.strftime('%a')
            working_hours = f"{record.total_hours:.1f}h" if record.total_hours else "-"

            status = record.status
            if record.is_weekend and status == 'Present':
                status = 'Weekend Work'

            user_row['attendance'][record.date] = {
                'status': status,
                'working_hours': working_hours,
                'day_name': day_name,
                'is_weekend': record.is_weekend,
                'is_holiday': record.is_holiday,
                'overtime_hours': record.overtime_hours,
                'late_minutes': record.late_minutes,
                'breaks': record.breaks,
                'location': record.location,
                'regularization_status': record.regularization_status,
                'regularization_reason': record.regularization_reason,
                'shift': record.shift.name if record.shift else None,
                'modified_by': record.modified_by.username if record.modified_by else None,
                'remarks': record.remarks,
                'clock_in': record.clock_in_time.strftime('%H:%M') if record.clock_in_time else None,
                'clock_out': record.clock_out_time.strftime('%H:%M') if record.clock_out_time else None
            }

        # Fill in leave records
        user_leaves = leave_records.filter(user=user)
        for leave in user_leaves:
            leave_dates = [first_day + timedelta(days=x) for x in range((last_day-first_day).days + 1)]
            leave_dates = [d for d in leave_dates if leave.start_date <= d <= leave.end_date]
            
            for date in leave_dates:
                if date in user_row['attendance']:
                    user_row['attendance'][date].update({
                        'status': 'On Leave',
                        'leave_type': leave.leave_type,
                        'is_half_day': leave.half_day,
                        'leave_reason': leave.reason,
                        'leave_approver': leave.approver.username if leave.approver else None
                    })

        attendance_matrix.append(user_row)

    # Calculate summary statistics
    summary = {
        'present_count': attendance_records.filter(status='Present').count(),
        'absent_count': attendance_records.filter(status='Absent').count(),
        'late_count': attendance_records.filter(status='Late').count(),
        'leave_count': attendance_records.filter(status='On Leave').count(),
        'wfh_count': attendance_records.filter(status='Work From Home').count(),
        'half_day_count': attendance_records.filter(is_half_day=True).count(),
        'weekend_work_count': attendance_records.filter(is_weekend=True, status='Present').count(),
        'total_overtime_hours': attendance_records.aggregate(Sum('overtime_hours'))['overtime_hours__sum'] or 0,
        'avg_working_hours': attendance_records.filter(total_hours__isnull=False).aggregate(Avg('total_hours'))['total_hours__avg'] or 0
    }

    # Get previous and next month links
    prev_month = 12 if month == 1 else month - 1
    prev_year = year - 1 if month == 1 else year
    next_month = 1 if month == 12 else month + 1
    next_year = year + 1 if month == 12 else year

    # Create days range for all days
    days_range = [datetime(year, month, day).date() for day in range(1, days_in_month + 1)]

    # Handle download requests
    if 'format' in request.GET:
        return handle_attendance_download(request)

    context = {
        'attendance_matrix': attendance_matrix,
        'days_range': days_range,
        'month': month,
        'year': year,
        'month_name': calendar.month_name[month],
        'prev_month': prev_month,
        'prev_year': prev_year,
        'next_month': next_month, 
        'next_year': next_year,
        **summary
    }

    return render(request, 'components/hr/hr_admin_attendance.html', context)

def handle_attendance_download(request):
    """Handle attendance download requests for both direct and custom month downloads"""
    try:
        # Get format and date parameters
        export_format = request.GET.get('format', 'excel')
        
        # Check if this is a custom month request
        custom_month = request.GET.get('custom_month')
        if custom_month:
            # Parse custom month (format: YYYY-MM)
            year, month = map(int, custom_month.split('-'))
        else:
            # Use month and year from query parameters
            month = int(request.GET.get('month', datetime.now().month))
            year = int(request.GET.get('year', datetime.now().year))

        # Get first and last day of selected month
        first_day = datetime(year, month, 1).date()
        last_day = datetime(year, month, calendar.monthrange(year, month)[1]).date()

        # Get all users except clients
        employees = User.objects.select_related('userdetails').exclude(
            groups__name='Client'
        ).order_by('username')

        # Get attendance records for the month
        attendance_records = Attendance.objects.filter(
            date__range=[first_day, last_day]
        ).select_related('user', 'user__userdetails')

        # Export based on format
        if export_format == 'excel':
            return export_attendance_excel(employees, attendance_records, month, year)
        elif export_format == 'csv':
            return export_attendance_csv(employees, attendance_records, month, year)
        elif export_format == 'pdf':
            return export_attendance_pdf(employees, attendance_records, month, year)
        else:
            raise Http404("Invalid export format")
            
    except Exception as e:
        # Log the error and return an error response
        print(f"Export error: {str(e)}")  # Replace with proper logging
        return HttpResponse(
            "Error generating report. Please try again.",
            status=500
        )

def export_attendance_excel(employees, attendance_records, month, year):
    """Generate Excel version of attendance report"""
    from openpyxl import Workbook
    from openpyxl.styles import PatternFill, Font, Alignment
    import calendar
    from io import BytesIO
    
    wb = Workbook()
    ws = wb.active
    
    # Define styles
    header_fill = PatternFill(start_color='4B5563', end_color='4B5563', fill_type='solid')
    header_font = Font(bold=True, color='FFFFFF')
    center_align = Alignment(horizontal='center', vertical='center')
    
    # Get all dates in month (including weekends)
    days_in_month = calendar.monthrange(year, month)[1]
    dates = [datetime(year, month, day).date() for day in range(1, days_in_month + 1)]
    
    # Write headers
    headers = ['Employee', 'Username', 'Location', 'Role'] + [d.strftime('%d') for d in dates]
    for col, header in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col, value=header)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = center_align
    
    # Write data
    row = 2
    for employee in employees:
        ws.cell(row=row, column=1, value=f"{employee.first_name} {employee.last_name}").alignment = center_align
        ws.cell(row=row, column=2, value=employee.username).alignment = center_align
        ws.cell(row=row, column=3, value=employee.userdetails.work_location or 'Unknown').alignment = center_align
        ws.cell(row=row, column=4, value=', '.join(group.name for group in employee.groups.all())).alignment = center_align
        
        col = 5
        for date in dates:
            try:
                record = attendance_records.get(user=employee, date=date)
                status = record.status
                if record.is_half_day:
                    status = 'Half Day'
                elif record.leave_type:
                    status = f"{status} ({record.leave_type})"
                elif record.is_weekend:
                    status = 'Weekend'
            except Attendance.DoesNotExist:
                if date.weekday() == 6:  # Sunday
                    status = 'Weekend'
                else:
                    status = '-'
            ws.cell(row=row, column=col, value=status).alignment = center_align
            col += 1
        row += 1
    
    # Adjust column widths
    for col in range(1, len(headers) + 1):
        ws.column_dimensions[ws.cell(row=1, column=col).column_letter].width = 15
    
    # Save to BytesIO
    output = BytesIO()
    wb.save(output)
    output.seek(0)
    
    response = HttpResponse(
        output.read(),
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename="attendance_{month}_{year}.xlsx"'
    return response

def export_attendance_csv(employees, attendance_records, month, year):
    """Generate CSV version of attendance report"""
    import csv
    from io import StringIO
    
    output = StringIO()
    writer = csv.writer(output)
    
    # Get all dates in month (including weekends)
    days_in_month = calendar.monthrange(year, month)[1]
    dates = [datetime(year, month, day).date() for day in range(1, days_in_month + 1)]
    
    # Write headers
    headers = ['Employee', 'Username', 'Location', 'Role'] + [d.strftime('%d') for d in dates]
    writer.writerow(headers)
    
    # Write data
    for employee in employees:
        row = [
            f"{employee.first_name} {employee.last_name}",
            employee.username,
            employee.userdetails.work_location or 'Unknown',
            ', '.join(group.name for group in employee.groups.all())
        ]
        
        for date in dates:
            try:
                record = attendance_records.get(user=employee, date=date)
                status = record.status
                if record.is_half_day:
                    status = 'Half Day'
                elif record.leave_type:
                    status = f"{status} ({record.leave_type})"
                elif record.is_weekend:
                    status = 'Weekend'
            except Attendance.DoesNotExist:
                if date.weekday() == 6:  # Sunday
                    status = 'Weekend'
                else:
                    status = '-'
            row.append(status)
            
        writer.writerow(row)
    
    output.seek(0)
    response = HttpResponse(output.getvalue(), content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="attendance_{month}_{year}.csv"'
    return response

def export_attendance_pdf(employees, attendance_records, month, year):
    """Generate PDF version of attendance report"""
    return HttpResponse("PDF export is currently unavailable. Please try Excel or CSV format instead.", status=501)

'''------------------------------------------------ SUPPORT  AREA------------------------------------------------'''


@login_required
@user_passes_test(is_employee)
def employee_support(request):
    """Employee's Support Home with the ability to create a ticket."""
    
    if request.method == 'POST':
        issue_type = request.POST.get('issue_type')
        description = request.POST.get('description', '').strip()
        subject = request.POST.get('subject', 'No subject').strip()
        
        # Validate required fields
        if not issue_type or not description:
            messages.error(request, "Issue Type and Description are required.")
            return redirect('aps_employee:employee_support')

        # Assign responsible department (HR or Admin)
        assigned_to = (
            Support.AssignedTo.HR if issue_type == Support.IssueType.HR else Support.AssignedTo.ADMIN
        )

        # Assign priority dynamically
        priority_mapping = {
            Support.IssueType.HARDWARE: Support.Priority.HIGH,
            Support.IssueType.SOFTWARE: Support.Priority.MEDIUM,
            Support.IssueType.NETWORK: Support.Priority.CRITICAL,
            Support.IssueType.INTERNET: Support.Priority.CRITICAL,
            Support.IssueType.APPLICATION: Support.Priority.MEDIUM,
            Support.IssueType.HR: Support.Priority.LOW,
            Support.IssueType.ACCESS: Support.Priority.HIGH,
            Support.IssueType.SECURITY: Support.Priority.CRITICAL,
            Support.IssueType.SERVICE: Support.Priority.MEDIUM,
        }
        priority = priority_mapping.get(issue_type, Support.Priority.MEDIUM)

        # Set due date based on priority
        due_date_mapping = {
            Support.Priority.CRITICAL: now() + timedelta(hours=4),
            Support.Priority.HIGH: now() + timedelta(days=1),
            Support.Priority.MEDIUM: now() + timedelta(days=3),
            Support.Priority.LOW: now() + timedelta(days=5),
        }
        due_date = due_date_mapping.get(priority)

        try:
            with transaction.atomic():
                ticket = Support.objects.create(
                    user=request.user,
                    issue_type=issue_type,
                    description=description,
                    subject=subject,
                    status=Support.Status.NEW,
                    priority=priority,
                    assigned_to=assigned_to,
                    due_date=due_date,
                )
            messages.success(request, f"Ticket #{ticket.ticket_id} created successfully.")
        except Exception as e:
            messages.error(request, f"Error: {str(e)}")
            return redirect('aps_employee:employee_support')

    # Fetch tickets raised by the logged-in employee
    tickets = Support.objects.filter(user=request.user).order_by('-created_at')

    # Fetch issue type choices dynamically
    issue_type_choices = [choice[0] for choice in Support.IssueType.choices]

    return render(request, 'components/employee/support.html', {
        'tickets': tickets,
        'issue_type_choices': issue_type_choices
    })


from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.db.models import Q
from .models import Support, StatusLog
from django.utils.timezone import now

def is_admin(user):
    return user.groups.filter(name='Admin').exists()

@login_required
@user_passes_test(is_admin)
def admin_support(request, ticket_id=None):
    try:
        if ticket_id:
            ticket = get_object_or_404(Support, ticket_id=ticket_id)
            
            if request.method == 'POST':
                new_status = request.POST.get('status')
                if new_status in dict(Support.Status.choices):
                    old_status = ticket.status
                    ticket.status = new_status
                    
                    # Update resolved_at if status changed to Resolved
                    if new_status == Support.Status.RESOLVED and old_status != Support.Status.RESOLVED:
                        ticket.resolved_at = now()
                    elif new_status != Support.Status.RESOLVED:
                        ticket.resolved_at = None
                        
                    ticket.save()
                    
                    # Log status change
                    StatusLog.objects.create(
                        ticket=ticket,
                        old_status=old_status,
                        new_status=new_status,
                        changed_by=request.user
                    )
                    
                    messages.success(request, f"Ticket {ticket.ticket_id} updated to {new_status}.")
                    return redirect('aps_admin:admin_support')
                else:
                    messages.error(request, "Invalid status selected.")
            
            return render(request, 'components/admin/support_admin.html', {
                'ticket': ticket,
                'is_admin': True
            })
        
        # List view with filters
        tickets = Support.objects.all().select_related('user')
        
        # Apply filters
        status_filter = request.GET.get('status')
        issue_type_filter = request.GET.get('issue_type')
        
        if status_filter:
            tickets = tickets.filter(status=status_filter)
        if issue_type_filter:
            tickets = tickets.filter(issue_type=issue_type_filter)
            
        context = {
            'tickets': tickets,
            'open_tickets': Support.objects.filter(status=Support.Status.OPEN).count(),
            'in_progress_tickets': Support.objects.filter(status=Support.Status.IN_PROGRESS).count(),
            'resolved_tickets': Support.objects.filter(status=Support.Status.RESOLVED).count(),
            'is_admin': True
        }
        return render(request, 'components/admin/support_admin.html', context)
        
    except Exception as e:
        messages.error(request, f"An error occurred while managing tickets: {str(e)}")
        return redirect('aps_admin:admin_support')

def is_hr(user):
    return user.groups.filter(name='HR').exists()

@login_required
@user_passes_test(is_hr)
def hr_support(request, ticket_id=None):
    """HR view to manage tickets and see ticket details."""
    try:
        if ticket_id:
            ticket = get_object_or_404(Support, ticket_id=ticket_id)
            
            if request.method == 'POST':
                new_status = request.POST.get('status')
                if new_status in dict(Support.Status.choices):
                    if ticket.assigned_to == Support.AssignedTo.HR:
                        old_status = ticket.status
                        ticket.status = new_status
                        
                        # Update resolved_at if status changed to Resolved
                        if new_status == Support.Status.RESOLVED and old_status != Support.Status.RESOLVED:
                            ticket.resolved_at = now()
                        elif new_status != Support.Status.RESOLVED:
                            ticket.resolved_at = None
                            
                        ticket.save()
                        
                        # Log status change
                        StatusLog.objects.create(
                            ticket=ticket,
                            old_status=old_status,
                            new_status=new_status,
                            changed_by=request.user
                        )
                        
                        messages.success(request, f"Ticket {ticket.ticket_id} updated to {new_status}.")
                        return redirect('aps_hr:hr_support')
                    else:
                        messages.error(request, "You can only update HR-assigned tickets.")
                else:
                    messages.error(request, "Invalid status selected.")
            
            return render(request, 'components/hr/support_hr.html', {
                'ticket': ticket,
                'is_hr': True,
                'can_update': ticket.assigned_to == Support.AssignedTo.HR
            })
        
        # List view with filters
        tickets = Support.objects.filter(
            Q(assigned_to=Support.AssignedTo.HR) |
            Q(issue_type=Support.IssueType.HR)
        ).select_related('user').order_by('-created_at')
        
        # Apply filters
        status_filter = request.GET.get('status')
        if status_filter:
            tickets = tickets.filter(status=status_filter)
        
        context = {
            'tickets': tickets,
            'open_tickets': tickets.filter(status=Support.Status.OPEN).count(),
            'in_progress_tickets': tickets.filter(status=Support.Status.IN_PROGRESS).count(),
            'resolved_tickets': tickets.filter(status=Support.Status.RESOLVED).count(),
            'is_hr': True,
            'total_tickets': tickets.count()
        }
        
        return render(request, 'components/hr/support_hr.html', context)
        
    except Exception as e:
        print(f"HR Support Error: {str(e)}")  # For debugging
        messages.error(request, f"An error occurred while managing tickets: {str(e)}")
        return redirect('aps_hr:hr_support')

'''----- Temeporray views -----'''

# Assign Tasks View
@login_required
def assign_tasks(request):
    # Placeholder context data
    context = {
        'title': 'Assign Tasks',
        'tasks': [],  # Example data (you can replace this with actual task data)
    }
    return render(request, 'components/manager/assign_tasks.html', context)

# Approve Leaves View
@login_required
def approve_leave(request):
    # Placeholder context data
    context = {
        'title': 'Approve Leaves',
        'leave_requests': [],  # Example data (you can replace this with actual leave request data)
    }
    return render(request, 'components/manager/approve_leave.html', context)

'''-------------------------- CHAT SYSTEM --------------------------------'''
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User, Group
from django.contrib import messages
from django.db.models import Q, Count, OuterRef, Subquery, F
from django.core.exceptions import PermissionDenied
from django.utils import timezone
from django.http import JsonResponse
from functools import wraps
import re

from .models import ChatGroup, GroupMember, DirectMessage, Message, MessageRead
from .services import get_chat_history, mark_messages_as_read, get_unread_counts, create_group
from .utils import validate_user_in_chat, send_notification

@login_required
def chat_home(request, chat_type=None, chat_id=None):
    """Main chat view that renders the chat interface and handles all chat functionality"""
    try:
        # Get available users based on role
        is_admin = request.user.groups.filter(name='Admin').exists()
        is_manager = request.user.groups.filter(name='Manager').exists()

        available_users = User.objects.exclude(id=request.user.id)
        if not is_admin:
            if is_manager:
                available_users = available_users.filter(groups__name='Employee')
            else:
                available_users = available_users.filter(
                    Q(groups__name='Manager') | Q(groups__name='HR')
                )

        # Get chat lists for sidebar - Updated query
        group_chats = ChatGroup.objects.filter(
            memberships__user=request.user,
            memberships__is_active=True,
            is_active=True
        ).annotate(
            unread_count=Count(
                'messages',
                filter=Q(
                    messages__read_receipts__user=request.user,
                    messages__read_receipts__read_at__isnull=True,
                    messages__is_deleted=False
                )
            ),
            latest_message=Subquery(
                Message.objects.filter(
                    group=OuterRef('pk'),
                    is_deleted=False
                ).order_by('-sent_at').values('content')[:1]
            )
        ).prefetch_related('memberships', 'messages')

        direct_messages = DirectMessage.objects.filter(
            participants=request.user,
            is_active=True
        ).annotate(
            unread_count=Count(
                'messages',
                filter=Q(
                    messages__read_receipts__user=request.user,
                    messages__read_receipts__read_at__isnull=True,
                    messages__is_deleted=False
                )
            ),
            latest_message=Subquery(
                Message.objects.filter(
                    direct_message=OuterRef('pk'),
                    is_deleted=False
                ).order_by('-sent_at').values('content')[:1]
            )
        ).prefetch_related('participants', 'messages')

        # Add other participant info for direct messages
        for dm in direct_messages:
            dm.other_user = dm.participants.exclude(id=request.user.id).first()

        context = {
            'group_chats': group_chats,
            'direct_messages': direct_messages,
            'available_users': available_users,
            'is_admin': is_admin,
            'is_manager': is_manager,
            'unread_counts': get_unread_counts(request.user)
        }

        # Handle chat detail view
        if chat_type and chat_id:
            try:
                validate_user_in_chat(request.user, chat_id)
                
                if chat_type == 'group':
                    chat = get_object_or_404(ChatGroup, id=chat_id, is_active=True)
                    other_participant = None
                else:
                    chat = get_object_or_404(DirectMessage, id=chat_id, is_active=True)
                    other_participant = chat.participants.exclude(id=request.user.id).first()

                messages_list = get_chat_history(chat_id, request.user, chat_type)
                
                # Mark messages as read and only send notification if messages were actually read
                unread_count = mark_messages_as_read(chat_id, request.user, chat_type)
                
                # Only send notification if there were unread messages
                if unread_count > 0:
                    try:
                        send_notification(
                            request.user.id,
                            "Messages marked as read",
                            "read_status",
                            chat_id
                        )
                    except Exception as notify_error:
                        # Log notification errors without breaking the app flow
                        import logging
                        logger = logging.getLogger(__name__)
                        logger.error(f"Notification error: {str(notify_error)}")
                
                context.update({
                    'chat': chat,
                    'chat_type': chat_type,
                    'messages': messages_list,
                    'other_participant': other_participant,
                    'can_manage': request.user.groups.filter(name__in=['Admin', 'Manager']).exists(),
                    'chat_detail_view': True                
                })

            except Exception as e:
                messages.error(request, f'Error loading chat: {str(e)}')
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({'error': str(e)}, status=400)
                return redirect('dashboard')
            

        # Handle create group chat
        if request.method == 'POST' and request.POST.get('action') == 'create_group':
            if not request.user.groups.filter(name__in=['Admin', 'Manager']).exists():
                raise PermissionDenied("You don't have permission to create groups")
                
            try:
                name = request.POST.get('name')
                description = request.POST.get('description', '')
                member_ids = request.POST.getlist('members')

                chat = create_group(name, request.user, description)
                GroupMember.objects.bulk_create([
                    GroupMember(group=chat, user_id=member_id, role='member', is_active=True)
                    for member_id in member_ids
                ])

                for member_id in member_ids:
                    send_notification(
                        member_id,
                        f"You've been added to group chat: {name}",
                        "group_add",
                        chat.id,
                        request.user.username
                    )

                messages.success(request, 'Group chat created successfully')
                return redirect('chat:detail', chat_type='group', chat_id=chat.id)

            except Exception as e:
                messages.error(request, f'Error creating group: {str(e)}')
                return redirect('dashboard')

        # Handle create direct message
        if request.method == 'POST' and request.POST.get('action') == 'create_direct':
            try:
                user_id = request.POST.get('user_id')
                if not user_id:
                    raise ValueError("No user_id provided")
                    
                other_user = get_object_or_404(User, id=user_id)

                existing_chat = DirectMessage.objects.filter(
                    participants=request.user
                ).filter(
                    participants=other_user,
                    is_active=True
                ).first()

                if existing_chat:
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return JsonResponse({'chat_id': existing_chat.id})
                    return redirect('chat:detail', chat_type='direct', chat_id=existing_chat.id)

                chat = DirectMessage.objects.create(is_active=True)
                chat.participants.add(request.user)
                chat.participants.add(other_user)
                chat.save()

                send_notification(
                    other_user.id,
                    f"New message from {request.user.get_full_name() or request.user.username}",
                    "direct_message",
                    chat.id,
                    request.user.username
                )

                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({'chat_id': chat.id})
                return redirect('chat:detail', chat_type='direct', chat_id=chat.id)

            except Exception as e:
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({'error': str(e)}, status=400)
                messages.error(request, f'Error creating chat: {str(e)}')
                return redirect('dashboard')

        # Handle message sending
        if request.method == 'POST' and request.POST.get('message'):
            try:
                content = request.POST.get('message')
                message_type = request.POST.get('message_type', 'text')
                file_attachment = request.FILES.get('file_attachment')  # Get the file attachment
                
                # Start a database transaction to ensure message and read receipts are created atomically
                from django.db import transaction
                
                with transaction.atomic():
                    if chat_type == 'group':
                        chat = get_object_or_404(ChatGroup, id=chat_id)
                        message = Message.objects.create(
                            group=chat,
                            sender=request.user,
                            content=content,
                            message_type=message_type,
                            file_attachment=file_attachment  # Attach the file
                        )
                        
                        # Get all active members for this group
                        participants = User.objects.filter(
                            group_memberships__group=chat,
                            group_memberships__is_active=True
                        )
                        
                    else:
                        chat = get_object_or_404(DirectMessage, id=chat_id)
                        message = Message.objects.create(
                            direct_message=chat,
                            sender=request.user,
                            content=content,
                            message_type=message_type,
                            file_attachment=file_attachment  # Attach the file
                        )
                        
                        # Get all participants for this direct message
                        participants = chat.participants.all()
                    
                    # Create read receipt for sender (already read)
                    MessageRead.objects.create(
                        message=message, 
                        user=request.user, 
                        read_at=timezone.now()
                    )
                    
                    # Create read receipts for other participants (unread)
                    other_participants = participants.exclude(id=request.user.id)
                    read_receipts = [
                        MessageRead(message=message, user=participant)
                        for participant in other_participants
                    ]
                    
                    if read_receipts:
                        MessageRead.objects.bulk_create(read_receipts)
                        
                    # Notify other participants about the new message
                    for participant in other_participants:
                        try:
                            sender_name = request.user.get_full_name() or request.user.username
                            send_notification(
                                participant.id,
                                f"New message from {sender_name}",
                                "new_message",
                                chat_id,
                                sender_name
                            )
                        except Exception as notify_error:
                            # Log notification errors without breaking the message flow
                            import logging
                            logger = logging.getLogger(__name__)
                            logger.error(f"Notification error: {str(notify_error)}")

            except Exception as e:
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({'status': 'error', 'error': str(e)}, status=400)
                messages.error(request, f'Error sending message: {str(e)}')
                return redirect('chat:detail', chat_type=chat_type, chat_id=chat_id)
                    
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'status': 'success', 'message_id': message.id})
            return redirect('chat:detail', chat_type=chat_type, chat_id=chat_id)
        
        # Default return for GET requests when no other actions are taken
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return render(request, 'chat/chat_content.html', context)
        return render(request, 'chat/chat_home.html', context)

    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error in chat_home view: {str(e)}")
                
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'status': 'error', 'error': str(e)}, status=400)
        messages.error(request, f'Error: {str(e)}')
        return redirect('dashboard')





'''-------------------------- MANUAL ATTENDACE BY HR  --------------------------------'''
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.utils.timezone import now
from django.contrib.auth.models import User, Group
from .models import Presence, PresenceStatus
from datetime import datetime
from django.db.models import Q
from trueAlign.context_processors import is_management


def is_hr(user):
    """Check if user is HR"""
    return user.groups.filter(name="HR").exists()

def is_management(request):
    """Check if the user belongs to the 'Management' group."""
    return {'is_management': request.user.groups.filter(name="Management").exists()} if request.user.is_authenticated else {'is_management': False}

@login_required
@user_passes_test(is_hr)
def manual_attendance(request):
    try:
        # Get date from query parameters or use current date
        date_str = request.GET.get('date')
        attendance_date = datetime.strptime(date_str, '%Y-%m-%d').date() if date_str else now().date()

        # Get manageable users (Management and Backoffice users)
        manageable_users = User.objects.filter(is_active=True).filter(
            Q(groups__name="Management") | Q(groups__name="Backoffice")
        ).distinct()

        if request.method == "POST":
            attendance_date = datetime.strptime(request.POST.get('date'), '%Y-%m-%d').date()
            
            # Process each user's attendance data
            for user in manageable_users:
                user_id = str(user.id)
                status_key = f'attendance[{user_id}][status]'
                notes_key = f'attendance[{user_id}][notes]'
                
                if status_key in request.POST:
                    status = request.POST.get(status_key)
                    notes = request.POST.get(notes_key, '').strip()
                    
                    # Update or create attendance record
                    Presence.objects.update_or_create(
                        user=user,
                        date=attendance_date,
                        defaults={
                            'status': status,
                            'notes': notes,
                            'marked_by': request.user,
                            'marked_at': now()
                        }
                    )
            
            messages.success(request, "Attendance marked successfully")
            return redirect('aps_hr:manual_attendance')

        # Get existing presence records for the selected date
        presences = Presence.objects.filter(date=attendance_date, user__in=manageable_users)
        
        # Check if user is in Management group directly
        is_management_user = request.user.groups.filter(name="Management").exists()
        
        # Prepare context for template rendering
        context = {
            'presences': presences,
            'employees': manageable_users,
            'statuses': PresenceStatus.choices,
            'date_filter': attendance_date,
            'today': now().date(),
            'is_hr': True,
            'is_management': is_management(request)  # Add this directly
        }
        
        # Debug line to verify the context
        print(f"Context contains is_management: {context}")

        return render(request, 'components/hr/markAttendace.html', context)

    except Exception as e:
        messages.error(request, f"An error occurred: {str(e)}")
        return redirect('aps_hr:manual_attendance')
    

'''----------------------------------- APPLICATION FOR EMPLOYEE --------------------------------'''

def is_employee(user):
    """
    Check if user is an employee (not admin/management).
    Returns True if user belongs to Employee group.
    """
    return user.groups.filter(name='Employee').exists()
@login_required
@user_passes_test(is_employee)
def application_for_user(request):
    """
    Placeholder view that renders the application dashboard template.
    This is currently a dummy view that will be implemented later.
    """
    try:
        # Dummy data for now
        context = {
            'applications': {},
            'user': request.user,
            'page_title': 'Application Dashboard'
        }
        return render(request, 'components/employee/application_dashboard.html', context)

    except Exception as e:
        messages.error(request, f"Error loading application dashboard: {str(e)}")
        return redirect('dashboard')



'''------------------------------------- SHIFTS ----------------------------------'''
"""
SHIFT MASTER VIEWS
This module provides views for managing shifts, assignments and holidays.
Access is restricted to users in the 'Manager' or 'Admin' groups.
"""
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.utils import timezone
from django.db.models import Q, Count, Prefetch
from django.core.paginator import Paginator
from django.http import JsonResponse, HttpResponseBadRequest
from django.contrib.auth.models import User
from django.db import transaction
from datetime import timedelta, datetime

from .models import ShiftMaster, ShiftAssignment, Holiday

def is_manager_or_admin(user):
    return user.groups.filter(name__in=['Manager', 'Admin']).exists() or user.is_superuser
@login_required
@user_passes_test(is_manager_or_admin)
def shift_dashboard(request):
    # Get shift statistics
    shift_stats = ShiftMaster.objects.aggregate(
        total_shifts=Count('id'),
        active_shifts=Count('id', filter=Q(is_active=True))
    )

    # Get upcoming holidays
    today = timezone.now().date()
    upcoming_holidays = Holiday.objects.filter(
        date__gte=today
    ).order_by('date')[:5]

    # Get current user's shift
    user_shift = ShiftAssignment.get_user_current_shift(request.user)

    # Get recent shift assignments with user and shift details
    recent_assignments = ShiftAssignment.objects.filter(
        is_current=True
    ).select_related(
        'user',
        'shift'
    ).order_by(
        '-created_at'
    )[:10]

    context = {
        'total_shifts': shift_stats['total_shifts'],
        'active_shifts': shift_stats['active_shifts'], 
        'total_holidays': Holiday.objects.count(),
        'upcoming_holidays': upcoming_holidays,
        'user_shift': user_shift,
        'recent_assignments': recent_assignments,
    }

    return render(request, 'components/manager/shifts/dashboard.html', context)

@login_required
@user_passes_test(is_manager_or_admin)
def shift_list(request):
    try:
        is_active = request.GET.get('is_active')
        search_query = request.GET.get('search', '')
        shifts = ShiftMaster.objects.all()
        if is_active in ['true', 'false']:
            shifts = shifts.filter(is_active=(is_active == 'true'))
        if search_query:
            shifts = shifts.filter(Q(name__icontains=search_query))
        shifts = shifts.prefetch_related(
            Prefetch(
                'shiftassignment_set',
                queryset=ShiftAssignment.objects.filter(is_current=True),
                to_attr='current_assignments'
            )
        ).order_by('-created_at')
        paginator = Paginator(shifts, 10)
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)
        
        # Get shift detail if requested
        shift_detail = None
        shift_pk = request.GET.get('shift_detail')
        assignments = None
        total_assigned = None
        if shift_pk:
            try:
                shift_detail = get_object_or_404(ShiftMaster, pk=shift_pk)
                assignments = ShiftAssignment.objects.filter(
                    shift=shift_detail,
                    is_current=True
                ).select_related('user')
                total_assigned = assignments.count()
            except ShiftMaster.DoesNotExist:
                messages.error(request, "Requested shift does not exist.")
                return redirect('aps_manager:shift_list')
        
        context = {
            'page_obj': page_obj,
            'search_query': search_query,
            'is_active': is_active,
            'weekdays': ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'],
            'shift_detail': shift_detail,
            'assignments': assignments,
            'total_assigned': total_assigned,
        }
        
        # If editing a shift, add it to context
        shift_edit_pk = request.GET.get('shift_edit')
        if shift_edit_pk:
            try:
                shift = get_object_or_404(ShiftMaster, pk=shift_edit_pk)
                context['shift'] = shift
                context['selected_days'] = shift.custom_work_days.split(',') if shift.custom_work_days else []
            except ShiftMaster.DoesNotExist:
                messages.error(request, "Shift to edit does not exist.")
                return redirect('aps_manager:shift_list')
        
        # If deleting a shift, add delete context
        shift_delete_pk = request.GET.get('shift_delete')
        if shift_delete_pk:
            try:
                shift = get_object_or_404(ShiftMaster, pk=shift_delete_pk)
                active_assignments = ShiftAssignment.objects.filter(shift=shift, is_current=True)
                has_active_assignments = active_assignments.exists()
                all_assignments = ShiftAssignment.objects.filter(shift=shift)
                has_any_assignments = all_assignments.exists()
                
                context['shift'] = shift
                context['has_active_assignments'] = has_active_assignments
                context['has_any_assignments'] = has_any_assignments
                context['assignment_count'] = all_assignments.count()
            except ShiftMaster.DoesNotExist:
                messages.error(request, "Shift to delete does not exist.")
                return redirect('aps_manager:shift_list')
        
        return render(request, 'components/manager/shifts/shift_list.html', context)
        
    except Exception as e:
        messages.error(request, f"An error occurred while loading shifts: {str(e)}")
        return redirect('aps_manager:shift_list')

@login_required
@user_passes_test(is_manager_or_admin)
def shift_detail(request, pk):
    try:
        # Redirect to shift_list with shift_detail parameter
        return redirect(f'aps_manager:shift_list')
    except Exception as e:
        messages.error(request, f"Error accessing shift detail: {str(e)}")
        return redirect('aps_manager:shift_list')

@login_required
@user_passes_test(is_manager_or_admin)
def shift_create(request):
    try:
        if request.method == 'POST':
            name = request.POST.get('name')
            start_time = request.POST.get('start_time')
            end_time = request.POST.get('end_time')
            is_active = request.POST.get('is_active') == 'on'
            work_days = request.POST.get('work_days')
            
            if not name or not start_time or not end_time or not work_days:
                messages.error(request, "All fields are required.")
                return redirect('aps_manager:shift_list')
            
            # Handle custom work days
            custom_work_days = None
            if work_days == 'Custom':
                custom_days = request.POST.getlist('custom_days')
                if not custom_days:
                    messages.error(request, "Please select at least one day for custom schedule.")
                    return redirect('aps_manager:shift_list')
                custom_work_days = ','.join(custom_days)
            
            try:
                shift = ShiftMaster.objects.create(
                    name=name,
                    start_time=start_time,
                    end_time=end_time,
                    is_active=is_active,
                    work_days=work_days,
                    custom_work_days=custom_work_days
                )
                messages.success(request, f"Shift '{shift.name}' created successfully!")
                return redirect('aps_manager:shift_list')
            except Exception as e:
                messages.error(request, f"Error creating shift: {str(e)}")
                return redirect('aps_manager:shift_list')
        
        # For GET requests, redirect to shift_list with shift_create parameter
        return redirect('aps_manager:shift_list')
    except Exception as e:
        messages.error(request, f"An unexpected error occurred: {str(e)}")
        return redirect('aps_manager:shift_list')

@login_required
@user_passes_test(is_manager_or_admin)
def shift_update(request, pk):
    try:
        shift = get_object_or_404(ShiftMaster, pk=pk)
        if request.method == 'POST':
            try:
                name = request.POST.get('name')
                start_time = request.POST.get('start_time')
                end_time = request.POST.get('end_time')
                is_active = request.POST.get('is_active') == 'on'
                work_days = request.POST.get('work_days')
                
                if not name or not start_time or not end_time or not work_days:
                    messages.error(request, "All fields are required.")
                    return redirect('aps_manager:shift_list')
                    
                # Handle custom work days
                custom_work_days = None
                if work_days == 'Custom':
                    custom_days = request.POST.getlist('custom_days')
                    if not custom_days:
                        messages.error(request, "Please select at least one day for custom schedule.")
                        return redirect('aps_manager:shift_list')
                    custom_work_days = ','.join(custom_days)
                    
                shift.name = name
                shift.start_time = start_time
                shift.end_time = end_time
                shift.is_active = is_active
                shift.work_days = work_days
                shift.custom_work_days = custom_work_days
                shift.save()
                messages.success(request, f"Shift '{shift.name}' updated successfully!")
                return redirect('aps_manager:shift_list')
            except Exception as e:
                messages.error(request, f"Error updating shift: {str(e)}")
                return redirect('aps_manager:shift_list')
        else:
            # Redirect to shift_list with shift_edit parameter
            return redirect(f'aps_manager:shift_list')
    except ShiftMaster.DoesNotExist:
        messages.error(request, "Shift not found.")
        return redirect('aps_manager:shift_list')
    except Exception as e:
        messages.error(request, f"An unexpected error occurred: {str(e)}")
        return redirect('aps_manager:shift_list')

@login_required
@user_passes_test(is_manager_or_admin)
def shift_delete(request, pk):
    try:
        shift = get_object_or_404(ShiftMaster, pk=pk)
        
        if request.method == 'POST':
            try:
                # Check for active assignments
                active_assignments = ShiftAssignment.objects.filter(shift=shift, is_current=True)
                has_active_assignments = active_assignments.exists()
                all_assignments = ShiftAssignment.objects.filter(shift=shift)
                
                # Check if force delete option was selected
                force_delete = request.POST.get('force_delete') == 'true'
                
                if has_active_assignments and not force_delete:
                    # Only show warning if not forcing deletion
                    messages.warning(
                        request,
                        f"Shift '{shift.name}' has active assignments. Use the force delete option to delete anyway."
                    )
                    return redirect('aps_manager:shift_list')
                
                with transaction.atomic():
                    shift_name = shift.name
                    # Delete all assignments related to this shift
                    all_assignments.delete()
                    shift.delete()
                    messages.success(request, f"Shift '{shift_name}' deleted successfully!")
                
                return redirect('aps_manager:shift_list')
            except Exception as e:
                messages.error(request, f"Error during shift deletion: {str(e)}")
                return redirect('aps_manager:shift_list')
        else:
            # Redirect to shift_list with shift_delete parameter
            return redirect(f'aps_manager:shift_list')
    except ShiftMaster.DoesNotExist:
        messages.error(request, "Shift not found.")
        return redirect('aps_manager:shift_list')
    except Exception as e:
        messages.error(request, f"An unexpected error occurred: {str(e)}")
        return redirect('aps_manager:shift_list')

@login_required
@user_passes_test(is_manager_or_admin)
def holiday_list(request):
    year = request.GET.get('year', timezone.now().year)
    try:
        year = int(year)
    except (ValueError, TypeError):
        year = timezone.now().year
    recurring_only = request.GET.get('recurring_only') == 'true'
    
    # Fix: Initialize holidays query properly
    if recurring_only:
        holidays = Holiday.objects.filter(recurring_yearly=True)
    else:
        start_date = datetime(year, 1, 1).date()
        end_date = datetime(year, 12, 31).date()
        holidays = Holiday.objects.filter(
            Q(recurring_yearly=True) | 
            Q(date__range=(start_date, end_date))
        )
    
    # Use database-agnostic way to extract month and day
    holidays = holidays.order_by('date__month', 'date__day')
    
    current_year = timezone.now().year
    year_range = range(current_year - 2, current_year + 3)
    paginator = Paginator(holidays, 15)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    context = {
        'page_obj': page_obj,
        'year': year,
        'year_range': year_range,
        'recurring_only': recurring_only,
    }
    return render(request, 'components/manager/shifts/holiday_list.html', context)

@login_required
@user_passes_test(is_manager_or_admin)
def holiday_create(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        date = request.POST.get('date')
        recurring_yearly = request.POST.get('recurring_yearly') == 'on'
        if not name or not date:
            messages.error(request, "Name and date are required.")
            return redirect('aps_manager:holiday_list')
        try:
            # Validate date format before creating
            date_obj = datetime.strptime(date, '%Y-%m-%d').date()
            holiday = Holiday.objects.create(
                name=name,
                date=date_obj,
                recurring_yearly=recurring_yearly
            )
            messages.success(request, f"Holiday '{holiday.name}' created successfully!")
            return redirect('aps_manager:holiday_list')
        except ValueError:
            messages.error(request, "Invalid date format. Please use YYYY-MM-DD.")
            return redirect('aps_manager:holiday_list')
        except Exception as e:
            messages.error(request, f"Error creating holiday: {str(e)}")
            return redirect('aps_manager:holiday_list')
    else:
        return redirect('aps_manager:holiday_list')

@login_required
@user_passes_test(is_manager_or_admin)
def holiday_update(request, pk):
    holiday = get_object_or_404(Holiday, pk=pk)
    if request.method == 'POST':
        name = request.POST.get('name')
        date = request.POST.get('date')
        recurring_yearly = request.POST.get('recurring_yearly') == 'on'
        if not name or not date:
            messages.error(request, "Name and date are required.")
            return redirect('aps_manager:holiday_list')
        try:
            # Validate date format before updating
            date_obj = datetime.strptime(date, '%Y-%m-%d').date()
            holiday.name = name
            holiday.date = date_obj
            holiday.recurring_yearly = recurring_yearly
            holiday.save()
            messages.success(request, f"Holiday '{holiday.name}' updated successfully!")
            return redirect('aps_manager:holiday_list')
        except ValueError:
            messages.error(request, "Invalid date format. Please use YYYY-MM-DD.")
            return redirect('aps_manager:holiday_list')
        except Exception as e:
            messages.error(request, f"Error updating holiday: {str(e)}")
            return redirect('aps_manager:holiday_list')
    else:
        return redirect('aps_manager:holiday_list')

@login_required
@user_passes_test(is_manager_or_admin)
def holiday_delete(request, pk):
    holiday = get_object_or_404(Holiday, pk=pk)
    if request.method == 'POST':
        with transaction.atomic():
            holiday_name = holiday.name
            holiday.delete()
            messages.success(request, f"Holiday '{holiday_name}' deleted successfully!")
        return redirect('aps_manager:holiday_list')
    else:
        return redirect('aps_manager:holiday_list')

@login_required
@user_passes_test(is_manager_or_admin)
def assignment_list(request):
    assignments = ShiftAssignment.objects.all().select_related('user', 'shift')
    current_only = request.GET.get('current_only') == 'true'
    user_id = request.GET.get('user_id')
    shift_id = request.GET.get('shift_id')
    if current_only:
        assignments = assignments.filter(is_current=True)
    if user_id and user_id.isdigit():
        assignments = assignments.filter(user_id=int(user_id))
    if shift_id and shift_id.isdigit():
        assignments = assignments.filter(shift_id=int(shift_id))
    assignments = assignments.order_by('-created_at')
    paginator = Paginator(assignments, 15)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    users = User.objects.all().order_by('username')
    shifts = ShiftMaster.objects.filter(is_active=True).order_by('name')
    context = {
        'page_obj': page_obj,
        'users': users,
        'shifts': shifts,
        'current_only': current_only,
        'selected_user': int(user_id) if user_id and user_id.isdigit() else None,
        'selected_shift': int(shift_id) if shift_id and shift_id.isdigit() else None,
    }
    return render(request, 'components/manager/shifts/assignment_list.html', context)

@login_required
@user_passes_test(is_manager_or_admin)
def assignment_create(request):
    if request.method != 'POST':
        return HttpResponseBadRequest("Only POST requests are allowed")
    user_id = request.POST.get('user')
    shift_id = request.POST.get('shift')
    effective_from = request.POST.get('effective_from')
    effective_to = request.POST.get('effective_to')
    is_current = request.POST.get('is_current') == 'on'
    # Validate required fields
    if not user_id or not shift_id or not effective_from:
        messages.error(request, "User, shift, and effective from date are required.")
        return redirect('aps_manager:assignment_list')
    # Validate date format
    try:
        effective_from_date = datetime.strptime(effective_from, "%Y-%m-%d").date()
    except (ValueError, TypeError):
        messages.error(request, "Effective from date must be in YYYY-MM-DD format.")
        return redirect('aps_manager:assignment_list')
    effective_to_date = None
    if effective_to:
        try:
            effective_to_date = datetime.strptime(effective_to, "%Y-%m-%d").date()
            # Validate date range
            if effective_to_date < effective_from_date:
                messages.error(request, "Effective to date cannot be earlier than effective from date.")
                return redirect('aps_manager:assignment_list')
        except (ValueError, TypeError):
            messages.error(request, "Effective to date must be in YYYY-MM-DD format.")
            return redirect('aps_manager:assignment_list')
    try:
        user = User.objects.get(pk=user_id)
        shift = ShiftMaster.objects.get(pk=shift_id)
        
        # Check if shift is active
        if not shift.is_active:
            messages.error(request, f"Cannot assign inactive shift '{shift.name}'.")
            return redirect('aps_manager:assignment_list')
            
        assignment = ShiftAssignment.objects.create(
            user=user,
            shift=shift,
            effective_from=effective_from_date,
            effective_to=effective_to_date,
            is_current=is_current
        )
        messages.success(request, f"Shift assignment for {assignment.user.username} created successfully!")
    except User.DoesNotExist:
        messages.error(request, "Selected user does not exist.")
    except ShiftMaster.DoesNotExist:
        messages.error(request, "Selected shift does not exist.")
    except Exception as e:
        messages.error(request, f"Failed to create shift assignment: {str(e)}")
    return redirect('aps_manager:assignment_list')

@login_required
@user_passes_test(is_manager_or_admin)
def bulk_assignment(request):
    if request.method != 'POST':
        return HttpResponseBadRequest("Only POST requests are allowed")
    user_ids = request.POST.getlist('user_ids')
    if not user_ids:
        messages.error(request, "No users selected for bulk assignment")
        return redirect('aps_manager:assignment_list')
    shift_id = request.POST.get('shift_id')
    effective_from = request.POST.get('effective_from')
    effective_to = request.POST.get('effective_to')
    is_current = request.POST.get('is_current') == 'on'
    # Validate required fields
    if not shift_id or not effective_from:
        messages.error(request, "Shift and effective from date are required for adding users")
        return redirect('aps_manager:assignment_list')
    # Validate date format
    try:
        effective_from_date = datetime.strptime(effective_from, "%Y-%m-%d").date()
    except (ValueError, TypeError):
        messages.error(request, "Effective from date must be in YYYY-MM-DD format.")
        return redirect('aps_manager:assignment_list')
    effective_to_date = None
    if effective_to:
        try:
            effective_to_date = datetime.strptime(effective_to, "%Y-%m-%d").date()
            # Validate date range
            if effective_to_date < effective_from_date:
                messages.error(request, "Effective to date cannot be earlier than effective from date.")
                return redirect('aps_manager:assignment_list')
        except (ValueError, TypeError):
            messages.error(request, "Effective to date must be in YYYY-MM-DD format.")
            return redirect('aps_manager:assignment_list')
    try:
        shift = ShiftMaster.objects.get(pk=shift_id)
        # Check if shift is active
        if not shift.is_active:
            messages.error(request, f"Cannot assign inactive shift '{shift.name}'.")
            return redirect('aps_manager:assignment_list')
    except ShiftMaster.DoesNotExist:
        messages.error(request, "Selected shift does not exist")
        return redirect('aps_manager:assignment_list')
    created_count = 0
    errors = []
    with transaction.atomic():
        for user_id in user_ids:
            try:
                user = User.objects.get(pk=user_id)
                exists = ShiftAssignment.objects.filter(
                    user=user,
                    shift=shift,
                    effective_from=effective_from_date,
                    effective_to=effective_to_date,
                ).exists()
                if not exists:
                    ShiftAssignment.objects.create(
                        user=user,
                        shift=shift,
                        effective_from=effective_from_date,
                        effective_to=effective_to_date,
                        is_current=is_current,
                    )
                    created_count += 1
            except User.DoesNotExist:
                errors.append(f"User ID {user_id}: User does not exist")
            except ValueError as ve:
                errors.append(f"User ID {user_id}: Invalid date format. {str(ve)}")
            except Exception as e:
                errors.append(f"User ID {user_id}: {str(e)}")
    if created_count:
        messages.success(request, f"Shift assigned to {created_count} employee(s) successfully!")
    if errors:
        messages.error(request, "Some assignments failed: " + "; ".join(errors))
    return redirect('aps_manager:assignment_list')

@login_required
@user_passes_test(is_manager_or_admin)
def assignment_update(request, pk):
    if request.method != 'POST':
        return HttpResponseBadRequest("Only POST requests are allowed")
    assignment = get_object_or_404(ShiftAssignment, pk=pk)
    user_id = request.POST.get('user')
    shift_id = request.POST.get('shift')
    effective_from = request.POST.get('effective_from')
    effective_to = request.POST.get('effective_to')
    is_current = request.POST.get('is_current') == 'on'
    # Validate required fields
    if not user_id or not shift_id or not effective_from:
        messages.error(request, "User, shift, and effective from date are required.")
        return redirect('aps_manager:assignment_list')
    # Validate date format
    try:
        effective_from_date = datetime.strptime(effective_from, "%Y-%m-%d").date()
    except (ValueError, TypeError):
        messages.error(request, "Effective from date must be in YYYY-MM-DD format.")
        return redirect('aps_manager:assignment_list')
    effective_to_date = None
    if effective_to:
        try:
            effective_to_date = datetime.strptime(effective_to, "%Y-%m-%d").date()
            # Validate date range
            if effective_to_date < effective_from_date:
                messages.error(request, "Effective to date cannot be earlier than effective from date.")
                return redirect('aps_manager:assignment_list')
        except (ValueError, TypeError):
            messages.error(request, "Effective to date must be in YYYY-MM-DD format.")
            return redirect('aps_manager:assignment_list')
    try:
        user = User.objects.get(pk=user_id)
        shift = ShiftMaster.objects.get(pk=shift_id)
        
        # Check if shift is active
        if not shift.is_active:
            messages.error(request, f"Cannot assign inactive shift '{shift.name}'.")
            return redirect('aps_manager:assignment_list')
            
        assignment.user = user
        assignment.shift = shift
        assignment.effective_from = effective_from_date
        assignment.effective_to = effective_to_date
        assignment.is_current = is_current
        assignment.save()
        messages.success(request, f"Shift assignment for {assignment.user.username} updated successfully!")
    except User.DoesNotExist:
        messages.error(request, "Selected user does not exist.")
    except ShiftMaster.DoesNotExist:
        messages.error(request, "Selected shift does not exist.")
    except Exception as e:
        messages.error(request, f"Failed to update shift assignment: {str(e)}")
    return redirect('aps_manager:assignment_list')

@login_required
@user_passes_test(is_manager_or_admin)
def assignment_delete(request, pk):
    if request.method != 'POST':
        return HttpResponseBadRequest("Only POST requests are allowed")
    assignment = get_object_or_404(ShiftAssignment, pk=pk)
    try:
        with transaction.atomic():
            user_name = assignment.user.username
            assignment.delete()
            messages.success(request, f"Shift assignment for {user_name} deleted successfully!")
    except Exception as e:
        messages.error(request, f"Failed to delete shift assignment: {str(e)}")
    return redirect('aps_manager:assignment_list')

@login_required
@user_passes_test(is_manager_or_admin)
def user_shift_info(request, user_id=None):
    try:
        if user_id:
            user = get_object_or_404(User, pk=user_id)
        else:
            user = request.user
        current_date = timezone.now().date()
        shift = ShiftAssignment.get_user_current_shift(user, current_date)
        if not shift:
            context = {
                'user': user,
                'shift': None,
                'error': "No active shift assignment found for this user"
            }
            return render(request, 'components/manager/shifts/user_shift_info.html', context)
        is_holiday = Holiday.is_holiday(current_date)
        is_working_day = shift.is_working_day(current_date) and not is_holiday
        
        # Get holidays for the next 7 days
        date_range = [current_date + timedelta(days=i) for i in range(7)]
        holidays = Holiday.objects.filter(date__in=date_range)
        recurring_holidays = Holiday.objects.filter(recurring_yearly=True)
        
        schedule = []
        for i in range(7):
            date = current_date + timedelta(days=i)
            
            # Check if date is a holiday (exact match or recurring)
            is_day_holiday = False
            holiday_name = None
            
            # Check exact date match
            exact_holiday = holidays.filter(date=date).first()
            if exact_holiday:
                is_day_holiday = True
                holiday_name = exact_holiday.name
            else:
                # Check recurring holidays
                for h in recurring_holidays:
                    if h.date.day == date.day and h.date.month == date.month:
                        is_day_holiday = True
                        holiday_name = h.name
                        break
            
            is_day_working = shift.is_working_day(date) and not is_day_holiday
            schedule.append({
                'date': date.strftime('%Y-%m-%d'),
                'day_name': date.strftime('%A'),
                'is_working_day': is_day_working,
                'is_holiday': is_day_holiday,
                'holiday_name': holiday_name,
                'shift_start': shift.start_time.strftime('%H:%M') if is_day_working else 'Off',
                'shift_end': shift.end_time.strftime('%H:%M') if is_day_working else 'Off',
            })
        context = {
            'user': user,
            'shift': shift,
            'is_holiday': is_holiday,
            'is_working_day': is_working_day,
            'schedule': schedule,
        }
        return render(request, 'components/manager/shifts/user_shift_info.html', context)
    except Exception as e:
        context = {
            'user': user if 'user' in locals() else request.user,
            'error': f"Error retrieving shift information: {str(e)}"
        }
        return render(request, 'components/manager/shifts/user_shift_info.html', context)

@login_required
@user_passes_test(is_manager_or_admin)
def shift_calendar(request):
    today = timezone.now().date()
    try:
        start_date_str = request.GET.get('start_date')
        if start_date_str:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        else:
            start_date = today.replace(day=1)
    except ValueError:
        start_date = today.replace(day=1)
    try:
        end_date_str = request.GET.get('end_date')
        if end_date_str:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        else:
            if start_date.month == 12:
                end_date = start_date.replace(year=start_date.year+1, month=1, day=1) - timedelta(days=1)
            else:
                end_date = start_date.replace(month=start_date.month+1, day=1) - timedelta(days=1)
    except ValueError:
        if start_date.month == 12:
            end_date = start_date.replace(year=start_date.year+1, month=1, day=1) - timedelta(days=1)
        else:
            end_date = start_date.replace(month=start_date.month+1, day=1) - timedelta(days=1)
    
    # Get all holidays that might apply to the date range
    date_specific_holidays = Holiday.objects.filter(
        date__range=(start_date, end_date),
        recurring_yearly=False
    )
    recurring_holidays = Holiday.objects.filter(recurring_yearly=True)
    
    calendar_data = []
    current_date = start_date
    while current_date <= end_date:
        is_holiday = False
        holiday_name = None
        
        # Check for date-specific holiday
        date_holiday = date_specific_holidays.filter(date=current_date).first()
        if date_holiday:
            is_holiday = True
            holiday_name = date_holiday.name
        else:
            # Check for recurring holiday
            for h in recurring_holidays:
                if h.date.day == current_date.day and h.date.month == current_date.month:
                    is_holiday = True
                    holiday_name = h.name
                    break
        
        shift_assignments = []
        if request.GET.get('show_shifts') == 'true':
            active_assignments = ShiftAssignment.objects.filter(
                is_current=True,
                effective_from__lte=current_date,
            ).filter(
                Q(effective_to__isnull=True) | Q(effective_to__gte=current_date)
            ).select_related('user', 'shift')[:5]
            for assignment in active_assignments:
                if assignment.shift.is_working_day(current_date) and not is_holiday:
                    shift_assignments.append({
                        'user': assignment.user.get_full_name() or assignment.user.username,
                        'shift_name': assignment.shift.name,
                        'start_time': assignment.shift.start_time.strftime('%H:%M'),
                        'end_time': assignment.shift.end_time.strftime('%H:%M'),
                    })
        calendar_data.append({
            'date': current_date,
            'day_name': current_date.strftime('%a'),
            'is_holiday': is_holiday,
            'holiday_name': holiday_name,
            'is_weekend': current_date.weekday() >= 5,
            'shift_assignments': shift_assignments,
            'is_today': current_date == today,
        })
        current_date += timedelta(days=1)
    if start_date.day == 1:
        prev_month = (start_date - timedelta(days=1)).replace(day=1)
        if start_date.month == 12:
            next_month = start_date.replace(year=start_date.year+1, month=1, day=1)
        else:
            next_month = start_date.replace(month=start_date.month+1, day=1)
    else:
        days_displayed = (end_date - start_date).days + 1
        prev_month = start_date - timedelta(days=days_displayed)
        next_month = end_date + timedelta(days=1)
    context = {
        'calendar_data': calendar_data,
        'start_date': start_date,
        'end_date': end_date,
        'prev_month': prev_month,
        'next_month': next_month,
        'show_shifts': request.GET.get('show_shifts') == 'true',
        'today': today,
    }
    return render(request, 'components/manager/shifts/shift_calendar.html', context)

@login_required
@user_passes_test(is_manager_or_admin)
def api_get_shift_users(request, shift_id):
    shift = get_object_or_404(ShiftMaster, pk=shift_id)
    assignments = ShiftAssignment.objects.filter(
        shift=shift,
        is_current=True
    ).select_related('user')
    users = [{
        'id': a.user.id,
        'username': a.user.username,
        'full_name': a.user.get_full_name(),
        'email': a.user.email,
        'assignment_id': a.id,
        'effective_from': a.effective_from.strftime('%Y-%m-%d'),
        'effective_to': a.effective_to.strftime('%Y-%m-%d') if a.effective_to else None,
    } for a in assignments]
    return JsonResponse({'users': users})

@login_required
@user_passes_test(is_manager_or_admin)
def api_get_user_shift(request, user_id):
    user = get_object_or_404(User, pk=user_id)
    current_date = timezone.now().date()
    shift = ShiftAssignment.get_user_current_shift(user, current_date)
    if not shift:
        return JsonResponse({'success': False, 'error': 'No active shift found for this user'})
    is_holiday = Holiday.is_holiday(current_date)
    is_working_day = shift.is_working_day(current_date) and not is_holiday
    shift_data = {
        'id': shift.id,
        'name': shift.name,
        'description': getattr(shift, 'description', ''),
        'start_time': shift.start_time.strftime('%H:%M'),
        'end_time': shift.end_time.strftime('%H:%M'),
        'is_active': shift.is_active,
        'working_days': shift.working_days,
        'is_working_today': is_working_day,
        'is_holiday_today': is_holiday,
    }
    return JsonResponse({'success': True, 'shift': shift_data})

@login_required
@user_passes_test(is_manager_or_admin)
def api_toggle_shift_active(request, pk):
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Only POST requests are allowed'})
    shift = get_object_or_404(ShiftMaster, pk=pk)
    try:
        with transaction.atomic():
            shift.is_active = not shift.is_active
            shift.save()
        return JsonResponse({'success': True, 'is_active': shift.is_active})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})
    

'''---------------------------------- APPRAISAL --------------------------------'''
from .models import Appraisal, AppraisalItem, AppraisalAttachment, AppraisalWorkflow


def is_manager_or_admin(user):
    return user.groups.filter(name="Manager").exists() or user.is_superuser

def is_hr_or_admin(user):
    return user.groups.filter(name="HR").exists() or user.is_superuser

def is_finance_or_admin(user):
    return user.groups.filter(name="Finance").exists() or user.is_superuser

def is_management_or_admin(user):
    return user.groups.filter(name="Management").exists() or user.is_superuser

@login_required
def appraisal_list(request):
    """View for listing appraisals based on user role"""
    print(f"[DEBUG] Accessing appraisal_list view for user: {request.user}")
    context = {}
    user = request.user

    # Check if user is in any of the special groups
    special_groups = ["Manager", "HR", "Finance", "Management"]
    is_special_user = user.groups.filter(name__in=special_groups).exists()
    context['is_special_user'] = is_special_user
    print(f"[DEBUG] User {user} is_special_user: {is_special_user}")

    if user.groups.filter(name="Manager").exists():
        print("[DEBUG] User is in Manager group")
        # Managers see appraisals where they are assigned as manager and status is submitted
        appraisals = Appraisal.objects.filter(
            manager=user,
            status='submitted'  # Only show submitted appraisals to manager
        )
        pending_reviews = appraisals.count()
        print(f"[DEBUG] Manager pending reviews: {pending_reviews}")
        context['pending_reviews'] = pending_reviews

    elif user.groups.filter(name="HR").exists():
        print("[DEBUG] User is in HR group")
        # HR sees appraisals in HR review status
        appraisals = Appraisal.objects.filter(status='hr_review')
        pending_reviews = appraisals.count()
        print(f"[DEBUG] HR pending reviews: {pending_reviews}")
        context['pending_reviews'] = pending_reviews

    elif user.groups.filter(name="Finance").exists():
        print("[DEBUG] User is in Finance group")
        # Finance sees appraisals in finance review status
        appraisals = Appraisal.objects.filter(status='finance_review')
        pending_reviews = appraisals.count()
        print(f"[DEBUG] Finance pending reviews: {pending_reviews}")
        context['pending_reviews'] = pending_reviews

    else:
        print("[DEBUG] User is regular employee")
        # Regular employees see their own appraisals
        appraisals = Appraisal.objects.filter(user=user)

    # Add special group flags to context
    group_flags = {
        'is_manager': user.groups.filter(name="Manager").exists(),
        'is_hr': user.groups.filter(name="HR").exists(), 
        'is_finance': user.groups.filter(name="Finance").exists(),
        'is_management': user.groups.filter(name="Management").exists()
    }
    print(f"[DEBUG] User group flags: {group_flags}")
    context.update(group_flags)

    # Add stats for management view
    if group_flags['is_management']:
        all_appraisals = Appraisal.objects.all()
        context.update({
            'total_appraisals': all_appraisals.count(),
            'pending_reviews': all_appraisals.filter(status='submitted').count(),
            'approved_appraisals': all_appraisals.filter(status='approved').count(),
            'rejected_appraisals': all_appraisals.filter(status='rejected').count()
        })

    context['appraisals'] = appraisals
    print(f"[DEBUG] Total appraisals in context: {appraisals.count()}")
    return render(request, 'components/appraisal/appraisal_list.html', context)

@login_required
def appraisal_detail(request, pk):
    """View for displaying appraisal details"""
    print(f"[DEBUG] Accessing appraisal_detail view for pk: {pk}")
    appraisal = get_object_or_404(Appraisal, pk=pk)
    user = request.user

    print(f"[DEBUG] User {user} accessing appraisal for user {appraisal.user}")

    # Check permissions based on role and status
    if not (user == appraisal.user or 
            user == appraisal.manager or
            user.groups.filter(name__in=['HR', 'Finance', 'Management']).exists()):
        print(f"[DEBUG] Permission denied for user {user}")
        raise PermissionDenied

    context = {
        'appraisal': appraisal,
        'items': appraisal.items.all(),
        'attachments': appraisal.attachments.all(),
        'workflow_history': appraisal.workflow_history.all()
    }
    
    # Add ability to change status from draft to submit
    if appraisal.status == 'draft' and user == appraisal.user:
        context['can_submit'] = True
    
    print(f"[DEBUG] Appraisal details - Items: {context['items'].count()}, Attachments: {context['attachments'].count()}")
    return render(request, 'components/appraisal/appraisal_detail.html', context)
def is_valid_status_transition(from_status, to_status):
    """
    Validates that status transitions follow the correct workflow
    
    Valid transitions:
    - draft -> submitted
    - submitted -> hr_review (if approved by manager)
    - submitted -> rejected (if rejected by manager)
    - hr_review -> finance_review (if approved by HR)
    - hr_review -> rejected (if rejected by HR)
    - finance_review -> approved (if approved by Finance)
    - finance_review -> rejected (if rejected by Finance)
    """
    valid_transitions = {
        'draft': ['submitted'],
        'submitted': ['hr_review', 'rejected'],
        'hr_review': ['finance_review', 'rejected'],
        'finance_review': ['approved', 'rejected']
    }
    
    return to_status in valid_transitions.get(from_status, [])

@login_required
def appraisal_create(request):
    """View for creating new appraisal"""
    print(f"[DEBUG] Accessing appraisal_create view for user: {request.user}")
    
    if request.method == 'POST':
        print("[DEBUG] Processing POST request for appraisal creation")
        try:
            with transaction.atomic():
                # Get manager user object
                manager_id = request.POST.get('manager')
                print(f"[DEBUG] Selected manager ID: {manager_id}")
                
                if not manager_id:
                    raise ValueError("Manager selection is required")
                    
                manager = User.objects.get(id=manager_id)
                
                # Validate required fields
                required_fields = ['title', 'overview', 'period_start', 'period_end']
                for field in required_fields:
                    if not request.POST.get(field):
                        raise ValueError(f"{field} is required")
                
                # Create main appraisal
                appraisal_data = {
                    'user': request.user,
                    'manager': manager,
                    'title': request.POST['title'],
                    'overview': request.POST['overview'],
                    'period_start': request.POST['period_start'],
                    'period_end': request.POST['period_end'],
                    'status': 'draft',
                    'submitted_at': None
                }
                print(f"[DEBUG] Creating appraisal with data: {appraisal_data}")
                appraisal = Appraisal.objects.create(**appraisal_data)

                # Create initial workflow history entry
                workflow_data = {
                    'appraisal': appraisal,
                    'from_status': None,
                    'to_status': 'draft',
                    'action_by': request.user,
                    'comments': 'Initial appraisal creation'
                }
                print(f"[DEBUG] Creating initial workflow history: {workflow_data}")
                AppraisalWorkflow.objects.create(**workflow_data)

                # Handle appraisal items
                items_data = json.loads(request.POST.get('items', '[]'))
                print(f"[DEBUG] Processing {len(items_data)} appraisal items")
                
                # Require at least one item
                if not items_data:
                    raise ValueError("At least one appraisal item is required")
                
                # Additional validation for items - ensure required fields exist
                for idx, item in enumerate(items_data):
                    if not item.get('category'):
                        raise ValueError(f"Category is required for item #{idx+1}")
                    if not item.get('title'):
                        raise ValueError(f"Title is required for item #{idx+1}")
                    if not item.get('description'):
                        raise ValueError(f"Description is required for item #{idx+1}")
                
                for item in items_data:
                    AppraisalItem.objects.create(
                        appraisal=appraisal,
                        category=item['category'],
                        title=item['title'],
                        description=item['description'],
                        date=item.get('date'),
                        employee_rating=item.get('employee_rating')
                    )

                # Handle file attachments
                attachments = request.FILES.getlist('attachments')
                print(f"[DEBUG] Processing {len(attachments)} file attachments")
                for file in attachments:
                    AppraisalAttachment.objects.create(
                        appraisal=appraisal,
                        file=file,
                        title=file.name,
                        uploaded_by=request.user
                    )

                # Notify manager
                print(f"[DEBUG] Notifying manager {manager.email} about new appraisal")

                print(f"[DEBUG] Successfully created appraisal with ID: {appraisal.id}")
                return JsonResponse({'success': True, 'appraisal_id': appraisal.id})
        except ValueError as e:
            print(f"[DEBUG] Validation error: {str(e)}")
            return JsonResponse({'success': False, 'error': str(e)})
        except Exception as e:
            print(f"[DEBUG] Error creating appraisal: {str(e)}")
            return JsonResponse({'success': False, 'error': str(e)})

    # Get managers for select field
    managers = User.objects.filter(groups__name='Manager')
    print(f"[DEBUG] Available managers: {managers.count()}")
    
    # Get category choices from model
    categories = dict(AppraisalItem.CATEGORY_CHOICES)
    print(f"[DEBUG] Available categories: {categories}")

    context = {
        'managers': managers,
        'categories': categories
    }
    return render(request, 'components/appraisal/appraisal_form.html', context)

@login_required
def appraisal_update(request, pk):
    """View for updating appraisal"""
    print(f"[DEBUG] Accessing appraisal_update view for pk: {pk}")
    appraisal = get_object_or_404(Appraisal, pk=pk)
    
    # Only allow updates if user owns the appraisal and it's in draft
    if not (request.user == appraisal.user and appraisal.status == 'draft'):
        print(f"[DEBUG] Permission denied for user {request.user}")
        raise PermissionDenied
        
    if request.method == 'POST':
        print("[DEBUG] Processing POST request for appraisal update")
        try:
            with transaction.atomic():
                # Update main appraisal
                appraisal.title = request.POST['title']
                appraisal.overview = request.POST['overview']
                appraisal.save()
                print(f"[DEBUG] Updated appraisal main details for ID: {appraisal.id}")

                # Update items
                items_data = json.loads(request.POST.get('items', '[]'))
                print(f"[DEBUG] Deleting existing items and creating {len(items_data)} new items")
                
                # Require at least one item
                if not items_data:
                    raise ValueError("At least one appraisal item is required")
                    
                appraisal.items.all().delete()  # Remove existing items
                for item in items_data:
                    AppraisalItem.objects.create(
                        appraisal=appraisal,
                        category=item['category'],
                        title=item['title'],
                        description=item['description'],
                        date=item.get('date'),
                        employee_rating=item.get('employee_rating')
                    )

                # Handle new attachments
                new_attachments = request.FILES.getlist('attachments')
                print(f"[DEBUG] Processing {len(new_attachments)} new attachments")
                for file in new_attachments:
                    AppraisalAttachment.objects.create(
                        appraisal=appraisal,
                        file=file,
                        title=file.name,
                        uploaded_by=request.user
                    )

                print("[DEBUG] Successfully updated appraisal")
                return JsonResponse({'success': True})
        except ValueError as e:
            print(f"[DEBUG] Validation error: {str(e)}")
            return JsonResponse({'success': False, 'error': str(e)})
        except Exception as e:
            print(f"[DEBUG] Error updating appraisal: {str(e)}")
            return JsonResponse({'success': False, 'error': str(e)})
        
    return render(request, 'components/appraisal/appraisal_form.html', {'appraisal': appraisal})

@login_required
def appraisal_submit(request, pk):
    """View for submitting appraisal for review"""
    print(f"[DEBUG] Accessing appraisal_submit view for pk: {pk}")
    appraisal = get_object_or_404(Appraisal, pk=pk)
    
    if not (request.user == appraisal.user and appraisal.status == 'draft'):
        print(f"[DEBUG] Permission denied for user {request.user}")
        raise PermissionDenied
        
    try:
        with transaction.atomic():
            # Verify manager is assigned
            if not appraisal.manager:
                raise ValueError("Cannot submit appraisal without assigned manager")
                
            # Enhanced verification that appraisal has valid items
            items = appraisal.items.all()
            if not items.exists():
                raise ValueError("Cannot submit appraisal without any items")
            
            # Check that all required item fields are filled
            for item in items:
                if not item.category:
                    raise ValueError(f"Category is required for item: {item.title}")
                if not item.title:
                    raise ValueError("Title is required for all items")
                if not item.description:
                    raise ValueError(f"Description is required for item: {item.title}")
                if not item.employee_rating:
                    raise ValueError(f"Self-rating is required for item: {item.title}")
            
            # Validate status transition
            if not is_valid_status_transition('draft', 'submitted'):
                raise ValueError("Invalid status transition from draft")
                
            appraisal.status = 'submitted'
            appraisal.submitted_at = timezone.now()
            appraisal.save()
            print(f"[DEBUG] Updated appraisal status to submitted for ID: {appraisal.id}")
            
            # Log workflow transition
            workflow_data = {
                'appraisal': appraisal,
                'from_status': 'draft',
                'to_status': 'submitted',
                'action_by': request.user,
                'comments': request.POST.get('comments', '')
            }
            print(f"[DEBUG] Creating workflow history entry: {workflow_data}")
            AppraisalWorkflow.objects.create(**workflow_data)
            print("[DEBUG] Successfully submitted appraisal")
            return redirect('appraisal:appraisal_detail', pk=appraisal.id)
    except ValueError as e:
        print(f"[DEBUG] Validation error: {str(e)}")
        messages.error(request, str(e))
        return redirect('appraisal:appraisal_detail', pk=appraisal.id)
    except Exception as e:
        print(f"[DEBUG] Error submitting appraisal: {str(e)}")
        messages.error(request, "An error occurred while submitting the appraisal")
        return redirect('appraisal:appraisal_detail', pk=appraisal.id)
    
@login_required
@user_passes_test(lambda u: is_manager_or_admin(u) or is_hr_or_admin(u) or is_finance_or_admin(u))
def appraisal_review(request, pk):
    """View for reviewing appraisals (Manager/HR/Finance)"""
    print(f"[DEBUG] Accessing appraisal_review view for pk: {pk}")
    appraisal = get_object_or_404(Appraisal, pk=pk)
    user = request.user
    
    if request.method == 'POST':
        print("[DEBUG] Processing POST request for appraisal review")
        try:
            with transaction.atomic():
                action = request.POST.get('action')
                from_status = appraisal.status
                comments = request.POST.get('comments', '')
                print(f"[DEBUG] Review action: {action}, Current status: {from_status}")

                # Manager Review
                if is_manager_or_admin(user) and appraisal.status == 'submitted':
                    print(f"[DEBUG] Processing manager review for user {user} on appraisal {appraisal.id}")
                    
                    if user != appraisal.manager:
                        print(f"[DEBUG] Permission denied for manager {user} - not assigned manager {appraisal.manager}")
                        raise PermissionDenied
                        
                    if appraisal.items.count() == 0:
                        print(f"[DEBUG] Appraisal {appraisal.id} has no items, cannot be reviewed")
                        raise ValueError("Cannot review an appraisal with no items")
                    
                    # Get all appraisal items that need review
                    appraisal_items = appraisal.items.all()
                    
                    # Process form data - NEW CODE STARTS HERE
                    print("[DEBUG] Extracting item data from form")
                    items_data = []
                    
                    # Extract data from POST dictionary
                    for item in appraisal_items:
                        item_id = str(item.id)
                        manager_rating = request.POST.get(f'items[{item_id}][manager_rating]')
                        manager_comments = request.POST.get(f'items[{item_id}][manager_comments]', '')
                        
                        print(f"[DEBUG] Extracted data for item {item_id}: Rating={manager_rating}, Comments={manager_comments}")
                        
                        if manager_rating:
                            items_data.append({
                                'id': item_id,
                                'manager_rating': manager_rating,
                                'manager_comments': manager_comments
                            })
                    # NEW CODE ENDS HERE
                    
                    print(f"[DEBUG] Items data processed: {items_data}")
                    
                    # Validate that all items have ratings
                    if not items_data:
                        print("[DEBUG] No items data received")
                        raise ValueError("Manager must provide ratings for all items")
                        
                    if len(items_data) != appraisal_items.count():
                        print(f"[DEBUG] Mismatch in items count - Expected: {appraisal_items.count()}, Received: {len(items_data)}")
                        raise ValueError(f"Manager must rate all appraisal items. Expected {appraisal_items.count()} items, received {len(items_data)}.")
                    
                    # Validate each item has a rating
                    for item_data in items_data:
                        if not item_data.get('manager_rating'):
                            print(f"[DEBUG] Missing manager rating for item: {item_data.get('id')}")
                            raise ValueError("Manager rating is required for all items")
                    
                    print(f"[DEBUG] Updating {len(items_data)} items with manager ratings")
                    
                    # Process item updates only after all validations pass
                    for item_data in items_data:
                        print(f"[DEBUG] Processing item data: {item_data}")
                        item = get_object_or_404(AppraisalItem, pk=item_data['id'])
                        print(f"[DEBUG] Found appraisal item {item.id}")
                        
                        old_rating = item.manager_rating
                        old_comments = item.manager_comments
                        
                        item.manager_rating = item_data.get('manager_rating')
                        item.manager_comments = item_data.get('manager_comments', '')
                        item.save()
                        
                        print(f"[DEBUG] Updated item {item.id}:")
                        print(f"  - Rating changed from {old_rating} to {item.manager_rating}")
                        print(f"  - Comments changed from '{old_comments}' to '{item.manager_comments}'")
                    
                    to_status = 'hr_review' if action == 'approve' else 'rejected'
                    if not is_valid_status_transition(from_status, to_status):
                        print(f"[DEBUG] Invalid status transition from {from_status} to {to_status}")
                        raise ValueError(f"Invalid status transition")
                    print(f"[DEBUG] Setting new status to: {to_status} based on action: {action}")

                # HR Review
                elif is_hr_or_admin(user) and appraisal.status == 'hr_review':
                    print("[DEBUG] Processing HR review")
                    to_status = 'finance_review' if action == 'approve' else 'rejected'
                    if not is_valid_status_transition(from_status, to_status):
                        print(f"[DEBUG] Invalid status transition from {from_status} to {to_status}")
                        raise ValueError(f"Invalid status transition")

                # Finance Review
                elif is_finance_or_admin(user) and appraisal.status == 'finance_review':
                    print("[DEBUG] Processing Finance review")
                    to_status = 'approved' if action == 'approve' else 'rejected'
                    if not is_valid_status_transition(from_status, to_status):
                        print(f"[DEBUG] Invalid status transition from {from_status} to {to_status}")
                        raise ValueError(f"Invalid status transition")
                    if to_status == 'approved':
                        appraisal.approved_at = timezone.now()
                else:
                    print(f"[DEBUG] Invalid review state for user {user}")
                    raise PermissionDenied

                appraisal.status = to_status
                appraisal.save()
                print(f"[DEBUG] Updated appraisal status to: {to_status}")

                # Log workflow transition
                workflow_data = {
                    'appraisal': appraisal,
                    'from_status': from_status,
                    'to_status': to_status,
                    'action_by': user,
                    'comments': comments
                }
                print(f"[DEBUG] Creating workflow history entry: {workflow_data}")
                AppraisalWorkflow.objects.create(**workflow_data)
                print("[DEBUG] Successfully completed review")
                return redirect('appraisal:appraisal_list')
        except ValueError as e:
            print(f"[DEBUG] Validation error: {str(e)}")
            messages.error(request, str(e))
            return redirect('appraisal:appraisal_review', pk=appraisal.pk)
        except Exception as e:
            print(f"[DEBUG] Error during review: {str(e)}")
            messages.error(request, f"Error during review: {str(e)}")
            return redirect('appraisal:appraisal_review', pk=appraisal.pk)

    context = {
        'appraisal': appraisal,
        'items': appraisal.items.all(),
        'workflow_history': appraisal.workflow_history.all(),
        'is_manager': is_manager_or_admin(user),
        'is_hr': is_hr_or_admin(user),
        'is_finance': is_finance_or_admin(user)
    }
    print(f"[DEBUG] Rendering review template with {context['items'].count()} items")
    return render(request, 'components/appraisal/appraisal_review.html', context)

from django.db.models.functions import TruncMonth
from django.contrib.auth.decorators import login_required
from django.contrib.auth.decorators import user_passes_test
from django.db.models import Count, Avg, Min, Max, F, Q, FloatField, DurationField
from django.db.models.functions import Cast, TruncMonth
from django.utils import timezone
from datetime import timedelta

@login_required
@user_passes_test(lambda u: is_management_or_admin(u) or is_hr_or_admin(u) or is_finance_or_admin(u))
def appraisal_dashboard(request):
    """Dashboard view for management and HR"""
    print("[DEBUG] Accessing appraisal dashboard view")

    # Base queryset with related fields
    appraisals = Appraisal.objects.select_related('user', 'manager').all()

    # Calculate overall statistics
    total_appraisals = appraisals.count()
    completed_appraisals = appraisals.filter(status__in=['approved', 'rejected']).count()
    in_progress = appraisals.exclude(status__in=['approved', 'rejected', 'draft']).count()
    pending_reviews = appraisals.filter(status='submitted').count()

    # Calculate status distribution
    status_counts = appraisals.values('status').annotate(count=Count('id'))
    status_distribution = {
        status: count for status_obj in status_counts 
        for status, count in [(status_obj['status'], status_obj['count'])]
    }

    # Calculate monthly trends - using a safer approach
    # Get time range for trends
    end_date = timezone.now().date()
    start_date = end_date - timedelta(days=365)  # Last 12 months
    
    # Get all appraisals within date range
    period_appraisals = appraisals.filter(
        created_at__date__range=(start_date, end_date)
    )
    
    # Manual monthly aggregation
    monthly_trends = []
    current_date = start_date.replace(day=1)
    end_month = end_date.replace(day=1)
    
    while current_date <= end_month:
        next_month = (current_date.replace(day=28) + timedelta(days=4)).replace(day=1)
        month_appraisals = period_appraisals.filter(
            created_at__date__gte=current_date,
            created_at__date__lt=next_month
        )
        
        monthly_data = {
            'month': current_date,
            'total': month_appraisals.count(),
            'approved': month_appraisals.filter(status='approved').count(),
            'rejected': month_appraisals.filter(status='rejected').count()
        }
        monthly_trends.append(monthly_data)
        current_date = next_month

    # Calculate completion time statistics without relying on database duration calculations
    completed_appraisals_data = appraisals.filter(
        status__in=['approved', 'rejected'],
        submitted_at__isnull=False,
        approved_at__isnull=False
    )
    
    # Calculate durations in Python rather than at the database level
    completion_durations = []
    for appraisal in completed_appraisals_data:
        if appraisal.submitted_at and appraisal.approved_at:
            try:
                duration = appraisal.approved_at - appraisal.submitted_at
                completion_durations.append(duration.total_seconds())
            except (TypeError, ValueError):
                continue
    
    # Convert durations to human readable strings
    completion_times = {}
    if completion_durations:
        avg_seconds = sum(completion_durations)/len(completion_durations)
        min_seconds = min(completion_durations)
        max_seconds = max(completion_durations)
        
        completion_times = {
            'avg_time': f"{int(avg_seconds/86400)} days {int((avg_seconds%86400)/3600)} hours",
            'min_time': f"{int(min_seconds/86400)} days {int((min_seconds%86400)/3600)} hours",
            'max_time': f"{int(max_seconds/86400)} days {int((max_seconds%86400)/3600)} hours",
        }
    else:
        completion_times = {
            'avg_time': None,
            'min_time': None,
            'max_time': None
        }

    # Calculate rating statistics
    employee_ratings = AppraisalItem.objects.filter(
        appraisal__in=appraisals,
        employee_rating__isnull=False
    ).values_list('employee_rating', flat=True)
    
    manager_ratings = AppraisalItem.objects.filter(
        appraisal__in=appraisals,
        manager_rating__isnull=False
    ).values_list('manager_rating', flat=True)
    
    employee_ratings_list = list(employee_ratings)
    manager_ratings_list = list(manager_ratings)
    
    rating_stats = {
        'employee': {
            'avg': sum(employee_ratings_list) / len(employee_ratings_list) if employee_ratings_list else None,
            'min': min(employee_ratings_list) if employee_ratings_list else None,
            'max': max(employee_ratings_list) if employee_ratings_list else None,
        },
        'manager': {
            'avg': sum(manager_ratings_list) / len(manager_ratings_list) if manager_ratings_list else None,
            'min': min(manager_ratings_list) if manager_ratings_list else None,
            'max': max(manager_ratings_list) if manager_ratings_list else None,
        }
    }

    context = {
        'overview_stats': {
            'total_appraisals': total_appraisals,
            'completed_appraisals': completed_appraisals,
            'in_progress': in_progress,
            'pending_reviews': pending_reviews,
        },
        'status_distribution': status_distribution,
        'monthly_trends': monthly_trends,
        'completion_times': completion_times,
        'rating_stats': rating_stats,
        'filter_options': {
            'managers': User.objects.filter(groups__name='Manager'),
            'statuses': dict(Appraisal.STATUS_CHOICES),
            'date_range': {
                'start': start_date,
                'end': end_date
            }
        }
    }

    print(f"[DEBUG] Dashboard statistics prepared: {context}")
    return render(request, 'components/appraisal/dashboard.html', context)

'''--------------------------------- FINANCE --------------------------'''
# Finance Views

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib import messages
from django.http import JsonResponse, HttpResponse, FileResponse
from django.db.models import Sum, Count, Q, F, Value, Case, When
from django.db.models.functions import Coalesce, ExtractMonth, ExtractYear
from django.utils import timezone
from datetime import datetime, timedelta
from decimal import Decimal
import json
from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle

from .models import (
    DailyExpense, Voucher, VoucherDetail, BankAccount, 
    BankPayment, Subscription, ClientInvoice, ChartOfAccount
)
from django.contrib.auth.decorators import user_passes_test
from django.db.models import DecimalField

def is_finance(user):
    return user.groups.filter(name='Finance').exists()
@login_required
@user_passes_test(is_finance)
def expense_entry(request):
    """Handle daily expense entry and listing with advanced filtering and calculations"""
    if request.method == 'POST':
        try:
            # Create expense
            expense = DailyExpense.objects.create(
                expense_id=f"EXP-{timezone.now().strftime('%Y%m%d%H%M%S')}",
                department_id=request.POST.get('department'),
                date=request.POST.get('date'),
                category=request.POST.get('category'),
                description=request.POST.get('description'),
                amount=request.POST.get('amount'),
                paid_by=request.user,
                status='draft',
                attachments=request.FILES.get('attachments')
            )

            messages.success(request, 'Expense recorded successfully')
            return JsonResponse({'status': 'success', 'expense_id': expense.expense_id})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})

    # Advanced filtering and aggregation
    filters = {}
    if request.GET.get('start_date'):
        filters['date__gte'] = request.GET.get('start_date')
    if request.GET.get('end_date'):
        filters['date__lte'] = request.GET.get('end_date')
    if request.GET.get('category'):
        filters['category'] = request.GET.get('category')
    if request.GET.get('status'):
        filters['status'] = request.GET.get('status')

    expenses = DailyExpense.objects.filter(**filters).order_by('-date')
    
    # Calculate statistics
    stats = expenses.aggregate(
        total_amount=Coalesce(Sum('amount'), Value(0, output_field=DecimalField(max_digits=15, decimal_places=2))),
        avg_amount=Coalesce(
            Sum('amount') / Cast(Count('id'), DecimalField(max_digits=15, decimal_places=2)),
            Value(0),
            output_field=DecimalField(max_digits=15, decimal_places=2)
        ),
        count=Count('id')
    )

    # Monthly trend analysis
    monthly_trend = expenses.annotate(
        month=ExtractMonth('date'),
        year=ExtractYear('date')
    ).values('month', 'year').annotate(
        total=Sum('amount')
    ).order_by('year', 'month')

    context = {
        'expenses': expenses,
        'expense_categories': dict(DailyExpense.EXPENSE_CATEGORIES),
        'expense_statuses': dict(DailyExpense.EXPENSE_STATUS),
        'stats': stats,
        'monthly_trend': list(monthly_trend),
        'filters': request.GET
    }
    return render(request, 'components/finance/expense_entry.html', context)

@login_required
@user_passes_test(is_finance)
def voucher_entry(request):
    """Handle voucher creation and management with validation and auto-calculations"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            
            # Validate debit/credit equality
            total_debit = sum(Decimal(entry['debit']) for entry in data['entries'])
            total_credit = sum(Decimal(entry['credit']) for entry in data['entries'])
            
            if total_debit != total_credit:
                raise ValueError("Total debit must equal total credit")

            # Create voucher with transaction
            voucher = Voucher.objects.create(
                voucher_number=f"V-{timezone.now().strftime('%Y%m%d%H%M%S')}",
                type=data['type'],
                date=data['date'],
                party_name=data['party_name'],
                purpose=data['purpose'],
                amount=total_debit,
                status='draft'
            )

            # Create voucher details with validation
            for entry in data['entries']:
                if Decimal(entry['debit']) > 0 and Decimal(entry['credit']) > 0:
                    raise ValueError("An entry cannot have both debit and credit")
                    
                VoucherDetail.objects.create(
                    voucher=voucher,
                    account_id=entry['account'],
                    debit_amount=Decimal(entry['debit']),
                    credit_amount=Decimal(entry['credit'])
                )

            return JsonResponse({'status': 'success', 'voucher_id': voucher.id})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})

    # Get vouchers with filters
    filters = {}
    if request.GET.get('type'):
        filters['type'] = request.GET.get('type')
    if request.GET.get('status'):
        filters['status'] = request.GET.get('status')
    if request.GET.get('date_from'):
        filters['date__gte'] = request.GET.get('date_from')
    if request.GET.get('date_to'):
        filters['date__lte'] = request.GET.get('date_to')

    vouchers = Voucher.objects.filter(**filters).order_by('-date')
    accounts = ChartOfAccount.objects.filter(is_active=True)

    # Calculate voucher statistics
    stats = vouchers.aggregate(
        total_amount=Sum('amount'),
        count=Count('id'),
        pending_approval=Count('id', filter=Q(status='pending_approval'))
    )

    context = {
        'vouchers': vouchers,
        'accounts': accounts,
        'voucher_types': dict(Voucher.VOUCHER_TYPES),
        'voucher_statuses': dict(Voucher.VOUCHER_STATUS),
        'stats': stats,
        'filters': request.GET
    }
    return render(request, 'components/finance/voucher_entry.html', context)



@login_required
@user_passes_test(is_finance)
def invoice_generation(request):
    """Handle client invoice generation with calculations"""
    if request.method == 'POST':
        try:
            # Calculate invoice amounts
            rate = Decimal(request.POST.get('rate'))
            
            # Get the appropriate count based on billing model
            billing_model = request.POST.get('billing_model')
            if billing_model == 'per_order':
                count = Decimal(request.POST.get('order_count') or 0)
                fte_count = None
                order_count = count
            else:  # per_fte
                count = Decimal(request.POST.get('fte_count') or 0)
                fte_count = count
                order_count = None
                
            subtotal = rate * count
            
            tax_rate = Decimal(request.POST.get('tax_rate', '0'))
            tax_amount = (subtotal * tax_rate) / 100
            
            discount = Decimal(request.POST.get('discount', '0'))
            total_amount = subtotal + tax_amount - discount

            invoice = ClientInvoice.objects.create(
                invoice_number=f"INV-{timezone.now().strftime('%Y%m%d%H%M%S')}",
                client_id=request.POST.get('client'),
                billing_model=billing_model,
                billing_cycle_start=request.POST.get('cycle_start'),
                billing_cycle_end=request.POST.get('cycle_end'),
                order_count=order_count,
                fte_count=fte_count,
                rate=rate,
                subtotal=subtotal,
                tax_amount=tax_amount,
                discount=discount,
                total_amount=total_amount,
                due_date=request.POST.get('due_date'),
                status='draft'
            )
            
            messages.success(request, 'Invoice generated successfully')
            return redirect('aps_finance:invoice_detail', invoice_id=invoice.id)
        except Exception as e:
            messages.error(request, f'Error generating invoice: {str(e)}')
    
    # Get invoices with filters
    filters = {}
    if request.GET.get('status'):
        filters['status'] = request.GET.get('status')
    if request.GET.get('client'):
        filters['client'] = request.GET.get('client')
    if request.GET.get('date_from'):
        filters['billing_cycle_start__gte'] = request.GET.get('date_from')

    invoices = ClientInvoice.objects.filter(**filters).order_by('-created_at')
    
    # Calculate invoice statistics
    stats = {
        'total_amount': invoices.aggregate(total=Sum('total_amount'))['total'] or 0,
        'total_pending': invoices.filter(status='pending_approval').aggregate(total=Sum('total_amount'))['total'] or 0,
        'count': invoices.count()
    }

    # Get all clients from Client group
    clients = User.objects.filter(groups__name='Client')

    context = {
        'invoices': invoices,
        'clients': clients,
        'billing_models': dict(ClientInvoice.BILLING_MODELS),
        'invoice_statuses': dict(ClientInvoice.INVOICE_STATUS),
        'stats': stats,
        'filters': request.GET
    }
    return render(request, 'components/finance/invoice_generation.html', context)


@login_required
@user_passes_test(is_finance)
def invoice_detail(request, invoice_id):
    """Show detailed view of an invoice"""
    invoice = get_object_or_404(ClientInvoice, id=invoice_id)
    
    context = {
        'invoice': invoice,
        'billing_models': dict(ClientInvoice.BILLING_MODELS),
        'invoice_statuses': dict(ClientInvoice.INVOICE_STATUS),
        'user_is_finance': is_finance(request.user)
    }
    return render(request, 'components/finance/invoice_detail.html', context)


@login_required
@user_passes_test(is_finance)
def invoice_print(request, invoice_id):
    """Generate printable invoice view"""
    invoice = get_object_or_404(ClientInvoice, id=invoice_id)
    
    context = {
        'invoice': invoice,
        'billing_models': dict(ClientInvoice.BILLING_MODELS),
        'invoice_statuses': dict(ClientInvoice.INVOICE_STATUS),
    }
    return render(request, 'components/finance/invoice_print.html', context)


@login_required
@user_passes_test(is_finance)
def invoice_update_status(request, invoice_id):
    """Update invoice status"""
    if request.method == 'POST':
        invoice = get_object_or_404(ClientInvoice, id=invoice_id)
        new_status = request.POST.get('status')
        
        if new_status in dict(ClientInvoice.INVOICE_STATUS).keys():
            invoice.status = new_status
            invoice.save()
            messages.success(request, f'Invoice status updated to {dict(ClientInvoice.INVOICE_STATUS)[new_status]}')
        else:
            messages.error(request, 'Invalid status value')
            
    return redirect('aps_finance:invoice_detail', invoice_id=invoice_id)


@login_required
@user_passes_test(is_finance)
def invoice_edit(request, invoice_id):
    """Edit an existing invoice"""
    invoice = get_object_or_404(ClientInvoice, id=invoice_id)
    
    # Only draft invoices can be edited
    if invoice.status != 'draft':
        messages.error(request, 'Only draft invoices can be edited')
        return redirect('aps_finance:invoice_detail', invoice_id=invoice.id)
    
    if request.method == 'POST':
        try:
            # Update invoice data
            rate = Decimal(request.POST.get('rate'))
            
            # Get the appropriate count based on billing model
            billing_model = request.POST.get('billing_model')
            if billing_model == 'per_order':
                count = Decimal(request.POST.get('order_count') or 0)
                invoice.fte_count = None
                invoice.order_count = count
            else:  # per_fte
                count = Decimal(request.POST.get('fte_count') or 0)
                invoice.fte_count = count
                invoice.order_count = None
                
            subtotal = rate * count
            
            tax_rate = Decimal(request.POST.get('tax_rate', '0'))
            tax_amount = (subtotal * tax_rate) / 100
            
            discount = Decimal(request.POST.get('discount', '0'))
            total_amount = subtotal + tax_amount - discount

            # Update invoice fields
            invoice.client_id = request.POST.get('client')
            invoice.billing_model = billing_model
            invoice.billing_cycle_start = request.POST.get('cycle_start')
            invoice.billing_cycle_end = request.POST.get('cycle_end')
            invoice.rate = rate
            invoice.subtotal = subtotal
            invoice.tax_amount = tax_amount
            invoice.discount = discount
            invoice.total_amount = total_amount
            invoice.due_date = request.POST.get('due_date')
            invoice.save()
            
            messages.success(request, 'Invoice updated successfully')
            return redirect('aps_finance:invoice_detail', invoice_id=invoice.id)
        except Exception as e:
            messages.error(request, f'Error updating invoice: {str(e)}')
    
    # Get all clients from Client group
    clients = User.objects.filter(groups__name='Client')
    
    context = {
        'invoice': invoice,
        'clients': clients,
        'billing_models': dict(ClientInvoice.BILLING_MODELS),
    }
    return render(request, 'components/finance/invoice_edit.html', context)


@login_required
@user_passes_test(is_finance)
def finance_dashboard(request):
    """Finance module dashboard with key metrics and reports"""
    today = timezone.now().date()
    start_date = today - timedelta(days=30)
    
    # Expense metrics
    expense_metrics = DailyExpense.objects.filter(
        date__gte=start_date
    ).aggregate(
        total=Sum('amount'),
        count=Count('id'),
        pending=Count('id', filter=Q(status='pending_approval'))
    )

    # Invoice metrics
    invoice_metrics = ClientInvoice.objects.filter(
        created_at__date__gte=start_date
    ).aggregate(
        total=Sum('total_amount'),
        pending=Sum('total_amount', filter=Q(status='pending_approval')),
        overdue=Count('id', filter=Q(status='overdue'))
    )

    # Monthly trends
    monthly_expenses = DailyExpense.objects.filter(
        date__gte=start_date
    ).annotate(
        month=ExtractMonth('date')
    ).values('month').annotate(
        total=Sum('amount')
    ).order_by('month')

    monthly_invoices = ClientInvoice.objects.filter(
        created_at__date__gte=start_date
    ).annotate(
        month=ExtractMonth('created_at')
    ).values('month').annotate(
        total=Sum('total_amount')
    ).order_by('month')

    context = {
        'expense_metrics': expense_metrics,
        'invoice_metrics': invoice_metrics,
        'monthly_expenses': list(monthly_expenses),
        'monthly_invoices': list(monthly_invoices),
        'date_range': {
            'start': start_date,
            'end': today
        }
    }
    return render(request, 'components/finance/dashboard.html', context)
