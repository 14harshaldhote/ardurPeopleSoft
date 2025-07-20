from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import Group
from django.contrib import messages
from django.http import JsonResponse, HttpResponseForbidden
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.db.models import Q, Count, Avg, Sum, Max, Min, Prefetch
from django.utils import timezone
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from datetime import datetime, timedelta
import json
from collections import defaultdict

# Import models from the main trueAlign app
from trueAlign.models import (
    UserSession, OfficeLocation, UserDetails,
    ShiftAssignment, ShiftMaster
)
from django.contrib.auth.models import User


def is_admin_user(user):
    """
    Check if user has admin privileges.
    Returns True if user is superuser or belongs to 'Admin' group.
    """
    if not user.is_authenticated:
        return False

    # Check if user is superuser
    if user.is_superuser:
        return True

    # Check if user has is_admin attribute (custom field)
    if hasattr(user, 'is_admin') and user.is_admin:
        return True

    # Check if user belongs to Admin group
    try:
        admin_group = Group.objects.get(name='Admin')
        return user.groups.filter(id=admin_group.id).exists()
    except Group.DoesNotExist:
        return False


def get_admin_office_location(user):
    """
    Get the office location for the current admin user.
    Returns None if no office location is found.
    """
    try:
        user_details = UserDetails.objects.select_related('office_location').get(user=user)
        return user_details.office_location
    except UserDetails.DoesNotExist:
        return None


def get_user_shift_info(user, date=None):
    """
    Get current shift and shift history for a user.
    Returns a dictionary with shift information.
    """
    if date is None:
        date = timezone.now().date()

    shift_info = {
        'current_shift': None,
        'current_shift_name': 'No shift assigned',
        'shift_history': [],
        'has_shift_data': False
    }

    try:
        # Get current shift
        current_shift = ShiftAssignment.get_user_current_shift(user, date)
        if current_shift:
            shift_info['current_shift'] = current_shift
            shift_info['current_shift_name'] = current_shift.name
            shift_info['has_shift_data'] = True

        # Get shift history (last 5 assignments)
        shift_history = ShiftAssignment.get_shift_history(user).select_related('shift')[:5]
        shift_info['shift_history'] = [
            {
                'shift_name': assignment.shift.name,
                'effective_from': assignment.effective_from,
                'effective_to': assignment.effective_to,
                'is_current': assignment.is_current,
                'duration_days': assignment.total_duration()
            }
            for assignment in shift_history
        ]

        if shift_history:
            shift_info['has_shift_data'] = True

    except Exception as e:
        # Log the error but don't break the view
        print(f"Error getting shift info for user {user.username}: {str(e)}")

    return shift_info


def filter_sessions_by_office(sessions_queryset, admin_office_location):
    """
    Filter sessions to only include users from the same office location as admin.
    If admin has no office location, return all sessions.
    """
    if not admin_office_location:
        return sessions_queryset

    # Get all users in the same office
    office_users = UserDetails.objects.filter(
        office_location=admin_office_location
    ).values_list('user_id', flat=True)

    # Filter sessions to only include these users
    return sessions_queryset.filter(user_id__in=office_users)


@login_required
@user_passes_test(is_admin_user, login_url='/login/')
def session_dashboard(request):
    """
    Enhanced dashboard view with office location filtering and shift information.
    """
    context = {
        'page_title': 'Session Dashboard',
        'active_tab': 'dashboard'
    }

    try:
        # Get admin's office location
        admin_office = get_admin_office_location(request.user)

        # Get all sessions, filtered by office location
        all_sessions = UserSession.objects.select_related('user')
        filtered_sessions = filter_sessions_by_office(all_sessions, admin_office)

        # Get basic statistics
        total_sessions = filtered_sessions.count()
        active_sessions = filtered_sessions.filter(is_active=True).count()
        idle_sessions = filtered_sessions.filter(is_active=True, is_idle=True).count()

        # Recent sessions (last 24 hours)
        last_24h = timezone.now() - timedelta(hours=24)
        recent_sessions = filtered_sessions.filter(created_at__gte=last_24h).count()

        # Average session duration for completed sessions
        completed_sessions = filtered_sessions.filter(is_active=False, ended_at__isnull=False)
        avg_duration = None
        if completed_sessions.exists():
            durations = []
            for session in completed_sessions[:100]:  # Sample last 100 for performance
                if session.ended_at and session.created_at:
                    duration = (session.ended_at - session.created_at).total_seconds() / 60
                    durations.append(duration)

            if durations:
                avg_duration = sum(durations) / len(durations)

        # Top users by session count (from same office)
        top_users = (filtered_sessions
                    .values('user__username', 'user__first_name', 'user__last_name')
                    .annotate(session_count=Count('id'))
                    .order_by('-session_count')[:10])

        # Enhanced top users with shift information
        enhanced_top_users = []
        for user_data in top_users:
            try:
                user = User.objects.get(username=user_data['user__username'])
                shift_info = get_user_shift_info(user)
                user_data['current_shift'] = shift_info['current_shift_name']
                user_data['has_shift_data'] = shift_info['has_shift_data']
                enhanced_top_users.append(user_data)
            except User.DoesNotExist:
                enhanced_top_users.append(user_data)

        # Sessions by location
        location_stats = (filtered_sessions
                         .filter(location_city__isnull=False)
                         .values('location_city', 'location_country')
                         .annotate(session_count=Count('id'))
                         .order_by('-session_count')[:10])

        # Device type breakdown
        device_stats = (filtered_sessions
                       .filter(device_type__isnull=False)
                       .values('device_type')
                       .annotate(session_count=Count('id'))
                       .order_by('-session_count'))

        # Office location information
        if admin_office:
            office_info = {
                'name': admin_office.name,
                'location': admin_office.full_address(),
                'total_employees': UserDetails.objects.filter(office_location=admin_office).count()
            }
        else:
            office_info = {
                'name': 'All Offices',
                'location': 'System-wide view',
                'total_employees': UserDetails.objects.count()
            }

        context.update({
            'stats': {
                'total_sessions': total_sessions,
                'active_sessions': active_sessions,
                'idle_sessions': idle_sessions,
                'recent_sessions': recent_sessions,
                'avg_duration': round(avg_duration, 2) if avg_duration else None,
            },
            'top_users': enhanced_top_users,
            'location_stats': location_stats,
            'device_stats': device_stats,
            'office_info': office_info,
            'admin_office': admin_office,
        })

    except Exception as e:
        messages.error(request, f'Error loading dashboard data: {str(e)}')
        context.update({
            'stats': {
                'total_sessions': 0,
                'active_sessions': 0,
                'idle_sessions': 0,
                'recent_sessions': 0,
                'avg_duration': None,
            },
            'top_users': [],
            'location_stats': [],
            'device_stats': [],
            'office_info': {'name': 'Error', 'location': 'Unable to load', 'total_employees': 0},
            'admin_office': None,
        })

    return render(request, 'sessions/dashboard.html', context)


@login_required
@user_passes_test(is_admin_user, login_url='/login/')
def session_list(request):
    """
    Enhanced session list view with office location filtering and shift information.
    """
    context = {
        'page_title': 'User Sessions',
        'active_tab': 'sessions'
    }

    try:
        # Get admin's office location
        admin_office = get_admin_office_location(request.user)

        # Get sessions with optimized queries
        sessions = UserSession.objects.select_related(
            'user', 'user__profile'
        ).prefetch_related(
            Prefetch('user__shift_assignments',
                    queryset=ShiftAssignment.objects.select_related('shift').order_by('-effective_from'))
        ).order_by('-created_at')

        # Apply office location filtering
        sessions = filter_sessions_by_office(sessions, admin_office)

        # Apply additional filters
        search_query = request.GET.get('search', '').strip()
        status_filter = request.GET.get('status', '')
        user_filter = request.GET.get('user', '')
        location_filter = request.GET.get('location', '')
        shift_filter = request.GET.get('shift', '')
        date_from = request.GET.get('date_from', '')
        date_to = request.GET.get('date_to', '')

        if search_query:
            sessions = sessions.filter(
                Q(user__username__icontains=search_query) |
                Q(user__first_name__icontains=search_query) |
                Q(user__last_name__icontains=search_query) |
                Q(location_city__icontains=search_query) |
                Q(ip_address__icontains=search_query) |
                Q(device_type__icontains=search_query)
            )

        if status_filter == 'active':
            sessions = sessions.filter(is_active=True)
        elif status_filter == 'inactive':
            sessions = sessions.filter(is_active=False)
        elif status_filter == 'idle':
            sessions = sessions.filter(is_active=True, is_idle=True)

        if user_filter:
            sessions = sessions.filter(user__username=user_filter)

        if location_filter:
            sessions = sessions.filter(location_city__icontains=location_filter)

        if shift_filter:
            # Filter by users with specific shift
            shift_users = ShiftAssignment.objects.filter(
                shift__name__icontains=shift_filter,
                is_current=True
            ).values_list('user_id', flat=True)
            sessions = sessions.filter(user_id__in=shift_users)

        if date_from:
            try:
                date_from_obj = datetime.strptime(date_from, '%Y-%m-%d').date()
                sessions = sessions.filter(created_at__date__gte=date_from_obj)
            except ValueError:
                messages.warning(request, 'Invalid date format for "from" date')

        if date_to:
            try:
                date_to_obj = datetime.strptime(date_to, '%Y-%m-%d').date()
                sessions = sessions.filter(created_at__date__lte=date_to_obj)
            except ValueError:
                messages.warning(request, 'Invalid date format for "to" date')

        # Pagination
        page = request.GET.get('page', 1)
        paginator = Paginator(sessions, 25)  # Show 25 sessions per page

        try:
            sessions_page = paginator.page(page)
        except PageNotAnInteger:
            sessions_page = paginator.page(1)
        except EmptyPage:
            sessions_page = paginator.page(paginator.num_pages)

        # Enhanced sessions with shift information
        enhanced_sessions = []
        for session in sessions_page:
            try:
                shift_info = get_user_shift_info(session.user)

                # Get user's office location
                user_office = "No office location"
                try:
                    user_details = UserDetails.objects.select_related('office_location').get(user=session.user)
                    if user_details.office_location:
                        user_office = user_details.office_location.name
                except UserDetails.DoesNotExist:
                    pass

                session_data = {
                    'session': session,
                    'shift_info': shift_info,
                    'user_office': user_office,
                    'has_issues': False,
                    'issues': []
                }

                # Check for data issues
                if not shift_info['has_shift_data']:
                    session_data['has_issues'] = True
                    session_data['issues'].append('No shift data available')

                if user_office == "No office location":
                    session_data['has_issues'] = True
                    session_data['issues'].append('No office location assigned')

                if not session.location_city and not session.location_country:
                    session_data['has_issues'] = True
                    session_data['issues'].append('No location data')

                enhanced_sessions.append(session_data)

            except Exception as e:
                # Handle individual session errors gracefully
                session_data = {
                    'session': session,
                    'shift_info': {'current_shift_name': 'Error loading shift', 'has_shift_data': False},
                    'user_office': 'Error loading office',
                    'has_issues': True,
                    'issues': [f'Error loading data: {str(e)}']
                }
                enhanced_sessions.append(session_data)

        # Get filter options for dropdowns (filtered by office)
        office_filtered_users = User.objects.filter(
            sessions__in=filter_sessions_by_office(UserSession.objects.all(), admin_office)
        ).distinct().order_by('username')

        locations = (filter_sessions_by_office(UserSession.objects.all(), admin_office)
                    .filter(location_city__isnull=False)
                    .values_list('location_city', flat=True)
                    .distinct()
                    .order_by('location_city'))

        # Get available shifts for filtering
        available_shifts = ShiftMaster.objects.values_list('name', flat=True).distinct()

        context.update({
            'sessions': sessions_page,
            'enhanced_sessions': enhanced_sessions,
            'search_query': search_query,
            'status_filter': status_filter,
            'user_filter': user_filter,
            'location_filter': location_filter,
            'shift_filter': shift_filter,
            'date_from': date_from,
            'date_to': date_to,
            'users': office_filtered_users,
            'locations': locations,
            'available_shifts': available_shifts,
            'total_count': paginator.count,
            'admin_office': admin_office,
        })

    except Exception as e:
        messages.error(request, f'Error loading sessions: {str(e)}')
        context.update({
            'sessions': None,
            'enhanced_sessions': [],
            'search_query': '',
            'status_filter': '',
            'user_filter': '',
            'location_filter': '',
            'shift_filter': '',
            'date_from': '',
            'date_to': '',
            'users': [],
            'locations': [],
            'available_shifts': [],
            'total_count': 0,
            'admin_office': None,
        })

    return render(request, 'sessions/session_list.html', context)


@login_required
@user_passes_test(is_admin_user, login_url='/login/')
def session_detail(request, session_id):
    """
    Enhanced session detail view with comprehensive shift and office information.
    """
    context = {
        'page_title': 'Session Details',
        'active_tab': 'sessions'
    }

    try:
        # Get admin's office location for filtering
        admin_office = get_admin_office_location(request.user)

        # Get the session with related data
        session = get_object_or_404(
            UserSession.objects.select_related('user'),
            id=session_id
        )

        # Check if user is in admin's office (if admin has office restriction)
        if admin_office:
            try:
                user_details = UserDetails.objects.select_related('office_location').get(user=session.user)
                if user_details.office_location != admin_office:
                    messages.error(request, 'You can only view sessions from your office location.')
                    return redirect('sessions:session_list')
            except UserDetails.DoesNotExist:
                if not request.user.is_superuser:
                    messages.error(request, 'User has no office location assigned.')
                    return redirect('sessions:session_list')

        # Get comprehensive user information
        user_info = {
            'username': session.user.username,
            'full_name': f"{session.user.first_name} {session.user.last_name}".strip() or session.user.username,
            'email': session.user.email,
            'office_location': 'No office location',
            'employee_id': 'N/A',
            'employment_status': 'N/A',
            'reporting_manager': 'N/A'
        }

        try:
            user_details = UserDetails.objects.select_related(
                'office_location', 'reporting_manager'
            ).get(user=session.user)

            if user_details.office_location:
                user_info['office_location'] = user_details.office_location.name

            user_info.update({
                'employment_status': user_details.get_employment_status_display(),
                'reporting_manager': (
                    f"{user_details.reporting_manager.first_name} {user_details.reporting_manager.last_name}".strip()
                    if user_details.reporting_manager else 'N/A'
                )
            })

        except UserDetails.DoesNotExist:
            pass

        # Get shift information
        shift_info = get_user_shift_info(session.user, session.created_at.date())

        # Calculate session metrics
        session_metrics = {
            'duration': 'Active' if session.is_active else 'N/A',
            'productivity_score': session.productivity_score or 'N/A',
            'engagement_score': session.engagement_score or 'N/A',
            'security_score': session.security_score or 'N/A',
            'total_clicks': len(session.clicks) if session.clicks else 0,
            'total_scrolls': len(session.scrolls) if session.scrolls else 0,
            'page_views': len(session.page_views) if session.page_views else 0,
            'mouse_movements': session.mouse_movements or 0,
        }

        if session.ended_at and session.created_at:
            duration = session.ended_at - session.created_at
            hours = duration.total_seconds() // 3600
            minutes = (duration.total_seconds() % 3600) // 60
            session_metrics['duration'] = f"{int(hours)}h {int(minutes)}m"

        # Check for data quality issues
        data_issues = []
        if not shift_info['has_shift_data']:
            data_issues.append({
                'type': 'warning',
                'message': 'No shift assignment found for this user'
            })

        if user_info['office_location'] == 'No office location':
            data_issues.append({
                'type': 'warning',
                'message': 'User has no office location assigned'
            })

        if not session.location_city and not session.location_country:
            data_issues.append({
                'type': 'info',
                'message': 'No geographical location data available'
            })

        if session.security_anomalies:
            data_issues.append({
                'type': 'error',
                'message': f'Security anomalies detected: {len(session.security_anomalies)} issues'
            })

        context.update({
            'session': session,
            'user_info': user_info,
            'shift_info': shift_info,
            'session_metrics': session_metrics,
            'data_issues': data_issues,
            'admin_office': admin_office,
        })

    except Exception as e:
        messages.error(request, f'Error loading session details: {str(e)}')
        return redirect('sessions:session_list')

    return render(request, 'sessions/session_detail.html', context)


@login_required
@user_passes_test(is_admin_user, login_url='/login/')
def office_locations(request):
    """
    Enhanced office locations view with session statistics.
    """
    context = {
        'page_title': 'Office Locations',
        'active_tab': 'locations'
    }

    try:
        # Get admin's office location
        admin_office = get_admin_office_location(request.user)

        # If admin has office restriction, show only their office
        if admin_office and not request.user.is_superuser:
            offices = OfficeLocation.objects.filter(id=admin_office.id, is_active=True)
        else:
            offices = OfficeLocation.objects.filter(is_active=True)

        # Add session statistics for each office
        enhanced_offices = []
        for office in offices:
            # Get users in this office
            office_users = UserDetails.objects.filter(office_location=office).values_list('user_id', flat=True)

            # Get session statistics
            office_sessions = UserSession.objects.filter(user_id__in=office_users)

            office_stats = {
                'total_employees': len(office_users),
                'total_sessions': office_sessions.count(),
                'active_sessions': office_sessions.filter(is_active=True).count(),
                'recent_sessions': office_sessions.filter(
                    created_at__gte=timezone.now() - timedelta(hours=24)
                ).count()
            }

            enhanced_offices.append({
                'office': office,
                'stats': office_stats
            })

        context.update({
            'enhanced_offices': enhanced_offices,
            'admin_office': admin_office,
            'is_restricted': admin_office and not request.user.is_superuser,
        })

    except Exception as e:
        messages.error(request, f'Error loading office locations: {str(e)}')
        context.update({
            'enhanced_offices': [],
            'admin_office': None,
            'is_restricted': False,
        })

    return render(request, 'sessions/office_locations.html', context)


@login_required
@user_passes_test(is_admin_user, login_url='/login/')
def location_detail(request, location_id):
    """
    Enhanced location detail view with comprehensive analytics.
    """
    context = {
        'page_title': 'Location Details',
        'active_tab': 'locations'
    }

    try:
        # Get admin's office location
        admin_office = get_admin_office_location(request.user)

        # Get the office location
        office = get_object_or_404(OfficeLocation, id=location_id, is_active=True)

        # Check if admin can view this office
        if admin_office and admin_office != office and not request.user.is_superuser:
            messages.error(request, 'You can only view your own office location.')
            return redirect('sessions:office_locations')

        # Get employees and their shift information
        employees = UserDetails.objects.filter(
            office_location=office
        ).select_related('user', 'reporting_manager').order_by('user__username')

        enhanced_employees = []
        for employee in employees:
            shift_info = get_user_shift_info(employee.user)
            recent_sessions = UserSession.objects.filter(
                user=employee.user,
                created_at__gte=timezone.now() - timedelta(days=7)
            ).count()

            enhanced_employees.append({
                'employee': employee,
                'shift_info': shift_info,
                'recent_sessions': recent_sessions
            })

        # Office statistics
        office_users = employees.values_list('user_id', flat=True)
        office_sessions = UserSession.objects.filter(user_id__in=office_users)

        office_stats = {
            'total_employees': employees.count(),
            'total_sessions': office_sessions.count(),
            'active_sessions': office_sessions.filter(is_active=True).count(),
            'today_sessions': office_sessions.filter(
                created_at__date=timezone.now().date()
            ).count(),
            'week_sessions': office_sessions.filter(
                created_at__gte=timezone.now() - timedelta(days=7)
            ).count()
        }

        context.update({
            'office': office,
            'enhanced_employees': enhanced_employees,
            'office_stats': office_stats,
            'admin_office': admin_office,
        })

    except Exception as e:
        messages.error(request, f'Error loading location details: {str(e)}')
        return redirect('sessions:office_locations')

    return render(request, 'sessions/location_detail.html', context)


@login_required
@user_passes_test(is_admin_user, login_url='/login/')
@require_http_methods(["POST"])
def end_session(request, session_id):
    """
    Enhanced end session functionality with logging.
    """
    try:
        admin_office = get_admin_office_location(request.user)
        session = get_object_or_404(UserSession, id=session_id, is_active=True)

        # Check office access if admin has restrictions
        if admin_office:
            try:
                user_details = UserDetails.objects.get(user=session.user)
                if user_details.office_location != admin_office and not request.user.is_superuser:
                    return JsonResponse({'success': False, 'error': 'Access denied'})
            except UserDetails.DoesNotExist:
                if not request.user.is_superuser:
                    return JsonResponse({'success': False, 'error': 'User office not found'})

        session.end_session()
        return JsonResponse({'success': True})

    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})


@login_required
@user_passes_test(is_admin_user, login_url='/login/')
def session_analytics(request):
    """
    Enhanced analytics view with office-based filtering and shift analysis.
    """
    context = {
        'page_title': 'Session Analytics',
        'active_tab': 'analytics'
    }

    try:
        # Get admin's office location
        admin_office = get_admin_office_location(request.user)

        # Base queryset with office filtering
        base_sessions = UserSession.objects.select_related('user')
        filtered_sessions = filter_sessions_by_office(base_sessions, admin_office)

        # Time-based analytics
        now = timezone.now()
        periods = {
            'today': now.replace(hour=0, minute=0, second=0, microsecond=0),
            'week': now - timedelta(days=7),
            'month': now - timedelta(days=30),
        }

        analytics = {}
        for period_name, start_date in periods.items():
            period_sessions = filtered_sessions.filter(created_at__gte=start_date)

            analytics[period_name] = {
                'total_sessions': period_sessions.count(),
                'unique_users': period_sessions.values('user').distinct().count(),
                'avg_duration': 0,
                'top_shifts': []
            }

            # Calculate average duration
            completed = period_sessions.filter(ended_at__isnull=False)
            if completed.exists():
                durations = []
                for session in completed[:100]:  # Sample for performance
                    if session.ended_at and session.created_at:
                        duration = (session.ended_at - session.created_at).total_seconds() / 3600
                        durations.append(duration)
                if durations:
                    analytics[period_name]['avg_duration'] = round(sum(durations) / len(durations), 2)

        # Shift-based analytics
        shift_analytics = []
        for shift in ShiftMaster.objects.all():
            shift_users = ShiftAssignment.objects.filter(
                shift=shift,
                is_current=True
            ).values_list('user_id', flat=True)

            shift_sessions = filtered_sessions.filter(user_id__in=shift_users)

            shift_analytics.append({
                'shift_name': shift.name,
                'total_users': len(shift_users),
                'total_sessions': shift_sessions.count(),
                'active_sessions': shift_sessions.filter(is_active=True).count(),
                'avg_productivity': shift_sessions.filter(
                    productivity_score__isnull=False
                ).aggregate(avg_score=Avg('productivity_score'))['avg_score'] or 0
            })

        context.update({
            'analytics': analytics,
            'shift_analytics': shift_analytics,
            'admin_office': admin_office,
        })

    except Exception as e:
        messages.error(request, f'Error loading analytics: {str(e)}')
        context.update({
            'analytics': {},
            'shift_analytics': [],
            'admin_office': None,
        })

    return render(request, 'sessions/analytics.html', context)


@login_required
@user_passes_test(is_admin_user, login_url='/login/')
def session_export(request):
    """
    Enhanced export functionality with office filtering and shift data.
    """
    try:
        # Get admin's office location for filtering
        admin_office = get_admin_office_location(request.user)

        # Get filter parameters
        date_from = request.GET.get('date_from')
        date_to = request.GET.get('date_to')
        user_id = request.GET.get('user_id')
        include_shift_data = request.GET.get('include_shift_data', 'true').lower() == 'true'

        # Build base query with office filtering
        sessions = UserSession.objects.select_related('user')
        sessions = filter_sessions_by_office(sessions, admin_office)

        # Apply additional filters
        if date_from:
            try:
                date_from_obj = datetime.strptime(date_from, '%Y-%m-%d').date()
                sessions = sessions.filter(created_at__date__gte=date_from_obj)
            except ValueError:
                pass

        if date_to:
            try:
                date_to_obj = datetime.strptime(date_to, '%Y-%m-%d').date()
                sessions = sessions.filter(created_at__date__lte=date_to_obj)
            except ValueError:
                pass

        if user_id:
            sessions = sessions.filter(user_id=user_id)

        # Limit to prevent memory issues
        sessions = sessions[:1000]

        # Prepare enhanced export data
        export_data = []
        for session in sessions:
            # Basic session data
            session_data = {
                'session_id': str(session.id),
                'user_username': session.user.username,
                'user_full_name': f"{session.user.first_name} {session.user.last_name}".strip(),
                'created_at': session.created_at.isoformat(),
                'last_activity': session.last_activity.isoformat(),
                'ended_at': session.ended_at.isoformat() if session.ended_at else None,
                'is_active': session.is_active,
                'is_idle': session.is_idle,
                'device_info': {
                    'device_type': session.device_type,
                    'browser': session.browser,
                    'os': session.os,
                    'screen_resolution': session.screen_resolution,
                },
                'location_info': {
                    'ip_address': session.ip_address,
                    'country': session.location_country,
                    'city': session.location_city,
                    'location_type': session.location_type,
                    'latitude': session.location_latitude,
                    'longitude': session.location_longitude,
                },
                'performance_metrics': {
                    'productivity_score': session.productivity_score,
                    'engagement_score': session.engagement_score,
                    'security_score': session.security_score,
                    'page_views': len(session.page_views) if session.page_views else 0,
                    'clicks': len(session.clicks) if session.clicks else 0,
                    'scrolls': len(session.scrolls) if session.scrolls else 0,
                    'mouse_movements': session.mouse_movements or 0,
                },
            }

            # Add user office information
            try:
                user_details = UserDetails.objects.select_related('office_location').get(user=session.user)
                session_data['office_info'] = {
                    'office_name': user_details.office_location.name if user_details.office_location else None,
                    'office_code': user_details.office_location.code if user_details.office_location else None,
                    'employment_status': user_details.employment_status,
                }
            except UserDetails.DoesNotExist:
                session_data['office_info'] = {
                    'office_name': None,
                    'office_code': None,
                    'employment_status': None,
                }

            # Add shift information if requested
            if include_shift_data:
                shift_info = get_user_shift_info(session.user, session.created_at.date())
                session_data['shift_info'] = {
                    'current_shift': shift_info['current_shift_name'],
                    'has_shift_data': shift_info['has_shift_data'],
                    'shift_history_count': len(shift_info['shift_history']),
                }

            export_data.append(session_data)

        # Prepare metadata
        metadata = {
            'export_timestamp': timezone.now().isoformat(),
            'exported_by': request.user.username,
            'admin_office': admin_office.name if admin_office else 'All Offices',
            'filters_applied': {
                'date_from': date_from,
                'date_to': date_to,
                'user_id': user_id,
                'include_shift_data': include_shift_data,
            },
            'total_count': len(export_data),
            'office_restricted': bool(admin_office and not request.user.is_superuser),
        }

        response = JsonResponse({
            'metadata': metadata,
            'sessions': export_data,
        }, json_dumps_params={'indent': 2})

        # Set filename for download
        office_suffix = f"_{admin_office.code}" if admin_office else "_all_offices"
        filename = f"sessions_export{office_suffix}_{timezone.now().strftime('%Y%m%d_%H%M%S')}.json"
        response['Content-Disposition'] = f'attachment; filename="{filename}"'

        return response

    except Exception as e:
        return JsonResponse({
            'error': f'Export failed: {str(e)}',
            'timestamp': timezone.now().isoformat()
        }, status=500)
