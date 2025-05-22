Primary Issues:
1. Field Name Mismatch
* Your JavaScript is looking for total_users but your backend is sending total_employees
* This causes the user count to not display properly in the location cards
2. Status Filtering Problems
* "Present & Late" status is not being handled correctly in your backend
* The JavaScript assumes this status exists but your backend might not be filtering for it properly
* Your debug logs show "Present & Late" count of 2, but when clicked, it shows "No records found"
3. Null Value Display Issues
* Many fields are showing as "null" instead of proper names
* This suggests your database joins or field selections are not working correctly
* User names, locations, and shift details are not being populated properly
4. Backend Query Logic
* Your location filtering in the get_status_users view might not be working correctly
* The view might not be properly joining user details with attendance records
* Status detection logic seems inconsistent between the analytics view and the detail view
5. Data Structure Inconsistencies
* The data structure returned by get_status_users doesn't match what the JavaScript expects
* Field names like name, work_location, shift_name might not be the actual field names in your response
Root Causes:
Backend Issues:
* Your get_status_users view is probably not properly joining tables
* Status filtering logic is incomplete or incorrect
* Field selection in queries is missing proper field names or relationships
Frontend Issues:
* JavaScript is hardcoded to expect specific field names that don't match backend response
* Status name parsing logic is too simplistic for compound statuses like "Present & Late"
Data Flow Problems:
* The analytics view calculates stats correctly (you see counts)
* But the detail view (get_status_users) uses different logic and fails to return matching records
* This creates a disconnect where summary shows data but details show empty
What You Need to Fix:
1. Fix the get_status_users view to properly handle all status types, especially "Present & Late"
2. Ensure proper database joins so user names and details are populated
3. Standardize field names between backend response and frontend expectations
4. Add proper null handling for missing data
5. Debug the query logic to ensure location filtering works correctly



---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

[DEBUG] Query Params: time_period=today, view_type=daily, custom_start=None, custom_end=None, location=None, user_id=None, drill_down=None, status_filter=None, global_search=
[DEBUG] Date filters: start_date=2025-05-22, end_date=2025-05-22
[DEBUG] Base attendance query count: 6
[DEBUG] Loaded user_details_dict with 6 users
[DEBUG] Loaded active_shifts: [1]
[DEBUG] Default shift: Day Shift (09:00 - 17:30)
[DEBUG] Using trunc_function for view_type 'daily': <class 'django.db.models.functions.datetime.TruncDay'>
[DEBUG] attendance_stats: [{'period': datetime.date(2025, 5, 22), 'total': 6, 'present_count': 4, 'present_late_count': 2, 'absent_count': 0, 'leave_count': 0, 'wfh_count': 0, 'weekend_count': 0, 'holiday_count': 0, 'comp_off_count': 0, 'not_marked_count': 0, 'avg_hours': Decimal('4.171667'), 'avg_late_minutes': 299.3333}]
[DEBUG] status_counts: [{'status': 'Present', 'count': 4}, {'status': 'Present & Late', 'count': 2}]
[DEBUG] working_days_count (excluding weekends/holidays): 6
[DEBUG] present_count: 6
[DEBUG] overall_stats: {'total_records': 6, 'present_percentage': 100.0, 'absent_percentage': 0.0, 'leave_percentage': 0.0, 'avg_working_hours': Decimal('4.171667'), 'total_late_instances': 2, 'avg_late_minutes': 299.3333, 'status_counts': [{'status': 'Present', 'count': 4}, {'status': 'Present & Late', 'count': 2}]}
[DEBUG] active_sessions: []
[DEBUG] top_absent_users: []
[DEBUG] top_late_users: [{'user_id': 3, 'user__username': 'managerSupport', 'user__first_name': '', 'user__last_name': '', 'late_count': 1, 'avg_late_minutes': 64.0}, {'user_id': 6, 'user__username': 'ATS0012', 'user__first_name': 'Wikas', 'user__last_name': 'Raut', 'late_count': 1, 'avg_late_minutes': 90.0}]
[DEBUG] leave_distribution: []
[DEBUG] Processing locations: ['Betul', 'Unspecified']
[DEBUG] Location 'Betul': user_ids=[6]
[DEBUG] Location 'Betul': attendance count=1
[DEBUG] Location 'Betul': present=1, absent=0, leave=0, wfh=0
[DEBUG] Location 'Betul': active_users=1, users_with_attendance=1, yet_to_clock_in=0
[DEBUG] Location 'Betul': working_users=1, present_percentage=100.0
[DEBUG] Location 'Unspecified': user_ids=[1, 2, 3, 4, 5]
[DEBUG] Location 'Unspecified': attendance count=5
[DEBUG] Location 'Unspecified': present=5, absent=0, leave=0, wfh=0
[DEBUG] Location 'Unspecified': active_users=5, users_with_attendance=5, yet_to_clock_in=0
[DEBUG] Location 'Unspecified': working_users=5, present_percentage=100.0
[DEBUG] Final location_stats: [{'location': 'Unspecified', 'total_employees': 5, 'present_count': 5, 'absent_count': 0, 'leave_count': 0, 'wfh_count': 0, 'present_percentage': 100.0, 'yet_to_clock_in_count': 0}, {'location': 'Betul', 'total_employees': 1, 'present_count': 1, 'absent_count': 0, 'leave_count': 0, 'wfh_count': 0, 'present_percentage': 100.0, 'yet_to_clock_in_count': 0}]
[DEBUG] location_stats: [{'location': 'Unspecified', 'total_employees': 5, 'present_count': 5, 'absent_count': 0, 'leave_count': 0, 'wfh_count': 0, 'present_percentage': 100.0, 'yet_to_clock_in_count': 0}, {'location': 'Betul', 'total_employees': 1, 'present_count': 1, 'absent_count': 0, 'leave_count': 0, 'wfh_count': 0, 'present_percentage': 100.0, 'yet_to_clock_in_count': 0}]
[DEBUG] today: 2025-05-22, week_start: 2025-05-19, prev_week_start: 2025-05-12
[DEBUG] this_week_data: [{'status': 'Present', 'count': 7}, {'status': 'Present & Late', 'count': 5}]
[DEBUG] prev_week_data: []
[DEBUG] Calculating yet to clock in users for end_date=2025-05-22, location=None, global_search=
[DEBUG] Current date: 2025-05-22, Current time: 2025-05-22 17:04:46.651598+05:30
[DEBUG] Initial user_qs count: 6
[DEBUG] Clocked in users for 2025-05-22: [1, 2, 3, 4, 5, 6]
[DEBUG] Excluded users (leave/holiday/weekend/absent) for 2025-05-22: []
[DEBUG] All marked users for 2025-05-22: [1, 2, 3, 4, 5, 6]
[DEBUG] Unmarked users count: 0
[DEBUG] Total yet_to_clock_in_users: 0
[DEBUG] Final context: {'time_period': 'today', 'view_type': 'daily', 'start_date': datetime.date(2025, 5, 22), 'end_date': datetime.date(2025, 5, 22), 'overall_stats': {'total_records': 6, 'present_percentage': 100.0, 'absent_percentage': 0.0, 'leave_percentage': 0.0, 'avg_working_hours': Decimal('4.171667'), 'total_late_instances': 2, 'avg_late_minutes': 299.3333, 'status_counts': [{'status': 'Present', 'count': 4}, {'status': 'Present & Late', 'count': 2}]}, 'attendance_stats': [{'period': datetime.date(2025, 5, 22), 'total': 6, 'present_count': 4, 'present_late_count': 2, 'absent_count': 0, 'leave_count': 0, 'wfh_count': 0, 'weekend_count': 0, 'holiday_count': 0, 'comp_off_count': 0, 'not_marked_count': 0, 'avg_hours': Decimal('4.171667'), 'avg_late_minutes': 299.3333}], 'active_sessions': [], 'top_absent_users': [], 'top_late_users': [{'user_id': 3, 'user__username': 'managerSupport', 'user__first_name': '', 'user__last_name': '', 'late_count': 1, 'avg_late_minutes': 64.0}, {'user_id': 6, 'user__username': 'ATS0012', 'user__first_name': 'Wikas', 'user__last_name': 'Raut', 'late_count': 1, 'avg_late_minutes': 90.0}], 'leave_distribution': [], 'location_stats': [{'location': 'Unspecified', 'total_employees': 5, 'present_count': 5, 'absent_count': 0, 'leave_count': 0, 'wfh_count': 0, 'present_percentage': 100.0, 'yet_to_clock_in_count': 0}, {'location': 'Betul', 'total_employees': 1, 'present_count': 1, 'absent_count': 0, 'leave_count': 0, 'wfh_count': 0, 'present_percentage': 100.0, 'yet_to_clock_in_count': 0}], 'this_week_data': [{'status': 'Present', 'count': 7}, {'status': 'Present & Late', 'count': 5}], 'prev_week_data': [], 'yet_to_clock_in_users': [], 'global_search': ''}
[DEBUG] Rendering attendance_analytics.html with context
HTTP GET /attendance/analytics/ 200 [0.18, 127.0.0.1:50306]





--------------------------------------------------------


@login_required
@user_passes_test(is_hr_check)
def get_status_users(request):
    """
    Updated function with comprehensive fixes for attendance status queries
    """
    from .models import Attendance, User, UserDetails, ShiftMaster, LeaveRequest
    from django.db.models import Q, Count, Avg, Max
    import logging
    from django.utils import timezone
    from django.utils.dateparse import parse_date
    import pytz
    from django.conf import settings

    logger = logging.getLogger(__name__)

    # Constants for validation and thresholds
    LATE_THRESHOLD_MINUTES = 30  # Grace period before marking as late
    MAX_REALISTIC_LATE_MINUTES = 480  # 8 hours - flag unrealistic values
    HISTORICAL_QUERY_DAYS_LIMIT = 7  # Days after which "Yet to Clock In" becomes "Absent"

    try:
        # Get and validate parameters
        status = request.GET.get('status')
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')
        location = request.GET.get('location')
        global_search = request.GET.get('search', '').strip()

        if not status or not start_date or not end_date:
            logger.warning("Missing required parameters in get_status_users")
            return JsonResponse({'error': 'Missing required parameters'}, status=400)

        # Parse dates with error handling
        try:
            start_date = parse_date(start_date)
            end_date = parse_date(end_date)
            if not start_date or not end_date:
                raise ValueError("Invalid date format")
        except (ValueError, TypeError) as e:
            logger.error(f"Invalid date format in get_status_users: {e}")
            return JsonResponse({'error': 'Invalid date format'}, status=400)

        # Get all user details and shifts with optimized queries
        try:
            # Use select_related and prefetch_related for better performance
            user_details_dict = {
                ud.user_id: ud 
                for ud in UserDetails.objects.select_related('user', 'shift').all()
            }
            
            # Cache active shifts
            active_shifts = {
                s.id: s 
                for s in ShiftMaster.objects.filter(is_active=True).only(
                    'id', 'name', 'start_time', 'end_time', 'is_active'
                )
            }
            
            default_shift = next(iter(active_shifts.values()), None)
            
        except Exception as e:
            logger.error(f"Error loading user details and shifts: {e}")
            user_details_dict = {}
            active_shifts = {}
            default_shift = None

        # Handle "Yet to Clock In" status with improved logic
        if status in ['Yet to Clock In', 'Not Clocked In']:
            try:
                IST = pytz.timezone('Asia/Kolkata')
                current_date = timezone.localtime(timezone.now(), IST).date()
                current_time = timezone.localtime(timezone.now(), IST).time()
                
                # Allow historical "Yet to Clock In" queries but adjust logic based on date
                is_historical_query = end_date < current_date
                
                # For historical dates, check if query is too old
                if is_historical_query:
                    days_diff = (current_date - end_date).days
                    if days_diff > HISTORICAL_QUERY_DAYS_LIMIT:
                        # Too old - likely absent, not "yet to clock in"
                        return JsonResponse({
                            'status': 'success',
                            'data': {
                                'users': [],
                                'count': 0,
                                'message': f'For dates older than {HISTORICAL_QUERY_DAYS_LIMIT} days, check "Absent" status instead',
                                'suggestion': 'Use "Absent" status for historical attendance queries'
                            }
                        })

                # Get base user queryset - only active users with optimized query
                try:
                    user_qs = User.objects.filter(
                        is_active=True
                    ).select_related('profile').only(
                        'id', 'username', 'first_name', 'last_name', 'is_active'
                    )
                except Exception as e:
                    logger.error(f"Error getting active users: {e}")
                    return JsonResponse({'error': 'Error loading users'}, status=500)

                # Apply location filter with error handling
                try:
                    if location and location not in ['all', 'Unspecified']:
                        user_qs = user_qs.filter(profile__work_location=location)
                    elif location == 'Unspecified':
                        user_qs = user_qs.filter(
                            Q(profile__work_location__isnull=True) | 
                            Q(profile__work_location__exact='') |
                            Q(profile__isnull=True)
                        )
                except Exception as e:
                    logger.error(f"Error applying location filter: {e}")
                    # Continue without location filter

                # Apply global search with error handling
                try:
                    if global_search:
                        user_qs = user_qs.filter(
                            Q(username__icontains=global_search) |
                            Q(first_name__icontains=global_search) |
                            Q(last_name__icontains=global_search) |
                            Q(profile__work_location__icontains=global_search)
                        )
                except Exception as e:
                    logger.error(f"Error applying global search filter: {e}")
                    # Continue without global search filter

                # Get users who haven't clocked in for the specified date range
                try:
                    users_with_attendance = list(Attendance.objects.filter(
                        date__range=[start_date, end_date]  # Check entire range, not just end_date
                    ).values_list('user_id', flat=True).distinct())

                    # Filter to users without any attendance record in the date range
                    yet_to_clock_in_qs = user_qs.exclude(id__in=users_with_attendance)
                    
                except Exception as e:
                    logger.error(f"Error filtering users with attendance: {e}")
                    return JsonResponse({'error': 'Error processing attendance data'}, status=500)

                result = []

                # Process each user
                for user in yet_to_clock_in_qs:
                    try:
                        # Get user profile safely
                        try:
                            user_profile = user.profile
                            work_location = user_profile.work_location or "Unspecified"
                        except UserDetails.DoesNotExist:
                            work_location = "Unspecified"
                            user_profile = None

                        # Get shift information with error handling
                        shift = None
                        shift_name = "Regular"
                        shift_start = None
                        shift_end = None
                        
                        try:
                            if user_profile and hasattr(user_profile, 'shift_id') and user_profile.shift_id and user_profile.shift_id in active_shifts:
                                shift = active_shifts[user_profile.shift_id]
                            else:
                                shift = default_shift

                            if shift:
                                shift_name = shift.name
                                shift_start = shift.start_time
                                shift_end = shift.end_time
                        except Exception as e:
                            logger.error(f"Error getting shift info for user {user.id}: {e}")

                        # Calculate late minutes with improved validation
                        late_by = 0
                        is_realistic_late = True

                        try:
                            if shift_start and not is_historical_query:  # Only calculate for current day
                                shift_minutes = shift_start.hour * 60 + shift_start.minute
                                current_minutes = current_time.hour * 60 + current_time.minute
                                
                                # Only calculate late if beyond grace period
                                if current_minutes > shift_minutes + LATE_THRESHOLD_MINUTES:
                                    late_by = current_minutes - shift_minutes
                                    
                                    # Validate realistic late minutes
                                    if late_by > MAX_REALISTIC_LATE_MINUTES:
                                        logger.warning(f"Unrealistic late minutes: {late_by} for user {user.id}")
                                        late_by = min(late_by, MAX_REALISTIC_LATE_MINUTES)  # Cap at max
                                        is_realistic_late = False
                                else:
                                    late_by = 0  # Within grace period
                                    
                        except Exception as e:
                            logger.error(f"Error calculating late minutes for user {user.id}: {e}")
                            late_by = 0

                        result.append({
                            'user_id': user.id,
                            'username': user.username,
                            'name': f"{user.first_name or ''} {user.last_name or ''}".strip() or user.username,
                            'work_location': work_location,
                            'shift_name': shift_name,
                            'shift_start_time': shift_start.strftime('%H:%M') if shift_start else None,
                            'shift_end_time': shift_end.strftime('%H:%M') if shift_end else None,
                            'late_by': late_by,
                            'late_validation': 'realistic' if is_realistic_late else 'capped'
                        })

                    except Exception as e:
                        logger.error(f"Error processing user {user.id}: {e}")
                        continue

                return JsonResponse({
                    'status': 'success',
                    'data': {
                        'users': result,
                        'count': len(result),
                        'filters_applied': {
                            'status': status,
                            'date_range': f"{start_date} to {end_date}",
                            'location': location,
                            'search': global_search
                        },
                        'query_info': {
                            'is_historical': is_historical_query,
                            'total_active_users': user_qs.count(),
                            'users_with_attendance': len(users_with_attendance),
                            'grace_period_minutes': LATE_THRESHOLD_MINUTES
                        }
                    }
                })

            except Exception as e:
                logger.error(f"Critical error in Yet to Clock In processing: {e}")
                return JsonResponse({'error': 'Error processing yet to clock in data'}, status=500)

        # Handle other statuses with proper joins and filtering
        try:
            # Base query with proper joins
            query = Attendance.objects.filter(
                status=status,
                date__gte=start_date,
                date__lte=end_date
            ).select_related('user', 'user__profile')

            # Apply location filter if provided
            if location and location != 'all':
                try:
                    if location == 'Unspecified':
                        query = query.filter(
                            Q(user__profile__work_location__isnull=True) | 
                            Q(user__profile__work_location__exact='') |
                            Q(user__profile__isnull=True)
                        )
                    else:
                        query = query.filter(user__profile__work_location=location)
                except Exception as e:
                    logger.error(f"Error applying location filter for status {status}: {e}")

            # Global search filter
            if global_search:
                try:
                    query = query.filter(
                        Q(user__username__icontains=global_search) |
                        Q(user__first_name__icontains=global_search) |
                        Q(user__last_name__icontains=global_search) |
                        Q(user__id__icontains=global_search) |
                        Q(user__profile__work_location__icontains=global_search)
                    )
                except Exception as e:
                    logger.error(f"Error applying global search for status {status}: {e}")

            # Get leave requests for leave status
            leave_requests = {}
            if status == 'On Leave':
                try:
                    user_ids = list(set(query.values_list('user_id', flat=True)))
                    leave_reqs = LeaveRequest.objects.filter(
                        user_id__in=user_ids,
                        status='Approved',
                        start_date__lte=end_date,
                        end_date__gte=start_date
                    ).select_related('leave_type')
                    
                    for lr in leave_reqs:
                        if lr.user_id not in leave_requests or lr.end_date > leave_requests[lr.user_id]['end_date']:
                            leave_requests[lr.user_id] = {
                                'start_date': lr.start_date,
                                'end_date': lr.end_date,
                                'leave_type': lr.leave_type.name if lr.leave_type else 'Unknown',
                                'days': float(lr.leave_days) if lr.leave_days else 1
                            }
                except Exception as e:
                    logger.error(f"Error getting leave requests: {e}")

            # Get attendance records with proper aggregation and validation
            try:
                attendance_records = query.values(
                    'user_id', 
                    'user__username', 
                    'user__first_name', 
                    'user__last_name',
                    'clock_in_time', 
                    'clock_out_time', 
                    'leave_type', 
                    'date',
                    'total_hours',
                    'late_minutes'
                ).annotate(
                    count=Count('id'),
                    avg_late_minutes=Avg('late_minutes'),
                    avg_hours=Avg('total_hours'),
                    last_date=Max('date')
                ).order_by('user__first_name')
                
                # Validate query results
                if not attendance_records.exists():
                    return JsonResponse({
                        'status': 'success',
                        'data': {
                            'users': [],
                            'count': 0,
                            'message': f'No {status} records found for the specified criteria'
                        }
                    })
                    
            except Exception as e:
                logger.error(f"Error querying attendance data for status {status}: {e}")
                return JsonResponse({
                    'error': f'Database error while fetching {status} data',
                    'details': str(e) if settings.DEBUG else 'Contact administrator'
                }, status=500)

            # Process user data
            result = []
            processed_users = set()  # To handle duplicates
            
            for record in attendance_records:
                try:
                    user_id = record['user_id']
                    
                    # Skip if already processed (for aggregated data)
                    if user_id in processed_users:
                        continue
                    processed_users.add(user_id)
                    
                    # Get user profile safely
                    try:
                        user_detail = user_details_dict.get(user_id)
                        work_location = user_detail.work_location if user_detail else "Unspecified"
                    except Exception as e:
                        logger.error(f"Error getting user detail for {user_id}: {e}")
                        work_location = "Unspecified"

                    # Get user's shift information with error handling
                    try:
                        shift = None
                        if user_detail and hasattr(user_detail, 'shift_id') and user_detail.shift_id and user_detail.shift_id in active_shifts:
                            shift = active_shifts[user_detail.shift_id]
                        else:
                            shift = default_shift

                        shift_name = shift.name if shift else "Regular"
                        shift_start = shift.start_time if shift else None
                        shift_end = shift.end_time if shift else None
                    except Exception as e:
                        logger.error(f"Error getting shift info for user {user_id}: {e}")
                        shift_name = "Regular"
                        shift_start = None
                        shift_end = None

                    # Format shift times
                    shift_start_str = shift_start.strftime('%H:%M') if shift_start else None
                    shift_end_str = shift_end.strftime('%H:%M') if shift_end else None

                    # Base user data
                    user_data = {
                        'user_id': user_id,
                        'username': record['user__username'] or '',
                        'name': f"{record['user__first_name'] or ''} {record['user__last_name'] or ''}".strip() or record['user__username'],
                        'work_location': work_location,
                        'count': record['count'],
                        'last_attendance_date': record['last_date'].strftime('%Y-%m-%d') if record['last_date'] else '',
                        'shift_name': shift_name,
                        'shift_start_time': shift_start_str,
                        'shift_end_time': shift_end_str,
                    }

                    # Add status-specific information with validation
                    if status in ['Present', 'Present & Late', 'Work From Home']:
                        try:
                            # Format clock in/out times
                            clock_in_time = record['clock_in_time']
                            clock_out_time = record['clock_out_time']
                            
                            # Validate late minutes
                            late_minutes = record['late_minutes'] or 0
                            avg_late_minutes = float(record['avg_late_minutes']) if record['avg_late_minutes'] else 0
                            
                            # Flag unrealistic late minutes
                            late_validation = 'realistic'
                            if avg_late_minutes > MAX_REALISTIC_LATE_MINUTES:
                                late_validation = 'needs_review'
                                logger.warning(f"User {user_id} has unrealistic average late minutes: {avg_late_minutes}")
                            
                            user_data.update({
                                'clock_in_time': clock_in_time.strftime('%H:%M') if clock_in_time else None,
                                'clock_out_time': clock_out_time.strftime('%H:%M') if clock_out_time else None,
                                'avg_late_minutes': avg_late_minutes,
                                'avg_hours': float(record['avg_hours']) if record['avg_hours'] else 0,
                                'late_minutes': late_minutes,
                                'total_hours': float(record['total_hours']) if record['total_hours'] else 0,
                                'late_validation': late_validation
                            })
                        except Exception as e:
                            logger.error(f"Error formatting clock times for user {user_id}: {e}")
                            user_data.update({
                                'clock_in_time': None,
                                'clock_out_time': None,
                                'avg_late_minutes': 0,
                                'avg_hours': 0,
                                'late_minutes': 0,
                                'total_hours': 0,
                                'late_validation': 'error'
                            })
                            
                    elif status == 'On Leave':
                        try:
                            leave_info = leave_requests.get(user_id, {})
                            leave_start = leave_info.get('start_date', record['date'])
                            leave_end = leave_info.get('end_date', record['date'])
                            leave_type = leave_info.get('leave_type', record['leave_type'] or 'Unknown')
                            leave_days = leave_info.get('days', 1)

                            user_data.update({
                                'leave_type': leave_type,
                                'leave_start_date': leave_start.strftime('%Y-%m-%d') if hasattr(leave_start, 'strftime') else str(leave_start),
                                'leave_end_date': leave_end.strftime('%Y-%m-%d') if hasattr(leave_end, 'strftime') else str(leave_end),
                                'leave_days': leave_days
                            })
                        except Exception as e:
                            logger.error(f"Error formatting leave data for user {user_id}: {e}")
                            user_data.update({
                                'leave_type': record.get('leave_type', 'Unknown'),
                                'leave_start_date': record.get('date', '').strftime('%Y-%m-%d') if record.get('date') else '',
                                'leave_end_date': record.get('date', '').strftime('%Y-%m-%d') if record.get('date') else '',
                                'leave_days': 1
                            })

                    result.append(user_data)

                except Exception as e:
                    logger.error(f"Error processing user data for user {record.get('user_id', 'unknown')}: {e}")
                    continue

            return JsonResponse({
                'status': 'success',
                'data': {
                    'users': result,
                    'count': len(result),
                    'filters_applied': {
                        'status': status,
                        'date_range': f"{start_date} to {end_date}",
                        'location': location,
                        'search': global_search
                    }
                }
            })

        except Exception as e:
            logger.error(f"Critical error processing status {status}: {e}")
            return JsonResponse({'error': f'Error processing {status} data'}, status=500)

    except Exception as e:
        logger.error(f"Critical error in get_status_users: {e}")
        return JsonResponse({'error': 'Internal server error'}, status=500)
