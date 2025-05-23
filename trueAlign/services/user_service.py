from .date_service import DateService
from .attendance_service import AttendanceService
from django.db.models import Q, Count, Avg, Max
from ..models import User, Attendance

# services/user_service.py
class UserService:
    """User-related data access service"""
    
    def __init__(self):
        self.date_service = DateService()
    
    def get_users_by_status(self, status, start_date, end_date, filters=None):
        """Get users by attendance status with optimized queries"""
        print(f"[DEBUG] get_users_by_status called with status={status}, start_date={start_date}, end_date={end_date}, filters={filters}")
        
        if status == 'Yet to Clock In':
            print("[DEBUG] Status is 'Yet to Clock In', delegating to _get_yet_to_clock_in_users")
            return self._get_yet_to_clock_in_users(end_date, filters)
        
        # Standard status query with proper joins
        print("[DEBUG] Building Attendance query for status:", status)
        query = Attendance.objects.filter(
            status=status,
            date__gte=start_date,
            date__lte=end_date
        ).select_related(
            'user', 
            'user__userdetails',
            'shift'
        ).prefetch_related(
            'user__leaverequest_set'
        )
        
        # Apply filters
        if filters:
            print(f"[DEBUG] Applying filters: {filters}")
            if filters.get('location') and filters['location'] != 'all':
                print(f"[DEBUG] Filtering by location: {filters['location']}")
                if filters['location'] == 'Unspecified':
                    query = query.filter(
                        Q(user__userdetails__work_location__isnull=True) |
                        Q(user__userdetails__work_location__exact='')
                    )
                else:
                    query = query.filter(user__userdetails__work_location=filters['location'])
            
            if filters.get('search'):
                search = filters['search']
                print(f"[DEBUG] Filtering by search: {search}")
                query = query.filter(
                    Q(user__username__icontains=search) |
                    Q(user__first_name__icontains=search) |
                    Q(user__last_name__icontains=search) |
                    Q(user__userdetails__work_location__icontains=search)
                )
        
        # Aggregate user data
        print("[DEBUG] Aggregating user data with values and annotate")
        users_data = query.values(
            'user_id',
            'user__username',
            'user__first_name', 
            'user__last_name',
            'user__userdetails__work_location',
            'clock_in_time',
            'clock_out_time',
            'total_hours',
            'late_minutes',
            'leave_type',
            'shift__name',
            'shift__start_time',
            'shift__end_time'
        ).annotate(
            attendance_count=Count('id'),
            avg_hours=Avg('total_hours'),
            avg_late_minutes=Avg('late_minutes'),
            last_date=Max('date')
        ).order_by('user__first_name')
        
        print(f"[DEBUG] users_data count: {users_data.count()}")
        return self._format_user_data(users_data, status)
    
    def _get_yet_to_clock_in_users(self, target_date, filters=None):
        """Get users who haven't clocked in yet - optimized version"""
        print(f"[DEBUG] _get_yet_to_clock_in_users called with target_date={target_date}, filters={filters}")
        current_date = self.date_service.get_current_date()
        print(f"[DEBUG] Current date: {current_date}")
        
        # Only process for current date
        if target_date != current_date:
            print("[DEBUG] Target date does not match current date, returning empty list")
            return []
        
        # Get all active users with their details in one query
        print("[DEBUG] Querying all active users with userdetails and shift")
        users_query = User.objects.filter(
            is_active=True
        ).select_related('userdetails', 'userdetails__shift')
        
        # Apply filters
        if filters:
            print(f"[DEBUG] Applying filters: {filters}")
            if filters.get('location') and filters['location'] != 'all':
                print(f"[DEBUG] Filtering by location: {filters['location']}")
                if filters['location'] == 'Unspecified':
                    users_query = users_query.filter(
                        Q(userdetails__work_location__isnull=True) |
                        Q(userdetails__work_location__exact='')
                    )
                else:
                    users_query = users_query.filter(userdetails__work_location=filters['location'])
            
            if filters.get('search'):
                search = filters['search']
                print(f"[DEBUG] Filtering by search: {search}")
                users_query = users_query.filter(
                    Q(username__icontains=search) |
                    Q(first_name__icontains=search) |
                    Q(last_name__icontains=search) |
                    Q(userdetails__work_location__icontains=search)
                )
        
        # Get users who already have attendance records today
        print(f"[DEBUG] Querying Attendance for users with attendance on {target_date}")
        users_with_attendance = set(
            Attendance.objects.filter(date=target_date).values_list('user_id', flat=True)
        )
        print(f"[DEBUG] users_with_attendance count: {len(users_with_attendance)}")
        
        # Filter out users who already have attendance
        yet_to_clock_in_users = []
        current_time = self.date_service.get_current_date_time().time()
        print(f"[DEBUG] Current time: {current_time}")
        
        for user in users_query:
            if user.id in users_with_attendance:
                print(f"[DEBUG] Skipping user {user.id} ({user.username}) - already has attendance")
                continue
            
            # Get user details
            user_detail = getattr(user, 'userdetails', None)
            shift = getattr(user_detail, 'shift', None) if user_detail else None
            
            # Calculate if user should have clocked in by now
            should_be_clocked_in = True  # Default assumption
            late_by = 0
            
            if shift and shift.start_time:
                grace_period_minutes = 30  # 30 minutes grace period
                shift_start_minutes = shift.start_time.hour * 60 + shift.start_time.minute
                current_minutes = current_time.hour * 60 + current_time.minute
                print(f"[DEBUG] User {user.id} shift start: {shift.start_time}, current_minutes: {current_minutes}, shift_start_minutes: {shift_start_minutes}")
                
                if current_minutes > shift_start_minutes + grace_period_minutes:
                    late_by = current_minutes - shift_start_minutes
                    print(f"[DEBUG] User {user.id} is late by {late_by} minutes")
                else:
                    should_be_clocked_in = False
                    print(f"[DEBUG] User {user.id} should not be clocked in yet (within grace period)")
            
            if should_be_clocked_in:
                print(f"[DEBUG] Adding user {user.id} ({user.username}) to yet_to_clock_in_users")
                yet_to_clock_in_users.append({
                    'user_id': user.id,
                    'username': user.username,
                    'name': f"{user.first_name or ''} {user.last_name or ''}".strip() or user.username,
                    'work_location': user_detail.work_location if user_detail else 'Unspecified',
                    'shift_name': shift.name if shift else 'Regular',
                    'shift_start_time': shift.start_time.strftime('%H:%M') if shift and shift.start_time else None,
                    'shift_end_time': shift.end_time.strftime('%H:%M') if shift and shift.end_time else None,
                    'late_by': late_by,
                    'status': 'Yet to Clock In'
                })
        
        print(f"[DEBUG] yet_to_clock_in_users count: {len(yet_to_clock_in_users)}")
        return yet_to_clock_in_users
    
    def _format_user_data(self, users_data, status):
        """Format user data for display"""
        print(f"[DEBUG] _format_user_data called with status={status}")
        formatted_users = []
        
        for user in users_data:
            print(f"[DEBUG] Formatting user: {user.get('user_id', 'N/A')}")
            user_info = {
                'user_id': user['user_id'],
                'username': user['user__username'],
                'name': f"{user['user__first_name'] or ''} {user['user__last_name'] or ''}".strip() or user['user__username'],
                'work_location': user['user__userdetails__work_location'] or 'Unspecified',
                'shift_name': user['shift__name'] or 'Regular',
                'shift_start_time': user['shift__start_time'].strftime('%H:%M') if user['shift__start_time'] else None,
                'shift_end_time': user['shift__end_time'].strftime('%H:%M') if user['shift__end_time'] else None,
                'attendance_count': user['attendance_count'],
                'last_date': user['last_date'].strftime('%Y-%m-%d') if user['last_date'] else '',
                'status': status
            }
            
            # Add status-specific fields
            if status in ['Present', 'Present & Late', 'Work From Home']:
                user_info.update({
                    'clock_in_time': user['clock_in_time'].strftime('%H:%M') if user['clock_in_time'] else None,
                    'clock_out_time': user['clock_out_time'].strftime('%H:%M') if user['clock_out_time'] else None,
                    'total_hours': float(user['total_hours']) if user['total_hours'] else 0,
                    'avg_hours': float(user['avg_hours']) if user['avg_hours'] else 0,
                    'late_minutes': user['late_minutes'] or 0,
                    'avg_late_minutes': float(user['avg_late_minutes']) if user['avg_late_minutes'] else 0
                })
                print(f"[DEBUG] Added present/late/WFH fields for user {user['user_id']}")
            elif status == 'On Leave':
                user_info.update({
                    'leave_type': user['leave_type'] or 'Unknown'
                })
                print(f"[DEBUG] Added leave_type for user {user['user_id']}")
            
            formatted_users.append(user_info)
        
        print(f"[DEBUG] Returning {len(formatted_users)} formatted users")
        return formatted_users