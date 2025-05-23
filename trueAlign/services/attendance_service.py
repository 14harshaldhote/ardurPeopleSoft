# services/attendance_service.py
from django.db.models import Q, Count, Avg, Max, F, Case, When
from django.db.models.functions import TruncDay, TruncWeek, TruncMonth, TruncQuarter, TruncYear
from ..models import Attendance, User, UserDetails, ShiftMaster
import logging
from .date_service import DateService

logger = logging.getLogger(__name__)

class AttendanceService:
    """Core attendance business logic service"""
    
    def __init__(self):
        self.date_service = DateService()
    
    def get_trunc_function(self, view_type):
        """Get appropriate truncation function for date grouping"""
        print(f"[DEBUG] get_trunc_function called with view_type={view_type}")
        trunc_map = {
            'daily': TruncDay,
            'weekly': TruncWeek,
            'monthly': TruncMonth,
            'quarterly': TruncQuarter,
            'yearly': TruncYear,
        }
        trunc_func = trunc_map.get(view_type, TruncDay)
        print(f"[DEBUG] get_trunc_function returning {trunc_func}")
        return trunc_func
    
    def get_base_attendance_query(self, start_date, end_date, filters=None):
        """Get optimized base attendance query with all necessary joins"""
        print(f"[DEBUG] get_base_attendance_query called with start_date={start_date}, end_date={end_date}, filters={filters}")
        query = Attendance.objects.filter(
            date__gte=start_date,
            date__lte=end_date
        ).select_related('user', 'shift')
        
        if filters:
            print(f"[DEBUG] Filters provided: {filters}")
            if filters.get('location'):
                print(f"[DEBUG] Filtering by location: {filters['location']}")
                if filters['location'] == 'Unspecified':
                    query = query.filter(
                        Q(user__profile__work_location__isnull=True) |
                        Q(user__profile__work_location__exact='')
                    )
                    print("[DEBUG] Applied filter for Unspecified location")
                else:
                    query = query.filter(user__profile__work_location=filters['location'])
                    print(f"[DEBUG] Applied filter for location: {filters['location']}")
            
            if filters.get('user_id'):
                query = query.filter(user_id=filters['user_id'])
                print(f"[DEBUG] Applied filter for user_id: {filters['user_id']}")
            
            if filters.get('status'):
                query = query.filter(status=filters['status'])
                print(f"[DEBUG] Applied filter for status: {filters['status']}")
            
            if filters.get('search'):
                search = filters['search']
                query = query.filter(
                    Q(user__username__icontains=search) |
                    Q(user__first_name__icontains=search) |
                    Q(user__last_name__icontains=search) |
                    Q(user__profile__work_location__icontains=search)
                )
                print(f"[DEBUG] Applied search filter: {search}")
        
        print(f"[DEBUG] Returning base attendance query: {query}")
        return query
    
    def get_attendance_statistics(self, base_query, view_type):
        """Get aggregated attendance statistics"""
        print(f"[DEBUG] get_attendance_statistics called with view_type={view_type}")
        trunc_function = self.get_trunc_function(view_type)
        print(f"[DEBUG] Using trunc_function: {trunc_function}")
        
        result = base_query.annotate(
            period=trunc_function('date')
        ).values('period').annotate(
            total=Count('id'),
            present_count=Count(Case(When(status='Present', then=1))),
            present_late_count=Count(Case(When(status='Present & Late', then=1))),
            absent_count=Count(Case(When(status='Absent', then=1))),
            leave_count=Count(Case(When(status='On Leave', then=1))),
            wfh_count=Count(Case(When(status='Work From Home', then=1))),
            weekend_count=Count(Case(When(status='Weekend', then=1))),
            holiday_count=Count(Case(When(status='Holiday', then=1))),
            comp_off_count=Count(Case(When(status='Comp Off', then=1))),
            not_marked_count=Count(Case(When(status='Not Marked', then=1))),
            avg_hours=Avg('total_hours'),
            avg_late_minutes=Avg(Case(When(late_minutes__gt=0, then=F('late_minutes'))))
        ).order_by('period')
        print(f"[DEBUG] get_attendance_statistics result: {list(result)}")
        return result
    
    def get_overall_statistics(self, base_query):
        """Calculate overall attendance statistics"""
        print("[DEBUG] get_overall_statistics called")
        status_counts = base_query.values('status').annotate(count=Count('id')).order_by('-count')
        print(f"[DEBUG] status_counts: {list(status_counts)}")
        
        # Calculate percentages excluding weekends and holidays
        working_days_count = base_query.exclude(status__in=['Weekend', 'Holiday']).count()
        print(f"[DEBUG] working_days_count (excluding weekends/holidays): {working_days_count}")
        present_count = base_query.filter(status__in=['Present', 'Present & Late', 'Work From Home']).count()
        print(f"[DEBUG] present_count: {present_count}")
        
        total_records = base_query.count()
        print(f"[DEBUG] total_records: {total_records}")
        absent_count = base_query.filter(status='Absent').count()
        print(f"[DEBUG] absent_count: {absent_count}")
        leave_count = base_query.filter(status='On Leave').count()
        print(f"[DEBUG] leave_count: {leave_count}")
        avg_working_hours = base_query.filter(total_hours__isnull=False).aggregate(avg=Avg('total_hours'))['avg'] or 0
        print(f"[DEBUG] avg_working_hours: {avg_working_hours}")
        total_late_instances = base_query.filter(status='Present & Late').count()
        print(f"[DEBUG] total_late_instances: {total_late_instances}")
        avg_late_minutes = base_query.filter(late_minutes__gt=0).aggregate(avg=Avg('late_minutes'))['avg'] or 0
        print(f"[DEBUG] avg_late_minutes: {avg_late_minutes}")
        
        result = {
            'total_records': total_records,
            'present_percentage': round(present_count / max(working_days_count, 1) * 100, 2),
            'absent_percentage': round(absent_count / max(working_days_count, 1) * 100, 2),
            'leave_percentage': round(leave_count / max(working_days_count, 1) * 100, 2),
            'avg_working_hours': avg_working_hours,
            'total_late_instances': total_late_instances,
            'avg_late_minutes': avg_late_minutes,
            'status_counts': list(status_counts)
        }
        print(f"[DEBUG] get_overall_statistics result: {result}")
        return result
    
    def get_location_statistics(self, start_date, end_date, base_query):
        """Calculate location-based statistics efficiently"""
        print(f"[DEBUG] get_location_statistics called with start_date={start_date}, end_date={end_date}")
        
        # Get all locations with user counts in a single query
        location_stats = UserDetails.objects.filter(
            user__is_active=True
        ).exclude(
            Q(work_location__isnull=True) | Q(work_location__exact='')
        ).values('work_location').annotate(
            total_employees=Count('user_id')
        ).order_by('-total_employees')
        print(f"[DEBUG] location_stats: {list(location_stats)}")
        
        # Get attendance counts by location in single query
        attendance_by_location = base_query.filter(
            user__profile__work_location__isnull=False
        ).values('user__profile__work_location', 'status').annotate(
            count=Count('user_id', distinct=True)
        )
        print(f"[DEBUG] attendance_by_location: {list(attendance_by_location)}")
        
        # Process results
        location_data = {}
        for stat in location_stats:
            location = stat['work_location']
            location_data[location] = {
                'location': location,
                'total_employees': stat['total_employees'],
                'present_count': 0,
                'absent_count': 0,
                'leave_count': 0,
                'wfh_count': 0,
                'present_percentage': 0.0
            }
        print(f"[DEBUG] Initialized location_data: {location_data}")
        
        # Aggregate attendance data by location
        for att in attendance_by_location:
            location = att['user__profile__work_location']
            status = att['status']
            count = att['count']
            print(f"[DEBUG] Processing attendance: location={location}, status={status}, count={count}")
            
            if location in location_data:
                if status in ['Present', 'Present & Late']:
                    location_data[location]['present_count'] += count
                elif status == 'Absent':
                    location_data[location]['absent_count'] += count
                elif status == 'On Leave':
                    location_data[location]['leave_count'] += count
                elif status == 'Work From Home':
                    location_data[location]['wfh_count'] += count
        print(f"[DEBUG] location_data after aggregation: {location_data}")
        
        # Calculate percentages
        for location, data in location_data.items():
            working_users = data['total_employees'] - data['leave_count']
            print(f"[DEBUG] Calculating present_percentage for location={location}, working_users={working_users}")
            if working_users > 0:
                data['present_percentage'] = round(
                    (data['present_count'] + data['wfh_count']) / working_users * 100, 2
                )
        print(f"[DEBUG] Final location_data: {location_data}")
        
        result = list(location_data.values())
        print(f"[DEBUG] get_location_statistics result: {result}")
        return result