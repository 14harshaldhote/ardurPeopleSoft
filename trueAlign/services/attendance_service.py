# services/attendance_service.py
from django.db.models import Q, Count, Avg, Max, F, Case, When
from django.db.models.functions import TruncDay, TruncWeek, TruncMonth, TruncQuarter, TruncYear
from .models import Attendance, User, UserDetails, ShiftMaster
import logging

logger = logging.getLogger(__name__)

class AttendanceService:
    """Core attendance business logic service"""
    
    def __init__(self):
        self.date_service = DateService()
    
    def get_trunc_function(self, view_type):
        """Get appropriate truncation function for date grouping"""
        trunc_map = {
            'daily': TruncDay,
            'weekly': TruncWeek,
            'monthly': TruncMonth,
            'quarterly': TruncQuarter,
            'yearly': TruncYear,
        }
        return trunc_map.get(view_type, TruncDay)
    
    def get_base_attendance_query(self, start_date, end_date, filters=None):
        """Get optimized base attendance query with all necessary joins"""
        query = Attendance.objects.filter(
            date__gte=start_date,
            date__lte=end_date
        ).select_related('user', 'shift')
        
        if filters:
            if filters.get('location'):
                if filters['location'] == 'Unspecified':
                    query = query.filter(
                        Q(user__userdetails__work_location__isnull=True) |
                        Q(user__userdetails__work_location__exact='')
                    )
                else:
                    query = query.filter(user__userdetails__work_location=filters['location'])
            
            if filters.get('user_id'):
                query = query.filter(user_id=filters['user_id'])
            
            if filters.get('status'):
                query = query.filter(status=filters['status'])
            
            if filters.get('search'):
                search = filters['search']
                query = query.filter(
                    Q(user__username__icontains=search) |
                    Q(user__first_name__icontains=search) |
                    Q(user__last_name__icontains=search) |
                    Q(user__userdetails__work_location__icontains=search)
                )
        
        return query
    
    def get_attendance_statistics(self, base_query, view_type):
        """Get aggregated attendance statistics"""
        trunc_function = self.get_trunc_function(view_type)
        
        return base_query.annotate(
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
    
    def get_overall_statistics(self, base_query):
        """Calculate overall attendance statistics"""
        status_counts = base_query.values('status').annotate(count=Count('id')).order_by('-count')
        
        # Calculate percentages excluding weekends and holidays
        working_days_count = base_query.exclude(status__in=['Weekend', 'Holiday']).count()
        present_count = base_query.filter(status__in=['Present', 'Present & Late', 'Work From Home']).count()
        
        return {
            'total_records': base_query.count(),
            'present_percentage': round(present_count / max(working_days_count, 1) * 100, 2),
            'absent_percentage': round(base_query.filter(status='Absent').count() / max(working_days_count, 1) * 100, 2),
            'leave_percentage': round(base_query.filter(status='On Leave').count() / max(working_days_count, 1) * 100, 2),
            'avg_working_hours': base_query.filter(total_hours__isnull=False).aggregate(avg=Avg('total_hours'))['avg'] or 0,
            'total_late_instances': base_query.filter(status='Present & Late').count(),
            'avg_late_minutes': base_query.filter(late_minutes__gt=0).aggregate(avg=Avg('late_minutes'))['avg'] or 0,
            'status_counts': list(status_counts)
        }
    
    def get_location_statistics(self, start_date, end_date, base_query):
        """Calculate location-based statistics efficiently"""
        # Get all locations with user counts in a single query
        location_stats = UserDetails.objects.filter(
            user__is_active=True
        ).exclude(
            Q(work_location__isnull=True) | Q(work_location__exact='')
        ).values('work_location').annotate(
            total_employees=Count('user_id')
        ).order_by('-total_employees')
        
        # Get attendance counts by location in single query
        attendance_by_location = base_query.filter(
            user__userdetails__work_location__isnull=False
        ).values('user__userdetails__work_location', 'status').annotate(
            count=Count('user_id', distinct=True)
        )
        
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
        
        # Aggregate attendance data by location
        for att in attendance_by_location:
            location = att['user__userdetails__work_location']
            status = att['status']
            count = att['count']
            
            if location in location_data:
                if status in ['Present', 'Present & Late']:
                    location_data[location]['present_count'] += count
                elif status == 'Absent':
                    location_data[location]['absent_count'] += count
                elif status == 'On Leave':
                    location_data[location]['leave_count'] += count
                elif status == 'Work From Home':
                    location_data[location]['wfh_count'] += count
        
        # Calculate percentages
        for location, data in location_data.items():
            working_users = data['total_employees'] - data['leave_count']
            if working_users > 0:
                data['present_percentage'] = round(
                    (data['present_count'] + data['wfh_count']) / working_users * 100, 2
                )
        
        return list(location_data.values())
