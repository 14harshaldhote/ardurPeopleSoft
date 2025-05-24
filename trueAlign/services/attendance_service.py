# services/attendance_service.py
from django.contrib.auth.models import User
from django.db.models import Q, Count, Avg, Sum, Case, When, IntegerField, F
from django.utils import timezone
from datetime import datetime, timedelta, time
from typing import Dict, List, Optional, Any, Tuple
import logging
from decimal import Decimal

logger = logging.getLogger(__name__)

class AttendanceService:
    """Service class for attendance-related operations and statistics"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def get_attendance_overview(self, start_date: datetime.date, end_date: datetime.date) -> Dict[str, Any]:
        """Get overall attendance statistics for date range"""
        try:
            from ..models import Attendance  # Import here to avoid circular imports
            
            total_employees = User.objects.filter(
                is_active=True,
                profile__employment_status='active'
            ).count()
            
            # Get attendance records for the date range
            attendance_records = Attendance.objects.filter(
                date__range=[start_date, end_date],
                user__is_active=True
            )
            
            # Count by status
            status_counts = attendance_records.values('status').annotate(
                count=Count('id')
            ).order_by('status')
            
            # Convert to dictionary for easier access
            status_dict = {item['status']: item['count'] for item in status_counts}
            
            # Calculate totals
            present_count = status_dict.get('Present', 0) + status_dict.get('Present & Late', 0)
            absent_count = status_dict.get('Absent', 0)
            leave_count = status_dict.get('On Leave', 0)
            yet_to_clock_in = status_dict.get('Yet to Clock In', 0)
            
            # Calculate percentages
            total_records = sum(status_dict.values())
            
            return {
                'total_employees': total_employees,
                'total_records': total_records,
                'present_count': present_count,
                'present_percentage': round((present_count / total_records * 100), 2) if total_records > 0 else 0,
                'absent_count': absent_count,
                'absent_percentage': round((absent_count / total_records * 100), 2) if total_records > 0 else 0,
                'leave_count': leave_count,
                'leave_percentage': round((leave_count / total_records * 100), 2) if total_records > 0 else 0,
                'yet_to_clock_in': yet_to_clock_in,
                'status_counts': list(status_counts),
                'date_range': {
                    'start_date': start_date,
                    'end_date': end_date
                }
            }
        except Exception as e:
            self.logger.error(f"Error getting attendance overview: {str(e)}")
            return {
                'total_employees': 0,
                'total_records': 0,
                'present_count': 0,
                'present_percentage': 0,
                'absent_count': 0,
                'absent_percentage': 0,
                'leave_count': 0,
                'leave_percentage': 0,
                'yet_to_clock_in': 0,
                'status_counts': [],
                'date_range': {'start_date': start_date, 'end_date': end_date}
            }
    
    def get_location_wise_attendance(self, start_date: datetime.date, end_date: datetime.date) -> List[Dict[str, Any]]:
        """Get attendance statistics grouped by location"""
        try:
            from ..models import Attendance
            
            # Get all locations
            locations = User.objects.filter(
                is_active=True,
                profile__employment_status='active',
                profile__work_location__isnull=False
            ).values_list('profile__work_location', flat=True).distinct()
            
            location_stats = []
            
            for location in locations:
                if not location or not location.strip():
                    continue
                
                # Get users in this location
                location_users = User.objects.filter(
                    is_active=True,
                    profile__employment_status='active',
                    profile__work_location=location
                )
                
                total_employees = location_users.count()
                
                # Get attendance records for this location
                attendance_records = Attendance.objects.filter(
                    date__range=[start_date, end_date],
                    user__in=location_users
                )
                
                # Count by status
                status_counts = attendance_records.aggregate(
                    present_count=Count('id', filter=Q(status__in=['Present', 'Present & Late'])),
                    absent_count=Count('id', filter=Q(status='Absent')),
                    leave_count=Count('id', filter=Q(status='On Leave')),
                    yet_to_clock_in_count=Count('id', filter=Q(status='Yet to Clock In'))
                )
                
                location_stats.append({
                    'location': location,
                    'total_employees': total_employees,
                    'present_count': status_counts['present_count'],
                    'absent_count': status_counts['absent_count'],
                    'leave_count': status_counts['leave_count'],
                    'yet_to_clock_in_count': status_counts['yet_to_clock_in_count']
                })
            
            return location_stats
            
        except Exception as e:
            self.logger.error(f"Error getting location-wise attendance: {str(e)}")
            return []
    
    def get_users_by_status(self, status: str, location: str = None, start_date: datetime.date = None, end_date: datetime.date = None) -> List[Dict[str, Any]]:
        """Get detailed user information by attendance status"""
        try:
            from ..models import Attendance, LeaveRequest, ShiftAssignment
            
            if not start_date:
                start_date = timezone.now().date()
            if not end_date:
                end_date = start_date
            
            # Base query for attendance records
            attendance_query = Attendance.objects.filter(
                date__range=[start_date, end_date],
                user__is_active=True
            )
            
            # Filter by location if provided
            if location:
                attendance_query = attendance_query.filter(user__profile__work_location=location)
            
            # Filter by status
            if status in ['Present', 'Present & Late']:
                attendance_query = attendance_query.filter(status__in=['Present', 'Present & Late'])
            else:
                attendance_query = attendance_query.filter(status=status)
            
            attendance_records = attendance_query.select_related('user', 'user__profile', 'shift')
            
            users_data = []
            
            for record in attendance_records:
                user_info = {
                    'user_id': record.user.id,
                    'name': f"{record.user.first_name} {record.user.last_name}".strip() or record.user.username,
                    'location': getattr(record.user.profile, 'work_location', 'N/A') if hasattr(record.user, 'profile') else 'N/A',
                    'status': record.status,
                    'date': record.date
                }
                
                # Add status-specific data
                if status in ['Present', 'Present & Late']:
                    user_info.update({
                        'clock_in': record.clock_in_time.strftime('%H:%M') if record.clock_in_time else 'N/A',
                        'clock_out': record.clock_out_time.strftime('%H:%M') if record.clock_out_time else 'N/A',
                        'hours': str(record.total_hours) if record.total_hours else '0.0',
                        'shift': record.shift.name if record.shift else 'N/A',
                        'late_by_mins': record.late_minutes if record.late_minutes > 0 else 0,
                        'is_late': record.late_minutes > 0
                    })
                
                elif status == 'On Leave':
                    # Get leave details
                    leave_request = LeaveRequest.objects.filter(
                        user=record.user,
                        start_date__lte=record.date,
                        end_date__gte=record.date,
                        status='Approved'
                    ).first()
                    
                    if leave_request:
                        user_info.update({
                            'leave_type': leave_request.leave_type.name if leave_request.leave_type else 'N/A',
                            'start_date': leave_request.start_date,
                            'end_date': leave_request.end_date,
                            'days': str(leave_request.leave_days)
                        })
                    else:
                        user_info.update({
                            'leave_type': record.leave_type or 'N/A',
                            'start_date': record.date,
                            'end_date': record.date,
                            'days': '1'
                        })
                
                elif status == 'Absent':
                    user_info.update({
                        'shift': record.shift.name if record.shift else 'N/A',
                        'date': record.date
                    })
                
                elif status == 'Yet to Clock In':
                      # Get current shift assignment
                    shift_assignment = ShiftAssignment.objects.filter(
                        Q(effective_to__isnull=True) | Q(effective_to__gte=record.date),
                        user=record.user,
                        effective_from__lte=record.date,
                        is_current=True
                    ).first()
                    
                    if shift_assignment:
                        # Calculate how late they are
                        current_time = timezone.now().time()
                        shift_start = shift_assignment.shift.start_time
                        grace_period_mins = int(shift_assignment.shift.grace_period.total_seconds() / 60)
                        
                        # Convert times to minutes for calculation
                        current_mins = current_time.hour * 60 + current_time.minute
                        shift_start_mins = shift_start.hour * 60 + shift_start.minute + grace_period_mins
                        
                        late_by = max(0, current_mins - shift_start_mins)
                        
                        user_info.update({
                            'shift': shift_assignment.shift.name,
                            'shift_timing': f"{shift_assignment.shift.start_time.strftime('%H:%M')} - {shift_assignment.shift.end_time.strftime('%H:%M')}",
                            'late_by_mins': late_by
                        })
                    else:
                        user_info.update({
                            'shift': 'N/A',
                            'shift_timing': 'N/A',
                            'late_by_mins': 0
                        })
                
                users_data.append(user_info)
            
            return users_data
            
        except Exception as e:
            self.logger.error(f"Error getting users by status {status}: {str(e)}")
            return []
    
    def get_top_absent_users(self, days: int = 30, limit: int = 10) -> List[Dict[str, Any]]:
        """Get users with highest absence count"""
        try:
            from ..models import Attendance
            
            end_date = timezone.now().date()
            start_date = end_date - timedelta(days=days)
            
            absent_stats = Attendance.objects.filter(
                date__range=[start_date, end_date],
                status='Absent',
                user__is_active=True
            ).values(
                'user__id',
                'user__first_name',
                'user__last_name',
                'user__username',
                'user__profile__work_location'
            ).annotate(
                absence_count=Count('id')
            ).order_by('-absence_count')[:limit]
            
            return [
                {
                    'user_id': item['user__id'],
                    'name': f"{item['user__first_name']} {item['user__last_name']}".strip() or item['user__username'],
                    'location': item['user__profile__work_location'] or 'N/A',
                    'absence_count': item['absence_count']
                }
                for item in absent_stats
            ]
            
        except Exception as e:
            self.logger.error(f"Error getting top absent users: {str(e)}")
            return []
    
    def get_top_late_users(self, days: int = 30, limit: int = 10) -> List[Dict[str, Any]]:
        """Get users who are frequently late"""
        try:
            from ..models import Attendance
            
            end_date = timezone.now().date()
            start_date = end_date - timedelta(days=days)
            
            late_stats = Attendance.objects.filter(
                date__range=[start_date, end_date],
                status__in=['Present & Late', 'Late'],
                late_minutes__gt=0,
                user__is_active=True
            ).values(
                'user__id',
                'user__first_name',
                'user__last_name',
                'user__username',
                'user__profile__work_location'
            ).annotate(
                late_count=Count('id'),
                avg_late_minutes=Avg('late_minutes')
            ).order_by('-late_count')[:limit]
            
            return [
                {
                    'user_id': item['user__id'],
                    'name': f"{item['user__first_name']} {item['user__last_name']}".strip() or item['user__username'],
                    'location': item['user__profile__work_location'] or 'N/A',
                    'late_count': item['late_count'],
                    'avg_late_minutes': round(item['avg_late_minutes'], 1) if item['avg_late_minutes'] else 0
                }
                for item in late_stats
            ]
            
        except Exception as e:
            self.logger.error(f"Error getting top late users: {str(e)}")
            return []
    
    def get_yet_to_clock_in_users(self, date: datetime.date = None) -> List[Dict[str, Any]]:
        """Get users who haven't clocked in yet for the given date"""
        try:
            from ..models import Attendance, ShiftAssignment
            
            if not date:
                date = timezone.now().date()
            
            # Get users who haven't clocked in yet
            yet_to_clock_in = Attendance.objects.filter(
                date=date,
                status='Yet to Clock In',
                user__is_active=True
            ).select_related('user', 'user__profile')
            
            users_data = []
            
            for record in yet_to_clock_in:
                # Get current shift assignment
                shift_assignment = ShiftAssignment.objects.filter(
                    Q(effective_to__isnull=True) | Q(effective_to__gte=date),
                    user=record.user,
                    effective_from__lte=date,
                    is_current=True
                ).first()
                
                user_info = {
                    'user_id': record.user.id,
                    'name': f"{record.user.first_name} {record.user.last_name}".strip() or record.user.username,
                    'location': getattr(record.user.profile, 'work_location', 'N/A') if hasattr(record.user, 'profile') else 'N/A'
                }
                
                if shift_assignment:
                    # Calculate how late they are
                    current_time = timezone.now().time()
                    shift_start = shift_assignment.shift.start_time
                    grace_period_mins = int(shift_assignment.shift.grace_period.total_seconds() / 60)
                    
                    # Convert times to minutes for calculation
                    current_mins = current_time.hour * 60 + current_time.minute
                    shift_start_mins = shift_start.hour * 60 + shift_start.minute + grace_period_mins
                    
                    late_by = max(0, current_mins - shift_start_mins)
                    
                    user_info.update({
                        'shift': shift_assignment.shift.name,
                        'shift_timing': f"{shift_assignment.shift.start_time.strftime('%H:%M')} - {shift_assignment.shift.end_time.strftime('%H:%M')}",
                        'late_by_mins': late_by
                    })
                else:
                    user_info.update({
                        'shift': 'N/A',
                        'shift_timing': 'N/A',
                        'late_by_mins': 0
                    })
                
                users_data.append(user_info)
            
            return users_data
            
        except Exception as e:
            self.logger.error(f"Error getting yet to clock in users: {str(e)}")
            return []
    
    def get_attendance_by_date(self, date: datetime.date) -> Dict[str, Any]:
        """Get attendance data for a specific date"""
        try:
            from ..models import Attendance
            
            attendance_records = Attendance.objects.filter(
                date=date,
                user__is_active=True
            ).select_related('user', 'user__profile', 'shift')
            
            # Group by status
            status_groups = {}
            for record in attendance_records:
                status = record.status
                if status not in status_groups:
                    status_groups[status] = []
                
                user_data = {
                    'user_id': record.user.id,
                    'name': f"{record.user.first_name} {record.user.last_name}".strip() or record.user.username,
                    'location': getattr(record.user.profile, 'work_location', 'N/A') if hasattr(record.user, 'profile') else 'N/A',
                    'clock_in': record.clock_in_time.strftime('%H:%M') if record.clock_in_time else None,
                    'clock_out': record.clock_out_time.strftime('%H:%M') if record.clock_out_time else None,
                    'total_hours': str(record.total_hours) if record.total_hours else '0.0',
                    'late_minutes': record.late_minutes,
                    'shift': record.shift.name if record.shift else 'N/A'
                }
                
                status_groups[status].append(user_data)
            
            return {
                'date': date,
                'total_records': attendance_records.count(),
                'status_groups': status_groups,
                'status_counts': {status: len(users) for status, users in status_groups.items()}
            }
        except Exception as e:
            self.logger.error(f"Error getting attendance for date {date}: {str(e)}")
            return {
                'date': date,
                'total_records': 0,
                'status_groups': {},
                'status_counts': {}
            }
        
       
    def get_user_attendance_history(self, user_id: int, start_date: datetime.date, end_date: datetime.date) -> List[Dict[str, Any]]:
        """Get attendance history for a specific user"""
        try:
            from ..models import Attendance
            
            attendance_records = Attendance.objects.filter(
                user_id=user_id,
                date__range=[start_date, end_date]
            ).select_related('shift').order_by('-date')
            
            history = []
            for record in attendance_records:
                history.append({
                    'date': record.date,
                    'status': record.status,
                    'clock_in': record.clock_in_time.strftime('%H:%M') if record.clock_in_time else None,
                    'clock_out': record.clock_out_time.strftime('%H:%M') if record.clock_out_time else None,
                    'total_hours': str(record.total_hours) if record.total_hours else '0.0',
                    'late_minutes': record.late_minutes,
                    'shift': record.shift.name if record.shift else 'N/A',
                    'leave_type': record.leave_type if hasattr(record, 'leave_type') else None
                })
            
            return history
            
        except Exception as e:
            self.logger.error(f"Error getting user attendance history: {str(e)}")
            return []
    
    def get_monthly_attendance_summary(self, year: int, month: int) -> Dict[str, Any]:
        """Get monthly attendance summary with daily breakdown"""
        try:
            from ..models import Attendance
            from calendar import monthrange
            
            # Get first and last day of the month
            start_date = datetime(year, month, 1).date()
            last_day = monthrange(year, month)[1]
            end_date = datetime(year, month, last_day).date()
            
            # Get all attendance records for the month
            attendance_records = Attendance.objects.filter(
                date__range=[start_date, end_date],
                user__is_active=True
            )
            
            # Daily breakdown
            daily_stats = {}
            for day in range(1, last_day + 1):
                current_date = datetime(year, month, day).date()
                day_records = attendance_records.filter(date=current_date)
                
                status_counts = day_records.values('status').annotate(
                    count=Count('id')
                ).order_by('status')
                
                daily_stats[day] = {
                    'date': current_date,
                    'total': day_records.count(),
                    'status_counts': {item['status']: item['count'] for item in status_counts}
                }
            
            # Monthly totals
            monthly_totals = attendance_records.values('status').annotate(
                count=Count('id')
            ).order_by('status')
            
            return {
                'year': year,
                'month': month,
                'start_date': start_date,
                'end_date': end_date,
                'daily_stats': daily_stats,
                'monthly_totals': {item['status']: item['count'] for item in monthly_totals},
                'total_records': attendance_records.count()
            }
            
        except Exception as e:
            self.logger.error(f"Error getting monthly attendance summary: {str(e)}")
            return {
                'year': year,
                'month': month,
                'daily_stats': {},
                'monthly_totals': {},
                'total_records': 0
            }
    
    def get_department_wise_attendance(self, start_date: datetime.date, end_date: datetime.date) -> List[Dict[str, Any]]:
        """Get attendance statistics grouped by department"""
        try:
            from ..models import Attendance
            
            # Get all departments
            departments = User.objects.filter(
                is_active=True,
                profile__employment_status='active',
                profile__department__isnull=False
            ).values_list('profile__department', flat=True).distinct()
            
            department_stats = []
            
            for department in departments:
                if not department or not department.strip():
                    continue
                
                # Get users in this department
                dept_users = User.objects.filter(
                    is_active=True,
                    profile__employment_status='active',
                    profile__department=department
                )
                
                total_employees = dept_users.count()
                
                # Get attendance records for this department
                attendance_records = Attendance.objects.filter(
                    date__range=[start_date, end_date],
                    user__in=dept_users
                )
                
                # Count by status
                status_counts = attendance_records.aggregate(
                    present_count=Count('id', filter=Q(status__in=['Present', 'Present & Late'])),
                    absent_count=Count('id', filter=Q(status='Absent')),
                    leave_count=Count('id', filter=Q(status='On Leave')),
                    yet_to_clock_in_count=Count('id', filter=Q(status='Yet to Clock In'))
                )
                
                # Calculate average hours worked
                avg_hours = attendance_records.filter(
                    status__in=['Present', 'Present & Late'],
                    total_hours__isnull=False
                ).aggregate(
                    avg_hours=Avg('total_hours')
                )['avg_hours'] or 0
                
                department_stats.append({
                    'department': department,
                    'total_employees': total_employees,
                    'present_count': status_counts['present_count'],
                    'absent_count': status_counts['absent_count'],
                    'leave_count': status_counts['leave_count'],
                    'yet_to_clock_in_count': status_counts['yet_to_clock_in_count'],
                    'average_hours': round(float(avg_hours), 2)
                })
            
            return department_stats
            
        except Exception as e:
            self.logger.error(f"Error getting department-wise attendance: {str(e)}")
            return []
    
    def get_attendance_trends(self, days: int = 30) -> Dict[str, Any]:
        """Get attendance trends over the specified number of days"""
        try:
            from ..models import Attendance
            
            end_date = timezone.now().date()
            start_date = end_date - timedelta(days=days)
            
            # Get daily attendance counts
            daily_trends = []
            current_date = start_date
            
            while current_date <= end_date:
                day_records = Attendance.objects.filter(
                    date=current_date,
                    user__is_active=True
                )
                
                status_counts = day_records.values('status').annotate(
                    count=Count('id')
                )
                
                status_dict = {item['status']: item['count'] for item in status_counts}
                
                daily_trends.append({
                    'date': current_date,
                    'present': status_dict.get('Present', 0) + status_dict.get('Present & Late', 0),
                    'absent': status_dict.get('Absent', 0),
                    'leave': status_dict.get('On Leave', 0),
                    'yet_to_clock_in': status_dict.get('Yet to Clock In', 0),
                    'total': sum(status_dict.values())
                })
                
                current_date += timedelta(days=1)
            
            # Calculate averages
            if daily_trends:
                avg_present = sum(day['present'] for day in daily_trends) / len(daily_trends)
                avg_absent = sum(day['absent'] for day in daily_trends) / len(daily_trends)
                avg_leave = sum(day['leave'] for day in daily_trends) / len(daily_trends)
            else:
                avg_present = avg_absent = avg_leave = 0
            
            return {
                'start_date': start_date,
                'end_date': end_date,
                'daily_trends': daily_trends,
                'averages': {
                    'present': round(avg_present, 2),
                    'absent': round(avg_absent, 2),
                    'leave': round(avg_leave, 2)
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error getting attendance trends: {str(e)}")
            return {
                'start_date': start_date,
                'end_date': end_date,
                'daily_trends': [],
                'averages': {'present': 0, 'absent': 0, 'leave': 0}
            }
    
    def calculate_attendance_percentage(self, user_id: int, start_date: datetime.date, end_date: datetime.date) -> Dict[str, Any]:
        """Calculate attendance percentage for a specific user"""
        try:
            from ..models import Attendance
            
            total_records = Attendance.objects.filter(
                user_id=user_id,
                date__range=[start_date, end_date]
            ).count()
            
            if total_records == 0:
                return {
                    'user_id': user_id,
                    'total_days': 0,
                    'present_days': 0,
                    'absent_days': 0,
                    'leave_days': 0,
                    'attendance_percentage': 0
                }
            
            status_counts = Attendance.objects.filter(
                user_id=user_id,
                date__range=[start_date, end_date]
            ).aggregate(
                present_days=Count('id', filter=Q(status__in=['Present', 'Present & Late'])),
                absent_days=Count('id', filter=Q(status='Absent')),
                leave_days=Count('id', filter=Q(status='On Leave'))
            )
            
            attendance_percentage = round(
                (status_counts['present_days'] / total_records) * 100, 2
            ) if total_records > 0 else 0
            
            return {
                'user_id': user_id,
                'total_days': total_records,
                'present_days': status_counts['present_days'],
                'absent_days': status_counts['absent_days'],
                'leave_days': status_counts['leave_days'],
                'attendance_percentage': attendance_percentage
            }
            
        except Exception as e:
            self.logger.error(f"Error calculating attendance percentage for user {user_id}: {str(e)}")
            return {
                'user_id': user_id,
                'total_days': 0,
                'present_days': 0,
                'absent_days': 0,
                'leave_days': 0,
                'attendance_percentage': 0
            }