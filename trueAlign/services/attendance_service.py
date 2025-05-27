# services/attendance_service.py
from django.contrib.auth.models import User
from django.db.models import Q, Count, Avg, Sum, Case, When, IntegerField, F
from django.utils import timezone
from datetime import datetime, timedelta, time
from typing import Dict, List, Optional, Any, Tuple
import logging
from decimal import Decimal
import pytz

logger = logging.getLogger(__name__)

# Asia/Kolkata timezone
IST_TIMEZONE = pytz.timezone('Asia/Kolkata')

def get_current_time_ist():
    """Return current time in Asia/Kolkata timezone (aware)."""
    current_time = timezone.now().astimezone(IST_TIMEZONE)
    print(f"Current IST time: {current_time}")
    return current_time

def to_ist(dt):
    """Convert a datetime to Asia/Kolkata timezone (aware)."""
    if dt is None:
        print("Converting None to IST: None returned")
        return None
    if timezone.is_naive(dt):
        ist_time = IST_TIMEZONE.localize(dt)
    else:
        ist_time = dt.astimezone(IST_TIMEZONE)
    print(f"Converting {dt} to IST: {ist_time}")
    return ist_time

def format_time_ist_ampm(dt):
    """Format datetime in IST with AM/PM format."""
    if dt is None:
        return 'N/A'
    ist_time = to_ist(dt)
    return ist_time.strftime('%I:%M %p')

class AttendanceService:
    """Service class for attendance-related operations and statistics"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        print("[AttendanceService.__init__] Logger initialized for AttendanceService.")

    def get_attendance_overview(self, start_date: datetime.date, end_date: datetime.date) -> Dict[str, Any]:
        """Get overall attendance statistics for date range"""
        print(f"[get_attendance_overview] Called with start_date={start_date}, end_date={end_date}")
        try:
            from ..models import Attendance  # Import here to avoid circular imports
            print("[get_attendance_overview] Imported Attendance model successfully.")

            total_employees = User.objects.filter(
                is_active=True,
                profile__employment_status='active'
            ).count()
            print(f"[get_attendance_overview] Total active employees found: {total_employees}")

            attendance_records = Attendance.objects.filter(
                date__range=[start_date, end_date],
                user__is_active=True
            )
            print(f"[get_attendance_overview] Attendance records fetched for date range: {attendance_records.count()} records found.")

            status_counts = attendance_records.values('status').annotate(
                count=Count('id')
            ).order_by('status')
            print(f"[get_attendance_overview] Status counts aggregated: {list(status_counts)}")

            status_dict = {item['status']: item['count'] for item in status_counts}
            print(f"[get_attendance_overview] Status dict created for easier access: {status_dict}")

            present_count = status_dict.get('Present', 0) + status_dict.get('Present & Late', 0)
            absent_count = status_dict.get('Absent', 0)
            leave_count = status_dict.get('On Leave', 0)
            yet_to_clock_in = status_dict.get('Yet to Clock In', 0)
            print(f"[get_attendance_overview] present_count={present_count}, absent_count={absent_count}, leave_count={leave_count}, yet_to_clock_in={yet_to_clock_in}")

            total_records = sum(status_dict.values())
            print(f"[get_attendance_overview] Total attendance records in range: {total_records}")

            present_percentage = round((present_count / total_records * 100), 2) if total_records > 0 else 0
            absent_percentage = round((absent_count / total_records * 100), 2) if total_records > 0 else 0
            leave_percentage = round((leave_count / total_records * 100), 2) if total_records > 0 else 0
            print(f"[get_attendance_overview] Calculated percentages - present: {present_percentage}%, absent: {absent_percentage}%, leave: {leave_percentage}%")

            result = {
                'total_employees': total_employees,
                'total_records': total_records,
                'present_count': present_count,
                'present_percentage': present_percentage,
                'absent_count': absent_count,
                'absent_percentage': absent_percentage,
                'leave_count': leave_count,
                'leave_percentage': leave_percentage,
                'yet_to_clock_in': yet_to_clock_in,
                'status_counts': list(status_counts),
                'date_range': {
                    'start_date': start_date,
                    'end_date': end_date
                }
            }
            print(f"[get_attendance_overview] Returning overview result: {result}")
            return result
        except Exception as e:
            self.logger.error(f"Error getting attendance overview: {str(e)}")
            print(f"[get_attendance_overview] Exception occurred: {str(e)}. Returning default zeroed result.")
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
        print(f"[get_location_wise_attendance] Called with start_date={start_date}, end_date={end_date}")
        try:
            from ..models import Attendance
            print("[get_location_wise_attendance] Imported Attendance model successfully.")

            locations = User.objects.filter(
                is_active=True,
                profile__employment_status='active',
                profile__work_location__isnull=False
            ).values_list('profile__work_location', flat=True).distinct()
            print(f"[get_location_wise_attendance] Distinct locations found: {list(locations)}")

            location_stats = []

            for location in locations:
                if not location or not location.strip():
                    print(f"[get_location_wise_attendance] Skipping empty or blank location: '{location}'")
                    continue

                location_users = User.objects.filter(
                    is_active=True,
                    profile__employment_status='active',
                    profile__work_location=location
                )
                total_employees = location_users.count()
                print(f"[get_location_wise_attendance] Location '{location}': {total_employees} active employees found.")

                attendance_records = Attendance.objects.filter(
                    date__range=[start_date, end_date],
                    user__in=location_users
                )
                print(f"[get_location_wise_attendance] Attendance records for location '{location}': {attendance_records.count()} records found.")

                status_counts = attendance_records.aggregate(
                    present_count=Count('id', filter=Q(status__in=['Present', 'Present & Late'])),
                    absent_count=Count('id', filter=Q(status='Absent')),
                    leave_count=Count('id', filter=Q(status='On Leave')),
                    yet_to_clock_in_count=Count('id', filter=Q(status='Yet to Clock In'))
                )
                print(f"[get_location_wise_attendance] Aggregated status counts for location '{location}': {status_counts}")

                location_stats.append({
                    'location': location,
                    'total_employees': total_employees,
                    'present_count': status_counts['present_count'],
                    'absent_count': status_counts['absent_count'],
                    'leave_count': status_counts['leave_count'],
                    'yet_to_clock_in_count': status_counts['yet_to_clock_in_count']
                })

            print(f"[get_location_wise_attendance] Returning location-wise stats: {location_stats}")
            return location_stats

        except Exception as e:
            self.logger.error(f"Error getting location-wise attendance: {str(e)}")
            print(f"[get_location_wise_attendance] Exception occurred: {str(e)}. Returning empty list.")
            return []

    def get_users_by_status(self, status: str, location: str = None, start_date: datetime.date = None, end_date: datetime.date = None) -> List[Dict[str, Any]]:
        """Get detailed user information by attendance status"""
        print(f"[get_users_by_status] Called with status={status}, location={location}, start_date={start_date}, end_date={end_date}")
        try:
            from ..models import Attendance, LeaveRequest, ShiftAssignment
            print("[get_users_by_status] Imported Attendance, LeaveRequest, ShiftAssignment models successfully.")

            if not start_date:
                start_date = get_current_time_ist().date()
                print(f"[get_users_by_status] start_date not provided, using current date: {start_date}")
            if not end_date:
                end_date = start_date
                print(f"[get_users_by_status] end_date not provided, using start_date: {end_date}")

            attendance_query = Attendance.objects.filter(
                date__range=[start_date, end_date],
                user__is_active=True
            )
            print(f"[get_users_by_status] Base attendance query for date range: {attendance_query.count()} records.")

            if location:
                attendance_query = attendance_query.filter(user__profile__work_location=location)
                print(f"[get_users_by_status] Filtered by location '{location}': {attendance_query.count()} records.")

            if status in ['Present', 'Present & Late']:
                attendance_query = attendance_query.filter(status__in=['Present', 'Present & Late'])
                print(f"[get_users_by_status] Filtered by status in ['Present', 'Present & Late']: {attendance_query.count()} records.")
            else:
                attendance_query = attendance_query.filter(status=status)
                print(f"[get_users_by_status] Filtered by status '{status}': {attendance_query.count()} records.")

            attendance_records = attendance_query.select_related('user', 'user__profile', 'shift')
            print(f"[get_users_by_status] Final attendance records to process: {attendance_records.count()}")

            users_data = []

            for record in attendance_records:
                user_info = {
                    'user_id': record.user.id,
                    'name': f"{record.user.first_name} {record.user.last_name}".strip() or record.user.username,
                    'location': getattr(record.user.profile, 'work_location', 'N/A') if hasattr(record.user, 'profile') else 'N/A',
                    'status': record.status,
                    'date': record.date
                }
                print(f"[get_users_by_status] Processing user: {user_info}")

                if status in ['Present', 'Present & Late']:
                    user_info.update({
                        'clock_in': format_time_ist_ampm(record.clock_in_time),
                        'clock_out': format_time_ist_ampm(record.clock_out_time),
                        'hours': str(record.total_hours) if record.total_hours else '0.0',
                        'shift': record.shift.name if record.shift else 'N/A',
                        'late_by_mins': record.late_minutes if record.late_minutes > 0 else 0,
                        'is_late': record.late_minutes > 0
                    })
                    print(f"[get_users_by_status] Added present/late details for user_id={record.user.id}: {user_info}")

                elif status == 'On Leave':
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
                        print(f"[get_users_by_status] Found approved leave for user_id={record.user.id}: {user_info}")
                    else:
                        user_info.update({
                            'leave_type': record.leave_type or 'N/A',
                            'start_date': record.date,
                            'end_date': record.date,
                            'days': '1'
                        })
                        print(f"[get_users_by_status] No approved leave found, using attendance record info for user_id={record.user.id}: {user_info}")

                elif status == 'Absent':
                    user_info.update({
                        'shift': record.shift.name if record.shift else 'N/A',
                        'date': record.date
                    })
                    print(f"[get_users_by_status] Added absent details for user_id={record.user.id}: {user_info}")

                elif status == 'Yet to Clock In':
                    shift_assignment = ShiftAssignment.objects.filter(
                        Q(effective_to__isnull=True) | Q(effective_to__gte=record.date),
                        user=record.user,
                        effective_from__lte=record.date,
                        is_current=True
                    ).first()
                    if shift_assignment:
                        current_time = get_current_time_ist().time()
                        shift_start = shift_assignment.shift.start_time
                        grace_period_mins = int(shift_assignment.shift.grace_period.total_seconds() / 60)
                        current_mins = current_time.hour * 60 + current_time.minute
                        shift_start_mins = shift_start.hour * 60 + shift_start.minute + grace_period_mins
                        late_by = max(0, current_mins - shift_start_mins)
                        user_info.update({
                            'shift': shift_assignment.shift.name,
                            'shift_timing': f"{shift_assignment.shift.start_time.strftime('%I:%M %p')} - {shift_assignment.shift.end_time.strftime('%I:%M %p')}",
                            'late_by_mins': late_by
                        })
                        print(f"[get_users_by_status] Calculated late_by for yet to clock in user_id={record.user.id}: {late_by} mins")
                    else:
                        user_info.update({
                            'shift': 'N/A',
                            'shift_timing': 'N/A',
                            'late_by_mins': 0
                        })
                        print(f"[get_users_by_status] No shift assignment found for yet to clock in user_id={record.user.id}")

                users_data.append(user_info)

            print(f"[get_users_by_status] Returning users data: {users_data}")
            return users_data

        except Exception as e:
            self.logger.error(f"Error getting users by status {status}: {str(e)}")
            print(f"[get_users_by_status] Exception occurred: {str(e)}. Returning empty list.")
            return []

    def get_top_absent_users(self, days: int = 30, limit: int = 10) -> List[Dict[str, Any]]:
        """Get users with highest absence count"""
        print(f"[get_top_absent_users] Called with days={days}, limit={limit}")
        try:
            from ..models import Attendance
            print("[get_top_absent_users] Imported Attendance model successfully.")

            end_date = get_current_time_ist().date()
            start_date = end_date - timedelta(days=days)
            print(f"[get_top_absent_users] Calculated date range: {start_date} to {end_date}")

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
            print(f"[get_top_absent_users] Top absent users fetched: {list(absent_stats)}")

            result = [
                {
                    'user_id': item['user__id'],
                    'name': f"{item['user__first_name']} {item['user__last_name']}".strip() or item['user__username'],
                    'location': item['user__profile__work_location'] or 'N/A',
                    'absence_count': item['absence_count']
                }
                for item in absent_stats
            ]
            print(f"[get_top_absent_users] Returning result: {result}")
            return result

        except Exception as e:
            self.logger.error(f"Error getting top absent users: {str(e)}")
            print(f"[get_top_absent_users] Exception occurred: {str(e)}. Returning empty list.")
            return []

    def get_top_late_users(self, days: int = 30, limit: int = 10) -> List[Dict[str, Any]]:
        """Get users who are frequently late"""
        print(f"[get_top_late_users] Called with days={days}, limit={limit}")
        try:
            from ..models import Attendance
            print("[get_top_late_users] Imported Attendance model successfully.")

            end_date = get_current_time_ist().date()
            start_date = end_date - timedelta(days=days)
            print(f"[get_top_late_users] Calculated date range: {start_date} to {end_date}")

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
            print(f"[get_top_late_users] Top late users fetched: {list(late_stats)}")

            result = [
                {
                    'user_id': item['user__id'],
                    'name': f"{item['user__first_name']} {item['user__last_name']}".strip() or item['user__username'],
                    'location': item['user__profile__work_location'] or 'N/A',
                    'late_count': item['late_count'],
                    'avg_late_minutes': round(item['avg_late_minutes'], 1) if item['avg_late_minutes'] else 0
                }
                for item in late_stats
            ]
            print(f"[get_top_late_users] Returning result: {result}")
            return result

        except Exception as e:
            self.logger.error(f"Error getting top late users: {str(e)}")
            print(f"[get_top_late_users] Exception occurred: {str(e)}. Returning empty list.")
            return []

    def get_yet_to_clock_in_users(self, date: datetime.date = None) -> List[Dict[str, Any]]:
        """Get users who haven't clocked in yet for the given date"""
        print(f"[get_yet_to_clock_in_users] Called with date={date}")
        try:
            from ..models import Attendance, ShiftAssignment
            print("[get_yet_to_clock_in_users] Imported Attendance and ShiftAssignment models successfully.")

            if not date:
                date = get_current_time_ist().date()
                print(f"[get_yet_to_clock_in_users] date not provided, using current date: {date}")

            yet_to_clock_in = Attendance.objects.filter(
                date=date,
                status='Yet to Clock In',
                user__is_active=True
            ).select_related('user', 'user__profile')
            print(f"[get_yet_to_clock_in_users] Yet to clock in records found: {yet_to_clock_in.count()}")

            users_data = []

            for record in yet_to_clock_in:
                shift_assignment = ShiftAssignment.objects.filter(
                    Q(effective_to__isnull=True) | Q(effective_to__gte=date),
                    user=record.user,
                    effective_from__lte=date,
                    is_current=True
                ).first()
                print(f"[get_yet_to_clock_in_users] Processing user_id={record.user.id}, shift_assignment found: {bool(shift_assignment)}")

                user_info = {
                    'user_id': record.user.id,
                    'name': f"{record.user.first_name} {record.user.last_name}".strip() or record.user.username,
                    'location': getattr(record.user.profile, 'work_location', 'N/A') if hasattr(record.user, 'profile') else 'N/A'
                }

                if shift_assignment:
                    current_time = get_current_time_ist().time()
                    shift_start = shift_assignment.shift.start_time
                    grace_period_mins = int(shift_assignment.shift.grace_period.total_seconds() / 60)
                    current_mins = current_time.hour * 60 + current_time.minute
                    shift_start_mins = shift_start.hour * 60 + shift_start.minute + grace_period_mins
                    late_by = max(0, current_mins - shift_start_mins)
                    user_info.update({
                        'shift': shift_assignment.shift.name,
                        'shift_timing': f"{shift_assignment.shift.start_time.strftime('%I:%M %p')} - {shift_assignment.shift.end_time.strftime('%I:%M %p')}",
                        'late_by_mins': late_by
                    })
                    print(f"[get_yet_to_clock_in_users] Calculated late_by for user_id={record.user.id}: {late_by} mins")
                else:
                    user_info.update({
                        'shift': 'N/A',
                        'shift_timing': 'N/A',
                        'late_by_mins': 0
                    })
                    print(f"[get_yet_to_clock_in_users] No shift assignment found for user_id={record.user.id}")

                users_data.append(user_info)

            print(f"[get_yet_to_clock_in_users] Returning users data: {users_data}")
            return users_data

        except Exception as e:
            self.logger.error(f"Error getting yet to clock in users: {str(e)}")
            print(f"[get_yet_to_clock_in_users] Exception occurred: {str(e)}. Returning empty list.")
            return []

    def get_attendance_by_date(self, date: datetime.date) -> Dict[str, Any]:
        """Get attendance data for a specific date"""
        print(f"[get_attendance_by_date] Called with date={date}")
        try:
            from ..models import Attendance
            print("[get_attendance_by_date] Imported Attendance model successfully.")

            attendance_records = Attendance.objects.filter(
                date=date,
                user__is_active=True
            ).select_related('user', 'user__profile', 'shift')
            print(f"[get_attendance_by_date] Attendance records found: {attendance_records.count()}")

            status_groups = {}
            for record in attendance_records:
                status = record.status
                if status not in status_groups:
                    status_groups[status] = []
                user_data = {
                    'user_id': record.user.id,
                    'name': f"{record.user.first_name} {record.user.last_name}".strip() or record.user.username,
                    'location': getattr(record.user.profile, 'work_location', 'N/A') if hasattr(record.user, 'profile') else 'N/A',
                    'clock_in': format_time_ist_ampm(record.clock_in_time),
                    'clock_out': format_time_ist_ampm(record.clock_out_time),
                    'total_hours': str(record.total_hours) if record.total_hours else '0.0',
                    'late_minutes': record.late_minutes,
                    'shift': record.shift.name if record.shift else 'N/A'
                }
                status_groups[status].append(user_data)
                print(f"[get_attendance_by_date] Added user to status group '{status}': {user_data}")

            result = {
                'date': date,
                'total_records': attendance_records.count(),
                'status_groups': status_groups,
                'status_counts': {status: len(users) for status, users in status_groups.items()}
            }
            print(f"[get_attendance_by_date] Returning result: {result}")
            return result
        except Exception as e:
            self.logger.error(f"Error getting attendance for date {date}: {str(e)}")
            print(f"[get_attendance_by_date] Exception occurred: {str(e)}. Returning default empty result.")
            return {
                'date': date,
                'total_records': 0,
                'status_groups': {},
                'status_counts': {}
            }


    def get_user_attendance_history(self, user_id: int, start_date: datetime.date, end_date: datetime.date) -> List[Dict[str, Any]]:
        """Get attendance history for a specific user"""
        print(f"[get_user_attendance_history] Called with user_id={user_id}, start_date={start_date}, end_date={end_date}")
        try:
            from ..models import Attendance
            print("[get_user_attendance_history] Imported Attendance model successfully.")

            attendance_records = Attendance.objects.filter(
                user_id=user_id,
                date__range=[start_date, end_date]
            ).select_related('shift').order_by('-date')
            print(f"[get_user_attendance_history] Attendance records found: {attendance_records.count()}")

            history = []
            for record in attendance_records:
                record_data = {
                    'date': record.date,
                    'status': record.status,
                    'clock_in': format_time_ist_ampm(record.clock_in_time),
                    'clock_out': format_time_ist_ampm(record.clock_out_time),
                    'total_hours': str(record.total_hours) if record.total_hours else '0.0',
                    'late_minutes': record.late_minutes,
                    'shift': record.shift.name if record.shift else 'N/A',
                    'leave_type': record.leave_type if hasattr(record, 'leave_type') else None
                }
                history.append(record_data)
                print(f"[get_user_attendance_history] Added record: {record_data}")

                print(f"[get_user_attendance_history] Returning history: {history}")
                return history

        except Exception as e:
            self.logger.error(f"Error getting user attendance history: {str(e)}")
            print(f"[get_user_attendance_history] Exception occurred: {str(e)}. Returning empty list.")
            return []

        def get_monthly_attendance_summary(self, year: int, month: int) -> Dict[str, Any]:
            """Get monthly attendance summary with daily breakdown"""
            print(f"[get_monthly_attendance_summary] Called with year={year}, month={month}")
            try:
                from ..models import Attendance
                from calendar import monthrange
                print("[get_monthly_attendance_summary] Imported Attendance model and monthrange successfully.")

                start_date = datetime(year, month, 1).date()
                last_day = monthrange(year, month)[1]
                end_date = datetime(year, month, last_day).date()
                print(f"[get_monthly_attendance_summary] Calculated start_date={start_date}, end_date={end_date}")

                attendance_records = Attendance.objects.filter(
                    date__range=[start_date, end_date],
                    user__is_active=True
                )
                print(f"[get_monthly_attendance_summary] Attendance records for month: {attendance_records.count()}")

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
                    print(f"[get_monthly_attendance_summary] Day {day}: {daily_stats[day]}")

                monthly_totals = attendance_records.values('status').annotate(
                    count=Count('id')
                ).order_by('status')
                print(f"[get_monthly_attendance_summary] Monthly totals: {list(monthly_totals)}")

                result = {
                    'year': year,
                    'month': month,
                    'start_date': start_date,
                    'end_date': end_date,
                    'daily_stats': daily_stats,
                    'monthly_totals': {item['status']: item['count'] for item in monthly_totals},
                    'total_records': attendance_records.count()
                }
                print(f"[get_monthly_attendance_summary] Returning result: {result}")
                return result

            except Exception as e:
                self.logger.error(f"Error getting monthly attendance summary: {str(e)}")
                print(f"[get_monthly_attendance_summary] Exception occurred: {str(e)}. Returning default empty result.")
                return {
                    'year': year,
                    'month': month,
                    'start_date': start_date,
                    'end_date': end_date,
                    'daily_stats': {},
                    'monthly_totals': {},
                    'total_records': 0
                }

        def get_attendance_trends(self, days: int = 30) -> Dict[str, Any]:
            """Get attendance trends over the specified number of days"""
            print(f"[get_attendance_trends] Called with days={days}")
            try:
                from ..models import Attendance
                print("[get_attendance_trends] Imported Attendance model successfully.")

                end_date = timezone.now().date()
                start_date = end_date - timedelta(days=days)
                print(f"[get_attendance_trends] Calculated start_date={start_date}, end_date={end_date}")

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
                    print(f"[get_attendance_trends] Processed date {current_date}: {daily_trends[-1]}")
                    current_date += timedelta(days=1)

                if daily_trends:
                    avg_present = sum(day['present'] for day in daily_trends) / len(daily_trends)
                    avg_absent = sum(day['absent'] for day in daily_trends) / len(daily_trends)
                    avg_leave = sum(day['leave'] for day in daily_trends) / len(daily_trends)
                else:
                    avg_present = avg_absent = avg_leave = 0
                print(f"[get_attendance_trends] Calculated averages - present: {avg_present}, absent: {avg_absent}, leave: {avg_leave}")

                result = {
                    'start_date': start_date,
                    'end_date': end_date,
                    'daily_trends': daily_trends,
                    'averages': {
                        'present': round(avg_present, 2),
                        'absent': round(avg_absent, 2),
                        'leave': round(avg_leave, 2)
                    }
                }
                print(f"[get_attendance_trends] Returning result: {result}")
                return result

            except Exception as e:
                self.logger.error(f"Error getting attendance trends: {str(e)}")
                print(f"[get_attendance_trends] Exception occurred: {str(e)}. Returning default empty result.")
                end_date = timezone.now().date()
                start_date = end_date - timedelta(days=days)
                return {
                    'start_date': start_date,
                    'end_date': end_date,
                    'daily_trends': [],
                    'averages': {'present': 0, 'absent': 0, 'leave': 0}
                }

        def calculate_attendance_percentage(self, user_id: int, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
            """Calculate attendance percentage for a specific user"""
            print(f"[calculate_attendance_percentage] Called with user_id={user_id}, start_date={start_date}, end_date={end_date}")
            try:
                from ..models import Attendance
                print("[calculate_attendance_percentage] Imported Attendance model successfully.")

                total_records = Attendance.objects.filter(
                    user_id=user_id,
                    date__range=[start_date, end_date]
                ).count()
                print(f"[calculate_attendance_percentage] Total attendance records for user: {total_records}")

                if total_records == 0:
                    print(f"[calculate_attendance_percentage] No attendance records found for user_id={user_id}. Returning zeroed result.")
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
                print(f"[calculate_attendance_percentage] Aggregated status counts: {status_counts}")

                attendance_percentage = round(
                    (status_counts['present_days'] / total_records) * 100, 2
                ) if total_records > 0 else 0
                print(f"[calculate_attendance_percentage] Calculated attendance percentage: {attendance_percentage}%")

                result = {
                    'user_id': user_id,
                    'total_days': total_records,
                    'present_days': status_counts['present_days'],
                    'absent_days': status_counts['absent_days'],
                    'leave_days': status_counts['leave_days'],
                    'attendance_percentage': attendance_percentage
                }
                print(f"[calculate_attendance_percentage] Returning result: {result}")
                return result

            except Exception as e:
                self.logger.error(f"Error calculating attendance percentage for user {user_id}: {str(e)}")
                print(f"[calculate_attendance_percentage] Exception occurred: {str(e)}. Returning zeroed result.")
                return {
                    'user_id': user_id,
                    'total_days': 0,
                    'present_days': 0,
                    'absent_days': 0,
                    'leave_days': 0,
                    'attendance_percentage': 0
                }
