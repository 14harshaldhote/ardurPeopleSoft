# attendance/services.py
from django.db.models import Q, Count, Sum, Avg, F, Case, When, IntegerField
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.paginator import Paginator
from django.db import transaction
from datetime import datetime, date, timedelta, time
from decimal import Decimal
import calendar
import logging
from typing import Dict, List, Optional, Any, Tuple

from ..models import Attendance, UserSession, ShiftAssignment, LeaveRequest, Holiday
from ..services.date_service import DateService
from ..services.user_service import UserService

logger = logging.getLogger(__name__)


class AttendanceManagementService:
    """
    Service for managing attendance records with CRUD operations
    """

    def __init__(self):
        self.date_service = DateService()
        self.user_service = UserService()
        self.logger = logging.getLogger(__name__)

    def create_attendance_record(self, user_id: int, attendance_data: Dict[str, Any]) -> Optional[Attendance]:
        """
        Create a new attendance record
        """
        try:
            user = User.objects.get(id=user_id)

            # Check if record already exists
            existing = Attendance.objects.filter(
                user=user,
                date=attendance_data['date']
            ).first()

            if existing:
                self.logger.warning(f"Attendance record already exists for user {user_id} on {attendance_data['date']}")
                return None

            # Get user's shift for the date
            shift = None
            try:
                shift = ShiftAssignment.get_user_current_shift(user, attendance_data['date'])
            except Exception as e:
                self.logger.error(f"Error getting shift: {str(e)}")

            # Create attendance record
            attendance = Attendance(
                user=user,
                date=attendance_data['date'],
                status=attendance_data.get('status', 'Present'),
                location=attendance_data.get('location', 'Office'),
                shift=shift,
                remarks=attendance_data.get('remarks', ''),
                modified_by_id=attendance_data.get('modified_by_id'),
                regularization_reason=attendance_data.get('regularization_reason', '')
            )

            # Set times if provided
            if attendance_data.get('clock_in_time'):
                clock_in_datetime = datetime.combine(
                    attendance_data['date'],
                    attendance_data['clock_in_time']
                )
                attendance.clock_in_time = timezone.make_aware(clock_in_datetime)

            if attendance_data.get('clock_out_time'):
                clock_out_datetime = datetime.combine(
                    attendance_data['date'],
                    attendance_data['clock_out_time']
                )
                attendance.clock_out_time = timezone.make_aware(clock_out_datetime)

            attendance.save()
            self.logger.info(f"Created attendance record for user {user_id} on {attendance_data['date']}")
            return attendance

        except User.DoesNotExist:
            self.logger.error(f"User with id {user_id} not found")
            return None
        except Exception as e:
            self.logger.error(f"Error creating attendance record: {str(e)}")
            return None

    def update_attendance_record(self, attendance_id: int, update_data: Dict[str, Any]) -> Optional[Attendance]:
        """
        Update an existing attendance record
        """
        try:
            attendance = Attendance.objects.get(id=attendance_id)

            # Store original values for audit
            original_status = attendance.status
            original_clock_in = attendance.clock_in_time
            original_clock_out = attendance.clock_out_time

            # Update fields
            for field, value in update_data.items():
                if hasattr(attendance, field):
                    setattr(attendance, field, value)

            # Store original values if they're being changed
            if 'status' in update_data and not attendance.original_status:
                attendance.original_status = original_status

            if 'clock_in_time' in update_data and not attendance.original_clock_in_time:
                attendance.original_clock_in_time = original_clock_in

            if 'clock_out_time' in update_data and not attendance.original_clock_out_time:
                attendance.original_clock_out_time = original_clock_out

            attendance.save()
            self.logger.info(f"Updated attendance record {attendance_id}")
            return attendance

        except Attendance.DoesNotExist:
            self.logger.error(f"Attendance record {attendance_id} not found")
            return None
        except Exception as e:
            self.logger.error(f"Error updating attendance record: {str(e)}")
            return None

    def bulk_create_attendance(self, user_ids: List[int], attendance_date: date,
                             status: str, reason: str = '') -> Dict[str, Any]:
        """
        Create attendance records for multiple users
        """
        try:
            created_count = 0
            skipped_count = 0
            errors = []

            with transaction.atomic():
                for user_id in user_ids:
                    try:
                        user = User.objects.get(id=user_id)

                        # Check if record already exists
                        if Attendance.objects.filter(user=user, date=attendance_date).exists():
                            skipped_count += 1
                            continue

                        # Get shift
                        shift = None
                        try:
                            shift = ShiftAssignment.get_user_current_shift(user, attendance_date)
                        except:
                            pass

                        # Create record
                        attendance = Attendance(
                            user=user,
                            date=attendance_date,
                            status=status,
                            shift=shift,
                            regularization_reason=f"Bulk operation: {reason}"
                        )
                        attendance.save()
                        created_count += 1

                    except User.DoesNotExist:
                        errors.append(f"User {user_id} not found")
                    except Exception as e:
                        errors.append(f"Error for user {user_id}: {str(e)}")

            result = {
                'created': created_count,
                'skipped': skipped_count,
                'errors': errors,
                'success': len(errors) == 0
            }

            self.logger.info(f"Bulk attendance creation: {result}")
            return result

        except Exception as e:
            self.logger.error(f"Error in bulk attendance creation: {str(e)}")
            return {'created': 0, 'skipped': 0, 'errors': [str(e)], 'success': False}

    def delete_attendance_record(self, attendance_id: int) -> bool:
        """
        Delete an attendance record
        """
        try:
            attendance = Attendance.objects.get(id=attendance_id)
            user_name = attendance.user.get_full_name()
            attendance_date = attendance.date

            attendance.delete()
            self.logger.info(f"Deleted attendance record for {user_name} on {attendance_date}")
            return True

        except Attendance.DoesNotExist:
            self.logger.error(f"Attendance record {attendance_id} not found")
            return False
        except Exception as e:
            self.logger.error(f"Error deleting attendance record: {str(e)}")
            return False


class AttendanceRegularizationService:
    """
    Service for handling attendance regularization requests
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def submit_regularization_request(self, user_id: int, attendance_id: int,
                                   request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Submit a regularization request
        """
        try:
            attendance = Attendance.objects.get(id=attendance_id, user_id=user_id)

            # Check if already has pending request
            if attendance.regularization_status == 'Pending':
                return {
                    'success': False,
                    'message': 'A regularization request is already pending for this date'
                }

            # Update attendance with request details
            attendance.requested_status = request_data.get('requested_status')
            attendance.regularization_reason = request_data.get('reason', '')
            attendance.regularization_status = 'Pending'
            attendance.regularization_attempts += 1
            attendance.last_regularization_date = timezone.now()
            attendance.save()

            self.logger.info(f"Regularization request submitted for attendance {attendance_id}")
            return {
                'success': True,
                'message': 'Regularization request submitted successfully'
            }

        except Attendance.DoesNotExist:
            return {
                'success': False,
                'message': 'Attendance record not found'
            }
        except Exception as e:
            self.logger.error(f"Error submitting regularization request: {str(e)}")
            return {
                'success': False,
                'message': 'An error occurred while submitting the request'
            }

    def process_regularization_request(self, attendance_id: int, action: str,
                                     comments: str = '', processed_by_id: int = None) -> Dict[str, Any]:
        """
        Process a regularization request (approve/reject)
        """
        try:
            attendance = Attendance.objects.get(id=attendance_id)

            if action == 'approve':
                # Store original values
                if not attendance.original_status:
                    attendance.original_status = attendance.status
                if not attendance.original_clock_in_time:
                    attendance.original_clock_in_time = attendance.clock_in_time
                if not attendance.original_clock_out_time:
                    attendance.original_clock_out_time = attendance.clock_out_time

                # Apply requested changes
                if attendance.requested_status:
                    attendance.status = attendance.requested_status

                attendance.regularization_status = 'Approved'
                message = f"Regularization approved for {attendance.user.get_full_name()}"

            elif action == 'reject':
                attendance.regularization_status = 'Rejected'
                message = f"Regularization rejected for {attendance.user.get_full_name()}"

            else:
                return {
                    'success': False,
                    'message': 'Invalid action specified'
                }

            if comments:
                attendance.remarks = comments

            if processed_by_id:
                attendance.modified_by_id = processed_by_id

            attendance.save()

            self.logger.info(f"Regularization {action}d for attendance {attendance_id}")
            return {
                'success': True,
                'message': message
            }

        except Attendance.DoesNotExist:
            return {
                'success': False,
                'message': 'Attendance record not found'
            }
        except Exception as e:
            self.logger.error(f"Error processing regularization: {str(e)}")
            return {
                'success': False,
                'message': 'An error occurred while processing the request'
            }

    def get_regularization_requests(self, filters: Dict[str, Any] = None,
                                  page: int = 1, per_page: int = 15) -> Dict[str, Any]:
        """
        Get regularization requests with filtering and pagination
        """
        try:
            queryset = Attendance.objects.filter(
                regularization_status__isnull=False
            ).select_related('user', 'shift', 'modified_by').order_by(
                'regularization_status', '-last_regularization_date'
            )

            # Apply filters
            if filters:
                if filters.get('status'):
                    queryset = queryset.filter(regularization_status=filters['status'])

                if filters.get('date_from'):
                    queryset = queryset.filter(date__gte=filters['date_from'])

                if filters.get('date_to'):
                    queryset = queryset.filter(date__lte=filters['date_to'])

                if filters.get('employee_search'):
                    search_term = filters['employee_search']
                    queryset = queryset.filter(
                        Q(user__first_name__icontains=search_term) |
                        Q(user__last_name__icontains=search_term) |
                        Q(user__username__icontains=search_term)
                    )

            # Pagination
            paginator = Paginator(queryset, per_page)
            page_obj = paginator.get_page(page)

            # Statistics
            stats = {
                'total': queryset.count(),
                'pending': queryset.filter(regularization_status='Pending').count(),
                'approved': queryset.filter(regularization_status='Approved').count(),
                'rejected': queryset.filter(regularization_status='Rejected').count(),
            }

            return {
                'requests': page_obj,
                'stats': stats,
                'has_next': page_obj.has_next(),
                'has_previous': page_obj.has_previous(),
                'total_pages': paginator.num_pages
            }

        except Exception as e:
            self.logger.error(f"Error getting regularization requests: {str(e)}")
            return {
                'requests': [],
                'stats': {},
                'has_next': False,
                'has_previous': False,
                'total_pages': 0
            }


class AttendanceCalendarService:
    """
    Service for calendar-related attendance operations
    """

    def __init__(self):
        self.date_service = DateService()
        self.logger = logging.getLogger(__name__)

    def get_monthly_calendar_data(self, user_id: int, year: int, month: int) -> Dict[str, Any]:
        """
        Get attendance data for a monthly calendar view
        """
        try:
            # Create calendar
            cal = calendar.monthcalendar(year, month)

            # Get attendance data for the month
            start_date = date(year, month, 1)
            if month == 12:
                end_date = date(year + 1, 1, 1) - timedelta(days=1)
            else:
                end_date = date(year, month + 1, 1) - timedelta(days=1)

            attendance_data = {}
            attendances = Attendance.objects.filter(
                user_id=user_id,
                date__range=[start_date, end_date]
            ).select_related('shift')

            for attendance in attendances:
                attendance_data[attendance.date.day] = {
                    'id': attendance.id,
                    'status': attendance.status,
                    'clock_in': attendance.clock_in_time.strftime('%H:%M') if attendance.clock_in_time else None,
                    'clock_out': attendance.clock_out_time.strftime('%H:%M') if attendance.clock_out_time else None,
                    'total_hours': float(attendance.total_hours) if attendance.total_hours else 0,
                    'late_minutes': attendance.late_minutes,
                    'location': attendance.location,
                    'is_regularizable': self._is_regularizable(attendance),
                    'regularization_status': attendance.regularization_status,
                    'shift_name': attendance.shift.name if attendance.shift else None
                }

            # Get current shift
            current_shift = None
            try:
                user = User.objects.get(id=user_id)
                current_shift = ShiftAssignment.get_user_current_shift(user, self.date_service.get_current_date())
            except Exception as e:
                self.logger.error(f"Error getting current shift: {str(e)}")

            return {
                'calendar': cal,
                'attendance_data': attendance_data,
                'month': month,
                'year': year,
                'month_name': calendar.month_name[month],
                'current_shift': {
                    'name': current_shift.name if current_shift else None,
                    'start_time': current_shift.start_time.strftime('%H:%M') if current_shift else None,
                    'end_time': current_shift.end_time.strftime('%H:%M') if current_shift else None
                } if current_shift else None
            }

        except Exception as e:
            self.logger.error(f"Error getting monthly calendar data: {str(e)}")
            return {
                'calendar': [],
                'attendance_data': {},
                'month': month,
                'year': year,
                'month_name': calendar.month_name[month],
                'current_shift': None
            }

    def _is_regularizable(self, attendance: Attendance) -> bool:
        """
        Check if an attendance record can be regularized
        """
        # Can't regularize if already approved or if too old
        if attendance.regularization_status == 'Approved':
            return False

        # Can't regularize records older than 30 days
        if (self.date_service.get_current_date() - attendance.date).days > 30:
            return False

        # Can't regularize if too many attempts
        if attendance.regularization_attempts >= 3:
            return False

        return True


class AttendanceReportService:
    """
    Service for generating attendance reports
    """

    def __init__(self):
        self.date_service = DateService()
        self.logger = logging.getLogger(__name__)

    def generate_attendance_report(self, filters: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Generate comprehensive attendance report
        """
        try:
            # Build base query
            queryset = Attendance.objects.select_related('user', 'shift')

            # Apply filters
            if filters:
                if filters.get('user_id'):
                    queryset = queryset.filter(user_id=filters['user_id'])

                if filters.get('location'):
                    queryset = queryset.filter(location=filters['location'])

                if filters.get('status'):
                    queryset = queryset.filter(status=filters['status'])

                if filters.get('start_date') and filters.get('end_date'):
                    queryset = queryset.filter(
                        date__range=[filters['start_date'], filters['end_date']]
                    )

            queryset = queryset.order_by('-date', 'user__first_name')

            # Generate summary statistics
            summary = queryset.aggregate(
                total_records=Count('id'),
                total_hours=Sum('total_hours'),
                total_overtime=Sum('overtime_hours'),
                present_count=Count('id', filter=Q(status__in=['Present', 'Present & Late'])),
                absent_count=Count('id', filter=Q(status='Absent')),
                leave_count=Count('id', filter=Q(status='On Leave')),
                wfh_count=Count('id', filter=Q(status='Work From Home')),
                late_count=Count('id', filter=Q(status='Present & Late')),
                avg_hours=Avg('total_hours'),
                total_late_minutes=Sum('late_minutes')
            )

            # Calculate attendance percentage
            if summary['total_records'] > 0:
                working_days = summary['total_records'] - summary['leave_count']
                if working_days > 0:
                    attendance_percentage = (summary['present_count'] / working_days) * 100
                else:
                    attendance_percentage = 0
            else:
                attendance_percentage = 0

            summary['attendance_percentage'] = round(attendance_percentage, 2)

            return {
                'records': queryset,
                'summary': summary,
                'filters_applied': filters or {}
            }

        except Exception as e:
            self.logger.error(f"Error generating attendance report: {str(e)}")
            return {
                'records': Attendance.objects.none(),
                'summary': {},
                'filters_applied': {}
            }

    def get_user_attendance_summary(self, user_id: int, start_date: date, end_date: date) -> Dict[str, Any]:
        """
        Get attendance summary for a specific user
        """
        try:
            user = User.objects.get(id=user_id)

            attendances = Attendance.objects.filter(
                user=user,
                date__range=[start_date, end_date]
            )

            summary = attendances.aggregate(
                total_days=Count('id'),
                present_days=Count('id', filter=Q(status__in=['Present', 'Present & Late'])),
                absent_days=Count('id', filter=Q(status='Absent')),
                leave_days=Count('id', filter=Q(status='On Leave')),
                wfh_days=Count('id', filter=Q(status='Work From Home')),
                late_days=Count('id', filter=Q(status='Present & Late')),
                total_hours=Sum('total_hours'),
                total_overtime=Sum('overtime_hours'),
                total_late_minutes=Sum('late_minutes')
            )

            # Calculate working days (excluding weekends, holidays, leaves)
            working_days = summary['total_days'] - summary['leave_days']
            holiday_weekend_days = attendances.filter(
                status__in=['Holiday', 'Weekend']
            ).count()
            working_days -= holiday_weekend_days

            # Calculate attendance percentage
            if working_days > 0:
                attendance_percentage = (summary['present_days'] / working_days) * 100
            else:
                attendance_percentage = 0

            summary.update({
                'user_name': user.get_full_name(),
                'working_days': working_days,
                'attendance_percentage': round(attendance_percentage, 2),
                'average_hours_per_day': round(
                    float(summary['total_hours'] or 0) / max(summary['present_days'], 1), 2
                ),
                'start_date': start_date,
                'end_date': end_date
            })

            return summary

        except User.DoesNotExist:
            self.logger.error(f"User {user_id} not found")
            return {}
        except Exception as e:
            self.logger.error(f"Error getting user attendance summary: {str(e)}")
            return {}


class AttendanceAnalyticsService:
    """
    Service for attendance analytics and insights
    """

    def __init__(self):
        self.date_service = DateService()
        self.logger = logging.getLogger(__name__)

    def get_attendance_analytics(self, start_date: date, end_date: date) -> Dict[str, Any]:
        """
        Get comprehensive attendance analytics
        """
        try:
            attendances = Attendance.objects.filter(
                date__range=[start_date, end_date]
            ).select_related('user', 'shift')

            # Overall statistics
            overall_stats = attendances.aggregate(
                total_records=Count('id'),
                unique_users=Count('user', distinct=True),
                total_hours=Sum('total_hours'),
                total_overtime=Sum('overtime_hours'),
                present_count=Count('id', filter=Q(status__in=['Present', 'Present & Late'])),
                absent_count=Count('id', filter=Q(status='Absent')),
                late_count=Count('id', filter=Q(status='Present & Late')),
                avg_hours_per_day=Avg('total_hours')
            )

            # Location-wise statistics
            location_stats = attendances.values('location').annotate(
                count=Count('id'),
                present_count=Count('id', filter=Q(status__in=['Present', 'Present & Late'])),
                absent_count=Count('id', filter=Q(status='Absent')),
                avg_hours=Avg('total_hours')
            ).order_by('-count')

            # Daily trends
            daily_trends = attendances.values('date').annotate(
                total_count=Count('id'),
                present_count=Count('id', filter=Q(status__in=['Present', 'Present & Late'])),
                absent_count=Count('id', filter=Q(status='Absent')),
                late_count=Count('id', filter=Q(status='Present & Late')),
                avg_hours=Avg('total_hours')
            ).order_by('date')

            # Top performers (by attendance percentage)
            user_stats = attendances.values('user__id', 'user__first_name', 'user__last_name').annotate(
                total_days=Count('id'),
                present_days=Count('id', filter=Q(status__in=['Present', 'Present & Late'])),
                absent_days=Count('id', filter=Q(status='Absent')),
                late_days=Count('id', filter=Q(status='Present & Late')),
                total_hours=Sum('total_hours'),
                avg_hours=Avg('total_hours')
            ).annotate(
                attendance_percentage=Case(
                    When(total_days=0, then=0),
                    default=F('present_days') * 100 / F('total_days'),
                    output_field=IntegerField()
                )
            ).order_by('-attendance_percentage')

            # Attendance by day of week
            day_of_week_stats = []
            for i in range(7):  # 0 = Monday, 6 = Sunday
                day_name = calendar.day_name[i]
                day_stats = attendances.filter(date__week_day=i+2).aggregate(  # Django week_day: 1=Sunday
                    total_count=Count('id'),
                    present_count=Count('id', filter=Q(status__in=['Present', 'Present & Late'])),
                    absent_count=Count('id', filter=Q(status='Absent')),
                    avg_hours=Avg('total_hours')
                )
                day_stats['day_name'] = day_name
                day_of_week_stats.append(day_stats)

            return {
                'overall_stats': overall_stats,
                'location_stats': list(location_stats),
                'daily_trends': list(daily_trends),
                'user_stats': list(user_stats[:10]),  # Top 10 users
                'day_of_week_stats': day_of_week_stats,
                'period': {
                    'start_date': start_date,
                    'end_date': end_date,
                    'total_days': (end_date - start_date).days + 1
                }
            }

        except Exception as e:
            self.logger.error(f"Error getting attendance analytics: {str(e)}")
            return {
                'overall_stats': {},
                'location_stats': [],
                'daily_trends': [],
                'user_stats': [],
                'day_of_week_stats': [],
                'period': {}
            }

    def get_tardiness_report(self, start_date: date, end_date: date) -> Dict[str, Any]:
        """
        Get detailed tardiness report
        """
        try:
            late_attendances = Attendance.objects.filter(
                date__range=[start_date, end_date],
                status='Present & Late',
                late_minutes__gt=0
            ).select_related('user', 'shift')

            # User-wise tardiness
            user_tardiness = late_attendances.values(
                'user__id', 'user__first_name', 'user__last_name'
            ).annotate(
                late_days=Count('id'),
                total_late_minutes=Sum('late_minutes'),
                avg_late_minutes=Avg('late_minutes'),
                max_late_minutes=Max('late_minutes')
            ).order_by('-total_late_minutes')

            # Late arrival patterns by hour
            late_patterns = {}
            for attendance in late_attendances:
                if attendance.clock_in_time:
                    hour = attendance.clock_in_time.hour
                    if hour not in late_patterns:
                        late_patterns[hour] = 0
                    late_patterns[hour] += 1

            return {
                'user_tardiness': list(user_tardiness),
                'late_patterns': late_patterns,
                'total_late_instances': late_attendances.count(),
                'total_late_minutes': late_attendances.aggregate(
                    total=Sum('late_minutes')
                )['total'] or 0
            }

        except Exception as e:
            self.logger.error(f"Error getting tardiness report: {str(e)}")
            return {
                'user_tardiness': [],
                'late_patterns': {},
                'total_late_instances': 0,
                'total_late_minutes': 0
            }


class AttendanceNotificationService:
    """
    Service for attendance-related notifications
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def send_regularization_notification(self, attendance_id: int, notification_type: str) -> bool:
        """
        Send notification for regularization events
        """
        try:
            attendance = Attendance.objects.get(id=attendance_id)

            # In a real implementation, this would send email/SMS notifications
            # For now, we'll just log the notification

            if notification_type == 'submitted':
                message = f"Regularization request submitted for {attendance.date}"
            elif notification_type == 'approved':
                message = f"Regularization request approved for {attendance.date}"
            elif notification_type == 'rejected':
                message = f"Regularization request rejected for {attendance.date}"
            else:
                message = f"Regularization update for {attendance.date}"

            self.logger.info(f"Notification sent to {attendance.user.email}: {message}")

            # Update notification flags
            if notification_type in ['approved', 'rejected']:
                attendance.is_employee_notified = True
                attendance.save(update_fields=['is_employee_notified'])

            return True

        except Attendance.DoesNotExist:
            self.logger.error(f"Attendance record {attendance_id} not found for notification")
            return False
        except Exception as e:
            self.logger.error(f"Error sending notification: {str(e)}")
            return False

    def send_absent_notification(self, user_id: int, date: date) -> bool:
        """
        Send notification for absent employees
        """
        try:
            user = User.objects.get(id=user_id)

            # In a real implementation
