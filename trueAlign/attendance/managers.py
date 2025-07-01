# attendance/managers.py
from django.db import models
from django.utils import timezone
from django.db.models import Q, Count, Avg, Sum, Case, When, F
from django.contrib.auth import get_user_model
from datetime import datetime, timedelta, date
import pytz
import logging

logger = logging.getLogger(__name__)
User = get_user_model()

class AttendanceQuerySet(models.QuerySet):
    """
    Custom QuerySet for Attendance with optimized methods
    """

    def for_date(self, date):
        """Filter attendance for specific date"""
        return self.filter(date=date)

    def for_user(self, user):
        """Filter attendance for specific user"""
        return self.filter(user=user)

    def for_date_range(self, start_date, end_date):
        """Filter attendance for date range"""
        return self.filter(date__range=[start_date, end_date])

    def present(self):
        """Filter present attendance records"""
        return self.filter(status__in=['Present', 'Present & Late', 'Work From Home'])

    def absent(self):
        """Filter absent attendance records"""
        return self.filter(status='Absent')

    def late(self):
        """Filter late attendance records"""
        return self.filter(status__in=['Present & Late', 'Late'], late_minutes__gt=0)

    def pending_regularization(self):
        """Filter records with pending regularization"""
        return self.filter(regularization_status='Pending')

    def with_overtime(self):
        """Filter records with overtime"""
        return self.filter(overtime_hours__gt=0)

    def select_related_data(self):
        """Select related data for performance"""
        return self.select_related('user', 'shift', 'modified_by', 'first_session', 'last_session')

    def prefetch_user_data(self):
        """Prefetch user related data"""
        return self.select_related('user__profile')


class AttendanceManager(models.Manager):
    """
    Custom manager for Attendance model with optimized queries and business logic
    """

    def get_queryset(self):
        return AttendanceQuerySet(self.model, using=self._db)

    def for_date(self, date):
        return self.get_queryset().for_date(date)

    def for_user(self, user):
        return self.get_queryset().for_user(user)

    def for_date_range(self, start_date, end_date):
        return self.get_queryset().for_date_range(start_date, end_date)

    def present(self):
        return self.get_queryset().present()

    def absent(self):
        return self.get_queryset().absent()

    def late(self):
        return self.get_queryset().late()

    def pending_regularization(self):
        return self.get_queryset().pending_regularization()

    def with_overtime(self):
        return self.get_queryset().with_overtime()

    def get_or_create_today_attendance(self, user, date=None):
        """
        Get or create attendance record for specific date with proper defaults
        """
        if not date:
            IST = pytz.timezone('Asia/Kolkata')
            date = timezone.now().astimezone(IST).date()

        try:
            attendance, created = self.get_or_create(
                user=user,
                date=date,
                defaults={
                    'status': 'Not Marked',
                    'regularization_reason': 'Auto-created attendance record'
                }
            )

            if created:
                logger.info(f"Created new attendance record for {user.username} on {date}")
                # Initialize with shift and other data in a separate method
                attendance._initialize_attendance_defaults()
                attendance.save()

            return attendance, created

        except Exception as e:
            logger.error(f"Error creating attendance for {user.username} on {date}: {e}")
            raise

    def get_users_without_attendance_today(self, date=None):
        """
        Get users who don't have attendance record for given date
        """
        if not date:
            IST = pytz.timezone('Asia/Kolkata')
            date = timezone.now().astimezone(IST).date()

        users_with_attendance = self.filter(date=date).values_list('user_id', flat=True)
        return User.objects.filter(
            is_active=True
        ).exclude(id__in=users_with_attendance)

    def get_attendance_summary(self, date=None):
        """
        Get attendance summary for a specific date
        """
        if not date:
            IST = pytz.timezone('Asia/Kolkata')
            date = timezone.now().astimezone(IST).date()

        return self.filter(date=date).aggregate(
            total_employees=Count('id'),
            present_count=Count('id', filter=Q(status__in=['Present', 'Present & Late', 'Work From Home'])),
            absent_count=Count('id', filter=Q(status='Absent')),
            late_count=Count('id', filter=Q(status__in=['Present & Late', 'Late'])),
            on_leave_count=Count('id', filter=Q(status='On Leave')),
            holiday_count=Count('id', filter=Q(status='Holiday')),
            weekend_count=Count('id', filter=Q(status='Weekend')),
            not_marked_count=Count('id', filter=Q(status='Not Marked')),
            yet_to_clock_in_count=Count('id', filter=Q(status='Yet to Clock In'))
        )

    def get_user_attendance_for_period(self, user, start_date, end_date):
        """
        Get attendance records for a user within a specific period
        """
        return self.filter(
            user=user,
            date__range=[start_date, end_date]
        ).select_related('shift').order_by('date')

    def get_team_attendance(self, manager_user, date=None):
        """
        Get attendance for all team members under a manager
        """
        if not date:
            IST = pytz.timezone('Asia/Kolkata')
            date = timezone.now().astimezone(IST).date()

        # Get team members (assuming there's a relationship)
        try:
            team_members = User.objects.filter(
                profile__manager=manager_user,
                is_active=True
            )

            return self.filter(
                user__in=team_members,
                date=date
            ).select_related_data()

        except Exception as e:
            logger.error(f"Error getting team attendance for {manager_user.username}: {e}")
            return self.none()

    def bulk_create_attendance_records(self, users, date, status='Not Marked', reason=None):
        """
        Bulk create attendance records for multiple users
        """
        if not isinstance(users, (list, tuple)):
            users = list(users)

        if not reason:
            reason = f'Bulk created with status: {status}'

        # Check for existing records
        existing_user_ids = set(
            self.filter(date=date, user__in=users).values_list('user_id', flat=True)
        )

        # Create records for users without existing attendance
        attendance_records = []
        for user in users:
            if user.id not in existing_user_ids:
                attendance_records.append(
                    self.model(
                        user=user,
                        date=date,
                        status=status,
                        regularization_reason=reason
                    )
                )

        if attendance_records:
            created_attendances = self.bulk_create(attendance_records)
            logger.info(f"Bulk created {len(created_attendances)} attendance records for {date}")
            return created_attendances

        logger.info(f"No new attendance records created - all users already have records for {date}")
        return []

    def bulk_update_status(self, attendance_ids, status, reason=None, updated_by=None):
        """
        Bulk update status for multiple attendance records
        """
        if not reason:
            reason = f'Bulk updated to: {status}'

        update_fields = {
            'status': status,
            'regularization_reason': reason,
            'last_modified': timezone.now()
        }

        if updated_by:
            update_fields['modified_by'] = updated_by

        updated_count = self.filter(id__in=attendance_ids).update(**update_fields)
        logger.info(f"Bulk updated {updated_count} attendance records to status: {status}")
        return updated_count

    def get_attendance_analytics(self, start_date, end_date, users=None, group_by='date'):
        """
        Get attendance analytics for given period
        """
        queryset = self.filter(date__range=[start_date, end_date])

        if users:
            queryset = queryset.filter(user__in=users)

        if group_by == 'date':
            return queryset.values('date').annotate(
                total_count=Count('id'),
                present_count=Count('id', filter=Q(status__in=['Present', 'Present & Late', 'Work From Home'])),
                absent_count=Count('id', filter=Q(status='Absent')),
                late_count=Count('id', filter=Q(status__in=['Present & Late', 'Late'])),
                avg_hours=Avg('total_hours'),
                total_overtime=Sum('overtime_hours')
            ).order_by('date')

        elif group_by == 'user':
            return queryset.values('user__username', 'user__first_name', 'user__last_name').annotate(
                total_days=Count('id'),
                present_days=Count('id', filter=Q(status__in=['Present', 'Present & Late', 'Work From Home'])),
                absent_days=Count('id', filter=Q(status='Absent')),
                late_days=Count('id', filter=Q(status__in=['Present & Late', 'Late'])),
                avg_hours=Avg('total_hours'),
                total_overtime=Sum('overtime_hours'),
                attendance_percentage=Case(
                    When(total_days=0, then=0),
                    default=F('present_days') * 100.0 / F('total_days')
                )
            ).order_by('user__username')

        elif group_by == 'status':
            return queryset.values('status').annotate(
                count=Count('id'),
                percentage=Case(
                    When(count=0, then=0),
                    default=F('count') * 100.0 / Count('id', distinct=False)
                )
            ).order_by('status')

        else:
            return queryset.aggregate(
                total_records=Count('id'),
                present_count=Count('id', filter=Q(status__in=['Present', 'Present & Late', 'Work From Home'])),
                absent_count=Count('id', filter=Q(status='Absent')),
                late_count=Count('id', filter=Q(status__in=['Present & Late', 'Late'])),
                avg_hours=Avg('total_hours'),
                total_overtime=Sum('overtime_hours')
            )

    def get_late_attendances(self, date=None, threshold_minutes=10):
        """
        Get late attendance records above threshold
        """
        if not date:
            IST = pytz.timezone('Asia/Kolkata')
            date = timezone.now().astimezone(IST).date()

        return self.filter(
            date=date,
            status__in=['Present & Late', 'Late'],
            late_minutes__gt=threshold_minutes
        ).select_related('user', 'shift').order_by('-late_minutes')

    def get_overtime_records(self, start_date=None, end_date=None):
        """
        Get records with overtime
        """
        queryset = self.filter(overtime_hours__gt=0)

        if start_date and end_date:
            queryset = queryset.filter(date__range=[start_date, end_date])
        elif start_date:
            queryset = queryset.filter(date__gte=start_date)
        elif end_date:
            queryset = queryset.filter(date__lte=end_date)

        return queryset.select_related('user', 'shift').order_by('-overtime_hours')

    def get_regularization_requests(self, status=None, user=None):
        """
        Get regularization requests with optional filtering
        """
        queryset = self.exclude(regularization_status__isnull=True)

        if status:
            queryset = queryset.filter(regularization_status=status)

        if user:
            queryset = queryset.filter(user=user)

        return queryset.select_related('user', 'shift', 'modified_by').order_by('-last_regularization_date')

    def get_monthly_attendance_report(self, year, month, users=None):
        """
        Get monthly attendance report
        """
        start_date = date(year, month, 1)

        # Calculate last day of month
        if month == 12:
            end_date = date(year + 1, 1, 1) - timedelta(days=1)
        else:
            end_date = date(year, month + 1, 1) - timedelta(days=1)

        queryset = self.filter(date__range=[start_date, end_date])

        if users:
            queryset = queryset.filter(user__in=users)

        return queryset.values(
            'user__id',
            'user__username',
            'user__first_name',
            'user__last_name'
        ).annotate(
            total_days=Count('id'),
            present_days=Count('id', filter=Q(status__in=['Present', 'Present & Late', 'Work From Home'])),
            absent_days=Count('id', filter=Q(status='Absent')),
            late_days=Count('id', filter=Q(status__in=['Present & Late', 'Late'])),
            leave_days=Count('id', filter=Q(status='On Leave')),
            holiday_days=Count('id', filter=Q(status='Holiday')),
            weekend_days=Count('id', filter=Q(status='Weekend')),
            total_hours=Sum('total_hours'),
            total_overtime=Sum('overtime_hours'),
            avg_hours=Avg('total_hours'),
            attendance_percentage=Case(
                When(total_days=0, then=0),
                default=F('present_days') * 100.0 / F('total_days')
            )
        ).order_by('user__username')

    def cleanup_old_records(self, days_to_keep=365):
        """
        Clean up old attendance records (keep only specified number of days)
        """
        cutoff_date = timezone.now().date() - timedelta(days=days_to_keep)

        deleted_count = self.filter(date__lt=cutoff_date).delete()[0]
        logger.info(f"Cleaned up {deleted_count} old attendance records before {cutoff_date}")
        return deleted_count

    def get_attendance_trends(self, start_date, end_date, user=None):
        """
        Get attendance trends over time
        """
        queryset = self.filter(date__range=[start_date, end_date])

        if user:
            queryset = queryset.filter(user=user)

        # Group by week
        return queryset.extra(
            select={'week': "date_trunc('week', date)"}
        ).values('week').annotate(
            present_count=Count('id', filter=Q(status__in=['Present', 'Present & Late', 'Work From Home'])),
            absent_count=Count('id', filter=Q(status='Absent')),
            late_count=Count('id', filter=Q(status__in=['Present & Late', 'Late'])),
            avg_hours=Avg('total_hours')
        ).order_by('week')

    def get_department_attendance(self, department=None, date=None):
        """
        Get attendance by department
        """
        if not date:
            IST = pytz.timezone('Asia/Kolkata')
            date = timezone.now().astimezone(IST).date()

        queryset = self.filter(date=date)

        if department:
            queryset = queryset.filter(user__profile__department=department)

        return queryset.values(
            'user__profile__department'
        ).annotate(
            total_employees=Count('id'),
            present_count=Count('id', filter=Q(status__in=['Present', 'Present & Late', 'Work From Home'])),
            absent_count=Count('id', filter=Q(status='Absent')),
            late_count=Count('id', filter=Q(status__in=['Present & Late', 'Late'])),
            attendance_percentage=Case(
                When(total_employees=0, then=0),
                default=F('present_count') * 100.0 / F('total_employees')
            )
        ).order_by('user__profile__department')
