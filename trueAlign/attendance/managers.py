# attendance/managers.py
import logging
from datetime import timedelta
from decimal import Decimal

from django.db import models, transaction
from django.db.models import Q, Count, Avg, Sum, Case, When, F, Value
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.core.cache import cache
from django.core.exceptions import ObjectDoesNotExist
import pytz

logger = logging.getLogger(__name__)
User = get_user_model()
IST = pytz.timezone('Asia/Kolkata')


class AttendanceQuerySet(models.QuerySet):
    """
    Optimized QuerySet for Attendance with efficient filtering and aggregation methods
    """

    def for_date(self, date):
        """Filter attendance for specific date"""
        return self.filter(date=date)

    def for_user(self, user):
        """Filter attendance for specific user"""
        return self.filter(user=user)

    def for_users(self, users):
        """Filter attendance for multiple users efficiently"""
        if isinstance(users, (list, tuple)):
            user_ids = [u.id if hasattr(u, 'id') else u for u in users]
            return self.filter(user_id__in=user_ids)
        return self.filter(user__in=users)

    def for_date_range(self, start_date, end_date):
        """Filter attendance for date range"""
        return self.filter(date__range=[start_date, end_date])

    def for_month(self, year, month):
        """Filter attendance for specific month"""
        return self.filter(date__year=year, date__month=month)

    def for_year(self, year):
        """Filter attendance for specific year"""
        return self.filter(date__year=year)

    def present(self):
        """Filter present attendance records"""
        return self.filter(
            status__in=['Present', 'Present & Late', 'Work From Home']
        )

    def absent(self):
        """Filter absent attendance records"""
        return self.filter(status='Absent')

    def late(self):
        """Filter late attendance records"""
        return self.filter(
            Q(status__in=['Present & Late', 'Late']) | Q(late_minutes__gt=0)
        )

    def on_leave(self):
        """Filter leave attendance records"""
        return self.filter(status='On Leave')

    def weekend_or_holiday(self):
        """Filter weekend/holiday records"""
        return self.filter(status__in=['Weekend', 'Holiday'])

    def pending_regularization(self):
        """Filter records with pending regularization"""
        return self.filter(regularization_status='Pending')

    def approved_regularization(self):
        """Filter records with approved regularization"""
        return self.filter(regularization_status='Approved')

    def rejected_regularization(self):
        """Filter records with rejected regularization"""
        return self.filter(regularization_status='Rejected')

    def with_overtime(self):
        """Filter records with overtime"""
        return self.filter(overtime_hours__gt=0)

    def with_early_departure(self):
        """Filter records with early departure"""
        return self.filter(left_early=True, early_departure_minutes__gt=0)

    def incomplete_attendance(self):
        """Filter incomplete attendance records (no clock out)"""
        return self.filter(
            Q(clock_in_time__isnull=False) & Q(clock_out_time__isnull=True)
        ).exclude(status__in=['Weekend', 'Holiday', 'On Leave'])

    def not_marked(self):
        """Filter not marked records"""
        return self.filter(status__in=['Not Marked', 'Yet to Clock In'])

    def select_optimized(self):
        """Select related data for performance optimization"""
        return self.select_related(
            'user',
            'user__profile',
            'shift',
            'modified_by',
            'first_session',
            'last_session'
        ).prefetch_related('user__groups')

    def with_user_details(self):
        """Include user profile details"""
        return self.select_related('user__profile')

    def with_shift_details(self):
        """Include shift details"""
        return self.select_related('shift')

    def with_session_details(self):
        """Include session details"""
        return self.select_related('first_session', 'last_session')

    def order_by_date_user(self):
        """Default ordering by date and user"""
        return self.order_by('-date', 'user__username')

    def order_by_user_date(self):
        """Order by user then date"""
        return self.order_by('user__username', '-date')

    def annotate_working_hours(self):
        """Annotate with calculated working hours"""
        return self.annotate(
            working_hours=Case(
                When(total_hours__isnull=True, then=Value(0, output_field=models.DecimalField())),
                default=F('total_hours'),
                output_field=models.DecimalField(max_digits=5, decimal_places=2)
            )
        )

    def annotate_status_counts(self):
        """Annotate with status counts for user"""
        return self.annotate(
            user_present_count=Count(
                'user__attendance_records',
                filter=Q(user__attendance_records__status__in=['Present', 'Present & Late', 'Work From Home'])
            ),
            user_absent_count=Count(
                'user__attendance_records',
                filter=Q(user__attendance_records__status='Absent')
            ),
            user_late_count=Count(
                'user__attendance_records',
                filter=Q(user__attendance_records__status__in=['Present & Late', 'Late'])
            )
        )

    def get_summary_stats(self):
        """Get summary statistics for the queryset"""
        return self.aggregate(
            total_records=Count('id'),
            present_count=Count('id', filter=Q(status__in=['Present', 'Present & Late', 'Work From Home'])),
            absent_count=Count('id', filter=Q(status='Absent')),
            late_count=Count('id', filter=Q(status__in=['Present & Late', 'Late'])),
            on_leave_count=Count('id', filter=Q(status='On Leave')),
            holiday_count=Count('id', filter=Q(status='Holiday')),
            weekend_count=Count('id', filter=Q(status='Weekend')),
            not_marked_count=Count('id', filter=Q(status__in=['Not Marked', 'Yet to Clock In'])),
            total_hours=Sum('total_hours', filter=Q(total_hours__isnull=False)),
            avg_hours=Avg('total_hours', filter=Q(total_hours__isnull=False)),
            overtime_hours=Sum('overtime_hours', filter=Q(overtime_hours__gt=0)),
            late_minutes=Sum('late_minutes', filter=Q(late_minutes__gt=0)),
            early_departure_minutes=Sum('early_departure_minutes', filter=Q(early_departure_minutes__gt=0))
        )


class AttendanceManager(models.Manager):
    """
    Optimized manager for Attendance model with business logic and performance improvements
    """

    def get_queryset(self):
        return AttendanceQuerySet(self.model, using=self._db)

    def for_date(self, date=None):
        """Get attendance for specific date (defaults to today)"""
        if not date:
            date = timezone.now().astimezone(IST).date()
        return self.get_queryset().for_date(date)

    def for_user(self, user):
        """Get attendance for specific user"""
        return self.get_queryset().for_user(user)

    def for_users(self, users):
        """Get attendance for multiple users"""
        return self.get_queryset().for_users(users)

    def for_date_range(self, start_date, end_date):
        """Get attendance for date range"""
        return self.get_queryset().for_date_range(start_date, end_date)

    def for_month(self, year=None, month=None):
        """Get attendance for specific month"""
        if not year:
            today = timezone.now().astimezone(IST).date()
            year = today.year
            month = month or today.month
        return self.get_queryset().for_month(year, month)

    def present(self):
        """Get all present records"""
        return self.get_queryset().present()

    def absent(self):
        """Get all absent records"""
        return self.get_queryset().absent()

    def late(self):
        """Get all late records"""
        return self.get_queryset().late()

    def pending_regularization(self):
        """Get all pending regularization records"""
        return self.get_queryset().pending_regularization()

    def with_overtime(self):
        """Get records with overtime"""
        return self.get_queryset().with_overtime()

    def incomplete_attendance(self):
        """Get incomplete attendance records"""
        return self.get_queryset().incomplete_attendance()

    def get_or_create_today_attendance(self, user, date=None):
        """
        Get or create attendance record for specific date with optimized defaults
        """
        if not date:
            date = timezone.now().astimezone(IST).date()

        cache_key = f"attendance_today_{user.id}_{date}"
        cached_result = cache.get(cache_key)

        if cached_result:
            try:
                attendance = self.get(id=cached_result['id'])
                return attendance, False
            except self.model.DoesNotExist:
                cache.delete(cache_key)

        try:
            with transaction.atomic():
                attendance, created = self.get_or_create(
                    user=user,
                    date=date,
                    defaults=self._get_attendance_defaults(user, date)
                )

                if created:
                    logger.info(f"Created new attendance record for {user.username} on {date}")
                    self._initialize_attendance_record(attendance)

                # Cache for 1 hour
                cache.set(cache_key, {'id': attendance.id}, 3600)

                return attendance, created

        except Exception as e:
            logger.error(f"Error creating attendance for {user.username} on {date}: {e}")
            raise

    def _get_attendance_defaults(self, user, date):
        """Get default values for new attendance record"""
        return {
            'status': 'Not Marked',
            'regularization_reason': 'Auto-created attendance record',
            'created_at': timezone.now(),
        }

    def _initialize_attendance_record(self, attendance):
        """Initialize attendance record with shift and other data"""
        try:
            # Set shift if available
            from trueAlign.models import ShiftAssignment
            shift = ShiftAssignment.get_user_current_shift(attendance.user, attendance.date)
            if shift:
                attendance.shift = shift
                attendance.expected_hours = Decimal(str(shift.shift_duration))

            # Initialize status based on leave/holiday/weekend
            attendance._initialize_attendance_defaults()
            attendance.save()

        except Exception as e:
            logger.error(f"Error initializing attendance record: {e}")

    def bulk_create_attendance_records(self, users, date, status='Not Marked', reason=None):
        """
        Efficiently bulk create attendance records for multiple users
        """
        if not isinstance(users, (list, tuple)):
            users = list(users)

        if not reason:
            reason = f'Bulk created with status: {status}'

        # Get existing attendance user IDs to avoid duplicates
        existing_user_ids = set(
            self.filter(date=date, user__in=users).values_list('user_id', flat=True)
        )

        # Prepare records for users without existing attendance
        attendance_records = []
        for user in users:
            if user.id not in existing_user_ids:
                defaults = self._get_attendance_defaults(user, date)
                defaults.update({
                    'status': status,
                    'regularization_reason': reason
                })

                attendance_records.append(
                    self.model(user=user, date=date, **defaults)
                )

        if attendance_records:
            try:
                created_attendances = self.bulk_create(attendance_records, batch_size=100)
                logger.info(f"Bulk created {len(created_attendances)} attendance records for {date}")

                # Clear relevant caches
                cache_keys = [f"attendance_today_{user.id}_{date}" for user in users]
                cache.delete_many(cache_keys)

                return created_attendances
            except Exception as e:
                logger.error(f"Error in bulk create: {e}")
                raise
        else:
            logger.info(f"No new attendance records needed for {date} - all users already have records")
            return []

    def bulk_update_status(self, attendance_ids, status, reason=None, updated_by=None):
        """
        Efficiently bulk update status for multiple attendance records
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

        try:
            updated_count = self.filter(id__in=attendance_ids).update(**update_fields)
            logger.info(f"Bulk updated {updated_count} attendance records to status: {status}")

            # Clear relevant caches
            self._clear_attendance_caches(attendance_ids)

            return updated_count
        except Exception as e:
            logger.error(f"Error in bulk update: {e}")
            raise

    def _clear_attendance_caches(self, attendance_ids):
        """Clear caches for updated attendance records"""
        try:
            attendances = self.filter(id__in=attendance_ids).values('user_id', 'date')
            cache_keys = [f"attendance_today_{att['user_id']}_{att['date']}" for att in attendances]
            cache.delete_many(cache_keys)
        except Exception as e:
            logger.warning(f"Error clearing caches: {e}")

    def get_users_without_attendance(self, date=None):
        """
        Get active users who don't have attendance record for given date
        """
        if not date:
            date = timezone.now().astimezone(IST).date()

        cache_key = f"users_without_attendance_{date}"
        cached_result = cache.get(cache_key)

        if cached_result is not None:
            return User.objects.filter(id__in=cached_result)

        try:
            users_with_attendance = self.filter(date=date).values_list('user_id', flat=True)
            users_without_attendance = User.objects.filter(
                is_active=True
            ).exclude(id__in=users_with_attendance).values_list('id', flat=True)

            # Cache for 30 minutes
            cache.set(cache_key, list(users_without_attendance), 1800)

            return User.objects.filter(id__in=users_without_attendance)
        except Exception as e:
            logger.error(f"Error getting users without attendance: {e}")
            return User.objects.none()

    def get_attendance_summary(self, date=None, department=None, manager=None):
        """
        Get comprehensive attendance summary for a specific date
        """
        if not date:
            date = timezone.now().astimezone(IST).date()

        cache_key = f"attendance_summary_{date}_{department}_{manager.id if manager else 'all'}"
        cached_result = cache.get(cache_key)

        if cached_result:
            return cached_result

        try:
            queryset = self.for_date(date)

            # Apply filters
            if department:
                queryset = queryset.filter(user__profile__department=department)

            if manager:
                team_members = User.objects.filter(profile__manager=manager)
                queryset = queryset.filter(user__in=team_members)

            summary = queryset.get_summary_stats()

            # Calculate additional metrics
            if summary['total_records'] > 0:
                summary['attendance_percentage'] = (
                    (summary['present_count'] / summary['total_records']) * 100
                )
                summary['punctuality_percentage'] = (
                    ((summary['present_count'] - summary['late_count']) / summary['total_records']) * 100
                ) if summary['present_count'] > 0 else 0
            else:
                summary['attendance_percentage'] = 0
                summary['punctuality_percentage'] = 0

            # Cache for 15 minutes
            cache.set(cache_key, summary, 900)

            return summary
        except Exception as e:
            logger.error(f"Error getting attendance summary: {e}")
            return {}

    def get_user_attendance_for_period(self, user, start_date, end_date):
        """
        Get optimized attendance records for a user within a specific period
        """
        cache_key = f"user_attendance_{user.id}_{start_date}_{end_date}"
        cached_result = cache.get(cache_key)

        if cached_result is not None:
            return self.get_queryset().filter(id__in=cached_result).select_optimized().order_by('date')

        try:
            queryset = self.get_queryset().filter(
                user=user,
                date__range=[start_date, end_date]
            ).select_optimized().order_by('date')

            attendance_ids = list(queryset.values_list('id', flat=True))

            # Cache for 1 hour
            cache.set(cache_key, attendance_ids, 3600)

            return queryset
        except Exception as e:
            logger.error(f"Error getting user attendance for period: {e}")
            return self.none()

    def get_team_attendance(self, manager_user, date=None):
        """
        Get optimized attendance for all team members under a manager
        """
        if not date:
            date = timezone.now().astimezone(IST).date()

        cache_key = f"team_attendance_{manager_user.id}_{date}"
        cached_result = cache.get(cache_key)

        if cached_result is not None:
            return self.get_queryset().filter(id__in=cached_result).select_optimized()

        try:
            # Get team members efficiently
            team_members = User.objects.filter(
                profile__manager=manager_user,
                is_active=True
            ).values_list('id', flat=True)

            if not team_members:
                return self.none()

            queryset = self.get_queryset().filter(
                user_id__in=team_members,
                date=date
            ).select_optimized().order_by('user__username')

            attendance_ids = list(queryset.values_list('id', flat=True))

            # Cache for 30 minutes
            cache.set(cache_key, attendance_ids, 1800)

            return queryset

        except Exception as e:
            logger.error(f"Error getting team attendance for {manager_user.username}: {e}")
            return self.none()

    def get_attendance_analytics(self, start_date, end_date, users=None, department=None):
        """
        Get optimized attendance analytics for given period with caching
        """
        cache_key = f"attendance_analytics_{start_date}_{end_date}_{department}_{hash(str(users)) if users else 'all'}"
        cached_result = cache.get(cache_key)

        if cached_result:
            return cached_result

        try:
            queryset = self.for_date_range(start_date, end_date)

            if users:
                queryset = queryset.for_users(users)

            if department:
                queryset = queryset.filter(user__profile__department=department)

            # Get comprehensive analytics
            analytics = {
                'summary': queryset.get_summary_stats(),
                'daily_breakdown': self._get_daily_breakdown(queryset, start_date, end_date),
                'user_breakdown': self._get_user_breakdown(queryset),
                'trend_analysis': self._get_trend_analysis(queryset, start_date, end_date)
            }

            # Cache for 2 hours
            cache.set(cache_key, analytics, 7200)

            return analytics
        except Exception as e:
            logger.error(f"Error getting attendance analytics: {e}")
            return {}

    def _get_daily_breakdown(self, queryset, start_date, end_date):
        """Get daily breakdown of attendance"""
        return queryset.values('date').annotate(
            total=Count('id'),
            present=Count('id', filter=Q(status__in=['Present', 'Present & Late', 'Work From Home'])),
            absent=Count('id', filter=Q(status='Absent')),
            late=Count('id', filter=Q(status__in=['Present & Late', 'Late'])),
            on_leave=Count('id', filter=Q(status='On Leave'))
        ).order_by('date')

    def _get_user_breakdown(self, queryset):
        """Get user-wise breakdown of attendance"""
        return queryset.values('user__username', 'user__first_name', 'user__last_name').annotate(
            total=Count('id'),
            present=Count('id', filter=Q(status__in=['Present', 'Present & Late', 'Work From Home'])),
            absent=Count('id', filter=Q(status='Absent')),
            late=Count('id', filter=Q(status__in=['Present & Late', 'Late'])),
            avg_hours=Avg('total_hours', filter=Q(total_hours__isnull=False))
        ).order_by('user__username')

    def _get_trend_analysis(self, queryset, start_date, end_date):
        """Get trend analysis data"""
        total_days = (end_date - start_date).days + 1
        summary = queryset.get_summary_stats()

        return {
            'period_days': total_days,
            'attendance_rate': (summary['present_count'] / summary['total_records'] * 100) if summary['total_records'] > 0 else 0,
            'punctuality_rate': ((summary['present_count'] - summary['late_count']) / summary['total_records'] * 100) if summary['total_records'] > 0 else 0,
            'avg_working_hours': float(summary['avg_hours'] or 0),
            'total_overtime': float(summary['overtime_hours'] or 0)
        }

    def get_regularization_requests(self, status='Pending', manager=None, department=None):
        """
        Get regularization requests with efficient filtering
        """
        cache_key = f"regularization_requests_{status}_{manager.id if manager else 'all'}_{department}"
        cached_result = cache.get(cache_key)

        if cached_result is not None:
            return self.get_queryset().filter(id__in=cached_result).select_optimized()

        try:
            queryset = self.get_queryset().filter(regularization_status=status).select_optimized()

            if manager and not manager.is_superuser:
                # Filter by team members
                team_members = User.objects.filter(profile__manager=manager)
                queryset = queryset.filter(user__in=team_members)

            if department:
                queryset = queryset.filter(user__profile__department=department)

            queryset = queryset.order_by('-last_regularization_date', '-date')
            request_ids = list(queryset.values_list('id', flat=True))

            # Cache for 10 minutes
            cache.set(cache_key, request_ids, 600)

            return queryset

        except Exception as e:
            logger.error(f"Error getting regularization requests: {e}")
            return self.none()

    def cleanup_old_records(self, days_to_keep=1095):  # 3 years default
        """
        Cleanup old attendance records beyond retention period
        """
        try:
            cutoff_date = timezone.now().date() - timedelta(days=days_to_keep)

            old_records = self.filter(date__lt=cutoff_date)
            count = old_records.count()

            if count > 0:
                logger.info(f"Cleaning up {count} attendance records older than {cutoff_date}")
                old_records.delete()

                # Clear relevant caches (delete_pattern not available in all cache backends)
                try:
                    if hasattr(cache, 'delete_pattern'):
                        cache.delete_pattern("attendance_*")
                    else:
                        # Clear specific known cache keys
                        cache.clear()
                except Exception as e:
                    logger.warning(f"Could not clear cache: {e}")

                return count
            return 0
        except Exception as e:
            logger.error(f"Error cleaning up old attendance records: {e}")
            return 0

    def get_health_check_stats(self):
        """
        Get system health check statistics
        """
        try:
            today = timezone.now().astimezone(IST).date()

            return {
                'total_records_today': self.for_date(today).count(),
                'incomplete_records_today': self.for_date(today).incomplete_attendance().count(),
                'pending_regularizations': self.pending_regularization().count(),
                'recent_errors': 0,  # This would need error logging implementation
                'cache_hit_rate': 'N/A',  # This would need cache monitoring
                'last_auto_marking': 'N/A'  # This would need to track last run
            }
        except Exception as e:
            logger.error(f"Error getting health check stats: {e}")
            return {}
