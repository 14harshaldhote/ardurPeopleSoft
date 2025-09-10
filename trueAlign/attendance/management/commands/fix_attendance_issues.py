# Create: ardurPeopleSoft/trueAlign/attendance/management/commands/fix_attendance_issues.py

from django.core.management.base import BaseCommand
from django.db import transaction
from trueAlign.models import Attendance
from decimal import Decimal
from datetime import date, timedelta

class Command(BaseCommand):
    help = 'Fix attendance status calculation issues'

    def add_arguments(self, parser):
        parser.add_argument('--days-back', type=int, default=7, help='Days back to fix')
        parser.add_argument('--dry-run', action='store_true', help='Show what would be fixed')

    def handle(self, *args, **options):
        days_back = options['days_back']
        dry_run = options['dry_run']

        # Get problematic records
        end_date = date.today()
        start_date = end_date - timedelta(days=days_back)

        problematic = Attendance.objects.filter(
            date__range=[start_date, end_date],
            clock_in_time__isnull=False,
            status__in=['Not Marked', 'Yet to Clock In']
        )

        self.stdout.write(f'Found {problematic.count()} problematic records')

        if dry_run:
            for att in problematic:
                new_status = self._calculate_correct_status(att)
                self.stdout.write(f'{att.user.username} {att.date}: {att.status} -> {new_status}')
            return

        # Fix records
        fixed_count = 0
        with transaction.atomic():
            for attendance in problematic:
                old_status = attendance.status
                new_status = self._calculate_correct_status(attendance)

                if old_status != new_status:
                    attendance.status = new_status
                    attendance.save(update_fields=['status'])
                    fixed_count += 1

                    self.stdout.write(
                        f'Fixed {attendance.user.username} {attendance.date}: {old_status} -> {new_status}'
                    )

        self.stdout.write(self.style.SUCCESS(f'Fixed {fixed_count} attendance records'))

    def _calculate_correct_status(self, attendance):
        """Calculate correct status for attendance"""
        if not attendance.clock_in_time:
            return attendance.status

        # Has clock time but wrong status
        if attendance.total_hours and attendance.total_hours >= Decimal('0.5'):
            if attendance.late_minutes > 0:
                return 'Present & Late'
            else:
                return 'Present'
        else:
            return 'Present'  # Any clock in counts as present
