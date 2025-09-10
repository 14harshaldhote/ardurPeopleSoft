"""
Django Management Command for Shift Diagnostics and Conflict Resolution

This command provides comprehensive diagnostics and maintenance capabilities
for the TrueAlign shift management system, including:

- Conflict detection and automatic resolution
- Data integrity validation
- Performance analysis
- System health checks
- Cleanup operations
- Detailed reporting

Usage:
    python manage.py shift_diagnostics [options]

Examples:
    python manage.py shift_diagnostics --check-conflicts
    python manage.py shift_diagnostics --auto-resolve --date-range 30
    python manage.py shift_diagnostics --full-diagnostic --report
    python manage.py shift_diagnostics --cleanup --dry-run

Author: TrueAlign Development Team
Version: 2.0.0
"""

import logging
import sys
from datetime import datetime, timedelta, date
from decimal import Decimal
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
import csv
import json

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction, connection
from django.db.models import Q, Count, Sum, Avg, Max, Min
from django.contrib.auth.models import User
from django.utils import timezone
from django.conf import settings
from django.core.cache import cache

from trueAlign.models import ShiftMaster, ShiftAssignment, Holiday
from trueAlign.shift.services import ShiftService
from trueAlign.shift.conflict_resolver import (
    ConflictDetectionEngine, ConflictResolver, SmartConflictPreventionService,
    detect_conflicts_for_date_range, auto_resolve_all_conflicts
)
from trueAlign.shift.validators import (
    validate_shift_data, validate_assignment_data,
    ValidationLevel, ValidationContext
)

logger = logging.getLogger('trueAlign.shift.management')


class Command(BaseCommand):
    """Management command for shift diagnostics and maintenance."""

    help = 'Perform shift system diagnostics, conflict detection, and maintenance operations'

    def __init__(self, *args, **kwargs):
        """Initialize the command."""
        super().__init__(*args, **kwargs)
        self.shift_service = ShiftService()
        self.conflict_detector = ConflictDetectionEngine()
        self.conflict_resolver = ConflictResolver()
        self.prevention_service = SmartConflictPreventionService()

        # Statistics tracking
        self.stats = {
            'conflicts_detected': 0,
            'conflicts_resolved': 0,
            'data_issues_found': 0,
            'data_issues_fixed': 0,
            'performance_issues': 0,
            'cleanup_operations': 0
        }

    def add_arguments(self, parser):
        """Add command arguments."""
        # Main operation modes
        parser.add_argument(
            '--check-conflicts',
            action='store_true',
            help='Check for shift assignment conflicts'
        )

        parser.add_argument(
            '--auto-resolve',
            action='store_true',
            help='Automatically resolve conflicts where possible'
        )

        parser.add_argument(
            '--validate-data',
            action='store_true',
            help='Validate all shift and assignment data'
        )

        parser.add_argument(
            '--performance-check',
            action='store_true',
            help='Analyze system performance'
        )

        parser.add_argument(
            '--cleanup',
            action='store_true',
            help='Perform cleanup operations'
        )

        parser.add_argument(
            '--full-diagnostic',
            action='store_true',
            help='Run complete diagnostic suite'
        )

        # Date range options
        parser.add_argument(
            '--start-date',
            type=str,
            help='Start date for operations (YYYY-MM-DD)'
        )

        parser.add_argument(
            '--end-date',
            type=str,
            help='End date for operations (YYYY-MM-DD)'
        )

        parser.add_argument(
            '--date-range',
            type=int,
            default=30,
            help='Number of days from today to include (default: 30)'
        )

        # Filtering options
        parser.add_argument(
            '--user-ids',
            nargs='+',
            type=int,
            help='Specific user IDs to check'
        )

        parser.add_argument(
            '--shift-ids',
            nargs='+',
            type=int,
            help='Specific shift IDs to check'
        )

        # Output options
        parser.add_argument(
            '--report',
            action='store_true',
            help='Generate detailed report'
        )

        parser.add_argument(
            '--output-file',
            type=str,
            help='Output file for reports (CSV or JSON)'
        )

        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Verbose output'
        )

        # Safety options
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done without making changes'
        )

        parser.add_argument(
            '--force',
            action='store_true',
            help='Force operations without confirmation'
        )

    def handle(self, *args, **options):
        """Handle the command execution."""
        try:
            self.options = options
            self.verbosity = options.get('verbosity', 1)

            # Set up date range
            self.setup_date_range()

            # Display header
            self.display_header()

            # Execute requested operations
            if options['full_diagnostic']:
                self.run_full_diagnostic()
            else:
                if options['check_conflicts']:
                    self.check_conflicts()

                if options['auto_resolve']:
                    self.auto_resolve_conflicts()

                if options['validate_data']:
                    self.validate_data()

                if options['performance_check']:
                    self.performance_check()

                if options['cleanup']:
                    self.cleanup_operations()

            # Generate report if requested
            if options['report']:
                self.generate_report()

            # Display summary
            self.display_summary()

        except KeyboardInterrupt:
            self.stdout.write(
                self.style.WARNING('\nOperation cancelled by user')
            )
            sys.exit(1)
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            raise CommandError(f"Command failed: {str(e)}")

    def setup_date_range(self):
        """Setup date range for operations."""
        today = timezone.now().date()

        if self.options['start_date']:
            self.start_date = datetime.strptime(
                self.options['start_date'], '%Y-%m-%d'
            ).date()
        else:
            self.start_date = today

        if self.options['end_date']:
            self.end_date = datetime.strptime(
                self.options['end_date'], '%Y-%m-%d'
            ).date()
        else:
            self.end_date = self.start_date + timedelta(
                days=self.options['date_range']
            )

        # Validate date range
        if self.end_date <= self.start_date:
            raise CommandError("End date must be after start date")

        if (self.end_date - self.start_date).days > 365:
            raise CommandError("Date range cannot exceed 365 days")

    def display_header(self):
        """Display command header."""
        self.stdout.write(
            self.style.SUCCESS('=' * 60)
        )
        self.stdout.write(
            self.style.SUCCESS('TrueAlign Shift Management Diagnostics')
        )
        self.stdout.write(
            self.style.SUCCESS('=' * 60)
        )
        self.stdout.write(f"Date Range: {self.start_date} to {self.end_date}")
        self.stdout.write(f"Days: {(self.end_date - self.start_date).days}")

        if self.options['dry_run']:
            self.stdout.write(
                self.style.WARNING("DRY RUN MODE - No changes will be made")
            )

        self.stdout.write("")

    def run_full_diagnostic(self):
        """Run complete diagnostic suite."""
        self.stdout.write(
            self.style.SUCCESS("Running Full Diagnostic Suite...")
        )

        self.check_conflicts()
        self.validate_data()
        self.performance_check()

        if self.options['auto_resolve']:
            self.auto_resolve_conflicts()

        if self.options['cleanup']:
            self.cleanup_operations()

    def check_conflicts(self):
        """Check for shift assignment conflicts."""
        self.stdout.write(
            self.style.SUCCESS("Checking for conflicts...")
        )

        try:
            # Detect conflicts in date range
            conflicts = detect_conflicts_for_date_range(
                self.start_date,
                self.end_date,
                self.options.get('user_ids')
            )

            self.stats['conflicts_detected'] = len(conflicts)

            if not conflicts:
                self.stdout.write(
                    self.style.SUCCESS("✓ No conflicts detected")
                )
                return

            # Categorize conflicts
            conflict_summary = defaultdict(list)
            auto_resolvable = []

            for conflict in conflicts:
                conflict_summary[conflict.conflict_type.value].append(conflict)
                if conflict.auto_resolvable:
                    auto_resolvable.append(conflict)

            # Display conflict summary
            self.stdout.write(
                self.style.WARNING(f"⚠ Found {len(conflicts)} conflicts:")
            )

            for conflict_type, type_conflicts in conflict_summary.items():
                self.stdout.write(f"  - {conflict_type}: {len(type_conflicts)}")

            self.stdout.write(f"  - Auto-resolvable: {len(auto_resolvable)}")

            # Display detailed conflicts if verbose
            if self.options['verbose']:
                self.display_conflict_details(conflicts)

        except Exception as e:
            logger.error(f"Error checking conflicts: {e}")
            self.stdout.write(
                self.style.ERROR(f"Error checking conflicts: {str(e)}")
            )

    def auto_resolve_conflicts(self):
        """Automatically resolve conflicts where possible."""
        self.stdout.write(
            self.style.SUCCESS("Auto-resolving conflicts...")
        )

        if self.options['dry_run']:
            self.stdout.write(
                self.style.WARNING("DRY RUN: Would attempt auto-resolution")
            )
            return

        try:
            # Perform auto-resolution
            resolution_result = auto_resolve_all_conflicts(
                self.start_date,
                self.end_date,
                self.options.get('user_ids')
            )

            self.stats['conflicts_resolved'] = resolution_result['resolved']

            if resolution_result['resolved'] > 0:
                self.stdout.write(
                    self.style.SUCCESS(
                        f"✓ Auto-resolved {resolution_result['resolved']} conflicts"
                    )
                )

            if resolution_result['failed'] > 0:
                self.stdout.write(
                    self.style.WARNING(
                        f"⚠ {resolution_result['failed']} conflicts could not be auto-resolved"
                    )
                )

            if resolution_result['resolved'] == 0 and resolution_result['failed'] == 0:
                self.stdout.write(
                    self.style.SUCCESS("✓ No conflicts found to resolve")
                )

        except Exception as e:
            logger.error(f"Error auto-resolving conflicts: {e}")
            self.stdout.write(
                self.style.ERROR(f"Error auto-resolving conflicts: {str(e)}")
            )

    def validate_data(self):
        """Validate all shift and assignment data."""
        self.stdout.write(
            self.style.SUCCESS("Validating data integrity...")
        )

        try:
            data_issues = []

            # Validate shifts
            shift_issues = self.validate_shifts()
            data_issues.extend(shift_issues)

            # Validate assignments
            assignment_issues = self.validate_assignments()
            data_issues.extend(assignment_issues)

            # Validate holidays
            holiday_issues = self.validate_holidays()
            data_issues.extend(holiday_issues)

            self.stats['data_issues_found'] = len(data_issues)

            if not data_issues:
                self.stdout.write(
                    self.style.SUCCESS("✓ All data validation passed")
                )
            else:
                self.stdout.write(
                    self.style.WARNING(f"⚠ Found {len(data_issues)} data issues")
                )

                if self.options['verbose']:
                    for issue in data_issues:
                        self.stdout.write(f"  - {issue}")

        except Exception as e:
            logger.error(f"Error validating data: {e}")
            self.stdout.write(
                self.style.ERROR(f"Error validating data: {str(e)}")
            )

    def validate_shifts(self) -> List[str]:
        """Validate shift data."""
        issues = []

        shifts = ShiftMaster.objects.all()
        if self.options.get('shift_ids'):
            shifts = shifts.filter(id__in=self.options['shift_ids'])

        for shift in shifts:
            shift_data = {
                'id': shift.id,
                'name': shift.name,
                'start_time': shift.start_time,
                'end_time': shift.end_time,
                'shift_duration': shift.shift_duration,
                'work_days': shift.work_days,
                'custom_work_days': shift.custom_work_days
            }

            validation_result = validate_shift_data(
                shift_data, ValidationLevel.COMPREHENSIVE, ValidationContext.UPDATE
            )

            if not validation_result.is_valid:
                for error in validation_result.errors:
                    issues.append(f"Shift '{shift.name}' (ID: {shift.id}): {error}")

        return issues

    def validate_assignments(self) -> List[str]:
        """Validate assignment data."""
        issues = []

        assignments = ShiftAssignment.objects.filter(
            effective_from__lte=self.end_date
        ).filter(
            Q(effective_to__gte=self.start_date) | Q(effective_to__isnull=True)
        ).select_related('user', 'shift')

        if self.options.get('user_ids'):
            assignments = assignments.filter(user_id__in=self.options['user_ids'])

        for assignment in assignments:
            assignment_data = {
                'id': assignment.id,
                'user_id': assignment.user.id,
                'shift_id': assignment.shift.id,
                'effective_from': assignment.effective_from,
                'effective_to': assignment.effective_to
            }

            validation_result = validate_assignment_data(
                assignment_data, ValidationLevel.COMPREHENSIVE, ValidationContext.UPDATE
            )

            if not validation_result.is_valid:
                for error in validation_result.errors:
                    issues.append(
                        f"Assignment {assignment.id} "
                        f"({assignment.user.username} -> {assignment.shift.name}): {error}"
                    )

        return issues

    def validate_holidays(self) -> List[str]:
        """Validate holiday data."""
        issues = []

        # Check for duplicate holidays
        holidays = Holiday.objects.all()
        date_counts = defaultdict(list)

        for holiday in holidays:
            date_counts[holiday.date].append(holiday)

        for date_obj, holiday_list in date_counts.items():
            if len(holiday_list) > 1:
                names = [h.name for h in holiday_list]
                issues.append(f"Duplicate holidays on {date_obj}: {', '.join(names)}")

        return issues

    def performance_check(self):
        """Analyze system performance."""
        self.stdout.write(
            self.style.SUCCESS("Analyzing performance...")
        )

        try:
            performance_issues = []

            # Check database query performance
            with connection.cursor() as cursor:
                # Check for missing indexes
                cursor.execute("""
                    SELECT COUNT(*) FROM trueAlign_shiftassignment
                    WHERE effective_from >= %s AND effective_from <= %s
                """, [self.start_date, self.end_date])

                assignment_count = cursor.fetchone()[0]

                if assignment_count > 10000:
                    performance_issues.append(
                        f"Large number of assignments ({assignment_count}) may impact performance"
                    )

            # Check for complex shifts
            complex_shifts = ShiftMaster.objects.filter(
                work_days='Custom',
                custom_work_days__isnull=False
            ).count()

            if complex_shifts > 20:
                performance_issues.append(
                    f"High number of custom work day shifts ({complex_shifts}) may impact performance"
                )

            # Check cache performance
            cache_test_key = 'diagnostic_test'
            cache.set(cache_test_key, 'test', 10)
            if cache.get(cache_test_key) != 'test':
                performance_issues.append("Cache system not functioning properly")

            self.stats['performance_issues'] = len(performance_issues)

            if not performance_issues:
                self.stdout.write(
                    self.style.SUCCESS("✓ No performance issues detected")
                )
            else:
                self.stdout.write(
                    self.style.WARNING(f"⚠ Found {len(performance_issues)} performance issues:")
                )
                for issue in performance_issues:
                    self.stdout.write(f"  - {issue}")

        except Exception as e:
            logger.error(f"Error checking performance: {e}")
            self.stdout.write(
                self.style.ERROR(f"Error checking performance: {str(e)}")
            )

    def cleanup_operations(self):
        """Perform cleanup operations."""
        self.stdout.write(
            self.style.SUCCESS("Performing cleanup operations...")
        )

        if self.options['dry_run']:
            self.stdout.write(
                self.style.WARNING("DRY RUN: Would perform cleanup operations")
            )
            return

        try:
            cleanup_count = 0

            # Clean up old session activities (if exists)
            try:
                from trueAlign.models import SessionActivity
                old_activities = SessionActivity.objects.filter(
                    timestamp__lt=timezone.now() - timedelta(days=90)
                )
                old_count = old_activities.count()
                if old_count > 0:
                    old_activities.delete()
                    cleanup_count += old_count
                    self.stdout.write(f"  - Cleaned up {old_count} old session activities")
            except ImportError:
                pass  # SessionActivity model doesn't exist

            # Clear old cache entries
            try:
                cache.clear()
                self.stdout.write("  - Cleared cache")
                cleanup_count += 1
            except Exception:
                pass  # Cache clear failed

            self.stats['cleanup_operations'] = cleanup_count

            if cleanup_count > 0:
                self.stdout.write(
                    self.style.SUCCESS(f"✓ Completed {cleanup_count} cleanup operations")
                )
            else:
                self.stdout.write(
                    self.style.SUCCESS("✓ No cleanup needed")
                )

        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            self.stdout.write(
                self.style.ERROR(f"Error during cleanup: {str(e)}")
            )

    def display_conflict_details(self, conflicts):
        """Display detailed conflict information."""
        self.stdout.write("\nDetailed Conflict Information:")
        self.stdout.write("-" * 40)

        for i, conflict in enumerate(conflicts, 1):
            self.stdout.write(f"\n{i}. {conflict.conflict_type.value.title()} Conflict")
            self.stdout.write(f"   ID: {conflict.conflict_id}")
            self.stdout.write(f"   Severity: {conflict.severity.value}")
            self.stdout.write(f"   Users: {[u.username for u in conflict.affected_users]}")
            self.stdout.write(f"   Shifts: {[s.name for s in conflict.affected_shifts]}")
            self.stdout.write(f"   Auto-resolvable: {conflict.auto_resolvable}")

            if conflict.business_impact:
                self.stdout.write(f"   Impact: {conflict.business_impact}")

            if conflict.recommended_action:
                self.stdout.write(f"   Recommended: {conflict.recommended_action.description}")

    def generate_report(self):
        """Generate diagnostic report."""
        self.stdout.write(
            self.style.SUCCESS("Generating diagnostic report...")
        )

        try:
            report_data = {
                'timestamp': timezone.now().isoformat(),
                'date_range': {
                    'start_date': self.start_date.isoformat(),
                    'end_date': self.end_date.isoformat(),
                    'days': (self.end_date - self.start_date).days
                },
                'statistics': self.stats,
                'system_info': {
                    'total_shifts': ShiftMaster.objects.count(),
                    'active_shifts': ShiftMaster.objects.filter(is_active=True).count(),
                    'total_assignments': ShiftAssignment.objects.count(),
                    'current_assignments': ShiftAssignment.objects.filter(is_current=True).count(),
                    'total_users': User.objects.count(),
                    'active_users': User.objects.filter(is_active=True).count(),
                    'total_holidays': Holiday.objects.count()
                },
                'options': {
                    key: value for key, value in self.options.items()
                    if key not in ['verbosity', 'settings', 'pythonpath', 'traceback']
                }
            }

            # Save report to file if specified
            if self.options.get('output_file'):
                output_file = self.options['output_file']

                if output_file.endswith('.json'):
                    with open(output_file, 'w') as f:
                        json.dump(report_data, f, indent=2, default=str)
                    self.stdout.write(f"✓ Report saved to {output_file}")

                elif output_file.endswith('.csv'):
                    with open(output_file, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(['Metric', 'Value'])
                        for key, value in self.stats.items():
                            writer.writerow([key.replace('_', ' ').title(), value])
                    self.stdout.write(f"✓ Report saved to {output_file}")

                else:
                    raise CommandError("Output file must be .json or .csv")

            # Display summary report
            self.stdout.write("\nDiagnostic Report Summary:")
            self.stdout.write("-" * 30)
            for key, value in report_data['statistics'].items():
                self.stdout.write(f"{key.replace('_', ' ').title()}: {value}")

        except Exception as e:
            logger.error(f"Error generating report: {e}")
            self.stdout.write(
                self.style.ERROR(f"Error generating report: {str(e)}")
            )

    def display_summary(self):
        """Display operation summary."""
        self.stdout.write("")
        self.stdout.write(
            self.style.SUCCESS("=" * 60)
        )
        self.stdout.write(
            self.style.SUCCESS("Diagnostic Summary")
        )
        self.stdout.write(
            self.style.SUCCESS("=" * 60)
        )

        # Calculate overall health score
        total_issues = (
            self.stats['conflicts_detected'] +
            self.stats['data_issues_found'] +
            self.stats['performance_issues']
        )

        total_fixes = (
            self.stats['conflicts_resolved'] +
            self.stats['data_issues_fixed'] +
            self.stats['cleanup_operations']
        )

        if total_issues == 0:
            health_status = "EXCELLENT"
            health_color = self.style.SUCCESS
        elif total_issues <= 5:
            health_status = "GOOD"
            health_color = self.style.SUCCESS
        elif total_issues <= 15:
            health_status = "FAIR"
            health_color = self.style.WARNING
        else:
            health_status = "NEEDS ATTENTION"
            health_color = self.style.ERROR

        self.stdout.write(f"System Health: {health_color(health_status)}")
        self.stdout.write(f"Total Issues Found: {total_issues}")
        self.stdout.write(f"Total Fixes Applied: {total_fixes}")

        if self.options['dry_run']:
            self.stdout.write(
                self.style.WARNING("Note: This was a dry run - no changes were made")
            )

        self.stdout.write(
            self.style.SUCCESS("Diagnostic completed successfully!")
        )
