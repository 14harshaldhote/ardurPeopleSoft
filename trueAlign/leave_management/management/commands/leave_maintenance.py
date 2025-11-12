"""
Management command for leave system maintenance and optimization
"""
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db import transaction, models
from django.core.cache import cache
from django.contrib.auth.models import User
from datetime import datetime, timedelta
import logging

from trueAlign.models import (
    LeaveRequest, UserLeaveBalance, LeaveType, 
    LeavePolicy, LeaveAllocation, CompOffRequest
)
from trueAlign.leave_management.analytics import LeaveAnalytics
from trueAlign.leave_management.notifications import LeaveNotificationService

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Perform leave management system maintenance tasks'

    def add_arguments(self, parser):
        parser.add_argument(
            '--task',
            type=str,
            choices=[
                'cleanup', 'balance_check', 'send_reminders', 
                'generate_analytics', 'cache_warmup', 'data_integrity',
                'all'
            ],
            default='all',
            help='Specific maintenance task to run'
        )
        
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done without making changes'
        )
        
        parser.add_argument(
            '--year',
            type=int,
            default=timezone.now().year,
            help='Year for year-specific operations'
        )

    def handle(self, *args, **options):
        task = options['task']
        dry_run = options['dry_run']
        year = options['year']
        
        if dry_run:
            self.stdout.write(
                self.style.WARNING('DRY RUN MODE - No changes will be made')
            )
        
        if task == 'all':
            self.run_all_tasks(dry_run, year)
        elif task == 'cleanup':
            self.cleanup_old_data(dry_run)
        elif task == 'balance_check':
            self.check_balance_integrity(dry_run, year)
        elif task == 'send_reminders':
            self.send_reminder_notifications(dry_run)
        elif task == 'generate_analytics':
            self.generate_analytics_report(year)
        elif task == 'cache_warmup':
            self.warmup_cache()
        elif task == 'data_integrity':
            self.check_data_integrity(dry_run)

    def run_all_tasks(self, dry_run, year):
        """Run all maintenance tasks"""
        self.stdout.write("Running all maintenance tasks...")
        
        self.cleanup_old_data(dry_run)
        self.check_balance_integrity(dry_run, year)
        self.send_reminder_notifications(dry_run)
        self.generate_analytics_report(year)
        self.warmup_cache()
        self.check_data_integrity(dry_run)
        
        self.stdout.write(
            self.style.SUCCESS('All maintenance tasks completed')
        )

    def cleanup_old_data(self, dry_run):
        """Clean up old and unnecessary data"""
        self.stdout.write("Cleaning up old data...")
        
        # Remove old rejected/cancelled requests (older than 2 years)
        cutoff_date = timezone.now() - timedelta(days=730)
        
        old_requests = LeaveRequest.objects.filter(
            status__in=['Rejected', 'Cancelled'],
            created_at__lt=cutoff_date
        )
        
        count = old_requests.count()
        if count > 0:
            if not dry_run:
                old_requests.delete()
            self.stdout.write(f"  - Cleaned up {count} old leave requests")
        
        # Remove orphaned balance records
        orphaned_balances = UserLeaveBalance.objects.filter(
            user__is_active=False,
            year__lt=timezone.now().year - 2
        )
        
        count = orphaned_balances.count()
        if count > 0:
            if not dry_run:
                orphaned_balances.delete()
            self.stdout.write(f"  - Cleaned up {count} orphaned balance records")

    def check_balance_integrity(self, dry_run, year):
        """Check and fix balance integrity issues"""
        self.stdout.write(f"Checking balance integrity for {year}...")
        
        issues_found = 0
        
        # Check for negative balances
        negative_balances = UserLeaveBalance.objects.filter(
            year=year,
            used__gt=models.F('allocated') + models.F('carried_forward') + models.F('additional')
        )
        
        for balance in negative_balances:
            issues_found += 1
            self.stdout.write(
                self.style.ERROR(
                    f"  - Negative balance: {balance.user.username} "
                    f"{balance.leave_type.name} (Available: {balance.available})"
                )
            )
            
            if not dry_run:
                # Fix by adjusting used days to match available
                max_used = balance.allocated + balance.carried_forward + balance.additional
                balance.used = max_used
                balance.save()
                self.stdout.write(f"    Fixed: Set used days to {max_used}")
        
        # Check for missing balance records
        active_users = User.objects.filter(is_active=True)
        active_policies = LeavePolicy.objects.filter(is_active=True)
        
        for user in active_users:
            user_groups = user.groups.all()
            if not user_groups:
                continue
                
            policy = LeavePolicy.objects.filter(
                group__in=user_groups,
                is_active=True
            ).first()
            
            if not policy:
                continue
            
            allocations = LeaveAllocation.objects.filter(policy=policy)
            
            for allocation in allocations:
                try:
                    UserLeaveBalance.objects.get(
                        user=user,
                        leave_type=allocation.leave_type,
                        year=year
                    )
                except UserLeaveBalance.DoesNotExist:
                    issues_found += 1
                    self.stdout.write(
                        self.style.WARNING(
                            f"  - Missing balance: {user.username} "
                            f"{allocation.leave_type.name} for {year}"
                        )
                    )
                    
                    if not dry_run:
                        UserLeaveBalance.objects.create(
                            user=user,
                            leave_type=allocation.leave_type,
                            year=year,
                            allocated=allocation.annual_days,
                            used=0,
                            carried_forward=0,
                            additional=0,
                            is_deleted=False
                        )
                        self.stdout.write(f"    Fixed: Created balance record")
        
        if issues_found == 0:
            self.stdout.write(
                self.style.SUCCESS("  - No balance integrity issues found")
            )
        else:
            self.stdout.write(f"  - Found and fixed {issues_found} issues")

    def send_reminder_notifications(self, dry_run):
        """Send reminder notifications for pending approvals"""
        self.stdout.write("Sending reminder notifications...")
        
        if not dry_run:
            try:
                LeaveNotificationService.send_leave_reminder_notifications()
                self.stdout.write(
                    self.style.SUCCESS("  - Reminder notifications sent")
                )
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"  - Error sending notifications: {str(e)}")
                )
        else:
            # Count pending requests that would get reminders
            cutoff_date = timezone.now() - timedelta(days=2)
            pending_count = LeaveRequest.objects.filter(
                status='Pending',
                created_at__lte=cutoff_date
            ).count()
            
            self.stdout.write(f"  - Would send {pending_count} reminder notifications")

    def generate_analytics_report(self, year):
        """Generate and display analytics report"""
        self.stdout.write(f"Generating analytics report for {year}...")
        
        try:
            stats = LeaveAnalytics.get_leave_usage_stats(year)
            
            self.stdout.write(f"  - Total requests: {stats['total_requests']}")
            self.stdout.write(f"  - Approved requests: {stats['approved_requests']}")
            self.stdout.write(f"  - Pending requests: {stats['pending_requests']}")
            self.stdout.write(f"  - Total leave days: {stats['total_leave_days']}")
            self.stdout.write(f"  - Average leave days: {stats['average_leave_days']:.2f}")
            
            # Show top leave types
            self.stdout.write("  - Top leave types:")
            for lt in stats['leave_type_breakdown'][:3]:
                self.stdout.write(f"    * {lt['leave_type__name']}: {lt['total_days']} days")
            
            # Check for unusual patterns
            alerts = LeaveAnalytics.detect_unusual_patterns()
            if alerts:
                self.stdout.write(
                    self.style.WARNING(f"  - Found {len(alerts)} unusual patterns")
                )
                for alert in alerts[:5]:  # Show first 5
                    self.stdout.write(f"    * {alert['type']}: {alert['user']} - {alert['details']}")
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f"  - Error generating analytics: {str(e)}")
            )

    def warmup_cache(self):
        """Warm up frequently accessed cache entries"""
        self.stdout.write("Warming up cache...")
        
        try:
            # Cache active leave types
            leave_types = list(LeaveType.objects.filter(is_active=True))
            cache.set('active_leave_types', leave_types, 3600)
            
            # Cache active policies
            policies = list(LeavePolicy.objects.filter(is_active=True))
            cache.set('active_leave_policies', policies, 3600)
            
            # Cache user policies for active users
            active_users = User.objects.filter(is_active=True)[:100]  # Limit to first 100
            for user in active_users:
                user_groups = user.groups.all()
                if user_groups:
                    policy = LeavePolicy.objects.filter(
                        group__in=user_groups,
                        is_active=True
                    ).first()
                    if policy:
                        cache.set(f'leave_policy_{user.id}', policy, 3600)
            
            self.stdout.write(
                self.style.SUCCESS("  - Cache warmed up successfully")
            )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f"  - Error warming up cache: {str(e)}")
            )

    def check_data_integrity(self, dry_run):
        """Check overall data integrity"""
        self.stdout.write("Checking data integrity...")
        
        issues = []
        
        # Check for leave requests without users
        orphaned_requests = LeaveRequest.objects.filter(user__isnull=True)
        if orphaned_requests.exists():
            count = orphaned_requests.count()
            issues.append(f"Found {count} leave requests without users")
            if not dry_run:
                orphaned_requests.delete()
        
        # Check for leave requests with invalid dates
        invalid_date_requests = LeaveRequest.objects.filter(
            start_date__gt=models.F('end_date')
        )
        if invalid_date_requests.exists():
            count = invalid_date_requests.count()
            issues.append(f"Found {count} leave requests with invalid date ranges")
        
        # Check for comp-off requests without users
        orphaned_comp_offs = CompOffRequest.objects.filter(user__isnull=True)
        if orphaned_comp_offs.exists():
            count = orphaned_comp_offs.count()
            issues.append(f"Found {count} comp-off requests without users")
            if not dry_run:
                orphaned_comp_offs.delete()
        
        if issues:
            for issue in issues:
                self.stdout.write(self.style.WARNING(f"  - {issue}"))
        else:
            self.stdout.write(
                self.style.SUCCESS("  - No data integrity issues found")
            )
