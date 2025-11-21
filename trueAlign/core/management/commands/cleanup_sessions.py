"""
Management command to cleanup old session activity data
"""
from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from trueAlign.models import SessionActivity, UserSession


class Command(BaseCommand):
    help = 'Archive or delete old session activity data to prevent database bloat'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=30,
            help='Archive activities older than this many days (default: 30)'
        )
        parser.add_argument(
            '--delete',
            action='store_true',
            help='Delete archived records instead of just marking them'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done without making changes'
        )
    
    def handle(self, *args, **options):
        days = options['days']
        delete_mode = options['delete']
        dry_run = options['dry_run']
        
        cutoff_date = timezone.now() - timedelta(days=days)
        
        self.stdout.write(self.style.SUCCESS(
            f"{'[DRY RUN] ' if dry_run else ''}Session Activity Cleanup"
        ))
        self.stdout.write(f"Cutoff date: {cutoff_date.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Find old activities
        old_activities = SessionActivity.objects.filter(
            created_at__lt=cutoff_date,
            is_archived=False
        )
        
        count = old_activities.count()
        
        if count == 0:
            self.stdout.write(self.style.SUCCESS("No activities to archive"))
            return
        
        self.stdout.write(f"Found {count} activities older than {days} days")
        
        if dry_run:
            self.stdout.write(self.style.WARNING(
                f"[DRY RUN] Would {'delete' if delete_mode else 'archive'} {count} records"
            ))
            
            # Show sample records
            sample = old_activities[:5]
            self.stdout.write("\nSample records:")
            for activity in sample:
                self.stdout.write(
                    f"  - {activity.user.username} | {activity.activity_type} | {activity.created_at}"
                )
            return
        
        # Perform the action
        if delete_mode:
            # Delete archived records permanently
            archived_activities = SessionActivity.objects.filter(is_archived=True)
            archived_count = archived_activities.count()
            
            if archived_count > 0:
                archived_activities.delete()
                self.stdout.write(self.style.SUCCESS(
                    f"Deleted {archived_count} previously archived records"
                ))
            
            # Archive new old records
            old_activities.update(is_archived=True)
            self.stdout.write(self.style.SUCCESS(
                f"Marked {count} records as archived"
            ))
        else:
            # Just mark as archived
            old_activities.update(is_archived=True)
            self.stdout.write(self.style.SUCCESS(
                f"Archived {count} old activity records"
            ))
        
        # Show statistics
        total_activities = SessionActivity.objects.count()
        archived_total = SessionActivity.objects.filter(is_archived=True).count()
        active_total = total_activities - archived_total
        
        self.stdout.write("\nDatabase Statistics:")
        self.stdout.write(f"  Total activities: {total_activities}")
        self.stdout.write(f"  Active: {active_total}")
        self.stdout.write(f"  Archived: {archived_total}")
        self.stdout.write(f"  Archived %: {(archived_total/total_activities*100) if total_activities > 0 else 0:.1f}%")
        
        # Cleanup old sessions
        old_sessions = UserSession.objects.filter(
            is_active=False,
            ended_at__lt=cutoff_date
        )
        old_session_count = old_sessions.count()
        
        if old_session_count > 0:
            self.stdout.write(f"\nFound {old_session_count} old inactive sessions")
            if not dry_run:
                # Don't delete sessions, just log them
                self.stdout.write(self.style.WARNING(
                    "Note: Old sessions are kept for historical data"
                ))
