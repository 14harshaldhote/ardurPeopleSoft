"""
Cleanup Logs Management Command
Clean up old audit logs, system logs, and temporary files
"""

import logging
import os
import gzip
import shutil
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.conf import settings
from django.db import transaction
from trueAlign.support.logging_system import AuditLog
from trueAlign.models import Support, TicketActivity, TicketComment


class Command(BaseCommand):
    help = 'Clean up old logs and temporary files'

    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=90,
            help='Number of days to keep logs (default: 90)'
        )
        parser.add_argument(
            '--compress',
            action='store_true',
            help='Compress old logs before deletion'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Enable verbose output'
        )
        parser.add_argument(
            '--cleanup-files',
            action='store_true',
            help='Clean up temporary files and uploads'
        )
        parser.add_argument(
            '--optimize-db',
            action='store_true',
            help='Optimize database after cleanup'
        )

    def handle(self, *args, **options):
        self.logger = logging.getLogger(__name__)
        self.verbose = options['verbose']
        self.dry_run = options['dry_run']
        self.days = options['days']
        self.compress = options['compress']

        self.stdout.write(
            self.style.SUCCESS(
                f"Starting log cleanup (keeping {self.days} days) at {timezone.now()}"
            )
        )

        if self.dry_run:
            self.stdout.write(
                self.style.WARNING("DRY RUN MODE - No actual deletions will occur")
            )

        try:
            # Calculate cutoff date
            cutoff_date = timezone.now() - timedelta(days=self.days)

            # Track cleanup statistics
            stats = {
                'audit_logs_deleted': 0,
                'activity_logs_deleted': 0,
                'files_deleted': 0,
                'space_freed': 0,
                'errors': 0
            }

            # Clean up audit logs
            self._cleanup_audit_logs(cutoff_date, stats)

            # Clean up ticket activities
            self._cleanup_ticket_activities(cutoff_date, stats)

            # Clean up old comments if requested
            self._cleanup_old_comments(cutoff_date, stats)

            # Clean up temporary files
            if options['cleanup_files']:
                self._cleanup_temporary_files(stats)

            # Optimize database
            if options['optimize_db'] and not self.dry_run:
                self._optimize_database()

            # Display summary
            self._display_summary(stats)

            self.stdout.write(
                self.style.SUCCESS(
                    "Log cleanup completed successfully"
                )
            )

        except Exception as e:
            self.logger.error(f"Log cleanup failed: {str(e)}")
            self.stdout.write(
                self.style.ERROR(
                    f"Log cleanup failed: {str(e)}"
                )
            )

    def _cleanup_audit_logs(self, cutoff_date, stats):
        """Clean up old audit logs"""
        self.stdout.write("Cleaning up audit logs...")

        try:
            # Get old audit logs
            old_logs = AuditLog.objects.filter(timestamp__lt=cutoff_date)
            count = old_logs.count()

            if count > 0:
                if self.verbose:
                    self.stdout.write(f"  Found {count} old audit logs")

                # Compress logs before deletion if requested
                if self.compress and not self.dry_run:
                    self._compress_audit_logs(old_logs)

                # Delete old logs
                if not self.dry_run:
                    with transaction.atomic():
                        deleted_count = old_logs.delete()[0]
                        stats['audit_logs_deleted'] = deleted_count

                        self.stdout.write(f"  Deleted {deleted_count} audit logs")
                else:
                    stats['audit_logs_deleted'] = count
                    self.stdout.write(f"  Would delete {count} audit logs")

            else:
                self.stdout.write("  No old audit logs to clean up")

        except Exception as e:
            self.logger.error(f"Failed to cleanup audit logs: {str(e)}")
            stats['errors'] += 1
            self.stdout.write(
                self.style.ERROR(f"  Error cleaning audit logs: {str(e)}")
            )

    def _cleanup_ticket_activities(self, cutoff_date, stats):
        """Clean up old ticket activities"""
        self.stdout.write("Cleaning up ticket activities...")

        try:
            # Only clean up activities for resolved/closed tickets older than cutoff
            old_activities = TicketActivity.objects.filter(
                timestamp__lt=cutoff_date,
                ticket__status__in=['Resolved', 'Closed'],
                ticket__resolved_at__lt=cutoff_date
            )

            count = old_activities.count()

            if count > 0:
                if self.verbose:
                    self.stdout.write(f"  Found {count} old ticket activities")

                if not self.dry_run:
                    with transaction.atomic():
                        deleted_count = old_activities.delete()[0]
                        stats['activity_logs_deleted'] = deleted_count

                        self.stdout.write(f"  Deleted {deleted_count} ticket activities")
                else:
                    stats['activity_logs_deleted'] = count
                    self.stdout.write(f"  Would delete {count} ticket activities")

            else:
                self.stdout.write("  No old ticket activities to clean up")

        except Exception as e:
            self.logger.error(f"Failed to cleanup ticket activities: {str(e)}")
            stats['errors'] += 1
            self.stdout.write(
                self.style.ERROR(f"  Error cleaning ticket activities: {str(e)}")
            )

    def _cleanup_old_comments(self, cutoff_date, stats):
        """Clean up old comments from resolved tickets"""
        self.stdout.write("Cleaning up old comments...")

        try:
            # Clean up internal comments from very old resolved tickets
            very_old_date = timezone.now() - timedelta(days=self.days * 2)

            old_comments = TicketComment.objects.filter(
                created_at__lt=very_old_date,
                ticket__status__in=['Resolved', 'Closed'],
                ticket__resolved_at__lt=very_old_date,
                is_internal=True
            )

            count = old_comments.count()

            if count > 0:
                if self.verbose:
                    self.stdout.write(f"  Found {count} old internal comments")

                if not self.dry_run:
                    with transaction.atomic():
                        deleted_count = old_comments.delete()[0]
                        self.stdout.write(f"  Deleted {deleted_count} old internal comments")
                else:
                    self.stdout.write(f"  Would delete {count} old internal comments")

            else:
                self.stdout.write("  No old comments to clean up")

        except Exception as e:
            self.logger.error(f"Failed to cleanup old comments: {str(e)}")
            stats['errors'] += 1
            self.stdout.write(
                self.style.ERROR(f"  Error cleaning old comments: {str(e)}")
            )

    def _cleanup_temporary_files(self, stats):
        """Clean up temporary files and orphaned uploads"""
        self.stdout.write("Cleaning up temporary files...")

        try:
            # Clean up temporary upload files
            temp_dirs = [
                os.path.join(settings.MEDIA_ROOT, 'temp'),
                os.path.join(settings.MEDIA_ROOT, 'uploads', 'temp'),
                '/tmp/django_uploads'
            ]

            for temp_dir in temp_dirs:
                if os.path.exists(temp_dir):
                    self._cleanup_directory(temp_dir, stats)

            # Clean up old log files
            if hasattr(settings, 'LOGGING'):
                log_dir = getattr(settings, 'LOG_DIR', os.path.join(settings.BASE_DIR, 'logs'))
                if os.path.exists(log_dir):
                    self._cleanup_log_files(log_dir, stats)

        except Exception as e:
            self.logger.error(f"Failed to cleanup temporary files: {str(e)}")
            stats['errors'] += 1
            self.stdout.write(
                self.style.ERROR(f"  Error cleaning temporary files: {str(e)}")
            )

    def _cleanup_directory(self, directory, stats):
        """Clean up files in a directory"""
        try:
            cutoff_time = timezone.now() - timedelta(days=1)  # Files older than 1 day

            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        # Check file age
                        file_time = timezone.make_aware(
                            datetime.fromtimestamp(os.path.getmtime(file_path))
                        )

                        if file_time < cutoff_time:
                            file_size = os.path.getsize(file_path)

                            if not self.dry_run:
                                os.remove(file_path)
                                stats['files_deleted'] += 1
                                stats['space_freed'] += file_size

                                if self.verbose:
                                    self.stdout.write(f"  Deleted: {file_path}")
                            else:
                                stats['files_deleted'] += 1
                                stats['space_freed'] += file_size

                                if self.verbose:
                                    self.stdout.write(f"  Would delete: {file_path}")

                    except OSError as e:
                        if self.verbose:
                            self.stdout.write(f"  Error with file {file_path}: {str(e)}")
                        stats['errors'] += 1

        except Exception as e:
            self.logger.error(f"Failed to cleanup directory {directory}: {str(e)}")
            stats['errors'] += 1

    def _cleanup_log_files(self, log_dir, stats):
        """Clean up old log files"""
        try:
            cutoff_time = timezone.now() - timedelta(days=self.days)

            for file in os.listdir(log_dir):
                if file.endswith('.log') or file.endswith('.log.gz'):
                    file_path = os.path.join(log_dir, file)

                    try:
                        file_time = timezone.make_aware(
                            datetime.fromtimestamp(os.path.getmtime(file_path))
                        )

                        if file_time < cutoff_time:
                            file_size = os.path.getsize(file_path)

                            # Compress before deletion if requested
                            if self.compress and file.endswith('.log'):
                                self._compress_file(file_path)
                                continue

                            if not self.dry_run:
                                os.remove(file_path)
                                stats['files_deleted'] += 1
                                stats['space_freed'] += file_size

                                if self.verbose:
                                    self.stdout.write(f"  Deleted log file: {file}")
                            else:
                                stats['files_deleted'] += 1
                                stats['space_freed'] += file_size

                    except OSError as e:
                        if self.verbose:
                            self.stdout.write(f"  Error with log file {file}: {str(e)}")
                        stats['errors'] += 1

        except Exception as e:
            self.logger.error(f"Failed to cleanup log files: {str(e)}")
            stats['errors'] += 1

    def _compress_audit_logs(self, logs):
        """Compress audit logs before deletion"""
        self.stdout.write("  Compressing audit logs...")

        try:
            # Create compressed backup
            backup_dir = os.path.join(settings.BASE_DIR, 'logs', 'archive')
            os.makedirs(backup_dir, exist_ok=True)

            timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
            backup_file = os.path.join(backup_dir, f'audit_logs_{timestamp}.json.gz')

            # Export logs to compressed JSON
            import json
            log_data = []

            for log in logs:
                log_data.append({
                    'id': str(log.id),
                    'action': log.action,
                    'user': log.user.username if log.user else None,
                    'ticket_id': log.ticket_id,
                    'timestamp': log.timestamp.isoformat(),
                    'log_data': log.log_data
                })

            with gzip.open(backup_file, 'wt') as f:
                json.dump(log_data, f, indent=2)

            self.stdout.write(f"  Compressed {len(log_data)} logs to {backup_file}")

        except Exception as e:
            self.logger.error(f"Failed to compress audit logs: {str(e)}")
            self.stdout.write(
                self.style.ERROR(f"  Error compressing logs: {str(e)}")
            )

    def _compress_file(self, file_path):
        """Compress a single file"""
        try:
            compressed_path = file_path + '.gz'

            with open(file_path, 'rb') as f_in:
                with gzip.open(compressed_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)

            # Remove original file
            os.remove(file_path)

            if self.verbose:
                self.stdout.write(f"  Compressed: {file_path}")

        except Exception as e:
            self.logger.error(f"Failed to compress file {file_path}: {str(e)}")

    def _optimize_database(self):
        """Optimize database after cleanup"""
        self.stdout.write("Optimizing database...")

        try:
            from django.db import connection

            with connection.cursor() as cursor:
                # For PostgreSQL
                if connection.vendor == 'postgresql':
                    cursor.execute("VACUUM ANALYZE;")
                    self.stdout.write("  PostgreSQL database optimized")

                # For MySQL
                elif connection.vendor == 'mysql':
                    cursor.execute("OPTIMIZE TABLE trueAlign_support;")
                    cursor.execute("OPTIMIZE TABLE support_audit_log;")
                    self.stdout.write("  MySQL database optimized")

                # For SQLite
                elif connection.vendor == 'sqlite':
                    cursor.execute("VACUUM;")
                    self.stdout.write("  SQLite database optimized")

                else:
                    self.stdout.write("  Database optimization not supported for this backend")

        except Exception as e:
            self.logger.error(f"Failed to optimize database: {str(e)}")
            self.stdout.write(
                self.style.ERROR(f"  Error optimizing database: {str(e)}")
            )

    def _display_summary(self, stats):
        """Display cleanup summary"""
        self.stdout.write(
            self.style.WARNING(
                "\nCleanup Summary:"
            )
        )

        self.stdout.write(f"  Audit logs deleted: {stats['audit_logs_deleted']}")
        self.stdout.write(f"  Activity logs deleted: {stats['activity_logs_deleted']}")
        self.stdout.write(f"  Files deleted: {stats['files_deleted']}")

        # Format space freed
        space_freed = stats['space_freed']
        if space_freed > 1024 * 1024 * 1024:  # GB
            space_str = f"{space_freed / (1024 * 1024 * 1024):.2f} GB"
        elif space_freed > 1024 * 1024:  # MB
            space_str = f"{space_freed / (1024 * 1024):.2f} MB"
        elif space_freed > 1024:  # KB
            space_str = f"{space_freed / 1024:.2f} KB"
        else:
            space_str = f"{space_freed} bytes"

        self.stdout.write(f"  Space freed: {space_str}")

        if stats['errors'] > 0:
            self.stdout.write(
                self.style.ERROR(f"  Errors encountered: {stats['errors']}")
            )

        # Recommendations
        self.stdout.write(
            self.style.WARNING(
                "\nRecommendations:"
            )
        )

        if stats['audit_logs_deleted'] > 10000:
            self.stdout.write("  Consider running cleanup more frequently")

        if stats['space_freed'] > 100 * 1024 * 1024:  # 100 MB
            self.stdout.write("  Consider implementing automated log rotation")

        if not self.compress and stats['audit_logs_deleted'] > 1000:
            self.stdout.write("  Consider using --compress flag to archive logs")
