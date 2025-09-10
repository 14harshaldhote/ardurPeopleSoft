"""
Django management command for setting up and managing attendance logging system.

This command provides functionality to:
- Initialize attendance logging directories and configuration
- Validate logging setup
- Clean up old log files
- Display logging status and statistics
- Test logging functionality
"""

from django.core.management.base import BaseCommand, CommandError
from django.core.management.color import color_style
from django.conf import settings
import os
import logging
from datetime import datetime, timedelta
from pathlib import Path
import json

# Import attendance logging modules
try:
    from trueAlign.attendance.logging.config import (
        attendance_logging_config,
        initialize_attendance_logging,
        get_attendance_logging_status,
        LOG_FILE_CONFIGS,
        PERFORMANCE_THRESHOLDS
    )
    from trueAlign.attendance.logging import (
        get_attendance_logger,
        log_attendance_action,
        log_attendance_error,
        log_performance_metric
    )
except ImportError as e:
    attendance_logging_config = None
    print(f"Warning: Could not import attendance logging modules: {e}")

style = color_style()


class Command(BaseCommand):
    help = 'Setup and manage attendance logging system'

    def add_arguments(self, parser):
        parser.add_argument(
            '--action',
            type=str,
            choices=['init', 'status', 'cleanup', 'test', 'validate', 'rotate'],
            default='init',
            help='Action to perform (default: init)'
        )

        parser.add_argument(
            '--max-age',
            type=int,
            default=90,
            help='Maximum age in days for log cleanup (default: 90)'
        )

        parser.add_argument(
            '--force',
            action='store_true',
            help='Force action even if warnings are present'
        )

        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Enable verbose output'
        )

        parser.add_argument(
            '--format',
            type=str,
            choices=['json', 'text'],
            default='text',
            help='Output format for status (default: text)'
        )

    def handle(self, *args, **options):
        self.verbosity = options['verbosity']
        self.verbose = options['verbose']
        self.force = options['force']

        if attendance_logging_config is None:
            raise CommandError("Attendance logging modules could not be imported")

        action = options['action']

        try:
            if action == 'init':
                self.initialize_logging()
            elif action == 'status':
                self.show_status(options['format'])
            elif action == 'cleanup':
                self.cleanup_logs(options['max_age'])
            elif action == 'test':
                self.test_logging()
            elif action == 'validate':
                self.validate_configuration()
            elif action == 'rotate':
                self.rotate_logs()
            else:
                raise CommandError(f"Unknown action: {action}")

        except Exception as e:
            self.stdout.write(style.ERROR(f"Command failed: {e}"))
            if self.verbose:
                import traceback
                self.stdout.write(traceback.format_exc())
            raise CommandError(str(e))

    def initialize_logging(self):
        """Initialize the attendance logging system."""
        self.stdout.write(style.HTTP_INFO("=== Initializing Attendance Logging System ==="))

        # Check if Django logging is properly configured
        if not self._check_django_logging_config():
            if not self.force:
                raise CommandError(
                    "Django logging configuration issues detected. "
                    "Use --force to proceed anyway."
                )

        # Initialize the system
        if initialize_attendance_logging():
            self.stdout.write(style.SUCCESS("✓ Attendance logging system initialized successfully"))

            # Show initial status
            self.stdout.write(style.HTTP_INFO("\nInitial Status:"))
            self.show_status('text')

            # Create initial test logs
            self._create_initial_test_logs()

        else:
            raise CommandError("Failed to initialize attendance logging system")

    def show_status(self, output_format='text'):
        """Display the current status of the attendance logging system."""
        status = get_attendance_logging_status()

        if output_format == 'json':
            self.stdout.write(json.dumps(status, indent=2, default=str))
            return

        # Text format output
        self.stdout.write(style.HTTP_INFO("=== Attendance Logging System Status ==="))

        # Directory information
        self.stdout.write(f"\nLogs Directory: {status['logs_directory']}")
        self.stdout.write(f"Directory Exists: {self._format_bool(status['directory_exists'])}")

        # Validation results
        validation = status['validation']
        self.stdout.write(f"\nConfiguration Valid: {self._format_bool(validation['valid'])}")

        if validation['errors']:
            self.stdout.write(style.ERROR("\nErrors:"))
            for error in validation['errors']:
                self.stdout.write(style.ERROR(f"  ✗ {error}"))

        if validation['warnings']:
            self.stdout.write(style.WARNING("\nWarnings:"))
            for warning in validation['warnings']:
                self.stdout.write(style.WARNING(f"  ⚠ {warning}"))

        # Log file statistics
        self.stdout.write(style.HTTP_INFO("\nLog File Statistics:"))
        stats = status['log_statistics']

        total_size = 0
        for log_type, file_stats in stats.items():
            size_mb = file_stats['size_mb']
            total_size += size_mb
            exists_marker = "✓" if file_stats['exists'] else "✗"

            self.stdout.write(f"  {exists_marker} {log_type}: {size_mb:.2f} MB")

            if self.verbose and file_stats['modified']:
                modified_date = datetime.fromtimestamp(file_stats['modified'])
                self.stdout.write(f"      Last modified: {modified_date}")

        self.stdout.write(f"\nTotal log size: {total_size:.2f} MB")

        # Configuration summary
        if self.verbose:
            config = status['configuration']
            self.stdout.write(style.HTTP_INFO("\nConfiguration:"))
            self.stdout.write(f"  Log retention: {config['retention_days']} days")
            self.stdout.write(f"  Number of log files: {len(config['log_files'])}")
            self.stdout.write(f"  Performance threshold: {config['performance_thresholds']['slow_operation_seconds']}s")

    def cleanup_logs(self, max_age_days):
        """Clean up old log files."""
        self.stdout.write(style.HTTP_INFO(f"=== Cleaning up logs older than {max_age_days} days ==="))

        if not self.force:
            confirm = input("This will permanently delete old log files. Continue? [y/N]: ")
            if confirm.lower() != 'y':
                self.stdout.write(style.WARNING("Cleanup cancelled"))
                return

        results = attendance_logging_config.cleanup_old_logs(max_age_days)

        self.stdout.write(f"Files cleaned: {results['cleaned_files']}")
        self.stdout.write(f"Space freed: {results['freed_space_mb']:.2f} MB")

        if results['errors']:
            self.stdout.write(style.ERROR("\nErrors during cleanup:"))
            for error in results['errors']:
                self.stdout.write(style.ERROR(f"  ✗ {error}"))
        else:
            self.stdout.write(style.SUCCESS("✓ Cleanup completed successfully"))

    def test_logging(self):
        """Test the logging functionality."""
        self.stdout.write(style.HTTP_INFO("=== Testing Attendance Logging ==="))

        # Test different loggers
        test_cases = [
            ('main', 'info', 'Test log message from management command'),
            ('views', 'debug', 'Test debug message'),
            ('api_views', 'info', 'Test API logging'),
            ('services', 'warning', 'Test warning message'),
            ('security', 'warning', 'Test security event'),
            ('performance', 'info', 'Test performance logging')
        ]

        successful_tests = 0

        for component, level, message in test_cases:
            try:
                logger = get_attendance_logger(component)
                log_method = getattr(logger, level)
                log_method(f"[TEST] {message}")

                self.stdout.write(style.SUCCESS(f"✓ {component} logger ({level})"))
                successful_tests += 1

            except Exception as e:
                self.stdout.write(style.ERROR(f"✗ {component} logger failed: {e}"))

        # Test utility functions
        try:
            from django.contrib.auth import get_user_model
            User = get_user_model()

            # Create a test user or use an existing one
            test_user = User.objects.first()
            if test_user:
                log_attendance_action(
                    user=test_user,
                    action="Test attendance action from management command",
                    details={'test': True, 'source': 'management_command'}
                )

                log_performance_metric(
                    operation='test_operation',
                    duration=1.23,
                    user=test_user,
                    additional_metrics={'test_metric': 'success'}
                )

                successful_tests += 2
                self.stdout.write(style.SUCCESS("✓ Utility functions"))
            else:
                self.stdout.write(style.WARNING("⚠ No users found, skipping utility function tests"))

        except Exception as e:
            self.stdout.write(style.ERROR(f"✗ Utility function test failed: {e}"))

        self.stdout.write(f"\nTest Results: {successful_tests} tests passed")

        if successful_tests >= len(test_cases):
            self.stdout.write(style.SUCCESS("✓ All logging tests passed"))
        else:
            self.stdout.write(style.WARNING("⚠ Some tests failed, check configuration"))

    def validate_configuration(self):
        """Validate the logging configuration."""
        self.stdout.write(style.HTTP_INFO("=== Validating Attendance Logging Configuration ==="))

        validation = attendance_logging_config.validate_configuration()

        # Check Django logging configuration
        django_config_valid = self._check_django_logging_config()

        # Check file permissions
        permissions_valid = self._check_file_permissions()

        # Check disk space
        disk_space_ok = self._check_disk_space()

        # Overall validation
        overall_valid = (
            validation['valid'] and
            django_config_valid and
            permissions_valid and
            disk_space_ok
        )

        if overall_valid:
            self.stdout.write(style.SUCCESS("✓ All validation checks passed"))
        else:
            self.stdout.write(style.ERROR("✗ Validation failed"))

        return overall_valid

    def rotate_logs(self):
        """Manually rotate log files."""
        self.stdout.write(style.HTTP_INFO("=== Rotating Log Files ==="))

        try:
            result = attendance_logging_config.setup_log_rotation()
            self.stdout.write(style.SUCCESS("✓ Log rotation setup completed"))

            if self.verbose:
                self.stdout.write("Rotation configuration:")
                for key, value in result.items():
                    self.stdout.write(f"  {key}: {value}")

        except Exception as e:
            self.stdout.write(style.ERROR(f"✗ Log rotation failed: {e}"))

    def _check_django_logging_config(self):
        """Check if Django logging is properly configured for attendance."""
        try:
            django_logging = getattr(settings, 'LOGGING', {})

            # Check if attendance loggers are configured
            loggers = django_logging.get('loggers', {})
            attendance_loggers = [name for name in loggers.keys() if 'attendance' in name]

            if not attendance_loggers:
                self.stdout.write(style.WARNING("⚠ No attendance loggers found in Django configuration"))
                return False

            # Check if handlers exist
            handlers = django_logging.get('handlers', {})
            attendance_handlers = [name for name in handlers.keys() if 'attendance' in name]

            if not attendance_handlers:
                self.stdout.write(style.WARNING("⚠ No attendance handlers found in Django configuration"))
                return False

            self.stdout.write(style.SUCCESS(f"✓ Django logging configured ({len(attendance_loggers)} loggers, {len(attendance_handlers)} handlers)"))
            return True

        except Exception as e:
            self.stdout.write(style.ERROR(f"✗ Error checking Django logging config: {e}"))
            return False

    def _check_file_permissions(self):
        """Check file permissions for log directories."""
        try:
            log_dir = attendance_logging_config.logs_dir

            if not log_dir.exists():
                self.stdout.write(style.ERROR(f"✗ Log directory does not exist: {log_dir}"))
                return False

            if not os.access(log_dir, os.W_OK):
                self.stdout.write(style.ERROR(f"✗ Log directory is not writable: {log_dir}"))
                return False

            self.stdout.write(style.SUCCESS("✓ File permissions OK"))
            return True

        except Exception as e:
            self.stdout.write(style.ERROR(f"✗ Error checking file permissions: {e}"))
            return False

    def _check_disk_space(self):
        """Check available disk space."""
        try:
            log_dir = attendance_logging_config.logs_dir
            free_space = attendance_logging_config._get_free_space(log_dir)
            free_space_mb = free_space / (1024 * 1024)

            min_space_mb = 1024  # 1GB minimum

            if free_space_mb < min_space_mb:
                self.stdout.write(style.WARNING(f"⚠ Low disk space: {free_space_mb:.1f}MB available"))
                return False

            self.stdout.write(style.SUCCESS(f"✓ Disk space OK ({free_space_mb:.1f}MB available)"))
            return True

        except Exception as e:
            self.stdout.write(style.ERROR(f"✗ Error checking disk space: {e}"))
            return False

    def _create_initial_test_logs(self):
        """Create initial test log entries."""
        try:
            logger = get_attendance_logger('main')
            logger.info("Attendance logging system initialized via management command")

            # Test different log levels
            logger.debug("Debug level test message")
            logger.info("Info level test message")
            logger.warning("Warning level test message")

            self.stdout.write(style.SUCCESS("✓ Initial test logs created"))

        except Exception as e:
            self.stdout.write(style.WARNING(f"⚠ Could not create initial test logs: {e}"))

    def _format_bool(self, value):
        """Format boolean values with colors."""
        if value:
            return style.SUCCESS("Yes")
        else:
            return style.ERROR("No")
