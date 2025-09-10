#!/usr/bin/env python
"""
Attendance Logging System Initialization Script

This script initializes the attendance logging system on application startup.
It ensures all necessary directories exist, validates configuration, and
sets up initial logging.

Usage:
    python initialize_attendance_logging.py

Or import and call:
    from initialize_attendance_logging import initialize_system
    initialize_system()
"""

import os
import sys
import logging
from pathlib import Path
from datetime import datetime

def setup_django_environment():
    """Setup Django environment for the script."""
    # Add the project root to Python path
    project_root = Path(__file__).parent
    sys.path.insert(0, str(project_root))

    # Setup Django settings
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')

    try:
        import django
        django.setup()
        return True
    except Exception as e:
        print(f"Failed to setup Django environment: {e}")
        return False

def create_log_directories():
    """Create all necessary log directories."""
    print("Creating attendance log directories...")

    base_dir = Path(__file__).parent
    log_dirs = [
        base_dir / 'logs',
        base_dir / 'logs' / 'attendance',
        base_dir / 'logs' / 'attendance' / 'operations',
        base_dir / 'logs' / 'attendance' / 'api',
        base_dir / 'logs' / 'attendance' / 'cron',
        base_dir / 'logs' / 'attendance' / 'security',
        base_dir / 'logs' / 'attendance' / 'performance',
        base_dir / 'logs' / 'attendance' / 'exports'
    ]

    created_dirs = []
    failed_dirs = []

    for log_dir in log_dirs:
        try:
            log_dir.mkdir(parents=True, exist_ok=True)

            # Set appropriate permissions (readable/writable by owner and group)
            if os.name != 'nt':  # Not Windows
                os.chmod(log_dir, 0o775)

            created_dirs.append(str(log_dir))

        except Exception as e:
            failed_dirs.append((str(log_dir), str(e)))

    # Report results
    if created_dirs:
        print(f"✓ Created/verified {len(created_dirs)} log directories")
        if len(created_dirs) <= 5:  # Show details for small number
            for dir_path in created_dirs:
                print(f"  - {dir_path}")

    if failed_dirs:
        print(f"✗ Failed to create {len(failed_dirs)} directories:")
        for dir_path, error in failed_dirs:
            print(f"  - {dir_path}: {error}")
        return False

    return True

def validate_django_logging_config():
    """Validate Django logging configuration."""
    print("Validating Django logging configuration...")

    try:
        from django.conf import settings

        # Check if LOGGING is configured
        if not hasattr(settings, 'LOGGING'):
            print("✗ No LOGGING configuration found in Django settings")
            return False

        logging_config = settings.LOGGING

        # Check for attendance-specific loggers
        loggers = logging_config.get('loggers', {})
        attendance_loggers = [name for name in loggers.keys() if 'attendance' in name]

        if not attendance_loggers:
            print("✗ No attendance loggers found in Django configuration")
            return False

        # Check for attendance-specific handlers
        handlers = logging_config.get('handlers', {})
        attendance_handlers = [name for name in handlers.keys() if 'attendance' in name]

        if not attendance_handlers:
            print("✗ No attendance handlers found in Django configuration")
            return False

        print(f"✓ Found {len(attendance_loggers)} attendance loggers")
        print(f"✓ Found {len(attendance_handlers)} attendance handlers")

        return True

    except Exception as e:
        print(f"✗ Error validating Django logging config: {e}")
        return False

def test_logging_functionality():
    """Test basic logging functionality."""
    print("Testing logging functionality...")

    try:
        # Import attendance logging functions
        from trueAlign.attendance.logging import (
            get_attendance_logger,
            log_attendance_action,
            log_performance_metric
        )

        # Test basic logger
        logger = get_attendance_logger('main')
        logger.info("Attendance logging system initialized")

        # Test component loggers
        test_components = ['views', 'api_views', 'services', 'cron']
        for component in test_components:
            comp_logger = get_attendance_logger(component)
            comp_logger.info(f"Testing {component} logger initialization")

        print("✓ Basic logging functionality working")

        # Test with user context if possible
        try:
            from django.contrib.auth import get_user_model
            User = get_user_model()

            # Try to get a user for testing
            test_user = User.objects.first()
            if test_user:
                log_attendance_action(
                    user=test_user,
                    action="System initialization test",
                    details={'source': 'initialization_script'},
                    level='info'
                )

                log_performance_metric(
                    operation='system_initialization',
                    duration=0.1,
                    user=test_user
                )

                print("✓ User-context logging working")
            else:
                print("⚠ No users found, skipping user-context tests")

        except Exception as e:
            print(f"⚠ User-context logging test failed: {e}")

        return True

    except ImportError as e:
        print(f"✗ Failed to import attendance logging modules: {e}")
        return False
    except Exception as e:
        print(f"✗ Logging functionality test failed: {e}")
        return False

def check_disk_space():
    """Check available disk space for logging."""
    print("Checking disk space...")

    try:
        base_dir = Path(__file__).parent
        stat = os.statvfs(base_dir)

        # Calculate free space in MB
        free_space_mb = (stat.f_bavail * stat.f_frsize) / (1024 * 1024)

        # Check if we have at least 100MB free
        min_space_mb = 100

        if free_space_mb < min_space_mb:
            print(f"⚠ Low disk space: {free_space_mb:.1f}MB available (minimum: {min_space_mb}MB)")
            return False
        else:
            print(f"✓ Sufficient disk space: {free_space_mb:.1f}MB available")
            return True

    except Exception as e:
        print(f"⚠ Could not check disk space: {e}")
        return True  # Don't fail initialization for this

def create_initial_log_entries():
    """Create initial log entries to verify file creation."""
    print("Creating initial log entries...")

    try:
        from trueAlign.attendance.logging import get_attendance_logger

        # Create entries in different log files
        loggers_to_test = [
            ('main', 'Attendance logging system started'),
            ('views', 'Views logger initialized'),
            ('api_views', 'API views logger initialized'),
            ('services', 'Services logger initialized'),
            ('cron', 'Cron logger initialized'),
            ('security', 'Security logger initialized'),
            ('performance', 'Performance logger initialized')
        ]

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        for component, message in loggers_to_test:
            logger = get_attendance_logger(component)
            logger.info(f"[INIT {timestamp}] {message}")

        print("✓ Initial log entries created")
        return True

    except Exception as e:
        print(f"✗ Failed to create initial log entries: {e}")
        return False

def validate_log_files():
    """Validate that log files are being created."""
    print("Validating log file creation...")

    base_dir = Path(__file__).parent / 'logs' / 'attendance'

    expected_files = [
        'attendance.log',
        'attendance_api.log',
        'attendance_operations.log',
        'attendance_cron.log',
        'attendance_security.log',
        'attendance_performance.log'
    ]

    created_files = []
    missing_files = []

    for filename in expected_files:
        file_path = base_dir / filename
        if file_path.exists() and file_path.stat().st_size > 0:
            size = file_path.stat().st_size
            created_files.append(f"{filename} ({size} bytes)")
        else:
            missing_files.append(filename)

    if created_files:
        print(f"✓ Log files created: {len(created_files)}")
        for file_info in created_files[:3]:  # Show first 3
            print(f"  - {file_info}")
        if len(created_files) > 3:
            print(f"  ... and {len(created_files) - 3} more")

    if missing_files:
        print(f"⚠ Files not yet created (will be created on first use): {len(missing_files)}")

    return len(created_files) > 0

def print_system_info():
    """Print system information and status."""
    print("\n" + "=" * 60)
    print("ATTENDANCE LOGGING SYSTEM STATUS")
    print("=" * 60)

    # Basic info
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Project root: {Path(__file__).parent}")
    print(f"Python version: {sys.version.split()[0]}")

    # Django info
    try:
        import django
        print(f"Django version: {django.get_version()}")
    except:
        print("Django version: Unknown")

    # Log directory info
    log_dir = Path(__file__).parent / 'logs' / 'attendance'
    print(f"Log directory: {log_dir}")
    print(f"Log directory exists: {'Yes' if log_dir.exists() else 'No'}")

    if log_dir.exists():
        log_files = list(log_dir.glob('*.log'))
        total_size = sum(f.stat().st_size for f in log_files)
        print(f"Log files: {len(log_files)}")
        print(f"Total log size: {total_size / 1024:.1f} KB")

def initialize_system():
    """Main initialization function."""
    print("🚀 Initializing Attendance Logging System...")
    print("-" * 50)

    success_count = 0
    total_steps = 7

    # Step 1: Setup Django
    if setup_django_environment():
        print("✓ Django environment setup")
        success_count += 1
    else:
        print("✗ Django environment setup failed")
        return False

    # Step 2: Create directories
    if create_log_directories():
        print("✓ Log directories created")
        success_count += 1
    else:
        print("✗ Log directory creation failed")

    # Step 3: Validate Django config
    if validate_django_logging_config():
        print("✓ Django logging config validated")
        success_count += 1
    else:
        print("✗ Django logging config validation failed")

    # Step 4: Test logging
    if test_logging_functionality():
        print("✓ Logging functionality tested")
        success_count += 1
    else:
        print("✗ Logging functionality test failed")

    # Step 5: Check disk space
    if check_disk_space():
        print("✓ Disk space checked")
        success_count += 1
    else:
        print("⚠ Disk space check warning")
        success_count += 0.5

    # Step 6: Create initial logs
    if create_initial_log_entries():
        print("✓ Initial log entries created")
        success_count += 1
    else:
        print("✗ Initial log entry creation failed")

    # Step 7: Validate files
    if validate_log_files():
        print("✓ Log files validated")
        success_count += 1
    else:
        print("⚠ Log file validation incomplete")
        success_count += 0.5

    # Summary
    print("\n" + "-" * 50)
    print(f"Initialization completed: {success_count}/{total_steps} steps successful")

    if success_count >= total_steps - 0.5:
        print("🎉 Attendance logging system is ready!")
        print_system_info()
        return True
    else:
        print("⚠ Initialization completed with warnings")
        print("Some features may not work correctly.")
        return False

def main():
    """Script entry point."""
    try:
        success = initialize_system()

        if success:
            print("\nNext steps:")
            print("1. Check log files in: logs/attendance/")
            print("2. Monitor application logs for attendance events")
            print("3. Use the logging functions in your code")
            print("4. Run periodic log cleanup as needed")
        else:
            print("\nTroubleshooting:")
            print("1. Check file permissions on logs directory")
            print("2. Verify Django settings configuration")
            print("3. Ensure sufficient disk space")
            print("4. Check system logs for errors")

        return 0 if success else 1

    except KeyboardInterrupt:
        print("\n\nInitialization cancelled by user")
        return 1
    except Exception as e:
        print(f"\n\nUnexpected error during initialization: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
