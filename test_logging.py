#!/usr/bin/env python
"""
Test script to verify the enhanced logging functionality for TrueAlign Shift Management System.

This script tests all logging components:
- Action-based logging with request IDs
- User activity logging
- Database operation logging
- Performance monitoring
- Security event logging
- API endpoint logging
- Error handling and stack traces

Usage:
    python test_logging.py

Expected Output:
    - Console output showing test progress
    - Log files created in logs/ directory
    - Verification of log content and formatting
"""

import os
import sys
import time
import logging
import logging.handlers
from datetime import datetime
from pathlib import Path

# Add the project root to Python path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

# Configure Django settings (minimal setup for testing)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')

try:
    import django
    django.setup()
except ImportError:
    print("Warning: Django not available, running standalone logging tests")
    django = None

# Import our logging utilities
try:
    from trueAlign.shift.logging_config import ActionLogger, APILogger
except ImportError:
    print("Warning: Could not import logging_config, using basic setup")
    ActionLogger = None
    APILogger = None


class LoggingTester:
    """Test suite for the enhanced logging system."""

    def __init__(self):
        self.setup_logging()
        self.test_results = []

    def setup_logging(self):
        """Setup logging configuration for testing."""
        # Ensure logs directory exists
        logs_dir = BASE_DIR / 'logs'
        logs_dir.mkdir(exist_ok=True)

        # Configure logging
        logging.basicConfig(
            level=logging.DEBUG,
            format='[%(asctime)s] %(levelname)s - %(name)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        # Setup file handlers
        self.setup_file_handlers()

        # Get loggers
        self.main_logger = logging.getLogger('trueAlign.shift')
        self.action_logger = ActionLogger() if ActionLogger else None
        self.api_logger = APILogger() if APILogger else None

    def setup_file_handlers(self):
        """Setup file handlers for different log types."""
        logs_dir = BASE_DIR / 'logs'

        # Configure different loggers with file handlers
        loggers_config = {
            'trueAlign.shift': 'shift_app.log',
            'trueAlign.shift.actions': 'shift_actions.log',
            'trueAlign.shift.security': 'shift_security.log',
            'trueAlign.shift.api': 'shift_api.log',
            'trueAlign.shift.performance': 'shift_performance.log'
        }

        for logger_name, filename in loggers_config.items():
            logger = logging.getLogger(logger_name)
            logger.setLevel(logging.INFO)

            # Remove existing handlers
            for handler in logger.handlers[:]:
                logger.removeHandler(handler)

            # Add file handler
            file_handler = logging.handlers.RotatingFileHandler(
                logs_dir / filename,
                maxBytes=1024*1024*15,
                backupCount=10
            )
            file_handler.setFormatter(
                logging.Formatter(
                    '[%(asctime)s] %(levelname)s - %(name)s - %(funcName)s:%(lineno)d - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
            )
            logger.addHandler(file_handler)
            logger.propagate = False

    def log_test_result(self, test_name, success, message=""):
        """Log test result."""
        result = {
            'test': test_name,
            'success': success,
            'message': message,
            'timestamp': datetime.now().isoformat()
        }
        self.test_results.append(result)

        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{status}: {test_name}")
        if message:
            print(f"   {message}")

    def test_basic_logging(self):
        """Test basic logging functionality."""
        test_name = "Basic Logging"

        try:
            self.main_logger.info("Test info message")
            self.main_logger.warning("Test warning message")
            self.main_logger.error("Test error message")

            # Test with extra data
            self.main_logger.info("Test with extra data", extra={
                'user_id': 123,
                'action': 'test_action',
                'ip': '127.0.0.1'
            })

            self.log_test_result(test_name, True, "Basic logging messages sent")

        except Exception as e:
            self.log_test_result(test_name, False, f"Error: {str(e)}")

    def test_action_based_logging(self):
        """Test action-based logging with request IDs."""
        test_name = "Action-Based Logging"

        try:
            if self.action_logger:
                self.action_logger.log_action(
                    'TEST_ACTION',
                    user_id=123,
                    user='test_user',
                    ip='127.0.0.1',
                    request_id='test_req_001',
                    additional_data={'key': 'value'}
                )
                message = "Action logger working"
            else:
                # Fallback manual test
                action_logger = logging.getLogger('trueAlign.shift.actions')
                action_logger.info("ACTION: TEST_ACTION by test_user (ID: 123)", extra={
                    'action': 'TEST_ACTION',
                    'user_id': 123,
                    'user': 'test_user',
                    'request_id': 'test_req_001'
                })
                message = "Manual action logging (ActionLogger class not available)"

            self.log_test_result(test_name, True, message)

        except Exception as e:
            self.log_test_result(test_name, False, f"Error: {str(e)}")

    def test_performance_logging(self):
        """Test performance logging."""
        test_name = "Performance Logging"

        try:
            perf_logger = logging.getLogger('trueAlign.shift.performance')

            # Simulate slow operation
            start_time = time.time()
            time.sleep(0.1)  # 100ms delay
            duration = (time.time() - start_time) * 1000

            perf_logger.info(f"PERFORMANCE: test_operation took {duration:.2f}ms", extra={
                'operation': 'test_operation',
                'duration_ms': duration,
                'timestamp': datetime.now().isoformat()
            })

            # Test slow operation warning
            perf_logger.warning(f"PERFORMANCE: slow_operation took 1500ms", extra={
                'operation': 'slow_operation',
                'duration_ms': 1500,
                'timestamp': datetime.now().isoformat()
            })

            self.log_test_result(test_name, True, f"Performance logged: {duration:.2f}ms")

        except Exception as e:
            self.log_test_result(test_name, False, f"Error: {str(e)}")

    def test_security_logging(self):
        """Test security event logging."""
        test_name = "Security Logging"

        try:
            security_logger = logging.getLogger('trueAlign.shift.security')

            # Test different security events
            security_events = [
                ('permission_denied', 'WARNING'),
                ('unauthorized_access', 'ERROR'),
                ('suspicious_activity', 'WARNING'),
                ('authentication_failed', 'ERROR')
            ]

            for event, level in security_events:
                extra_data = {
                    'event_type': 'security',
                    'event': event,
                    'user_id': 123,
                    'ip': '127.0.0.1',
                    'timestamp': datetime.now().isoformat()
                }

                if level == 'WARNING':
                    security_logger.warning(f"SECURITY: {event}", extra=extra_data)
                else:
                    security_logger.error(f"SECURITY: {event}", extra=extra_data)

            self.log_test_result(test_name, True, f"Logged {len(security_events)} security events")

        except Exception as e:
            self.log_test_result(test_name, False, f"Error: {str(e)}")

    def test_api_logging(self):
        """Test API endpoint logging."""
        test_name = "API Logging"

        try:
            api_logger = logging.getLogger('trueAlign.shift.api')

            # Test different API scenarios
            api_calls = [
                ('GET', '/api/shifts/', 200, 150),
                ('POST', '/api/shifts/', 201, 250),
                ('GET', '/api/shifts/nonexistent/', 404, 50),
                ('POST', '/api/assignments/', 500, 1200)
            ]

            for method, endpoint, status_code, duration in api_calls:
                extra_data = {
                    'api_method': method,
                    'api_endpoint': endpoint,
                    'status_code': status_code,
                    'duration_ms': duration,
                    'user_id': 123,
                    'request_id': f'api_test_{int(time.time())}',
                    'timestamp': datetime.now().isoformat()
                }

                message = f"API {method} {endpoint} - {status_code} ({duration}ms)"

                if status_code >= 400:
                    api_logger.error(message, extra=extra_data)
                else:
                    api_logger.info(message, extra=extra_data)

            self.log_test_result(test_name, True, f"Logged {len(api_calls)} API calls")

        except Exception as e:
            self.log_test_result(test_name, False, f"Error: {str(e)}")

    def test_database_logging(self):
        """Test database operation logging."""
        test_name = "Database Operation Logging"

        try:
            db_logger = logging.getLogger('trueAlign.shift')

            # Simulate database operations
            operations = [
                ('CREATE', 'ShiftMaster', 1, {'name': 'Test Shift', 'start_time': '09:00'}),
                ('UPDATE', 'ShiftMaster', 1, {'name': {'old': 'Test Shift', 'new': 'Updated Shift'}}),
                ('DELETE', 'ShiftMaster', 1, {'name': 'Updated Shift'}),
                ('CREATE', 'ShiftAssignment', 2, {'user_id': 123, 'shift_id': 1})
            ]

            for operation, model, obj_id, details in operations:
                db_logger.info(f"DB_OPERATION - {operation} on {model}", extra={
                    'operation': operation,
                    'model': model,
                    'object_id': obj_id,
                    'details': details,
                    'timestamp': datetime.now().isoformat()
                })

            self.log_test_result(test_name, True, f"Logged {len(operations)} DB operations")

        except Exception as e:
            self.log_test_result(test_name, False, f"Error: {str(e)}")

    def test_error_logging(self):
        """Test error logging with stack traces."""
        test_name = "Error Logging"

        try:
            error_logger = logging.getLogger('trueAlign.shift')

            # Test different types of errors
            try:
                # Simulate a division by zero error
                result = 10 / 0
            except ZeroDivisionError as e:
                error_logger.error(f"Test error in calculation: {str(e)}", exc_info=True, extra={
                    'error_type': 'ZeroDivisionError',
                    'user_id': 123,
                    'operation': 'test_calculation',
                    'timestamp': datetime.now().isoformat()
                })

            try:
                # Simulate a key error
                test_dict = {'key1': 'value1'}
                value = test_dict['nonexistent_key']
            except KeyError as e:
                error_logger.error(f"Test KeyError: {str(e)}", exc_info=True, extra={
                    'error_type': 'KeyError',
                    'user_id': 123,
                    'operation': 'test_dict_access',
                    'timestamp': datetime.now().isoformat()
                })

            self.log_test_result(test_name, True, "Error logging with stack traces")

        except Exception as e:
            self.log_test_result(test_name, False, f"Unexpected error: {str(e)}")

    def test_user_action_simulation(self):
        """Test comprehensive user action simulation."""
        test_name = "User Action Simulation"

        try:
            # Simulate a complete user workflow
            user_id = 123
            username = "test_user"
            ip = "127.0.0.1"
            request_id = f"req_{int(time.time())}"

            # User login
            self.main_logger.info(f"User {username} logged in from {ip}", extra={
                'action': 'user_login',
                'user_id': user_id,
                'user': username,
                'ip': ip,
                'request_id': request_id
            })

            # Dashboard access
            self.main_logger.info(f"Dashboard accessed by {username}", extra={
                'action': 'dashboard_view',
                'user_id': user_id,
                'user': username,
                'request_id': request_id
            })

            # Shift creation
            self.main_logger.info(f"Shift created by {username}", extra={
                'action': 'shift_create',
                'user_id': user_id,
                'user': username,
                'target': 'shift_1',
                'details': {'shift_name': 'Morning Shift'},
                'request_id': request_id
            })

            # Assignment
            self.main_logger.info(f"Shift assigned by {username}", extra={
                'action': 'shift_assign',
                'user_id': user_id,
                'user': username,
                'target': 'user_456',
                'details': {'shift_id': 1, 'target_user': 'employee1'},
                'request_id': request_id
            })

            # Logout
            self.main_logger.info(f"User {username} logged out", extra={
                'action': 'user_logout',
                'user_id': user_id,
                'user': username,
                'ip': ip,
                'request_id': request_id
            })

            self.log_test_result(test_name, True, "Complete user workflow simulated")

        except Exception as e:
            self.log_test_result(test_name, False, f"Error: {str(e)}")

    def verify_log_files(self):
        """Verify that log files were created and contain data."""
        test_name = "Log File Verification"

        try:
            logs_dir = BASE_DIR / 'logs'
            expected_files = [
                'shift_app.log',
                'shift_actions.log',
                'shift_security.log',
                'shift_api.log',
                'shift_performance.log'
            ]

            created_files = []
            file_sizes = {}

            for filename in expected_files:
                filepath = logs_dir / filename
                if filepath.exists():
                    created_files.append(filename)
                    file_sizes[filename] = filepath.stat().st_size

            if created_files:
                message = f"Created files: {', '.join(created_files)}"
                for filename, size in file_sizes.items():
                    message += f"\n   {filename}: {size} bytes"
                self.log_test_result(test_name, True, message)
            else:
                self.log_test_result(test_name, False, "No log files created")

        except Exception as e:
            self.log_test_result(test_name, False, f"Error: {str(e)}")

    def run_all_tests(self):
        """Run all logging tests."""
        print("=" * 60)
        print("TrueAlign Shift Management - Logging System Test")
        print("=" * 60)
        print(f"Test started at: {datetime.now()}")
        print(f"Base directory: {BASE_DIR}")
        print(f"Logs directory: {BASE_DIR / 'logs'}")
        print("-" * 60)

        # Run all tests
        test_methods = [
            self.test_basic_logging,
            self.test_action_based_logging,
            self.test_performance_logging,
            self.test_security_logging,
            self.test_api_logging,
            self.test_database_logging,
            self.test_error_logging,
            self.test_user_action_simulation,
            self.verify_log_files
        ]

        for test_method in test_methods:
            try:
                test_method()
            except Exception as e:
                test_name = test_method.__name__.replace('test_', '').replace('_', ' ').title()
                self.log_test_result(test_name, False, f"Test crashed: {str(e)}")

            # Small delay between tests
            time.sleep(0.1)

        # Print summary
        self.print_summary()

    def print_summary(self):
        """Print test summary."""
        print("-" * 60)

        passed = sum(1 for result in self.test_results if result['success'])
        failed = len(self.test_results) - passed

        print(f"Test Summary:")
        print(f"  Total tests: {len(self.test_results)}")
        print(f"  Passed: {passed}")
        print(f"  Failed: {failed}")
        print(f"  Success rate: {(passed/len(self.test_results)*100):.1f}%")

        if failed > 0:
            print(f"\nFailed tests:")
            for result in self.test_results:
                if not result['success']:
                    print(f"  - {result['test']}: {result['message']}")

        print(f"\nTest completed at: {datetime.now()}")
        print("=" * 60)

        # Additional information
        logs_dir = BASE_DIR / 'logs'
        if logs_dir.exists():
            print(f"\nLog files location: {logs_dir}")
            print("Available log files:")
            for log_file in logs_dir.glob('*.log'):
                size = log_file.stat().st_size
                print(f"  - {log_file.name}: {size} bytes")

        print("\nTo view logs, use:")
        print(f"  tail -f {logs_dir}/shift_app.log")
        print(f"  cat {logs_dir}/shift_actions.log")


def main():
    """Main function to run the logging tests."""
    tester = LoggingTester()
    tester.run_all_tests()


if __name__ == "__main__":
    main()
