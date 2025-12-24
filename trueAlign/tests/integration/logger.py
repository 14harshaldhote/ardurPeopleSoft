"""
Integration Test Logger

Provides automated logging infrastructure with incremental file naming.
Logs test execution, database changes, API interactions, and generates
"Fixes Needed" summary reports.
"""

import logging
import os
from datetime import datetime
from pathlib import Path


class IntegrationTestLogger:
    """
    Custom logger for integration tests with auto-incrementing log file names.
    """
    
    def __init__(self, log_dir="/Users/harshalsmac/WORK/ardur/ardurHome/logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self._get_next_log_file()
        self.logger = self._setup_logger()
        self.failed_tests = []
        self.fixes_needed = []
        
    def _get_next_log_file(self):
        """
        Find the next available log file number and create the file path.
        Format: test1.log, test2.log, test3.log, ...
        """
        existing_logs = list(self.log_dir.glob("test*.log"))
        if not existing_logs:
            next_num = 1
        else:
            # Extract numbers from existing log files
            numbers = []
            for log in existing_logs:
                try:
                    # Extract number from filename (e.g., "test1.log" -> 1)
                    num_str = log.stem.replace("test", "")
                    if num_str.isdigit():
                        numbers.append(int(num_str))
                except:
                    pass
            next_num = max(numbers) + 1 if numbers else 1
        
        return self.log_dir / f"test{next_num}.log"
    
    def _setup_logger(self):
        """
        Setup Python logger with file and console handlers.
        """
        logger = logging.getLogger("IntegrationTestLogger")
        logger.setLevel(logging.DEBUG)
        
        # Remove existing handlers
        logger.handlers = []
        
        # File handler - detailed logs
        file_handler = logging.FileHandler(self.log_file, mode='w', encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        
        # Console handler - important logs only
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter('%(levelname)s: %(message)s')
        console_handler.setFormatter(console_formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def log_test_start(self, test_case_id, module_name, roles_involved, description):
        """Log the start of a test case."""
        separator = "=" * 100
        self.logger.info(separator)
        self.logger.info(f"TEST CASE: {test_case_id}")
        self.logger.info(f"MODULE: {module_name}")
        self.logger.info(f"ROLES: {', '.join(roles_involved)}")
        self.logger.info(f"DESCRIPTION: {description}")
        self.logger.info(separator)
    
    def log_precondition(self, description):
        """Log a test precondition."""
        self.logger.debug(f"PRECONDITION: {description}")
    
    def log_step(self, step_number, description):
        """Log a test step."""
        self.logger.info(f"STEP {step_number}: {description}")
    
    def log_database_change(self, table_name, operation, record_id=None, details=None):
        """Log database state changes."""
        msg = f"DATABASE [{operation}] Table: {table_name}"
        if record_id:
            msg += f", ID: {record_id}"
        if details:
            msg += f", Details: {details}"
        self.logger.debug(msg)
    
    def log_api_request(self, method, url, data=None):
        """Log API requests."""
        msg = f"API REQUEST [{method}] {url}"
        if data:
            msg += f" | Data: {data}"
        self.logger.debug(msg)
    
    def log_api_response(self, status_code, response_data=None):
        """Log API responses."""
        msg = f"API RESPONSE [Status: {status_code}]"
        if response_data:
            msg += f" | Data: {response_data}"
        self.logger.debug(msg)
    
    def log_assertion(self, assertion_type, expected, actual, passed):
        """Log test assertions."""
        status = "PASS" if passed else "FAIL"
        self.logger.info(f"ASSERTION [{status}] {assertion_type}")
        self.logger.debug(f"  Expected: {expected}")
        self.logger.debug(f"  Actual: {actual}")
        
        if not passed:
            self.fixes_needed.append({
                'assertion': assertion_type,
                'expected': expected,
                'actual': actual
            })
    
    def log_cross_module_interaction(self, module_from, module_to, interaction_type, data):
        """Log cross-module interactions."""
        self.logger.info(f"CROSS-MODULE [{module_from} → {module_to}] {interaction_type}")
        self.logger.debug(f"  Data: {data}")
    
    def log_security_check(self, check_type, user_role, resource, allowed):
        """Log security validations."""
        status = "ALLOWED" if allowed else "DENIED"
        self.logger.info(f"SECURITY [{status}] {check_type} | Role: {user_role} | Resource: {resource}")
    
    def log_notification_triggered(self, notification_type, recipient, module):
        """Log notification triggers."""
        self.logger.info(f"NOTIFICATION [{module}] Type: {notification_type}, Recipient: {recipient}")
    
    def log_test_end(self, test_case_id, passed, duration=None):
        """Log the end of a test case."""
        status = "PASSED" if passed else "FAILED"
        msg = f"TEST RESULT: {test_case_id} - {status}"
        if duration:
            msg += f" (Duration: {duration:.2f}s)"
        
        if passed:
            self.logger.info(msg)
        else:
            self.logger.error(msg)
            self.failed_tests.append(test_case_id)
        
        self.logger.info("=" * 100 + "\n")
    
    def log_error(self, error_message, exception=None):
        """Log errors and exceptions."""
        self.logger.error(f"ERROR: {error_message}")
        if exception:
            self.logger.exception(exception)
    
    def log_warning(self, warning_message):
        """Log warnings."""
        self.logger.warning(f"WARNING: {warning_message}")
    
    def add_fix_needed(self, area, issue, recommendation):
        """Add an item to the fixes needed list."""
        self.fixes_needed.append({
            'area': area,
            'issue': issue,
            'recommendation': recommendation
        })
    
    def generate_summary(self, total_tests, passed_tests, failed_tests, duration):
        """Generate test summary at the end of test run."""
        separator = "=" * 100
        self.logger.info("\n\n")
        self.logger.info(separator)
        self.logger.info("TEST EXECUTION SUMMARY")
        self.logger.info(separator)
        self.logger.info(f"Total Tests: {total_tests}")
        self.logger.info(f"Passed: {passed_tests}")
        self.logger.info(f"Failed: {failed_tests}")
        self.logger.info(f"Success Rate: {(passed_tests/total_tests*100):.2f}%")
        self.logger.info(f"Total Duration: {duration:.2f}s")
        self.logger.info(separator)
        
        if self.failed_tests:
            self.logger.error("\nFAILED TESTS:")
            for test_id in self.failed_tests:
                self.logger.error(f"  - {test_id}")
        
        # Generate "Fixes Needed" section
        self._generate_fixes_needed_section()
    
    def _generate_fixes_needed_section(self):
        """Generate the 'Fixes Needed' section."""
        separator = "=" * 100
        self.logger.info("\n\n")
        self.logger.info(separator)
        self.logger.info("FIXES NEEDED - DETAILED ANALYSIS")
        self.logger.info(separator)
        
        if not self.fixes_needed:
            self.logger.info("✅ NO FIXES NEEDED - All tests passed successfully!")
            return
        
        # Group fixes by area
        fixes_by_area = {}
        for fix in self.fixes_needed:
            area = fix.get('area', 'General')
            if area not in fixes_by_area:
                fixes_by_area[area] = []
            fixes_by_area[area].append(fix)
        
        # Output fixes by area
        for area, fixes in fixes_by_area.items():
            self.logger.error(f"\n{'─' * 100}")
            self.logger.error(f"AREA: {area}")
            self.logger.error(f"{'─' * 100}")
            
            for idx, fix in enumerate(fixes, 1):
                self.logger.error(f"\n{idx}. Issue:")
                if 'issue' in fix:
                    self.logger.error(f"   {fix['issue']}")
                elif 'assertion' in fix:
                    self.logger.error(f"   Assertion Failed: {fix['assertion']}")
                    self.logger.error(f"   Expected: {fix['expected']}")
                    self.logger.error(f"   Actual: {fix['actual']}")
                
                if 'recommendation' in fix:
                    self.logger.error(f"   Recommendation: {fix['recommendation']}")
        
        self.logger.info(f"\n{separator}")
        self.logger.info(f"Total Issues Found: {len(self.fixes_needed)}")
        self.logger.info(f"Areas Affected: {len(fixes_by_area)}")
        self.logger.info(separator)
    
    def get_log_file_path(self):
        """Return the path of the current log file."""
        return str(self.log_file)


# Global logger instance
_test_logger = None


def get_test_logger():
    """Get or create the global test logger instance."""
    global _test_logger
    if _test_logger is None:
        _test_logger = IntegrationTestLogger()
    return _test_logger
