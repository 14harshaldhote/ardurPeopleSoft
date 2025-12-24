"""
Comprehensive Test Runner and Configuration

Run this file to execute all integration tests with detailed logging.
"""

import os
import sys
import django
from pathlib import Path

# Setup Django settings
BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(BASE_DIR))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

import unittest
import time
from datetime import datetime
from .logger import get_test_logger


def run_all_tests():
    """
    Run all integration tests and generate comprehensive log.
    """
    # Get logger
    logger = get_test_logger()
    
    print(f"\n{'='*100}")
    print(f"TrueAlign ERP - Integration Test Suite")
    print(f"{'='*100}")
    print(f"Log File: {logger.get_log_file_path()}")
    print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*100}\n")
    
    # Log header
    logger.logger.info("=" * 100)
    logger.logger.info("TRUEALIGN ERP - INTEGRATION TEST SUITE")
    logger.logger.info("=" * 100)
    logger.logger.info(f"Test Execution Started: {datetime.now()}")
    logger.logger.info(f"Log File: {logger.get_log_file_path()}")
    logger.logger.info("=" * 100 + "\n")
    
    # Discover and run tests
    loader = unittest.TestLoader()
    start_dir = Path(__file__).parent
    suite = loader.discover(start_dir, pattern='test_*.py')
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    start_time = time.time()
    result = runner.run(suite)
    end_time = time.time()
    
    # Calculate results
    total_tests = result.testsRun
    failed_tests = len(result.failures) + len(result.errors)
    passed_tests = total_tests - failed_tests
    duration = end_time - start_time
    
    # Generate summary
    logger.generate_summary(total_tests, passed_tests, failed_tests, duration)
    
    print(f"\n{'='*100}")
    print(f"Test Execution Complete")
    print(f"{'='*100}")
    print(f"Total Tests: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {failed_tests}")
    print(f"Duration: {duration:.2f}s")
    print(f"Log File: {logger.get_log_file_path()}")
    print(f"{'='*100}\n")
    
    return result


if __name__ == '__main__':
    result = run_all_tests()
    sys.exit(0 if result.wasSuccessful() else 1)
