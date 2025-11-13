#!/usr/bin/env python
"""
Test runner script for profile module
"""
import os
import sys
import django
from django.conf import settings
from django.test.utils import get_runner

if __name__ == "__main__":
    os.environ['DJANGO_SETTINGS_MODULE'] = 'ardurTrueAlign.settings'
    django.setup()
    TestRunner = get_runner(settings)
    test_runner = TestRunner()
    
    # Run specific profile tests
    failures = test_runner.run_tests(["trueAlign.profile.tests"])
    
    if failures:
        sys.exit(bool(failures))
