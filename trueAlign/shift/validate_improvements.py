#!/usr/bin/env python
"""
Shift App Improvement Validation Script

This script validates all improvements made to the shift management app.
It checks models, services, forms, views, and overall functionality.

Usage:
    python manage.py shell < validate_improvements.py

Or run specific sections:
    python manage.py shell
    >>> exec(open('validate_improvements.py').read())
"""

import os
import sys
import traceback
from datetime import datetime, timedelta, time, date
from decimal import Decimal
from django.contrib.auth.models import User, Group
from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone
from django.core.exceptions import ValidationError

# Color codes for output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_success(message):
    print(f"{Colors.GREEN}✓ {message}{Colors.ENDC}")

def print_error(message):
    print(f"{Colors.RED}✗ {message}{Colors.ENDC}")

def print_warning(message):
    print(f"{Colors.YELLOW}⚠ {message}{Colors.ENDC}")

def print_info(message):
    print(f"{Colors.BLUE}ℹ {message}{Colors.ENDC}")

def print_header(message):
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}")
    print(f"{message}")
    print(f"{'='*60}{Colors.ENDC}")

class ShiftAppValidator:
    """Main validation class for shift app improvements"""

    def __init__(self):
        self.errors = []
        self.warnings = []
        self.successes = []

    def validate_all(self):
        """Run all validation checks"""
        print_header("SHIFT APP IMPROVEMENT VALIDATION")

        try:
            self.validate_imports()
            self.validate_models()
            self.validate_services()
            self.validate_forms()
            self.validate_views()
            self.validate_decorators()
            self.validate_urls()
            self.validate_integration()

            self.print_summary()

        except Exception as e:
            print_error(f"Critical validation error: {str(e)}")
            traceback.print_exc()

    def validate_imports(self):
        """Validate all imports work correctly"""
        print_header("VALIDATING IMPORTS")

        try:
            # Test model imports
            from trueAlign.models import ShiftMaster, ShiftAssignment, Holiday
            print_success("Model imports successful")

            # Test service imports
            from trueAlign.shift.services import ShiftService
            print_success("Service imports successful")

            # Test form imports
            from trueAlign.shift.forms import ShiftForm, ShiftAssignmentForm, HolidayForm, CSVUploadForm
            print_success("Form imports successful")

            # Test decorator imports
            from trueAlign.shift.decorators import group_required, superuser_required
            print_success("Decorator imports successful")

            # Test view imports
            from trueAlign.shift import views
            print_success("View imports successful")

        except ImportError as e:
            print_error(f"Import error: {str(e)}")
            self.errors.append(f"Import error: {str(e)}")
        except Exception as e:
            print_error(f"Unexpected import error: {str(e)}")
            self.errors.append(f"Unexpected import error: {str(e)}")

    def validate_models(self):
        """Validate model functionality"""
        print_header("VALIDATING MODELS")

        try:
            from trueAlign.models import ShiftMaster, ShiftAssignment, Holiday

            # Test ShiftMaster model
            try:
                shift_data = {
                    'name': 'Validation Test Shift',
                    'start_time': time(9, 0),
                    'end_time': time(17, 30),
                    'shift_duration': Decimal('8.5'),
                    'break_duration': timedelta(minutes=30),
                    'grace_period': timedelta(minutes=15),
                    'work_days': 'Weekdays',
                    'is_active': True
                }

                # Test creation
                shift = ShiftMaster(**shift_data)
                shift.full_clean()  # Validate without saving
                print_success("ShiftMaster model validation passed")

                # Test properties
                assert hasattr(shift, 'crosses_midnight'), "crosses_midnight property missing"
                assert hasattr(shift, 'working_days_list'), "working_days_list property missing"
                assert callable(getattr(shift, 'expected_hours')), "expected_hours method missing"
                print_success("ShiftMaster properties and methods exist")

                # Test midnight crossing detection
                night_shift = ShiftMaster(
                    name='Night Shift Test',
                    start_time=time(22, 0),
                    end_time=time(6, 0),
                    shift_duration=Decimal('8.0')
                )
                assert night_shift.crosses_midnight == True, "Midnight crossing detection failed"
                print_success("Midnight crossing detection works")

            except Exception as e:
                print_error(f"ShiftMaster validation failed: {str(e)}")
                self.errors.append(f"ShiftMaster: {str(e)}")

            # Test Holiday model
            try:
                holiday = Holiday(
                    name='Test Holiday',
                    date=date.today(),
                    recurring_yearly=True
                )
                holiday.full_clean()
                print_success("Holiday model validation passed")

                # Test is_holiday class method
                assert callable(getattr(Holiday, 'is_holiday')), "is_holiday class method missing"
                print_success("Holiday class methods exist")

            except Exception as e:
                print_error(f"Holiday validation failed: {str(e)}")
                self.errors.append(f"Holiday: {str(e)}")

        except Exception as e:
            print_error(f"Model validation error: {str(e)}")
            self.errors.append(f"Model validation: {str(e)}")

    def validate_services(self):
        """Validate service layer functionality"""
        print_header("VALIDATING SERVICES")

        try:
            from trueAlign.shift.services import ShiftService

            service = ShiftService()

            # Test service methods exist
            required_methods = [
                'get_all_shifts', 'get_shift_by_id', 'get_shift_by_name',
                'create_shift', 'update_shift', 'delete_shift',
                'assign_shift_to_user', 'assign_shifts_to_users',
                'get_shift_assignments', 'end_shift_assignment',
                'get_shift_statistics', 'get_shift_history',
                'create_holiday', 'get_holidays', 'validate_shift_assignment'
            ]

            for method_name in required_methods:
                if hasattr(service, method_name) and callable(getattr(service, method_name)):
                    print_success(f"Service method '{method_name}' exists")
                else:
                    print_error(f"Service method '{method_name}' missing")
                    self.errors.append(f"Missing service method: {method_name}")

            # Test service initialization
            assert hasattr(service, 'logger'), "Service logger not initialized"
            print_success("Service initialization successful")

            # Test type hints and documentation
            for method_name in required_methods[:5]:  # Test first 5 methods
                method = getattr(service, method_name, None)
                if method and hasattr(method, '__annotations__'):
                    print_success(f"Method '{method_name}' has type hints")
                else:
                    print_warning(f"Method '{method_name}' missing type hints")

        except Exception as e:
            print_error(f"Service validation error: {str(e)}")
            self.errors.append(f"Service validation: {str(e)}")

    def validate_forms(self):
        """Validate form functionality"""
        print_header("VALIDATING FORMS")

        try:
            from trueAlign.shift.forms import ShiftForm, ShiftAssignmentForm, HolidayForm, CSVUploadForm

            # Test ShiftForm
            try:
                form_data = {
                    'name': 'Test Form Shift',
                    'start_time': '09:00',
                    'end_time': '17:00',
                    'shift_duration': '8.0',
                    'break_duration': '30',
                    'grace_period': '15',
                    'work_days': 'Weekdays',
                    'is_active': True
                }

                form = ShiftForm(data=form_data)
                if form.is_valid():
                    print_success("ShiftForm basic validation passed")
                else:
                    print_error(f"ShiftForm validation failed: {form.errors}")
                    self.errors.append(f"ShiftForm validation: {form.errors}")

                # Test custom validation
                invalid_data = form_data.copy()
                invalid_data['break_duration'] = '600'  # Too long
                invalid_form = ShiftForm(data=invalid_data)
                if not invalid_form.is_valid():
                    print_success("ShiftForm custom validation works")
                else:
                    print_warning("ShiftForm custom validation may be missing")

            except Exception as e:
                print_error(f"ShiftForm error: {str(e)}")
                self.errors.append(f"ShiftForm: {str(e)}")

            # Test CSVUploadForm
            try:
                csv_form = CSVUploadForm()
                assert hasattr(csv_form, 'clean_csv_file'), "CSV form custom validation missing"
                print_success("CSVUploadForm structure validated")

            except Exception as e:
                print_error(f"CSVUploadForm error: {str(e)}")
                self.errors.append(f"CSVUploadForm: {str(e)}")

        except Exception as e:
            print_error(f"Form validation error: {str(e)}")
            self.errors.append(f"Form validation: {str(e)}")

    def validate_views(self):
        """Validate view functionality"""
        print_header("VALIDATING VIEWS")

        try:
            from trueAlign.shift import views

            # Test view functions exist
            required_views = [
                'shift_dashboard', 'shift_list', 'shift_detail',
                'create_shift', 'update_shift', 'delete_shift',
                'assign_shift', 'assignment_list', 'holiday_list',
                'api_shift_details', 'api_user_assignments'
            ]

            for view_name in required_views:
                if hasattr(views, view_name) and callable(getattr(views, view_name)):
                    print_success(f"View '{view_name}' exists")
                else:
                    print_error(f"View '{view_name}' missing")
                    self.errors.append(f"Missing view: {view_name}")

            # Test helper functions exist
            helper_functions = [
                '_handle_shift_creation', '_handle_shift_update',
                '_prepare_shift_for_template', '_handle_post_request'
            ]

            for func_name in helper_functions:
                if hasattr(views, func_name):
                    print_success(f"Helper function '{func_name}' exists")
                else:
                    print_warning(f"Helper function '{func_name}' may be missing")

        except Exception as e:
            print_error(f"View validation error: {str(e)}")
            self.errors.append(f"View validation: {str(e)}")

    def validate_decorators(self):
        """Validate decorator functionality"""
        print_header("VALIDATING DECORATORS")

        try:
            from trueAlign.shift.decorators import group_required, superuser_required

            # Test decorator structure
            assert callable(group_required), "group_required is not callable"
            assert callable(superuser_required), "superuser_required is not callable"
            print_success("Decorators are callable")

            # Test decorator with parameters
            try:
                decorator = group_required(['Manager'])
                assert callable(decorator), "group_required decorator not properly configured"
                print_success("group_required decorator configuration works")

                decorator_with_options = group_required(['Manager'], redirect_url='shift:dashboard')
                assert callable(decorator_with_options), "group_required with options failed"
                print_success("group_required with options works")

            except Exception as e:
                print_error(f"Decorator configuration error: {str(e)}")
                self.errors.append(f"Decorator config: {str(e)}")

        except Exception as e:
            print_error(f"Decorator validation error: {str(e)}")
            self.errors.append(f"Decorator validation: {str(e)}")

    def validate_urls(self):
        """Validate URL configuration"""
        print_header("VALIDATING URLS")

        try:
            from trueAlign.shift.urls import urlpatterns

            # Test URL patterns exist
            assert len(urlpatterns) > 0, "No URL patterns found"
            print_success(f"Found {len(urlpatterns)} URL patterns")

            # Test required URL names exist
            required_url_names = [
                'dashboard', 'list', 'create', 'update', 'delete',
                'assign', 'assignments', 'holidays'
            ]

            pattern_names = []
            for pattern in urlpatterns:
                if hasattr(pattern, 'name') and pattern.name:
                    pattern_names.append(pattern.name)

            for url_name in required_url_names:
                if url_name in pattern_names:
                    print_success(f"URL pattern '{url_name}' exists")
                else:
                    print_warning(f"URL pattern '{url_name}' may be missing")

        except Exception as e:
            print_error(f"URL validation error: {str(e)}")
            self.errors.append(f"URL validation: {str(e)}")

    def validate_integration(self):
        """Validate integration between components"""
        print_header("VALIDATING INTEGRATION")

        try:
            # Test service and model integration
            from trueAlign.shift.services import ShiftService
            from trueAlign.models import ShiftMaster

            service = ShiftService()

            # Test get_all_shifts returns proper type
            shifts = service.get_all_shifts()
            assert isinstance(shifts, list), "get_all_shifts should return a list"
            print_success("Service-Model integration working")

            # Test validation method
            is_valid, message = service.validate_shift_assignment(
                user_id=1,
                shift_id=1,
                effective_from=date.today()
            )
            assert isinstance(is_valid, bool), "validate_shift_assignment should return boolean"
            assert isinstance(message, str), "validate_shift_assignment should return string message"
            print_success("Validation method integration working")

        except Exception as e:
            print_error(f"Integration validation error: {str(e)}")
            self.errors.append(f"Integration validation: {str(e)}")

    def print_summary(self):
        """Print validation summary"""
        print_header("VALIDATION SUMMARY")

        total_checks = len(self.successes) + len(self.errors) + len(self.warnings)

        print_info(f"Total Checks: {total_checks}")
        print_success(f"Successful: {len(self.successes)}")
        print_warning(f"Warnings: {len(self.warnings)}")
        print_error(f"Errors: {len(self.errors)}")

        if self.errors:
            print_header("ERRORS FOUND")
            for error in self.errors:
                print_error(error)

        if self.warnings:
            print_header("WARNINGS")
            for warning in self.warnings:
                print_warning(warning)

        # Overall status
        if len(self.errors) == 0:
            print_success("\n🎉 ALL VALIDATIONS PASSED! Shift app improvements are working correctly.")
        else:
            print_error(f"\n❌ {len(self.errors)} errors found. Please fix these issues.")

        return len(self.errors) == 0

def run_quick_validation():
    """Run a quick validation of key components"""
    print_header("QUICK VALIDATION")

    try:
        # Test imports
        from trueAlign.models import ShiftMaster, ShiftAssignment, Holiday
        from trueAlign.shift.services import ShiftService
        from trueAlign.shift.forms import ShiftForm
        from trueAlign.shift.decorators import group_required
        print_success("All critical imports working")

        # Test service instantiation
        service = ShiftService()
        print_success("Service instantiation working")

        # Test basic functionality
        shifts = service.get_all_shifts()
        stats = service.get_shift_statistics()
        print_success("Basic service methods working")

        print_success("🎉 Quick validation passed!")
        return True

    except Exception as e:
        print_error(f"Quick validation failed: {str(e)}")
        return False

def run_performance_check():
    """Run basic performance checks"""
    print_header("PERFORMANCE CHECK")

    try:
        from trueAlign.shift.services import ShiftService
        import time

        service = ShiftService()

        # Test service method performance
        start_time = time.time()
        for _ in range(100):
            service.get_all_shifts()
        end_time = time.time()

        avg_time = (end_time - start_time) / 100
        if avg_time < 0.1:  # Should be under 0.1 seconds
            print_success(f"Service performance good: {avg_time:.4f}s average")
        else:
            print_warning(f"Service performance slow: {avg_time:.4f}s average")

        return True

    except Exception as e:
        print_error(f"Performance check failed: {str(e)}")
        return False

def main():
    """Main validation function"""
    print(f"{Colors.BOLD}Shift App Improvement Validation{Colors.ENDC}")
    print(f"Started at: {datetime.now()}")

    # Run validations
    validator = ShiftAppValidator()

    try:
        # Quick check first
        if run_quick_validation():
            # Full validation
            success = validator.validate_all()

            # Performance check
            run_performance_check()

            if success:
                print_success("\n✅ ALL IMPROVEMENTS VALIDATED SUCCESSFULLY!")
                print_info("The shift app has been successfully improved and is ready for use.")
            else:
                print_error("\n❌ SOME ISSUES FOUND")
                print_info("Please review and fix the errors above.")
        else:
            print_error("Quick validation failed. Please check basic setup.")

    except KeyboardInterrupt:
        print_warning("\nValidation interrupted by user.")
    except Exception as e:
        print_error(f"Validation failed with error: {str(e)}")
        traceback.print_exc()

    print(f"\nCompleted at: {datetime.now()}")

if __name__ == "__main__":
    main()

# Instructions for running this script:
# 1. In Django shell: exec(open('validate_improvements.py').read())
# 2. Or as module: python manage.py shell < validate_improvements.py
# 3. For quick check only: run_quick_validation()
