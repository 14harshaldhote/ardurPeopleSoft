"""
TrueAlign Shift Management System Validator
Comprehensive validation script to ensure all functionality works properly
"""

import os
import sys
import json
import logging
from datetime import date, time, timedelta
from decimal import Decimal
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User, Group
from django.test import Client
from django.urls import reverse
from django.db import transaction
from trueAlign.models import ShiftMaster, ShiftAssignment, Holiday
from trueAlign.shift.services import ShiftService, ConflictDetector
from trueAlign.shift.forms import ShiftForm, ShiftAssignmentForm


class SystemValidator:
    """Comprehensive system validator for shift management"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.client = Client()
        self.shift_service = ShiftService()
        self.conflict_detector = ConflictDetector()
        self.test_results = {
            'passed': 0,
            'failed': 0,
            'warnings': 0,
            'details': []
        }

    def log_test(self, test_name, passed, message="", is_warning=False):
        """Log test result"""
        status = "PASS" if passed else ("WARN" if is_warning else "FAIL")
        print(f"[{status}] {test_name}: {message}")

        if passed:
            self.test_results['passed'] += 1
        elif is_warning:
            self.test_results['warnings'] += 1
        else:
            self.test_results['failed'] += 1

        self.test_results['details'].append({
            'test': test_name,
            'status': status,
            'message': message
        })

    def setup_test_data(self):
        """Set up test data for validation"""
        try:
            # Create groups if they don't exist
            manager_group, _ = Group.objects.get_or_create(name='Manager')
            hr_group, _ = Group.objects.get_or_create(name='HR')
            employee_group, _ = Group.objects.get_or_create(name='Employee')

            # Create test manager
            self.test_manager = User.objects.create_user(
                username='test_manager_validator',
                email='test_manager@validator.com',
                password='testpass123',
                first_name='Test',
                last_name='Manager'
            )
            self.test_manager.groups.add(manager_group)

            # Create test employees
            self.test_employee1 = User.objects.create_user(
                username='test_employee1_validator',
                email='test_employee1@validator.com',
                password='testpass123',
                first_name='Test',
                last_name='Employee1'
            )
            self.test_employee1.groups.add(employee_group)

            self.test_employee2 = User.objects.create_user(
                username='test_employee2_validator',
                email='test_employee2@validator.com',
                password='testpass123',
                first_name='Test',
                last_name='Employee2'
            )
            self.test_employee2.groups.add(employee_group)

            self.log_test("Setup Test Data", True, "Test users and groups created successfully")
            return True

        except Exception as e:
            self.log_test("Setup Test Data", False, f"Failed to setup test data: {str(e)}")
            return False

    def test_shift_creation(self):
        """Test shift creation functionality"""
        print("\n=== Testing Shift Creation ===")

        # Login as manager
        self.client.login(username='test_manager_validator', password='testpass123')

        test_cases = [
            {
                'name': 'Basic Day Shift',
                'data': {
                    'name': 'Test Day Shift',
                    'start_time': '09:00',
                    'end_time': '17:00',
                    'shift_duration': '8.0',
                    'work_days': 'Weekdays',
                    'break_duration_minutes': '30',
                    'grace_period_minutes': '15',
                    'is_active': True
                },
                'should_pass': True
            },
            {
                'name': 'Overnight Shift',
                'data': {
                    'name': 'Test Night Shift',
                    'start_time': '22:00',
                    'end_time': '06:00',
                    'shift_duration': '8.0',
                    'work_days': 'Weekdays',
                    'break_duration_minutes': '30',
                    'grace_period_minutes': '15',
                    'is_active': True
                },
                'should_pass': True
            },
            {
                'name': 'Custom Work Days',
                'data': {
                    'name': 'Custom Days Shift',
                    'start_time': '10:00',
                    'end_time': '18:00',
                    'shift_duration': '8.0',
                    'work_days': 'Custom',
                    'custom_work_days': 'Monday,Wednesday,Friday',
                    'break_duration_minutes': '30',
                    'grace_period_minutes': '15',
                    'is_active': True
                },
                'should_pass': True
            },
            {
                'name': 'Overlapping Shift (Should be allowed)',
                'data': {
                    'name': 'Overlapping Test Shift',
                    'start_time': '13:00',  # Overlaps with day shift
                    'end_time': '21:00',
                    'shift_duration': '8.0',
                    'work_days': 'Weekdays',
                    'break_duration_minutes': '30',
                    'grace_period_minutes': '15',
                    'is_active': True
                },
                'should_pass': True
            }
        ]

        for test_case in test_cases:
            try:
                response = self.client.post(reverse('shift:create'), test_case['data'])

                if test_case['should_pass']:
                    success = response.status_code in [200, 302]
                    if success:
                        # Verify shift was created
                        shift_exists = ShiftMaster.objects.filter(name=test_case['data']['name']).exists()
                        success = success and shift_exists

                    self.log_test(
                        f"Create {test_case['name']}",
                        success,
                        "Created successfully" if success else f"Failed with status {response.status_code}"
                    )
                else:
                    success = response.status_code not in [200, 302]
                    self.log_test(
                        f"Create {test_case['name']}",
                        success,
                        "Properly rejected" if success else "Should have been rejected"
                    )

            except Exception as e:
                self.log_test(f"Create {test_case['name']}", False, f"Exception: {str(e)}")

    def test_overlapping_shifts_policy(self):
        """Test that overlapping shifts are now allowed"""
        print("\n=== Testing Overlapping Shifts Policy ===")

        try:
            # Create base shift
            shift1 = ShiftMaster.objects.create(
                name='Base Overlap Test Shift',
                start_time=time(9, 0),
                end_time=time(17, 0),
                shift_duration=Decimal('8.0'),
                work_days='Weekdays',
                is_active=True
            )

            # Try to create overlapping shift
            shift2_data = {
                'name': 'Overlapping Test Shift',
                'start_time': '13:00',  # 4-hour overlap
                'end_time': '21:00',
                'shift_duration': '8.0',
                'work_days': 'Weekdays',
                'break_duration_minutes': '30',
                'grace_period_minutes': '15',
                'is_active': True
            }

            response = self.client.post(reverse('shift:create'), shift2_data)

            if response.status_code in [200, 302]:
                # Check both shifts exist
                shift1_exists = ShiftMaster.objects.filter(name='Base Overlap Test Shift').exists()
                shift2_exists = ShiftMaster.objects.filter(name='Overlapping Test Shift').exists()

                if shift1_exists and shift2_exists:
                    self.log_test("Overlapping Shifts Creation", True, "Both overlapping shifts created successfully")
                else:
                    self.log_test("Overlapping Shifts Creation", False, "One or both shifts not found in database")
            else:
                self.log_test("Overlapping Shifts Creation", False, f"Failed with status {response.status_code}")

        except Exception as e:
            self.log_test("Overlapping Shifts Creation", False, f"Exception: {str(e)}")

    def test_assignment_functionality(self):
        """Test assignment functionality"""
        print("\n=== Testing Assignment Functionality ===")

        try:
            # Create test shift
            test_shift = ShiftMaster.objects.create(
                name='Assignment Test Shift',
                start_time=time(9, 0),
                end_time=time(17, 0),
                shift_duration=Decimal('8.0'),
                work_days='Weekdays',
                is_active=True
            )

            # Test single assignment
            assignment_data = {
                'user': self.test_employee1.id,
                'shift': test_shift.id,
                'effective_from': (date.today() + timedelta(days=1)).strftime('%Y-%m-%d'),
                'effective_to': (date.today() + timedelta(days=30)).strftime('%Y-%m-%d'),
                'reason': 'Test assignment'
            }

            response = self.client.post(reverse('shift:assign'), assignment_data)

            if response.status_code in [200, 302]:
                assignment_exists = ShiftAssignment.objects.filter(
                    user=self.test_employee1,
                    shift=test_shift
                ).exists()

                self.log_test("Single Assignment", assignment_exists,
                            "Assignment created successfully" if assignment_exists else "Assignment not found in database")
            else:
                self.log_test("Single Assignment", False, f"Failed with status {response.status_code}")

        except Exception as e:
            self.log_test("Single Assignment", False, f"Exception: {str(e)}")

    def test_bulk_assignment(self):
        """Test bulk assignment functionality"""
        print("\n=== Testing Bulk Assignment ===")

        try:
            # Create test shift
            bulk_shift = ShiftMaster.objects.create(
                name='Bulk Assignment Test Shift',
                start_time=time(10, 0),
                end_time=time(18, 0),
                shift_duration=Decimal('8.0'),
                work_days='Weekdays',
                is_active=True
            )

            # Test bulk assignment
            bulk_data = {
                'users': [self.test_employee1.id, self.test_employee2.id],
                'shift': bulk_shift.id,
                'effective_from': (date.today() + timedelta(days=2)).strftime('%Y-%m-%d'),
                'effective_to': (date.today() + timedelta(days=32)).strftime('%Y-%m-%d'),
                'reason': 'Bulk assignment test'
            }

            response = self.client.post(reverse('shift:bulk_assign'), bulk_data)

            if response.status_code in [200, 302]:
                assignment_count = ShiftAssignment.objects.filter(shift=bulk_shift).count()
                success = assignment_count == 2

                self.log_test("Bulk Assignment", success,
                            f"Created {assignment_count} assignments" if success else f"Expected 2, got {assignment_count}")
            else:
                self.log_test("Bulk Assignment", False, f"Failed with status {response.status_code}")

        except Exception as e:
            self.log_test("Bulk Assignment", False, f"Exception: {str(e)}")

    def test_api_endpoints(self):
        """Test API endpoints functionality"""
        print("\n=== Testing API Endpoints ===")

        # Create test shift for API testing
        api_shift = ShiftMaster.objects.create(
            name='API Test Shift',
            start_time=time(9, 0),
            end_time=time(17, 0),
            shift_duration=Decimal('8.0'),
            work_days='Weekdays',
            is_active=True
        )

        api_tests = [
            {
                'name': 'Shift Name Validation',
                'url': reverse('shift:api_validate_shift_name'),
                'method': 'POST',
                'data': json.dumps({'name': 'Unique API Test Name'}),
                'content_type': 'application/json'
            },
            {
                'name': 'Assignment Validation',
                'url': reverse('shift:api_validate_assignment'),
                'method': 'POST',
                'data': json.dumps({
                    'user_id': self.test_employee1.id,
                    'shift_id': api_shift.id,
                    'effective_from': (date.today() + timedelta(days=1)).strftime('%Y-%m-%d')
                }),
                'content_type': 'application/json'
            },
            {
                'name': 'Shift Details API',
                'url': reverse('shift:api_shift_details', kwargs={'shift_id': api_shift.id}),
                'method': 'GET',
                'data': None,
                'content_type': None
            },
            {
                'name': 'Dashboard Stats API',
                'url': reverse('shift:api_dashboard_stats'),
                'method': 'GET',
                'data': None,
                'content_type': None
            }
        ]

        for api_test in api_tests:
            try:
                if api_test['method'] == 'POST':
                    response = self.client.post(
                        api_test['url'],
                        api_test['data'],
                        content_type=api_test['content_type']
                    )
                else:
                    response = self.client.get(api_test['url'])

                success = response.status_code == 200

                if success:
                    try:
                        # Try to parse JSON response
                        json.loads(response.content)
                        self.log_test(f"API: {api_test['name']}", True, "Returns valid JSON response")
                    except json.JSONDecodeError:
                        self.log_test(f"API: {api_test['name']}", False, "Invalid JSON response")
                else:
                    self.log_test(f"API: {api_test['name']}", False, f"HTTP {response.status_code}")

            except Exception as e:
                self.log_test(f"API: {api_test['name']}", False, f"Exception: {str(e)}")

    def test_form_validation(self):
        """Test form validation logic"""
        print("\n=== Testing Form Validation ===")

        # Test ShiftForm validation
        valid_shift_data = {
            'name': 'Form Test Shift',
            'start_time': time(9, 0),
            'end_time': time(17, 0),
            'shift_duration': Decimal('8.0'),
            'work_days': 'Weekdays'
        }

        form = ShiftForm(data=valid_shift_data)
        is_valid = form.is_valid()
        self.log_test("ShiftForm Valid Data", is_valid,
                     "Form accepts valid data" if is_valid else f"Errors: {form.errors}")

        # Test invalid data
        invalid_shift_data = {
            'name': 'X',  # Too short
            'start_time': time(9, 0),
            'end_time': time(9, 15),  # Too short duration
            'shift_duration': Decimal('0.25'),
            'work_days': 'Weekdays'
        }

        form = ShiftForm(data=invalid_shift_data)
        is_invalid = not form.is_valid()
        self.log_test("ShiftForm Invalid Data", is_invalid,
                     "Form properly rejects invalid data" if is_invalid else "Should have rejected invalid data")

        # Test overlapping shifts (should be allowed now)
        ShiftMaster.objects.create(
            name='Existing Form Test Shift',
            start_time=time(9, 0),
            end_time=time(17, 0),
            shift_duration=Decimal('8.0'),
            work_days='Weekdays'
        )

        overlapping_shift_data = {
            'name': 'Overlapping Form Test Shift',
            'start_time': time(13, 0),  # Overlaps
            'end_time': time(21, 0),
            'shift_duration': Decimal('8.0'),
            'work_days': 'Weekdays'
        }

        form = ShiftForm(data=overlapping_shift_data)
        overlap_allowed = form.is_valid()
        self.log_test("Overlapping Shifts Allowed", overlap_allowed,
                     "Overlapping shifts are properly allowed" if overlap_allowed else f"Overlap rejected: {form.errors}")

    def test_assignment_validation(self):
        """Test assignment validation"""
        print("\n=== Testing Assignment Validation ===")

        # Create test shift
        assignment_test_shift = ShiftMaster.objects.create(
            name='Assignment Validation Test Shift',
            start_time=time(9, 0),
            end_time=time(17, 0),
            shift_duration=Decimal('8.0'),
            work_days='Weekdays'
        )

        # Test valid assignment
        valid_assignment_data = {
            'user': self.test_employee1.id,
            'shift': assignment_test_shift.id,
            'effective_from': date.today() + timedelta(days=1),
            'effective_to': date.today() + timedelta(days=30),
            'reason': 'Validation test'
        }

        form = ShiftAssignmentForm(data=valid_assignment_data)
        is_valid = form.is_valid()
        self.log_test("Assignment Form Valid", is_valid,
                     "Valid assignment accepted" if is_valid else f"Errors: {form.errors}")

        # Test assignment with past date
        invalid_assignment_data = {
            'user': self.test_employee1.id,
            'shift': assignment_test_shift.id,
            'effective_from': date.today() - timedelta(days=1),  # Past date
            'effective_to': date.today() + timedelta(days=30),
            'reason': 'Invalid validation test'
        }

        form = ShiftAssignmentForm(data=invalid_assignment_data)
        is_invalid = not form.is_valid()
        self.log_test("Assignment Form Past Date", is_invalid,
                     "Past date properly rejected" if is_invalid else "Should reject past dates")

    def test_frontend_backend_sync(self):
        """Test frontend and backend synchronization"""
        print("\n=== Testing Frontend-Backend Sync ===")

        # Test shift creation page renders
        try:
            response = self.client.get(reverse('shift:create'))
            renders = response.status_code == 200

            if renders:
                content = response.content.decode('utf-8')
                has_js_functions = all([
                    'function toggleCustomWorkDays()' in content,
                    'function validateForm()' in content,
                    'function calculateDuration()' in content,
                    'function validateShiftName(' in content
                ])

                self.log_test("Shift Form Rendering", has_js_functions,
                             "All required JS functions present" if has_js_functions else "Missing JS functions")
            else:
                self.log_test("Shift Form Rendering", False, f"Page failed to render: {response.status_code}")

        except Exception as e:
            self.log_test("Shift Form Rendering", False, f"Exception: {str(e)}")

        # Test assignment page renders
        try:
            response = self.client.get(reverse('shift:assign'))
            renders = response.status_code == 200
            self.log_test("Assignment Form Rendering", renders,
                         "Page renders successfully" if renders else f"Failed: {response.status_code}")

        except Exception as e:
            self.log_test("Assignment Form Rendering", False, f"Exception: {str(e)}")

    def test_csv_upload_functionality(self):
        """Test CSV upload functionality"""
        print("\n=== Testing CSV Upload ===")

        try:
            # Create test shift for CSV
            csv_shift = ShiftMaster.objects.create(
                name='CSV Upload Test Shift',
                start_time=time(9, 0),
                end_time=time(17, 0),
                shift_duration=Decimal('8.0'),
                work_days='Weekdays'
            )

            # Create CSV content
            start_date = (date.today() + timedelta(days=1)).strftime('%Y-%m-%d')
            end_date = (date.today() + timedelta(days=30)).strftime('%Y-%m-%d')

            csv_content = f"""username,shift_name,effective_from,effective_to,notes
test_employee1_validator,CSV Upload Test Shift,{start_date},{end_date},CSV test assignment
test_employee2_validator,CSV Upload Test Shift,{start_date},{end_date},CSV test assignment 2"""

            # Create temporary file
            from django.core.files.uploadedfile import SimpleUploadedFile
            csv_file = SimpleUploadedFile(
                "validator_test.csv",
                csv_content.encode('utf-8'),
                content_type="text/csv"
            )

            response = self.client.post(
                reverse('shift:csv_upload'),
                {'csv_file': csv_file}
            )

            success = response.status_code in [200, 302]

            if success:
                # Check assignments were created
                assignment_count = ShiftAssignment.objects.filter(shift=csv_shift).count()
                success = assignment_count >= 2

            self.log_test("CSV Upload", success,
                         f"CSV upload processed successfully, {assignment_count} assignments created" if success
                         else f"CSV upload failed or no assignments created")

        except Exception as e:
            self.log_test("CSV Upload", False, f"Exception: {str(e)}")

    def test_conflict_detection(self):
        """Test conflict detection with new policy"""
        print("\n=== Testing Conflict Detection ===")

        try:
            # Create overlapping shifts
            conflict_shift1 = ShiftMaster.objects.create(
                name='Conflict Test Shift 1',
                start_time=time(9, 0),
                end_time=time(17, 0),
                shift_duration=Decimal('8.0'),
                work_days='Weekdays'
            )

            conflict_shift2 = ShiftMaster.objects.create(
                name='Conflict Test Shift 2',
                start_time=time(13, 0),  # Overlaps
                end_time=time(21, 0),
                shift_duration=Decimal('8.0'),
                work_days='Weekdays'
            )

            # Create first assignment
            assignment1 = ShiftAssignment.objects.create(
                user=self.test_employee1,
                shift=conflict_shift1,
                effective_from=date.today() + timedelta(days=1),
                effective_to=date.today() + timedelta(days=30),
                is_current=True
            )

            # Test conflict detection
            conflicts = self.conflict_detector.check_assignment_conflicts(
                self.test_employee1,
                conflict_shift2,
                date.today() + timedelta(days=15),  # Overlapping period
                date.today() + timedelta(days=45)
            )

            # Conflicts should be detected
            conflicts_detected = len(conflicts) > 0
            self.log_test("Conflict Detection", conflicts_detected,
                         f"Detected {len(conflicts)} conflicts as expected" if conflicts_detected
                         else "No conflicts detected (should have detected overlaps)")

            # But assignment should still be allowed
            assignment2 = ShiftAssignment.objects.create(
                user=self.test_employee1,
                shift=conflict_shift2,
                effective_from=date.today() + timedelta(days=15),
                effective_to=date.today() + timedelta(days=45),
                is_current=True
            )

            assignment_created = assignment2 is not None
            self.log_test("Overlapping Assignment Allowed", assignment_created,
                         "Overlapping assignment created despite conflicts" if assignment_created
                         else "Failed to create overlapping assignment")

        except Exception as e:
            self.log_test("Conflict Detection", False, f"Exception: {str(e)}")

    def test_data_integrity(self):
        """Test data integrity and constraints"""
        print("\n=== Testing Data Integrity ===")

        try:
            # Test unique name constraint
            ShiftMaster.objects.create(
                name='Unique Test Shift',
                start_time=time(9, 0),
                end_time=time(17, 0),
                shift_duration=Decimal('8.0'),
                work_days='Weekdays'
            )

            # Try to create duplicate
            try:
                ShiftMaster.objects.create(
                    name='Unique Test Shift',  # Same name
                    start_time=time(10, 0),
                    end_time=time(18, 0),
                    shift_duration=Decimal('8.0'),
                    work_days='Weekdays'
                )
                self.log_test("Unique Name Constraint", False, "Duplicate name was allowed (should be blocked)")
            except Exception:
                self.log_test("Unique Name Constraint", True, "Duplicate name properly blocked")

        except Exception as e:
            self.log_test("Unique Name Constraint", False, f"Exception: {str(e)}")

    def test_user_interface_functionality(self):
        """Test user interface pages load correctly"""
        print("\n=== Testing User Interface ===")

        ui_pages = [
            ('Dashboard', reverse('shift:dashboard')),
            ('Shift List', reverse('shift:list')),
            ('Assignment List', reverse('shift:assignments')),
            ('Create Shift', reverse('shift:create')),
            ('Assign Shift', reverse('shift:assign')),
            ('Calendar', reverse('shift:calendar')),
            ('Statistics', reverse('shift:statistics')),
        ]

        for page_name, url in ui_pages:
            try:
                response = self.client.get(url)
                success = response.status_code == 200
                self.log_test(f"UI: {page_name}", success,
                             "Page loads successfully" if success else f"HTTP {response.status_code}")
            except Exception as e:
                self.log_test(f"UI: {page_name}", False, f"Exception: {str(e)}")

    def cleanup_test_data(self):
        """Clean up test data"""
        try:
            # Clean up in proper order to avoid constraint violations
            ShiftAssignment.objects.filter(
                user__username__contains='validator'
            ).delete()

            ShiftMaster.objects.filter(
                name__contains='Test'
            ).delete()

            User.objects.filter(
                username__contains='validator'
            ).delete()

            self.log_test("Cleanup Test Data", True, "Test data cleaned up successfully")

        except Exception as e:
            self.log_test("Cleanup Test Data", False, f"Cleanup failed: {str(e)}")

    def run_full_validation(self):
        """Run complete system validation"""
        print("=" * 60)
        print("TrueAlign Shift Management System Validation")
        print("=" * 60)

        # Setup
        if not self.setup_test_data():
            print("Failed to setup test data. Aborting validation.")
            return False

        # Run all tests
        try:
            self.test_shift_creation()
            self.test_overlapping_shifts_policy()
            self.test_assignment_functionality()
            self.test_bulk_assignment()
            self.test_api_endpoints()
            self.test_form_validation()
            self.test_assignment_validation()
            self.test_frontend_backend_sync()
            self.test_csv_upload_functionality()
            self.test_conflict_detection()
            self.test_data_integrity()
            self.test_user_interface_functionality()

        finally:
            # Always cleanup
            self.cleanup_test_data()

        # Print summary
        print("\n" + "=" * 60)
        print("VALIDATION SUMMARY")
        print("=" * 60)
        print(f"Tests Passed: {self.test_results['passed']}")
        print(f"Tests Failed: {self.test_results['failed']}")
        print(f"Warnings: {self.test_results['warnings']}")
        print(f"Total Tests: {sum([self.test_results['passed'], self.test_results['failed'], self.test_results['warnings']])}")

        if self.test_results['failed'] == 0:
            print("\n✅ ALL TESTS PASSED! System is working correctly.")
            return True
        else:
            print(f"\n❌ {self.test_results['failed']} TESTS FAILED. System needs attention.")
            print("\nFailed Tests:")
            for detail in self.test_results['details']:
                if detail['status'] == 'FAIL':
                    print(f"  - {detail['test']}: {detail['message']}")
            return False


class Command(BaseCommand):
    """Django management command for system validation"""
    help = 'Validate TrueAlign shift management system functionality'

    def add_arguments(self, parser):
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Enable verbose output',
        )

    def handle(self, *args, **options):
        """Handle the command"""
        if options['verbose']:
            logging.basicConfig(level=logging.DEBUG)

        validator = SystemValidator()
        success = validator.run_full_validation()

        if success:
            self.stdout.write(
                self.style.SUCCESS('System validation completed successfully!')
            )
        else:
            self.stdout.write(
                self.style.ERROR('System validation found issues that need attention.')
            )

        return success


def main():
    """Main function for standalone execution"""
    import django
    from django.conf import settings

    # Setup Django if not already configured
    if not settings.configured:
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
        django.setup()

    validator = SystemValidator()
    return validator.run_full_validation()


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
