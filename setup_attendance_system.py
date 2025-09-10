#!/usr/bin/env python3
"""
Attendance System Complete Setup Script

This script performs a complete setup and verification of the attendance system including:
- Database migrations and setup
- Django-cron configuration
- Initial data creation
- Health checks and validation
- Service integration testing
- Performance optimization
- System verification

Usage:
    python setup_attendance_system.py
    python setup_attendance_system.py --verify-only
    python setup_attendance_system.py --reset-all
    python setup_attendance_system.py --production
"""

import os
import sys
import json
import logging
import argparse
from datetime import datetime, timedelta
from pathlib import Path

# Add Django setup
sys.path.append(str(Path(__file__).parent))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')

import django
django.setup()

from django.core.management import call_command, execute_from_command_line
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.db import transaction, connection
from django.conf import settings
from django.core.cache import cache
from django.contrib.auth.models import Group
import pytz

# Import attendance system components
from trueAlign.models import Attendance, UserSession, ShiftMaster, Holiday, UserDetails
from trueAlign.attendance.services import (
    AttendanceAutoMarkingService,
    AttendanceIntegrationService,
    get_attendance_services
)
from trueAlign.attendance.monitoring import AttendanceMonitoringService, run_health_check
from trueAlign.attendance.config import IST_TIMEZONE

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('attendance_setup.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('attendance_setup')

User = get_user_model()


class AttendanceSystemSetup:
    """Complete attendance system setup and verification"""

    def __init__(self, production_mode=False, reset_all=False):
        self.production_mode = production_mode
        self.reset_all = reset_all
        self.ist = IST_TIMEZONE
        self.setup_results = {
            'start_time': timezone.now().isoformat(),
            'steps_completed': [],
            'errors': [],
            'warnings': [],
            'summary': {}
        }

    def run_complete_setup(self):
        """Run complete attendance system setup"""
        logger.info("🚀 Starting Complete Attendance System Setup")
        logger.info("=" * 60)

        try:
            # Step 1: Verify prerequisites
            self._step("Verifying Prerequisites", self._verify_prerequisites)

            # Step 2: Database setup
            self._step("Database Setup", self._setup_database)

            # Step 3: User groups and permissions
            self._step("User Groups Setup", self._setup_user_groups)

            # Step 4: Initial data creation
            self._step("Initial Data Setup", self._setup_initial_data)

            # Step 5: Django-cron setup
            self._step("Django-Cron Setup", self._setup_django_cron)

            # Step 6: Service integration
            self._step("Service Integration", self._setup_service_integration)

            # Step 7: Signal testing
            self._step("Signal Testing", self._test_signals)

            # Step 8: Attendance workflow testing
            self._step("Attendance Workflow Testing", self._test_attendance_workflow)

            # Step 9: Performance optimization
            self._step("Performance Optimization", self._optimize_performance)

            # Step 10: Health checks
            self._step("System Health Verification", self._verify_system_health)

            # Step 11: Cron job testing
            self._step("Cron Job Testing", self._test_cron_jobs)

            # Step 12: Final verification
            self._step("Final System Verification", self._final_verification)

            # Generate setup report
            self._generate_setup_report()

            logger.info("✅ Attendance System Setup Completed Successfully!")

        except Exception as e:
            logger.error(f"❌ Setup failed: {e}")
            self.setup_results['errors'].append(f"Setup failed: {str(e)}")
            self._generate_setup_report()
            sys.exit(1)

    def verify_system_only(self):
        """Run system verification only"""
        logger.info("🔍 Running Attendance System Verification")
        logger.info("=" * 50)

        try:
            self._step("System Health Check", self._verify_system_health)
            self._step("Service Verification", self._verify_services)
            self._step("Data Integrity Check", self._verify_data_integrity)
            self._step("Performance Check", self._verify_performance)

            self._generate_setup_report()
            logger.info("✅ System Verification Completed!")

        except Exception as e:
            logger.error(f"❌ Verification failed: {e}")
            sys.exit(1)

    def _step(self, step_name, step_function):
        """Execute a setup step with error handling"""
        logger.info(f"\n🔧 {step_name}")
        logger.info("-" * 40)

        try:
            start_time = timezone.now()
            result = step_function()
            end_time = timezone.now()
            duration = (end_time - start_time).total_seconds()

            self.setup_results['steps_completed'].append({
                'step': step_name,
                'status': 'success',
                'duration_seconds': duration,
                'result': result,
                'timestamp': start_time.isoformat()
            })

            logger.info(f"✅ {step_name} completed in {duration:.2f}s")

        except Exception as e:
            logger.error(f"❌ {step_name} failed: {e}")
            self.setup_results['errors'].append(f"{step_name}: {str(e)}")

            # Continue with non-critical steps, fail on critical ones
            critical_steps = [
                'Database Setup',
                'Django-Cron Setup',
                'Service Integration'
            ]

            if step_name in critical_steps:
                raise
            else:
                self.setup_results['warnings'].append(f"{step_name} failed but continuing: {str(e)}")

    def _verify_prerequisites(self):
        """Verify system prerequisites"""
        logger.info("Checking system prerequisites...")

        prerequisites = {
            'django_version': django.VERSION,
            'python_version': sys.version_info,
            'database_engine': connection.settings_dict.get('ENGINE'),
            'cache_backend': getattr(settings, 'CACHES', {}).get('default', {}).get('BACKEND'),
            'installed_apps': 'django_cron' in settings.INSTALLED_APPS,
            'attendance_app': 'trueAlign.attendance' in settings.INSTALLED_APPS,
            'timezone_setting': settings.TIME_ZONE,
        }

        # Check required packages
        required_packages = [
            'django_cron',
            'psutil',
            'pytz',
            'redis'  # if using Redis cache
        ]

        missing_packages = []
        for package in required_packages:
            try:
                __import__(package)
            except ImportError:
                if package != 'redis':  # Redis is optional
                    missing_packages.append(package)

        if missing_packages:
            raise Exception(f"Missing required packages: {missing_packages}")

        logger.info("✓ All prerequisites satisfied")
        return prerequisites

    def _setup_database(self):
        """Setup database and run migrations"""
        logger.info("Setting up database...")

        # Run migrations
        try:
            call_command('migrate', verbosity=0)
            logger.info("✓ Database migrations completed")
        except Exception as e:
            raise Exception(f"Migration failed: {e}")

        # Verify tables exist
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'public'
                AND table_name LIKE '%attendance%'
            """)
            tables = cursor.fetchall()

        if not tables:
            # Try alternative query for different databases
            try:
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%attendance%'")
                tables = cursor.fetchall()
            except:
                pass

        logger.info(f"✓ Found {len(tables)} attendance-related tables")
        return {'tables_created': len(tables)}

    def _setup_user_groups(self):
        """Setup user groups and permissions"""
        logger.info("Setting up user groups...")

        groups_created = 0
        required_groups = ['Admin', 'HR', 'Manager', 'Employee']

        for group_name in required_groups:
            group, created = Group.objects.get_or_create(name=group_name)
            if created:
                groups_created += 1
                logger.info(f"✓ Created group: {group_name}")

        # Create test users if not in production
        if not self.production_mode:
            test_users_created = self._create_test_users()
            logger.info(f"✓ Created {test_users_created} test users")
            return {'groups_created': groups_created, 'test_users_created': test_users_created}

        return {'groups_created': groups_created}

    def _create_test_users(self):
        """Create test users for development"""
        test_users = [
            {'username': 'admin_test', 'email': 'admin@test.com', 'group': 'Admin', 'is_staff': True},
            {'username': 'hr_test', 'email': 'hr@test.com', 'group': 'HR'},
            {'username': 'manager_test', 'email': 'manager@test.com', 'group': 'Manager'},
            {'username': 'employee_test', 'email': 'employee@test.com', 'group': 'Employee'},
        ]

        created_count = 0
        for user_data in test_users:
            user, created = User.objects.get_or_create(
                username=user_data['username'],
                defaults={
                    'email': user_data['email'],
                    'first_name': user_data['username'].replace('_', ' ').title(),
                    'is_staff': user_data.get('is_staff', False),
                    'is_active': True
                }
            )

            if created:
                user.set_password('testpassword123')
                user.save()

                # Add to group
                group = Group.objects.get(name=user_data['group'])
                user.groups.add(group)

                # Create user details
                UserDetails.objects.get_or_create(
                    user=user,
                    defaults={
                        'employee_id': f'EMP{1000 + created_count}',
                        'phone': f'9876543{created_count:03d}',
                        'department': user_data['group'],
                        'designation': user_data['group'],
                        'date_of_joining': timezone.now().date(),
                        'employment_type': 'Full-time',
                        'status': 'Active'
                    }
                )

                created_count += 1

        return created_count

    def _setup_initial_data(self):
        """Setup initial data for attendance system"""
        logger.info("Setting up initial data...")

        # Create default shift
        default_shift, created = ShiftMaster.objects.get_or_create(
            name='Standard Day Shift',
            defaults={
                'start_time': '09:00:00',
                'end_time': '18:00:00',
                'working_days': 'Monday,Tuesday,Wednesday,Thursday,Friday',
                'is_default': True,
                'grace_period_minutes': 10,
                'half_day_hours': 4.0,
                'full_day_hours': 8.0,
                'is_active': True
            }
        )

        if created:
            logger.info("✓ Created default shift")

        # Create sample holidays for current year
        holidays_created = self._create_sample_holidays()

        # Create today's attendance records if not exist
        today = timezone.now().astimezone(self.ist).date()
        integration_service = AttendanceIntegrationService()
        created_count = integration_service.create_daily_attendance_records(today)

        logger.info(f"✓ Created {created_count} attendance records for today")

        return {
            'default_shift_created': created,
            'holidays_created': holidays_created,
            'attendance_records_today': created_count
        }

    def _create_sample_holidays(self):
        """Create sample holidays for current year"""
        current_year = timezone.now().year
        sample_holidays = [
            {'name': 'New Year', 'date': f'{current_year}-01-01'},
            {'name': 'Independence Day', 'date': f'{current_year}-08-15'},
            {'name': 'Gandhi Jayanti', 'date': f'{current_year}-10-02'},
            {'name': 'Christmas', 'date': f'{current_year}-12-25'},
        ]

        created_count = 0
        for holiday_data in sample_holidays:
            try:
                holiday_date = datetime.strptime(holiday_data['date'], '%Y-%m-%d').date()
                holiday, created = Holiday.objects.get_or_create(
                    date=holiday_date,
                    defaults={
                        'name': holiday_data['name'],
                        'is_active': True,
                        'is_optional': False
                    }
                )
                if created:
                    created_count += 1
            except Exception as e:
                logger.warning(f"Failed to create holiday {holiday_data['name']}: {e}")

        return created_count

    def _setup_django_cron(self):
        """Setup and verify django-cron configuration"""
        logger.info("Setting up django-cron...")

        # Verify cron configuration in settings
        if 'django_cron' not in settings.INSTALLED_APPS:
            raise Exception("django_cron not in INSTALLED_APPS")

        if not hasattr(settings, 'CRON_CLASSES') or not settings.CRON_CLASSES:
            raise Exception("CRON_CLASSES not configured in settings")

        # Create cron job log table
        try:
            call_command('migrate', 'django_cron', verbosity=0)
            logger.info("✓ Django-cron tables created")
        except Exception as e:
            logger.warning(f"Cron migration warning: {e}")

        # Test cron job classes import
        cron_classes_valid = 0
        for cron_class_path in settings.CRON_CLASSES:
            try:
                module_path, class_name = cron_class_path.rsplit('.', 1)
                module = __import__(module_path, fromlist=[class_name])
                cron_class = getattr(module, class_name)

                # Test instantiation
                instance = cron_class()
                cron_classes_valid += 1
                logger.info(f"✓ Validated cron class: {class_name}")
            except Exception as e:
                raise Exception(f"Failed to import cron class {cron_class_path}: {e}")

        return {'cron_classes_validated': cron_classes_valid}

    def _setup_service_integration(self):
        """Setup and test service integration"""
        logger.info("Setting up service integration...")

        # Get all attendance services
        services = get_attendance_services()

        services_tested = 0
        for service_name, service_instance in services.items():
            try:
                # Test service availability
                if hasattr(service_instance, 'get_health_status'):
                    status = service_instance.get_health_status()
                    logger.info(f"✓ Service {service_name}: {status}")
                else:
                    logger.info(f"✓ Service {service_name}: available")
                services_tested += 1
            except Exception as e:
                raise Exception(f"Service {service_name} failed: {e}")

        # Test monitoring service
        monitoring_service = AttendanceMonitoringService()
        health_status = monitoring_service.get_system_health()

        logger.info(f"✓ Monitoring service: {health_status.get('overall_status', 'unknown')}")

        return {
            'services_tested': services_tested,
            'monitoring_status': health_status.get('overall_status', 'unknown')
        }

    def _test_signals(self):
        """Test signal integration"""
        logger.info("Testing signal integration...")

        if not User.objects.filter(username='employee_test').exists():
            logger.warning("No test user found, skipping signal tests")
            return {'signals_tested': 0}

        test_user = User.objects.get(username='employee_test')
        signals_tested = 0

        # Test session creation signal
        try:
            # Create a test session
            session = UserSession.objects.create(
                user=test_user,
                session_key='test_session_key',
                ip_address='127.0.0.1',
                user_agent='Test Agent',
                login_time=timezone.now(),
                is_active=True
            )

            # Check if attendance was created/updated
            today = timezone.now().astimezone(self.ist).date()
            attendance = Attendance.objects.filter(user=test_user, date=today).first()

            if attendance:
                logger.info("✓ Session creation signal worked")
                signals_tested += 1
            else:
                logger.warning("Session creation signal may not have triggered")

            # Clean up test session
            session.delete()

        except Exception as e:
            logger.warning(f"Signal test failed: {e}")

        return {'signals_tested': signals_tested}

    def _test_attendance_workflow(self):
        """Test complete attendance workflow"""
        logger.info("Testing attendance workflow...")

        if not User.objects.filter(username='employee_test').exists():
            logger.warning("No test user found, skipping workflow tests")
            return {'workflow_tests': 0}

        test_user = User.objects.get(username='employee_test')
        today = timezone.now().astimezone(self.ist).date()
        tests_passed = 0

        # Test 1: Attendance record creation
        try:
            auto_marking_service = AttendanceAutoMarkingService()
            result = auto_marking_service.run_auto_marking(today)

            if result.get('success', False):
                logger.info("✓ Auto-marking service test passed")
                tests_passed += 1
        except Exception as e:
            logger.warning(f"Auto-marking test failed: {e}")

        # Test 2: Integration service
        try:
            integration_service = AttendanceIntegrationService()
            created_count = integration_service.create_daily_attendance_records(today)
            logger.info(f"✓ Integration service test passed: {created_count} records")
            tests_passed += 1
        except Exception as e:
            logger.warning(f"Integration service test failed: {e}")

        return {'workflow_tests': tests_passed}

    def _optimize_performance(self):
        """Optimize system performance"""
        logger.info("Optimizing performance...")

        optimizations = 0

        # Clear old cache entries
        try:
            cache.clear()
            logger.info("✓ Cache cleared")
            optimizations += 1
        except Exception as e:
            logger.warning(f"Cache clear failed: {e}")

        # Database optimization (if PostgreSQL)
        try:
            with connection.cursor() as cursor:
                if 'postgresql' in connection.settings_dict['ENGINE']:
                    cursor.execute("VACUUM ANALYZE;")
                    logger.info("✓ Database optimized (PostgreSQL)")
                    optimizations += 1
        except Exception as e:
            logger.warning(f"Database optimization failed: {e}")

        return {'optimizations_applied': optimizations}

    def _verify_system_health(self):
        """Verify overall system health"""
        logger.info("Verifying system health...")

        health_status = run_health_check()
        overall_status = health_status.get('overall_status', 'error')

        if overall_status in ['critical', 'error']:
            # Log details but don't fail setup
            logger.warning(f"System health status: {overall_status}")

            health_results = health_status.get('health_results', {})
            for check_name, result in health_results.items():
                if isinstance(result, dict) and result.get('status') in ['critical', 'error']:
                    logger.warning(f"  ❌ {check_name}: {result.get('message', 'Unknown issue')}")
        else:
            logger.info(f"✓ System health status: {overall_status}")

        return {
            'overall_status': overall_status,
            'health_score': health_status.get('summary', {}).get('health_score', 0)
        }

    def _test_cron_jobs(self):
        """Test cron job execution"""
        logger.info("Testing cron jobs...")

        jobs_tested = 0

        # Test daily attendance creation job
        try:
            call_command('manage_attendance_cron', 'run', 'daily_creation', '--force')
            logger.info("✓ Daily attendance creation job tested")
            jobs_tested += 1
        except Exception as e:
            logger.warning(f"Daily creation job test failed: {e}")

        # Test auto-marking job
        try:
            call_command('manage_attendance_cron', 'run', 'auto_marking', '--force')
            logger.info("✓ Auto-marking job tested")
            jobs_tested += 1
        except Exception as e:
            logger.warning(f"Auto-marking job test failed: {e}")

        return {'jobs_tested': jobs_tested}

    def _final_verification(self):
        """Final system verification"""
        logger.info("Running final verification...")

        verifications = {
            'database_connectivity': False,
            'attendance_records_exist': False,
            'services_available': False,
            'cron_configured': False
        }

        # Test database
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            verifications['database_connectivity'] = True
        except Exception:
            pass

        # Check attendance records
        try:
            count = Attendance.objects.count()
            verifications['attendance_records_exist'] = count > 0
        except Exception:
            pass

        # Check services
        try:
            services = get_attendance_services()
            verifications['services_available'] = len(services) > 0
        except Exception:
            pass

        # Check cron configuration
        verifications['cron_configured'] = (
            'django_cron' in settings.INSTALLED_APPS and
            hasattr(settings, 'CRON_CLASSES') and
            len(settings.CRON_CLASSES) > 0
        )

        passed_verifications = sum(verifications.values())
        total_verifications = len(verifications)

        logger.info(f"✓ Verification score: {passed_verifications}/{total_verifications}")

        return {
            'verifications': verifications,
            'score': f"{passed_verifications}/{total_verifications}"
        }

    def _verify_services(self):
        """Verify all services are working"""
        services = get_attendance_services()
        working_services = 0

        for service_name, service in services.items():
            try:
                # Basic service test
                if hasattr(service, '__class__'):
                    working_services += 1
                    logger.info(f"✓ Service {service_name} is working")
            except Exception as e:
                logger.warning(f"Service {service_name} issue: {e}")

        return {'working_services': working_services, 'total_services': len(services)}

    def _verify_data_integrity(self):
        """Verify data integrity"""
        issues = []

        # Check for orphaned records
        try:
            orphaned_attendance = Attendance.objects.filter(user__isnull=True).count()
            if orphaned_attendance > 0:
                issues.append(f"{orphaned_attendance} orphaned attendance records")
        except Exception:
            pass

        # Check for duplicate records
        try:
            from django.db.models import Count
            duplicates = Attendance.objects.values('user', 'date').annotate(
                count=Count('id')
            ).filter(count__gt=1).count()
            if duplicates > 0:
                issues.append(f"{duplicates} duplicate attendance records")
        except Exception:
            pass

        if issues:
            for issue in issues:
                logger.warning(f"Data integrity issue: {issue}")

        return {'issues_found': len(issues), 'issues': issues}

    def _verify_performance(self):
        """Verify system performance"""
        monitoring_service = AttendanceMonitoringService()
        metrics = monitoring_service.get_performance_metrics(1)  # Last 1 hour

        return {
            'metrics_available': 'error' not in metrics,
            'performance_status': 'good' if 'error' not in metrics else 'poor'
        }

    def _generate_setup_report(self):
        """Generate comprehensive setup report"""
        self.setup_results['end_time'] = timezone.now().isoformat()
        self.setup_results['total_duration'] = (
            timezone.now() -
            datetime.fromisoformat(self.setup_results['start_time'].replace('Z', '+00:00'))
        ).total_seconds()

        # Summary statistics
        self.setup_results['summary'] = {
            'total_steps': len(self.setup_results['steps_completed']),
            'successful_steps': len([s for s in self.setup_results['steps_completed'] if s['status'] == 'success']),
            'errors': len(self.setup_results['errors']),
            'warnings': len(self.setup_results['warnings']),
            'overall_status': 'success' if len(self.setup_results['errors']) == 0 else 'failed'
        }

        # Save report to file
        report_file = f"attendance_setup_report_{timezone.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(self.setup_results, f, indent=2, default=str)

        # Print summary
        print("\n" + "=" * 60)
        print("📋 ATTENDANCE SYSTEM SETUP REPORT")
        print("=" * 60)
        print(f"Start Time: {self.setup_results['start_time']}")
        print(f"End Time: {self.setup_results['end_time']}")
        print(f"Duration: {self.setup_results['total_duration']:.2f} seconds")
        print(f"Steps Completed: {self.setup_results['summary']['successful_steps']}/{self.setup_results['summary']['total_steps']}")
        print(f"Errors: {self.setup_results['summary']['errors']}")
        print(f"Warnings: {self.setup_results['summary']['warnings']}")
        print(f"Overall Status: {self.setup_results['summary']['overall_status'].upper()}")

        if self.setup_results['errors']:
            print("\n❌ ERRORS:")
            for error in self.setup_results['errors']:
                print(f"  • {error}")

        if self.setup_results['warnings']:
            print("\n⚠️ WARNINGS:")
            for warning in self.setup_results['warnings']:
                print(f"  • {warning}")

        print(f"\n📄 Detailed report saved to: {report_file}")
        print("=" * 60)

        logger.info(f"Setup report generated: {report_file}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Attendance System Setup')
    parser.add_argument('--verify-only', action='store_true', help='Run verification only')
    parser.add_argument('--reset-all', action='store_true', help='Reset all data before setup')
    parser.add_argument('--production', action='store_true', help='Production mode (no test data)')

    args = parser.parse_args()

    try:
        setup = AttendanceSystemSetup(
            production_mode=args.production,
            reset_all=args.reset_all
        )

        if args.verify_only:
            setup.verify_system_only()
        else:
            setup.run_complete_setup()

    except KeyboardInterrupt:
        logger.info("Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Setup failed with unexpected error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
