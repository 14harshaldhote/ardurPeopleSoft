from django.core.management.base import BaseCommand
from django.contrib.auth.models import User, Group
from django.test import RequestFactory, Client
from django.urls import reverse
from django.utils import timezone
from django.http import JsonResponse
from trueAlign.models import GlobalUpdate
from trueAlign.notes.views import user_has_permission, global_update_ajax_status
import json


class Command(BaseCommand):
    help = 'Test global updates functionality and verify fixes'

    def add_arguments(self, parser):
        parser.add_argument(
            '--create-test-data',
            action='store_true',
            help='Create additional test data'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Enable verbose output'
        )

    def handle(self, *args, **options):
        self.verbose = options['verbose']
        self.stdout.write(self.style.SUCCESS('Testing Global Updates Functionality'))
        self.stdout.write('=' * 60)

        # Test 1: Check database state
        self.test_database_state()

        # Test 2: Check user roles and permissions
        self.test_user_permissions()

        # Test 3: Test AJAX endpoint functionality
        self.test_ajax_endpoints()

        # Test 4: Test view access permissions
        self.test_view_permissions()

        if options['create_test_data']:
            self.create_additional_test_data()

        self.stdout.write('\n' + '=' * 60)
        self.stdout.write(self.style.SUCCESS('Testing completed!'))

    def log(self, message, style=None):
        """Helper method for logging"""
        if style:
            self.stdout.write(style(message))
        else:
            self.stdout.write(message)

    def test_database_state(self):
        """Test the current state of global updates in database"""
        self.log('\n1. Testing Database State:', self.style.WARNING)

        total_updates = GlobalUpdate.objects.count()
        self.log(f'   Total Global Updates: {total_updates}')

        if total_updates == 0:
            self.log('   WARNING: No global updates found!', self.style.ERROR)
            return

        # Check updates by status
        for status, display_name in GlobalUpdate.STATUS_CHOICES:
            count = GlobalUpdate.objects.filter(status=status).count()
            self.log(f'   {display_name}: {count}')

        # Check for translation content
        updates_with_hindi = GlobalUpdate.objects.filter(
            title_hi__isnull=False, description_hi__isnull=False
        ).count()
        updates_with_marathi = GlobalUpdate.objects.filter(
            title_mr__isnull=False, description_mr__isnull=False
        ).count()

        self.log(f'   Updates with Hindi translation: {updates_with_hindi}')
        self.log(f'   Updates with Marathi translation: {updates_with_marathi}')

        # Test model methods
        sample_update = GlobalUpdate.objects.first()
        if sample_update:
            self.log(f'\n   Testing model methods on: "{sample_update.title}"')
            self.log(f'     English title: {sample_update.get_title("en")}')
            self.log(f'     Hindi title: {sample_update.get_title("hi")}')
            self.log(f'     Has Hindi translation: {sample_update.has_translation("hi")}')
            self.log(f'     Has Marathi translation: {sample_update.has_translation("mr")}')

    def test_user_permissions(self):
        """Test user permissions system"""
        self.log('\n2. Testing User Permissions:', self.style.WARNING)

        # Get test users
        test_users = {
            'hr': User.objects.filter(groups__name='HR').first(),
            'manager': User.objects.filter(groups__name='Manager').first(),
            'employee': User.objects.filter(groups__name='Employee').first(),
        }

        for role, user in test_users.items():
            if user:
                self.log(f'\n   Testing {role.upper()} user: {user.username}')

                # Test permissions
                can_view = user_has_permission(user, 'view')
                can_create = user_has_permission(user, 'create')
                can_update = user_has_permission(user, 'update')
                can_delete = user_has_permission(user, 'delete')

                self.log(f'     Can view: {can_view}')
                self.log(f'     Can create: {can_create}')
                self.log(f'     Can update: {can_update}')
                self.log(f'     Can delete: {can_delete}')

                # Test group membership
                user_groups = list(user.groups.values_list('name', flat=True))
                self.log(f'     Groups: {user_groups}')
            else:
                self.log(f'   No {role.upper()} user found!', self.style.ERROR)

    def test_ajax_endpoints(self):
        """Test AJAX endpoints with different user contexts"""
        self.log('\n3. Testing AJAX Endpoints:', self.style.WARNING)

        factory = RequestFactory()
        test_users = {
            'hr': User.objects.filter(groups__name='HR').first(),
            'manager': User.objects.filter(groups__name='Manager').first(),
            'employee': User.objects.filter(groups__name='Employee').first(),
        }

        for role, user in test_users.items():
            if not user:
                self.log(f'   No {role.upper()} user found, skipping', self.style.ERROR)
                continue

            self.log(f'\n   Testing AJAX for {role.upper()} user: {user.username}')

            # Create mock request
            request = factory.get('/notes/ajax/status/?lang=en&limit=5')
            request.user = user

            try:
                response = global_update_ajax_status(request)

                if hasattr(response, 'content'):
                    data = json.loads(response.content.decode('utf-8'))

                    self.log(f'     Response status: {response.status_code}')
                    self.log(f'     Success: {data.get("success", False)}')

                    if data.get('success'):
                        updates_count = len(data.get('updates', []))
                        self.log(f'     Updates returned: {updates_count}')
                        self.log(f'     Can view: {data.get("can_view", False)}')
                        self.log(f'     Is HR: {data.get("is_hr", False)}')
                        self.log(f'     Is Manager: {data.get("is_manager", False)}')
                        self.log(f'     Is Employee: {data.get("is_employee", False)}')

                        # Show update counts
                        counts = data.get('counts', {})
                        self.log(f'     Update counts: Released={counts.get("released", 0)}, '
                               f'Upcoming={counts.get("upcoming", 0)}, '
                               f'Scheduled={counts.get("scheduled", 0)}')
                    else:
                        error_msg = data.get('error', 'Unknown error')
                        self.log(f'     Error: {error_msg}', self.style.ERROR)

            except Exception as e:
                self.log(f'     Exception: {str(e)}', self.style.ERROR)

    def test_view_permissions(self):
        """Test view access permissions using Django test client"""
        self.log('\n4. Testing View Access Permissions:', self.style.WARNING)

        client = Client()
        test_users = {
            'hr': User.objects.filter(groups__name='HR').first(),
            'manager': User.objects.filter(groups__name='Manager').first(),
            'employee': User.objects.filter(groups__name='Employee').first(),
        }

        # Test URLs
        test_urls = {
            'list': reverse('notes:global_update_list'),
            'ajax_status': reverse('notes:global_update_ajax_status'),
        }

        # Test create URL only if we have updates
        if GlobalUpdate.objects.exists():
            first_update = GlobalUpdate.objects.first()
            test_urls['detail'] = reverse('notes:global_update_detail', args=[first_update.pk])

        for role, user in test_users.items():
            if not user:
                continue

            self.log(f'\n   Testing view access for {role.upper()}: {user.username}')
            client.force_login(user)

            for url_name, url in test_urls.items():
                try:
                    response = client.get(url)
                    status_code = response.status_code

                    if status_code == 200:
                        status_msg = self.style.SUCCESS(f'✓ {status_code}')
                    elif status_code == 302:
                        status_msg = self.style.WARNING(f'→ {status_code} (redirect)')
                    elif status_code == 403:
                        status_msg = self.style.ERROR(f'✗ {status_code} (forbidden)')
                    else:
                        status_msg = f'{status_code}'

                    self.log(f'     {url_name}: {status_msg}')

                    # For AJAX endpoint, also check JSON response
                    if url_name == 'ajax_status' and status_code == 200:
                        try:
                            data = response.json()
                            success = data.get('success', False)
                            updates_count = len(data.get('updates', []))
                            self.log(f'       → Success: {success}, Updates: {updates_count}')
                        except:
                            self.log(f'       → Could not parse JSON response')

                except Exception as e:
                    self.log(f'     {url_name}: ERROR - {str(e)}', self.style.ERROR)

            client.logout()

    def create_additional_test_data(self):
        """Create additional test data if needed"""
        self.log('\n5. Creating Additional Test Data:', self.style.WARNING)

        # Ensure we have test users
        self.ensure_test_users()

        # Create some additional updates if we have less than 5
        current_count = GlobalUpdate.objects.count()
        if current_count < 5:
            self.create_sample_updates(5 - current_count)
        else:
            self.log('   Sufficient test data already exists')

    def ensure_test_users(self):
        """Ensure test users exist with proper groups"""
        groups_to_create = ['HR', 'Manager', 'Employee']

        for group_name in groups_to_create:
            group, created = Group.objects.get_or_create(name=group_name)
            if created:
                self.log(f'   Created group: {group_name}')

        # Test users to ensure exist
        test_users = [
            ('hr_test', 'HR Test', 'HR'),
            ('manager_test', 'Manager Test', 'Manager'),
            ('employee_test', 'Employee Test', 'Employee'),
        ]

        for username, full_name, group_name in test_users:
            user, created = User.objects.get_or_create(
                username=username,
                defaults={
                    'first_name': full_name.split()[0],
                    'last_name': full_name.split()[1],
                    'email': f'{username}@company.com'
                }
            )

            if created:
                user.set_password('test123')
                user.save()
                self.log(f'   Created user: {username}')

            # Ensure user is in correct group
            group = Group.objects.get(name=group_name)
            if not user.groups.filter(name=group_name).exists():
                user.groups.add(group)
                self.log(f'   Added {username} to {group_name} group')

    def create_sample_updates(self, count):
        """Create sample updates"""
        hr_user = User.objects.filter(groups__name='HR').first()
        if not hr_user:
            self.log('   No HR user found to create updates', self.style.ERROR)
            return

        sample_data = [
            {
                'title': 'System Maintenance Scheduled',
                'description': 'Scheduled system maintenance will occur this weekend.',
                'status': 'scheduled',
                'scheduled_date': timezone.now() + timezone.timedelta(days=2)
            },
            {
                'title': 'New Policy Update',
                'description': 'Please review the updated company policies.',
                'status': 'released'
            },
            {
                'title': 'Upcoming Training Session',
                'description': 'Professional development training is coming soon.',
                'status': 'upcoming'
            },
        ]

        created = 0
        for i in range(min(count, len(sample_data))):
            data = sample_data[i]

            # Check if similar update exists
            if not GlobalUpdate.objects.filter(title=data['title']).exists():
                GlobalUpdate.objects.create(
                    title=data['title'],
                    description=data['description'],
                    status=data['status'],
                    scheduled_date=data.get('scheduled_date'),
                    primary_language='en',
                    managed_by=hr_user
                )
                created += 1
                self.log(f'   Created update: {data["title"]}')

        self.log(f'   Total new updates created: {created}')
