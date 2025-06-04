from django.test import TestCase, Client
from django.contrib.auth.models import User, Group
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone
from datetime import datetime, timedelta
from unittest.mock import patch, Mock
import json
from .models import Support, TicketComment, TicketAttachment, TicketActivity, StatusLog, TicketFieldChange
from .forms import TicketForm, CommentForm, TicketAttachmentForm


class SupportViewsTestCase(TestCase):
    """Comprehensive test cases for support views covering all possible scenarios"""

    def setUp(self):
        """Set up test data and users with different roles"""
        # Create groups
        self.admin_group = Group.objects.create(name='Admin')
        self.hr_group = Group.objects.create(name='HR')
        self.manager_group = Group.objects.create(name='Manager')
        self.employee_group = Group.objects.create(name='Employee')
        self.it_group = Group.objects.create(name='IT')

        # Create users with different roles
        self.admin_user = User.objects.create_user(
            username='admin', email='admin@test.com', password='testpass123',
            first_name='Admin', last_name='User'
        )
        self.admin_user.groups.add(self.admin_group)
        self.admin_user.is_superuser = True
        self.admin_user.save()

        self.hr_user = User.objects.create_user(
            username='hr', email='hr@test.com', password='testpass123',
            first_name='HR', last_name='User'
        )
        self.hr_user.groups.add(self.hr_group)

        self.manager_user = User.objects.create_user(
            username='manager', email='manager@test.com', password='testpass123',
            first_name='Manager', last_name='User'
        )
        self.manager_user.groups.add(self.manager_group)

        self.employee_user = User.objects.create_user(
            username='employee', email='employee@test.com', password='testpass123',
            first_name='Employee', last_name='User'
        )
        self.employee_user.groups.add(self.employee_group)

        self.it_user = User.objects.create_user(
            username='it', email='it@test.com', password='testpass123',
            first_name='IT', last_name='User'
        )
        self.it_user.groups.add(self.it_group)

        # Create another employee for manager testing
        self.managed_employee = User.objects.create_user(
            username='managed_emp', email='managed@test.com', password='testpass123'
        )
        self.managed_employee.groups.add(self.employee_group)

        # Create test tickets with various statuses and priorities
        self.ticket1 = Support.objects.create(
            user=self.employee_user,
            subject='Test Ticket 1',
            description='Test description 1',
            priority=Support.Priority.HIGH,
            status=Support.Status.NEW,
            issue_type=Support.IssueType.ACCESS,
            assigned_group=Support.AssignedGroup.HR,
            assigned_to_user=self.hr_user
        )

        self.ticket2 = Support.objects.create(
            user=self.managed_employee,
            subject='Test Ticket 2',
            description='Test description 2',
            priority=Support.Priority.MEDIUM,
            status=Support.Status.IN_PROGRESS,
            issue_type=Support.IssueType.INTERNET,
            assigned_group=Support.AssignedGroup.ADMIN,
            assigned_to_user=self.it_user
        )

        self.closed_ticket = Support.objects.create(
            user=self.employee_user,
            subject='Closed Ticket',
            description='Closed ticket description',
            priority=Support.Priority.LOW,
            status=Support.Status.CLOSED,
            closed_at=timezone.now() - timedelta(days=35)
        )

        # Create ticket with SLA breach
        self.sla_breached_ticket = Support.objects.create(
            user=self.employee_user,
            subject='SLA Breached Ticket',
            description='This ticket has breached SLA',
            priority=Support.Priority.CRITICAL,
            status=Support.Status.OPEN,
            sla_target_date=timezone.now() - timedelta(hours=2),
            sla_status=Support.SLAStatus.BREACHED
        )

        self.client = Client()


class TicketListViewTests(SupportViewsTestCase):
    """Test cases for ticket_list view"""

    def test_ticket_list_unauthenticated(self):
        """Test that unauthenticated users are redirected to login"""
        response = self.client.get(reverse('aps_support:ticket_list'))
        self.assertRedirects(response, '/accounts/login/?next=' + reverse('aps_support:ticket_list'))

    def test_admin_sees_all_tickets(self):
        """Test that admin users can see all tickets"""
        self.client.login(username='admin', password='testpass123')
        response = self.client.get(reverse('aps_support:ticket_list'))
        self.assertEqual(response.status_code, 200)
        tickets = response.context['page_obj'].object_list
        self.assertEqual(len(tickets), 4)  # All created tickets

    def test_hr_sees_hr_and_own_tickets(self):
        """Test that HR users see HR assigned tickets and their own"""
        self.client.login(username='hr', password='testpass123')
        response = self.client.get(reverse('aps_support:ticket_list'))
        self.assertEqual(response.status_code, 200)
        tickets = response.context['page_obj'].object_list
        # Should see ticket1 (assigned to HR)
        ticket_ids = [t.id for t in tickets]
        self.assertIn(self.ticket1.id, ticket_ids)
        self.assertNotIn(self.ticket2.id, ticket_ids)

    def test_manager_sees_team_tickets(self):
        """Test that managers see their team's tickets"""
        # Set up manager relationship
        self.managed_employee.department = type('Department', (), {'manager': self.manager_user})
        self.managed_employee.save()

        self.client.login(username='manager', password='testpass123')
        response = self.client.get(reverse('aps_support:ticket_list'))
        self.assertEqual(response.status_code, 200)

    def test_employee_sees_own_tickets_only(self):
        """Test that employees see only their own tickets"""
        self.client.login(username='employee', password='testpass123')
        response = self.client.get(reverse('aps_support:ticket_list'))
        self.assertEqual(response.status_code, 200)
        tickets = response.context['page_obj'].object_list
        for ticket in tickets:
            self.assertEqual(ticket.user, self.employee_user)

    def test_status_filtering(self):
        """Test ticket filtering by status"""
        self.client.login(username='admin', password='testpass123')
        response = self.client.get(reverse('aps_support:ticket_list'), {'status': 'New'})
        self.assertEqual(response.status_code, 200)
        tickets = response.context['page_obj'].object_list
        for ticket in tickets:
            self.assertEqual(ticket.status, Support.Status.NEW)

    def test_priority_filtering(self):
        """Test ticket filtering by priority"""
        self.client.login(username='admin', password='testpass123')
        response = self.client.get(reverse('aps_support:ticket_list'), {'priority': 'High'})
        self.assertEqual(response.status_code, 200)
        tickets = response.context['page_obj'].object_list
        for ticket in tickets:
            self.assertEqual(ticket.priority, Support.Priority.HIGH)

    def test_date_range_filtering(self):
        """Test ticket filtering by date range"""
        self.client.login(username='admin', password='testpass123')
        yesterday = (timezone.now() - timedelta(days=1)).strftime('%Y-%m-%d')
        tomorrow = (timezone.now() + timedelta(days=1)).strftime('%Y-%m-%d')

        response = self.client.get(reverse('aps_support:ticket_list'), {
            'date_from': yesterday,
            'date_to': tomorrow
        })
        self.assertEqual(response.status_code, 200)

    def test_invalid_date_filtering(self):
        """Test handling of invalid date formats"""
        self.client.login(username='admin', password='testpass123')
        response = self.client.get(reverse('aps_support:ticket_list'), {
            'date_from': 'invalid-date',
            'date_to': 'also-invalid'
        })
        self.assertEqual(response.status_code, 200)
        messages = list(response.context['messages'])
        self.assertTrue(any('Invalid date format' in str(m) for m in messages))

    def test_search_functionality(self):
        """Test ticket search functionality"""
        self.client.login(username='admin', password='testpass123')
        response = self.client.get(reverse('aps_support:ticket_list'), {'search': 'Test Ticket 1'})
        self.assertEqual(response.status_code, 200)
        tickets = response.context['page_obj'].object_list
        self.assertTrue(any('Test Ticket 1' in ticket.subject for ticket in tickets))

    def test_sorting_functionality(self):
        """Test ticket sorting"""
        self.client.login(username='admin', password='testpass123')
        response = self.client.get(reverse('aps_support:ticket_list'), {'sort': 'priority'})
        self.assertEqual(response.status_code, 200)

        # Test invalid sort field defaults to created_at
        response = self.client.get(reverse('aps_support:ticket_list'), {'sort': 'invalid_field'})
        self.assertEqual(response.status_code, 200)

    def test_pagination(self):
        """Test pagination functionality"""
        self.client.login(username='admin', password='testpass123')
        response = self.client.get(reverse('aps_support:ticket_list'), {'page_size': '2'})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context['page_obj'].has_other_pages())


class CreateTicketViewTests(SupportViewsTestCase):
    """Test cases for create_ticket view"""

    def test_create_ticket_get(self):
        """Test GET request to create ticket"""
        self.client.login(username='employee', password='testpass123')
        response = self.client.get(reverse('aps_support:create_ticket'))
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.context['form'], TicketForm)

    def test_employee_field_restrictions(self):
        """Test that employees have restricted fields"""
        self.client.login(username='employee', password='testpass123')
        response = self.client.get(reverse('aps_support:create_ticket'))
        form = response.context['form']
        # Employee should not have access to priority, assigned_group, assigned_to_user
        self.assertNotIn('priority', form.fields)
        self.assertNotIn('assigned_group', form.fields)
        self.assertNotIn('assigned_to_user', form.fields)

    def test_admin_has_all_fields(self):
        """Test that admin has access to all fields"""
        self.client.login(username='admin', password='testpass123')
        response = self.client.get(reverse('aps_support:create_ticket'))
        form = response.context['form']
        self.assertIn('priority', form.fields)
        self.assertIn('assigned_group', form.fields)
        self.assertIn('assigned_to_user', form.fields)

    def test_create_ticket_successful(self):
        """Test successful ticket creation"""
        self.client.login(username='employee', password='testpass123')
        data = {
            'subject': 'New Test Ticket',
            'description': 'New test description',
            'issue_type': Support.IssueType.ACCESS
        }
        response = self.client.post(reverse('aps_support:create_ticket'), data)

        # Should redirect to ticket detail
        self.assertEqual(response.status_code, 302)

        # Verify ticket was created
        ticket = Support.objects.filter(subject='New Test Ticket').first()
        self.assertIsNotNone(ticket)
        self.assertEqual(ticket.user, self.employee_user)

    def test_auto_assignment_hr_issue(self):
        """Test auto-assignment for HR issues"""
        self.client.login(username='employee', password='testpass123')
        data = {
            'subject': 'HR Issue',
            'description': 'Need HR help',
            'issue_type': Support.IssueType.HR
        }
        response = self.client.post(reverse('aps_support:create_ticket'), data)

        ticket = Support.objects.filter(subject='HR Issue').first()
        self.assertEqual(ticket.assigned_group, Support.AssignedGroup.HR)

    def test_auto_assignment_it_issue(self):
        """Test auto-assignment for IT issues"""
        self.client.login(username='employee', password='testpass123')
        data = {
            'subject': 'IT Issue',
            'description': 'Computer problem',
            'issue_type': Support.IssueType.INTERNET
        }
        response = self.client.post(reverse('aps_support:create_ticket'), data)

        ticket = Support.objects.filter(subject='IT Issue').first()
        self.assertEqual(ticket.assigned_group, Support.AssignedGroup.ADMIN)

    def test_file_upload_valid(self):
        """Test valid file upload"""
        self.client.login(username='employee', password='testpass123')

        # Create a small test file
        test_file = SimpleUploadedFile(
            "test.txt",
            b"file_content",
            content_type="text/plain"
        )

        data = {
            'subject': 'Ticket with file',
            'description': 'Has attachment',
            'issue_type': Support.IssueType.ACCESS,
            'attachments': test_file
        }
        response = self.client.post(reverse('aps_support:create_ticket'), data)

        ticket = Support.objects.filter(subject='Ticket with file').first()
        self.assertIsNotNone(ticket)
        self.assertTrue(ticket.attachments.exists())

    def test_file_upload_size_limit(self):
        """Test file upload size limit enforcement"""
        self.client.login(username='employee', password='testpass123')

        # Create a file larger than 5MB
        large_content = b'x' * (6 * 1024 * 1024)  # 6MB
        test_file = SimpleUploadedFile(
            "large.txt",
            large_content,
            content_type="text/plain"
        )

        data = {
            'subject': 'Ticket with large file',
            'description': 'Has large attachment',
            'issue_type': Support.IssueType.ACCESS,
            'attachments': test_file
        }
        response = self.client.post(reverse('aps_support:create_ticket'), data)

        # Check that warning message was added
        messages = list(response.context['messages'])
        self.assertTrue(any('exceeds the 5MB size limit' in str(m) for m in messages))

    def test_file_upload_invalid_type(self):
        """Test invalid file type rejection"""
        self.client.login(username='employee', password='testpass123')

        # Create an executable file (not allowed)
        test_file = SimpleUploadedFile(
            "test.exe",
            b"executable_content",
            content_type="application/x-executable"
        )

        data = {
            'subject': 'Ticket with invalid file',
            'description': 'Has invalid attachment',
            'issue_type': Support.IssueType.ACCESS,
            'attachments': test_file
        }
        response = self.client.post(reverse('aps_support:create_ticket'), data)

        # Check that warning message was added
        messages = list(response.context['messages'])
        self.assertTrue(any('type is not allowed' in str(m) for m in messages))

    def test_parent_ticket_assignment(self):
        """Test parent ticket assignment"""
        self.client.login(username='employee', password='testpass123')

        data = {
            'subject': 'Child Ticket',
            'description': 'Related to parent',
            'issue_type': Support.IssueType.ACCESS,
            'parent_ticket_id': self.ticket1.ticket_id
        }
        response = self.client.post(reverse('aps_support:create_ticket'), data)

        ticket = Support.objects.filter(subject='Child Ticket').first()
        self.assertEqual(ticket.parent_ticket, self.ticket1)

    def test_parent_ticket_not_found(self):
        """Test handling of non-existent parent ticket"""
        self.client.login(username='employee', password='testpass123')

        data = {
            'subject': 'Child Ticket',
            'description': 'Related to parent',
            'issue_type': Support.IssueType.ACCESS,
            'parent_ticket_id': 'NONEXISTENT'
        }
        response = self.client.post(reverse('aps_support:create_ticket'), data)

        messages = list(response.context['messages'])
        self.assertTrue(any('not found' in str(m) for m in messages))

    def test_manager_priority_default(self):
        """Test that managers get HIGH priority by default"""
        self.client.login(username='manager', password='testpass123')

        data = {
            'subject': 'Manager Ticket',
            'description': 'Manager issue',
            'issue_type': Support.IssueType.ACCESS
        }
        response = self.client.post(reverse('aps_support:create_ticket'), data)

        ticket = Support.objects.filter(subject='Manager Ticket').first()
        self.assertEqual(ticket.priority, Support.Priority.HIGH)

    @patch('trueAlign.utils.send_ticket_notification')
    def test_notification_sent(self, mock_send_notification):
        """Test that notification is sent after ticket creation"""
        self.client.login(username='employee', password='testpass123')

        data = {
            'subject': 'Notification Test',
            'description': 'Test notification',
            'issue_type': Support.IssueType.ACCESS
        }
        response = self.client.post(reverse('aps_support:create_ticket'), data)

        mock_send_notification.assert_called_once()


class TicketDetailViewTests(SupportViewsTestCase):
    """Test cases for ticket_detail view"""

    def test_ticket_detail_unauthenticated(self):
        """Test unauthenticated access is denied"""
        response = self.client.get(reverse('aps_support:ticket_detail', kwargs={'pk': self.ticket1.pk}))
        self.assertRedirects(response, f'/accounts/login/?next={reverse("aps_support:ticket_detail", kwargs={"pk": self.ticket1.pk})}')

    def test_owner_can_view_ticket(self):
        """Test ticket owner can view their ticket"""
        self.client.login(username='employee', password='testpass123')
        response = self.client.get(reverse('aps_support:ticket_detail', kwargs={'pk': self.ticket1.pk}))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['ticket'], self.ticket1)

    def test_admin_can_view_any_ticket(self):
        """Test admin can view any ticket"""
        self.client.login(username='admin', password='testpass123')
        response = self.client.get(reverse('aps_support:ticket_detail', kwargs={'pk': self.ticket1.pk}))
        self.assertEqual(response.status_code, 200)

    def test_hr_can_view_hr_tickets(self):
        """Test HR can view HR assigned tickets"""
        self.client.login(username='hr', password='testpass123')
        response = self.client.get(reverse('aps_support:ticket_detail', kwargs={'pk': self.ticket1.pk}))
        self.assertEqual(response.status_code, 200)

    def test_assigned_user_can_view_ticket(self):
        """Test assigned user can view their assigned ticket"""
        self.client.login(username='hr', password='testpass123')
        response = self.client.get(reverse('aps_support:ticket_detail', kwargs={'pk': self.ticket1.pk}))
        self.assertEqual(response.status_code, 200)

    def test_unauthorized_access_forbidden(self):
        """Test unauthorized users get 403"""
        # Employee trying to view ticket not owned by them
        self.client.login(username='employee', password='testpass123')
        response = self.client.get(reverse('aps_support:ticket_detail', kwargs={'pk': self.ticket2.pk}))
        self.assertEqual(response.status_code, 403)

    def test_sla_breach_detection(self):
        """Test SLA breach detection and update"""
        self.client.login(username='admin', password='testpass123')

        # Create ticket with past SLA target
        old_ticket = Support.objects.create(
            user=self.employee_user,
            subject='SLA Test',
            description='Test SLA',
            priority=Support.Priority.CRITICAL,
            status=Support.Status.OPEN,
            sla_target_date=timezone.now() - timedelta(hours=1)
        )

        response = self.client.get(reverse('aps_support:ticket_detail', kwargs={'pk': old_ticket.pk}))

        # Refresh from database
        old_ticket.refresh_from_db()
        self.assertEqual(old_ticket.sla_status, Support.SLAStatus.BREACHED)
        self.assertTrue(old_ticket.sla_breach)

    def test_add_comment_successful(self):
        """Test adding comment to ticket"""
        self.client.login(username='employee', password='testpass123')

        data = {
            'comment': 'This is a test comment',
            'is_internal': False
        }
        response = self.client.post(
            reverse('aps_support:ticket_detail', kwargs={'pk': self.ticket1.pk}),
            data
        )

        self.assertEqual(response.status_code, 302)  # Redirect after successful post

        # Verify comment was created
        comment = TicketComment.objects.filter(
            ticket=self.ticket1,
            content='This is a test comment'
        ).first()
        self.assertIsNotNone(comment)
        self.assertEqual(comment.user, self.employee_user)

    def test_employee_cannot_make_internal_comment(self):
        """Test employees cannot make internal comments"""
        self.client.login(username='employee', password='testpass123')

        data = {
            'comment': 'Trying internal comment',
            'is_internal': True
        }
        response = self.client.post(
            reverse('aps_support:ticket_detail', kwargs={'pk': self.ticket1.pk}),
            data
        )

        comment = TicketComment.objects.filter(
            ticket=self.ticket1,
            content='Trying internal comment'
        ).first()
        self.assertFalse(comment.is_internal)  # Should be forced to False

    def test_status_update_by_authorized_user(self):
        """Test status update by authorized user"""
        self.client.login(username='hr', password='testpass123')

        data = {
            'new_status': Support.Status.IN_PROGRESS
        }
        response = self.client.post(
            reverse('aps_support:ticket_detail', kwargs={'pk': self.ticket1.pk}),
            data
        )

        self.ticket1.refresh_from_db()
        self.assertEqual(self.ticket1.status, Support.Status.IN_PROGRESS)

    def test_status_update_unauthorized(self):
        """Test status update by unauthorized user"""
        # Regular employee trying to change status to something other than Closed
        self.client.login(username='employee', password='testpass123')

        data = {
            'new_status': Support.Status.IN_PROGRESS
        }
        response = self.client.post(
            reverse('aps_support:ticket_detail', kwargs={'pk': self.ticket1.pk}),
            data
        )

        self.ticket1.refresh_from_db()
        self.assertNotEqual(self.ticket1.status, Support.Status.IN_PROGRESS)

    def test_owner_can_close_ticket(self):
        """Test ticket owner can close their ticket"""
        self.client.login(username='employee', password='testpass123')

        data = {
            'new_status': Support.Status.CLOSED
        }
        response = self.client.post(
            reverse('aps_support:ticket_detail', kwargs={'pk': self.ticket1.pk}),
            data
        )

        self.ticket1.refresh_from_db()
        self.assertEqual(self.ticket1.status, Support.Status.CLOSED)

    def test_comment_with_attachment(self):
        """Test adding comment with file attachment"""
        self.client.login(username='employee', password='testpass123')

        test_file = SimpleUploadedFile(
            "comment_attachment.txt",
            b"comment file content",
            content_type="text/plain"
        )

        data = {
            'comment': 'Comment with attachment',
            'comment_attachments': test_file
        }
        response = self.client.post(
            reverse('aps_support:ticket_detail', kwargs={'pk': self.ticket1.pk}),
            data
        )

        # Verify attachment was created
        comment = TicketComment.objects.filter(
            ticket=self.ticket1,
            content='Comment with attachment'
        ).first()
        self.assertTrue(
            TicketAttachment.objects.filter(
                ticket=self.ticket1,
                comment=comment
            ).exists()
        )

    def test_escalate_ticket(self):
        """Test ticket escalation"""
        self.client.login(username='employee', password='testpass123')

        data = {
            'escalate_ticket': 'true',
            'escalation_reason': 'Urgent issue'
        }
        response = self.client.post(
            reverse('aps_support:ticket_detail', kwargs={'pk': self.ticket1.pk}),
            data
        )

        self.ticket1.refresh_from_db()
        self.assertGreater(self.ticket1.escalation_level, 0)

    def test_cannot_escalate_closed_ticket(self):
        """Test that closed tickets cannot be escalated"""
        self.client.login(username='employee', password='testpass123')

        data = {
            'escalate_ticket': 'true',
            'escalation_reason': 'Trying to escalate closed'
        }
        response = self.client.post(
            reverse('aps_support:ticket_detail', kwargs={'pk': self.closed_ticket.pk}),
            data
        )

        messages = list(response.context['messages'])
        self.assertTrue(any('Cannot escalate' in str(m) for m in messages))

    def test_add_cc_user(self):
        """Test adding user to CC list"""
        self.client.login(username='admin', password='testpass123')

        data = {
            'add_cc_user': self.manager_user.id
        }
        response = self.client.post(
            reverse('aps_support:ticket_detail', kwargs={'pk': self.ticket1.pk}),
            data
        )

        self.assertTrue(self.ticket1.cc_users.filter(id=self.manager_user.id).exists())

    def test_add_nonexistent_cc_user(self):
        """Test handling of adding non-existent CC user"""
        self.client.login(username='admin', password='testpass123')

        data = {
            'add_cc_user': 99999  # Non-existent user ID
        }
        response = self.client.post(
            reverse('aps_support:ticket_detail', kwargs={'pk': self.ticket1.pk}),
            data
        )

        messages = list(response.context['messages'])
        self.assertTrue(any('User not found' in str(m) for m in messages))

    def test_internal_comments_visibility(self):
        """Test internal comments are only visible to authorized users"""
        # Create internal comment
        internal_comment = TicketComment.objects.create(
            ticket=self.ticket1,
            user=self.hr_user,
            content='Internal comment',
            is_internal=True
        )

        # Employee should not see internal comments
        self.client.login(username='employee', password='testpass123')
        response = self.client.get(reverse('aps_support:ticket_detail', kwargs={'pk': self.ticket1.pk}))

        # Check that internal comment is not in visible comments
        visible_comments = response.context['comments']
        self.assertNotIn(internal_comment, visible_comments)

        # HR user should see internal comments
        self.client.login(username='hr', password='testpass123')
        response = self.client.get(reverse('aps_support:ticket_detail', kwargs={'pk': self.ticket1.pk}))

        visible_comments = response.context['comments']
        self.assertIn(internal_comment, visible_comments)
        def test_remove_cc_user(self):
            """Test removing user from CC list"""
            # First add user to CC
            self.ticket1.cc_users.add(self.manager_user)

            self.client.login(username='admin', password='testpass123')
            data = {
                'remove_cc_user': self.manager_user.id
            }
            response = self.client.post(
                reverse('aps_support:ticket_detail', kwargs={'pk': self.ticket1.pk}),
                data
            )

            self.assertFalse(self.ticket1.cc_users.filter(id=self.manager_user.id).exists())

        def test_ticket_activity_logging(self):
            """Test that ticket activities are logged"""
            self.client.login(username='hr', password='testpass123')

            # Update status
            data = {
                'new_status': Support.Status.IN_PROGRESS
            }
            response = self.client.post(
                reverse('aps_support:ticket_detail', kwargs={'pk': self.ticket1.pk}),
                data
            )

            # Check that activity was logged
            self.assertTrue(
                TicketActivity.objects.filter(
                    ticket=self.ticket1,
                    activity_type='status_change'
                ).exists()
            )

        def test_field_change_logging(self):
            """Test that field changes are logged"""
            self.client.login(username='admin', password='testpass123')

            # Change priority
            data = {
                'new_priority': Support.Priority.CRITICAL
            }
            response = self.client.post(
                reverse('aps_support:ticket_detail', kwargs={'pk': self.ticket1.pk}),
                data
            )

            # Check that field change was logged
            self.assertTrue(
                TicketFieldChange.objects.filter(
                    ticket=self.ticket1,
                    field_name='priority'
                ).exists()
            )

        def test_sla_status_calculation(self):
            """Test SLA status calculation on ticket view"""
            # Create ticket with approaching SLA
            approaching_ticket = Support.objects.create(
                user=self.employee_user,
                subject='Approaching SLA',
                description='SLA approaching deadline',
                priority=Support.Priority.HIGH,
                status=Support.Status.OPEN,
                sla_target_date=timezone.now() + timedelta(hours=1)
            )

            self.client.login(username='admin', password='testpass123')
            response = self.client.get(reverse('aps_support:ticket_detail', kwargs={'pk': approaching_ticket.pk}))
            self.assertEqual(response.status_code, 200)

            # Verify the SLA status is set to APPROACHING
            approaching_ticket.refresh_from_db()
            self.assertEqual(approaching_ticket.sla_status, Support.SLAStatus.APPROACHING)

            # Create ticket with met SLA
            met_ticket = Support.objects.create(
                user=self.employee_user,
                subject='Met SLA',
                description='SLA is on track',
                priority=Support.Priority.MEDIUM,
                status=Support.Status.OPEN,
                sla_target_date=timezone.now() + timedelta(days=2)
            )

            response = self.client.get(reverse('aps_support:ticket_detail', kwargs={'pk': met_ticket.pk}))
            self.assertEqual(response.status_code, 200)

            # Verify the SLA status is set to ON_TRACK
            met_ticket.refresh_from_db()
            self.assertEqual(met_ticket.sla_status, Support.SLAStatus.ON_TRACK)

    class APIViewTests(SupportViewsTestCase):
        """Test cases for the ticket API endpoints"""

        def test_api_list_authenticated(self):
            """Test authenticated access to ticket list API"""
            self.client.login(username='admin', password='testpass123')
            response = self.client.get(reverse('aps_support:api_ticket_list'))
            self.assertEqual(response.status_code, 200)
            self.assertIn('tickets', response.json())

        def test_api_list_unauthenticated(self):
            """Test unauthenticated access is denied for API"""
            response = self.client.get(reverse('aps_support:api_ticket_list'))
            self.assertEqual(response.status_code, 403)

        def test_api_ticket_detail(self):
            """Test ticket detail API endpoint"""
            self.client.login(username='admin', password='testpass123')
            response = self.client.get(reverse('aps_support:api_ticket_detail', kwargs={'pk': self.ticket1.pk}))
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertEqual(data['subject'], self.ticket1.subject)

        def test_api_create_ticket(self):
            """Test ticket creation via API"""
            self.client.login(username='employee', password='testpass123')
            data = {
                'subject': 'API Created Ticket',
                'description': 'Created via API',
                'issue_type': Support.IssueType.ACCESS
            }
            response = self.client.post(
                reverse('aps_support:api_create_ticket'),
                data=json.dumps(data),
                content_type='application/json'
            )
            self.assertEqual(response.status_code, 201)
            self.assertTrue(Support.objects.filter(subject='API Created Ticket').exists())

        def test_api_update_ticket(self):
            """Test ticket update via API"""
            self.client.login(username='admin', password='testpass123')
            data = {
                'status': Support.Status.IN_PROGRESS,
                'priority': Support.Priority.CRITICAL
            }
            response = self.client.patch(
                reverse('aps_support:api_ticket_detail', kwargs={'pk': self.ticket1.pk}),
                data=json.dumps(data),
                content_type='application/json'
            )
            self.assertEqual(response.status_code, 200)
            self.ticket1.refresh_from_db()
            self.assertEqual(self.ticket1.status, Support.Status.IN_PROGRESS)
            self.assertEqual(self.ticket1.priority, Support.Priority.CRITICAL)
