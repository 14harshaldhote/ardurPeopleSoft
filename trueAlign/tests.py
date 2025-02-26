from django.test import TestCase, Client
from django.contrib.auth.models import User, Group
from django.urls import reverse
from .models import ChatGroup, GroupMember, DirectMessage, Message, MessageRead
from django.utils import timezone
from django.core.files.uploadedfile import SimpleUploadedFile

class ChatTestCase(TestCase):
    def setUp(self):
        # Create user groups
        self.admin_group = Group.objects.create(name='Admin')
        self.manager_group = Group.objects.create(name='Manager')
        self.employee_group = Group.objects.create(name='Employee')
        self.hr_group = Group.objects.create(name='HR')

        # Create test users
        self.admin_user = User.objects.create_user('admin', 'admin@test.com', 'adminpass')
        self.manager_user = User.objects.create_user('manager', 'manager@test.com', 'managerpass')
        self.employee1 = User.objects.create_user('employee1', 'emp1@test.com', 'emp1pass')
        self.employee2 = User.objects.create_user('employee2', 'emp2@test.com', 'emp2pass')
        self.hr_user = User.objects.create_user('hr', 'hr@test.com', 'hrpass')

        # Assign groups
        self.admin_user.groups.add(self.admin_group)
        self.manager_user.groups.add(self.manager_group)
        self.employee1.groups.add(self.employee_group)
        self.employee2.groups.add(self.employee_group)
        self.hr_user.groups.add(self.hr_group)

        # Create test client
        self.client = Client()

    def test_chat_home_access(self):
        """Test access to chat home page"""
        # Test unauthenticated access
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)  # Should redirect to login

        # Test authenticated access
        self.client.force_login(self.employee1)
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

    def test_create_group_chat(self):
        """Test group chat creation"""
        self.client.force_login(self.manager_user)
        
        # Test creating a group chat
        response = self.client.post('/', {
            'action': 'create_group',
            'name': 'Test Group',
            'description': 'Test Description',
            'members': [self.employee1.id, self.employee2.id]
        })
        
        self.assertEqual(ChatGroup.objects.count(), 1)
        group = ChatGroup.objects.first()
        self.assertEqual(group.name, 'Test Group')
        self.assertEqual(group.memberships.count(), 2)

        # Test employee cannot create group
        self.client.force_login(self.employee1)
        response = self.client.post('/', {
            'action': 'create_group',
            'name': 'Employee Group',
            'members': [self.employee2.id]
        })
        self.assertEqual(ChatGroup.objects.count(), 1)  # Should not increase

    def test_direct_message(self):
        """Test direct message functionality"""
        self.client.force_login(self.employee1)
        
        # Create direct message
        response = self.client.post('/', {
            'action': 'create_direct',
            'user_id': self.hr_user.id
        })
        
        self.assertEqual(DirectMessage.objects.count(), 1)
        dm = DirectMessage.objects.first()
        self.assertTrue(dm.participants.filter(id=self.employee1.id).exists())
        self.assertTrue(dm.participants.filter(id=self.hr_user.id).exists())

    def test_send_message(self):
        """Test sending messages in both group and direct chats"""
        # Create a group chat
        group = ChatGroup.objects.create(
            name='Test Group',
            created_by=self.manager_user
        )
        GroupMember.objects.create(group=group, user=self.employee1)
        
        # Create a direct message
        dm = DirectMessage.objects.create()
        dm.participants.add(self.employee1, self.hr_user)

        self.client.force_login(self.employee1)

        # Test sending message to group
        response = self.client.post(f'/group/{group.id}/', {
            'message': 'Test group message',
            'message_type': 'text'
        })
        self.assertEqual(Message.objects.filter(group=group).count(), 1)

        # Test sending message to DM
        response = self.client.post(f'/direct/{dm.id}/', {
            'message': 'Test DM message',
            'message_type': 'text'
        })
        self.assertEqual(Message.objects.filter(direct_message=dm).count(), 1)

    def test_file_attachment(self):
        """Test file attachment in messages"""
        self.client.force_login(self.employee1)
        
        # Create a direct message
        dm = DirectMessage.objects.create()
        dm.participants.add(self.employee1, self.hr_user)

        # Create a test file
        test_file = SimpleUploadedFile("test.txt", b"test content")

        # Send message with attachment
        response = self.client.post(
            f'/direct/{dm.id}/',
            {
                'message': 'File message',
                'message_type': 'file',
                'file_attachment': test_file
            }
        )

        message = Message.objects.first()
        self.assertEqual(message.message_type, 'file')
        self.assertTrue(message.file_attachment)

    def test_read_receipts(self):
        """Test message read receipts"""
        # Create a direct message
        dm = DirectMessage.objects.create()
        dm.participants.add(self.employee1, self.hr_user)

        # Send a message
        message = Message.objects.create(
            direct_message=dm,
            sender=self.employee1,
            content='Test message'
        )

        # Create read receipt
        MessageRead.objects.create(message=message, user=self.hr_user)
        
        # Check read status
        self.assertEqual(message.read_receipts.count(), 1)
        self.assertIsNone(message.read_receipts.first().read_at)

        # Mark as read
        read_receipt = message.read_receipts.first()
        read_receipt.mark_as_read()
        self.assertIsNotNone(read_receipt.read_at)

    def test_chat_permissions(self):
        """Test chat access permissions"""
        # Create a group chat
        group = ChatGroup.objects.create(
            name='Manager Group',
            created_by=self.manager_user
        )
        GroupMember.objects.create(group=group, user=self.manager_user)

        # Test unauthorized access
        self.client.force_login(self.employee2)
        response = self.client.get(f'/group/{group.id}/')
        self.assertEqual(response.status_code, 302)  # Should redirect

        # Test authorized access
        self.client.force_login(self.manager_user)
        response = self.client.get(f'/group/{group.id}/')
        self.assertEqual(response.status_code, 200)

    def tearDown(self):
        # Clean up any created files
        Message.objects.all().delete()
        DirectMessage.objects.all().delete()
        ChatGroup.objects.all().delete()
        User.objects.all().delete()
        Group.objects.all().delete()
