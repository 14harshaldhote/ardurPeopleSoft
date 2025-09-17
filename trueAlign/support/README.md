# Support Ticket System

A comprehensive support ticket management system integrated into the TrueAlign platform, designed to handle IT support requests, HR issues, and other organizational support needs.

## Overview

The Support Ticket System provides a robust platform for managing support requests across different departments. It implements role-based access control, automated ticket routing, SLA tracking, and comprehensive audit trails.

## Features

### Core Features
- **Ticket Creation & Management**: Create, view, update, and track support tickets
- **Role-Based Access Control**: Different permissions for Admin, HR, Manager, and Employee groups
- **Automated Assignment**: Tickets automatically assigned to appropriate groups based on issue type
- **Status Tracking**: Complete ticket lifecycle management with status transitions
- **Priority Management**: Four priority levels (Critical, High, Medium, Low)
- **SLA Monitoring**: Automatic SLA target calculation and breach tracking
- **Escalation System**: Multi-level escalation with priority auto-adjustment
- **File Attachments**: Support for file uploads on tickets and comments
- **Internal Notes**: Staff-only comments for internal communication
- **Activity Logging**: Comprehensive audit trail of all ticket activities
- **Search & Filtering**: Advanced search and filtering capabilities
- **Dashboard Analytics**: Statistics and metrics for ticket management

### Issue Types Supported
- Hardware Issues
- Software Issues
- Network Issues
- Internet Issues
- Application Issues
- HR Related Issues
- Access Management
- Security Incidents
- Service Requests

## User Roles & Permissions

### Groups and Access Levels

| Group ID | Group Name | Permissions |
|----------|------------|-------------|
| 2        | Admin      | Full access: Create, view, update, resolve, reassign, close all tickets |
| 5        | Employee   | Limited access: Create tickets, view own tickets, add comments |
| 4        | HR         | Full access: Create, view, update, resolve, close all tickets |
| 11       | Manager    | Same as Employee (create and view own tickets) |

### Permission Matrix

| Action | Admin | HR | Manager | Employee |
|--------|-------|----|---------| ---------|
| Create Tickets | ✅ | ✅ | ✅ | ✅ |
| View All Tickets | ✅ | ✅ | ❌ | ❌ |
| View Own Tickets | ✅ | ✅ | ✅ | ✅ |
| Resolve Tickets | ✅ | ✅ | ❌ | ❌ |
| Reassign Tickets | ✅ | ❌ | ❌ | ❌ |
| Close Tickets | ✅ | ✅ | ❌ | ❌ |
| Internal Notes | ✅ | ✅ | ❌ | ❌ |
| Escalate Tickets | ✅ | ✅ | ✅ | ✅ |

## URL Structure

```
/support/                           - Main dashboard
/support/create/                    - Create new ticket
/support/ticket/<id>/               - View ticket details
/support/my-tickets/                - User's personal tickets
/support/ticket/<id>/update-status/ - Update ticket status (POST)
/support/ticket/<id>/reassign/      - Reassign ticket (POST)
/support/ticket/<id>/comment/       - Add comment (POST)
/support/ticket/<id>/attachment/    - Upload attachment (POST)
/support/ticket/<id>/escalate/      - Escalate ticket (POST)
/support/ajax/stats/                - AJAX ticket statistics
/support/ajax/search/               - AJAX ticket search
```

## Models

### Support (Main Ticket Model)
- **ticket_id**: Auto-generated unique identifier
- **user**: Ticket creator
- **issue_type**: Category of the issue
- **subject**: Brief description
- **description**: Detailed issue description
- **status**: Current ticket status
- **priority**: Urgency level
- **assigned_to_user**: Currently assigned user
- **assigned_group**: Currently assigned group
- **timestamps**: Creation, update, resolution times
- **sla_fields**: SLA tracking and breach detection
- **escalation_level**: Current escalation level

### TicketComment
- **ticket**: Foreign key to Support
- **user**: Comment author
- **content**: Comment text
- **is_internal**: Staff-only flag
- **created_at**: Timestamp

### TicketAttachment
- **ticket**: Foreign key to Support
- **file**: Uploaded file
- **original_filename**: Original file name
- **formatted_filename**: System-generated name
- **uploaded_by**: User who uploaded
- **file_size**: File size in bytes

### TicketActivity
- **ticket**: Foreign key to Support
- **action**: Type of activity (CREATED, UPDATED, ASSIGNED, etc.)
- **user**: User who performed the action
- **details**: Additional information
- **timestamp**: When the activity occurred

### StatusLog
- **ticket**: Foreign key to Support
- **old_status**: Previous status
- **new_status**: New status
- **changed_by**: User who changed the status
- **changed_at**: When the status was changed

## Installation & Setup

### 1. Add to URL Configuration

Add to your main `urls.py`:
```python
path('support/', include('trueAlign.support.urls')),
```

### 2. Database Migration

The support models are already in the main `trueAlign.models.py` file. Run migrations:
```bash
python manage.py makemigrations
python manage.py migrate
```

### 3. Create User Groups

Ensure the following groups exist with the correct IDs:
```python
# In Django shell or management command
from django.contrib.auth.models import Group

Group.objects.get_or_create(id=2, name='Admin')
Group.objects.get_or_create(id=5, name='Employee')
Group.objects.get_or_create(id=4, name='HR')
Group.objects.get_or_create(id=11, name='Manager')
```

### 4. Media Files Configuration

Ensure your settings handle file uploads:
```python
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# File upload settings
FILE_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024  # 10MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024   # 10MB
```

## Usage Guide

### Creating a Ticket
1. Navigate to `/support/create/`
2. Select issue type and priority
3. Fill in subject and detailed description
4. Add optional information (department, location, asset ID)
5. Submit the form

### Managing Tickets (Admin/HR)
1. Access main dashboard at `/support/`
2. View all tickets with filtering options
3. Click on any ticket to view details
4. Use action buttons to:
   - Update status
   - Reassign to users/groups
   - Add comments (internal or public)
   - Upload attachments
   - Escalate priority

### User Actions
- **View own tickets**: `/support/my-tickets/`
- **Add comments**: Available on ticket detail page
- **Upload files**: Use attachment form on ticket page
- **Escalate issues**: Use escalate button with reason

## Service Layer

The `SupportTicketService` class handles all business logic:

### Key Methods
- `create_ticket()`: Creates new support ticket
- `get_tickets_for_user()`: Retrieves tickets based on user role
- `update_ticket_status()`: Changes ticket status with validation
- `reassign_ticket()`: Reassigns tickets (Admin only)
- `add_comment()`: Adds comments with permission checking
- `escalate_ticket()`: Escalates ticket priority and level
- `get_dashboard_stats()`: Returns dashboard statistics

## Templates

### Main Templates
- `dashboard.html`: Main support dashboard with ticket list and statistics
- `create_ticket.html`: Ticket creation form
- `ticket_detail.html`: Detailed ticket view with actions
- `my_tickets.html`: Personal ticket list for users

### Error Templates
- `403.html`: Access denied page
- `404.html`: Page not found for support section

## Admin Interface

Full Django admin integration available at `/admin/`:

### Support Models Available
- Support tickets with inline comments, attachments, and activities
- Ticket comments with content preview
- File attachments with size and type information
- Activity logs with action tracking
- Status change logs

### Admin Actions
- Bulk status updates (resolve, close)
- Bulk assignment to groups
- Advanced filtering and search

## SLA Management

### Automatic SLA Calculation
Based on priority levels:
- **Critical**: 4 hours
- **High**: 8 hours  
- **Medium**: 24 hours
- **Low**: 48 hours

### SLA Tracking
- `sla_target_date`: Calculated target resolution time
- `sla_breach`: Boolean flag for SLA violations
- `sla_status`: WITHIN_SLA or BREACHED

## Security Features

- **Role-based Access Control**: Strict permission checking based on Django groups
- **Ticket Ownership**: Users can only access tickets they created, are assigned to, or are CC'd on
- **Admin-only Actions**: Reassignment restricted to Admin group only
- **File Upload Validation**: File type and size restrictions on attachments
- **CSRF Protection**: All forms include CSRF tokens
- **Input Validation**: Server-side validation of all user inputs
- **Soft Delete**: Tickets marked as deleted rather than physically removed
- **Activity Logging**: Complete audit trail of all actions

## API Endpoints

### AJAX Endpoints
- `GET /support/ajax/stats/`: Returns JSON with ticket statistics
- `GET /support/ajax/search/?q=<query>`: Returns JSON with search results

### Response Format
```json
{
  "total_tickets": 25,
  "open_tickets": 10,
  "pending_tickets": 5,
  "resolved_tickets": 10,
  "can_resolve": true,
  "can_reassign": false
}
```

## Configuration

### Settings Variables
```python
# File upload settings
SUPPORT_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB default
SUPPORT_ALLOWED_FILE_TYPES = [
    'pdf', 'doc', 'docx', 'txt', 'jpg', 'jpeg', 
    'png', 'gif', 'zip', 'rar'
]

# SLA settings (can be customized)
SUPPORT_SLA_HOURS = {
    'Critical': 4,
    'High': 8,
    'Medium': 24,
    'Low': 48
}
```

## Troubleshooting

### Common Issues

**Issue**: "Import forms could not be resolved"
**Solution**: Ensure all form imports are correct in views.py

**Issue**: "Permission denied" errors
**Solution**: Verify user is in correct Django group (Admin, HR, Employee, Manager)

**Issue**: "File upload fails"
**Solution**: Check file size limits and allowed file types

**Issue**: "Tickets not showing in dashboard"
**Solution**: Verify `is_deleted=False` and user has appropriate permissions

### Debug Mode
Enable Django debug mode to see detailed error messages:
```python
DEBUG = True  # Only in development
```

## Customization

### Adding New Issue Types
Edit the `Support.IssueType` choices in `models.py`:
```python
class IssueType(models.TextChoices):
    # ... existing types ...
    CUSTOM_TYPE = 'Custom Issue', 'Custom Issue'
```

### Modifying SLA Times
Override the `set_sla_target_date()` method in the Support model or customize the service layer.

### Custom Notifications
Extend the service methods to add email or other notification systems:
```python
# In services.py
def create_ticket(cls, user, ticket_data):
    ticket = # ... create ticket logic
    # Add custom notification here
    send_notification_email(ticket)
    return ticket
```

## Performance Considerations

### Database Optimization
- Models include appropriate indexes on frequently queried fields
- Use `select_related()` and `prefetch_related()` for related data
- Pagination implemented for large ticket lists

### File Storage
- Consider using cloud storage (AWS S3, etc.) for production file uploads
- Implement file compression for large attachments
- Regular cleanup of soft-deleted tickets and their attachments

## Testing

### Test Data Creation
```python
from django.contrib.auth.models import User, Group
from trueAlign.models import Support

# Create test user
user = User.objects.create_user('testuser', 'test@example.com', 'password')
user.groups.add(Group.objects.get(name='Employee'))

# Create test ticket
ticket = Support.objects.create(
    user=user,
    issue_type='Software Issue',
    subject='Test ticket',
    description='Test description',
    priority='Medium'
)
```

### Running Tests
```bash
python manage.py test trueAlign.support
```

## Future Enhancements

### Potential Features
- **Email Integration**: Automatic email notifications for status changes
- **Knowledge Base**: Link tickets to FAQ/solution articles  
- **Custom Fields**: Configurable additional fields per issue type
- **Reporting**: Advanced analytics and reporting dashboard
- **Mobile App**: Dedicated mobile application
- **Integration**: REST API for third-party integrations
- **Automation**: Automated ticket routing based on keywords
- **Customer Portal**: External customer support portal
- **Chat Integration**: Real-time chat support
- **Workflow Automation**: Custom approval workflows

## Support & Maintenance

### Regular Maintenance Tasks
- Monitor SLA performance and adjust targets as needed
- Archive old resolved tickets periodically
- Clean up orphaned file attachments
- Review and update user group assignments
- Monitor disk space usage for file uploads

### Monitoring
- Track ticket volume trends
- Monitor response and resolution times
- Review escalation patterns
- Analyze user satisfaction ratings

## License & Credits

This support system is part of the TrueAlign platform and follows the same licensing terms. Built using Django framework with modern web technologies.

---

For additional support or questions about this system, please create a support ticket through the platform or contact your system administrator.