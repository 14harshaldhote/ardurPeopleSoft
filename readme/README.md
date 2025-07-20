# Conference Room Booking System

A comprehensive Django-based conference room booking and management system with advanced analytics, real-time availability checking, and automated notifications.

## 🚀 Features

### Core Booking Features
- **Dynamic Room Management**: Fully configurable rooms with capacity, facilities, and location tracking
- **Real-time Availability**: Instant conflict detection and alternative slot suggestions
- **Advanced Booking Form**: Meeting types, priority levels, attendee tracking, and external guest management
- **Check-in System**: Meeting check-in functionality with no-show tracking
- **Recurring Bookings**: Support for daily, weekly, and monthly recurring meetings
- **Smart Cancellation**: Automated room availability updates and notification system

### Analytics & Reporting
- **Room Utilization Analytics**: Detailed usage statistics and efficiency metrics
- **Peak Hours Analysis**: Identify busy periods and optimize room scheduling
- **User Behavior Tracking**: Individual booking patterns and preferences
- **Comprehensive Reports**: Daily, weekly, and monthly booking reports
- **Export Functionality**: CSV export for all data and reports

### Administrative Features
- **Advanced Admin Interface**: Rich admin panel with real-time status indicators
- **Maintenance Scheduling**: Room maintenance mode with conflict checking
- **Approval Workflow**: Optional booking approval process
- **Audit Trail**: Complete tracking of all booking changes and cancellations
- **Bulk Operations**: Mass booking confirmations, cancellations, and updates

### User Experience
- **Dashboard Integration**: Seamless integration with existing user dashboard
- **Smart Room Suggestions**: AI-powered room recommendations based on requirements
- **Mobile Responsive**: Works perfectly on all devices
- **Notification System**: Email notifications for confirmations, reminders, and cancellations
- **Real-time Status**: Live room occupancy status and upcoming bookings

## 📋 Prerequisites

- Django 3.2+
- Python 3.8+
- PostgreSQL/MySQL (recommended) or SQLite
- Redis (for caching, optional)

## 🛠️ Installation & Setup

### 1. Database Migration

First, run the Django migrations to create the new Room model:

```bash
python manage.py makemigrations
python manage.py migrate
```

### 2. Setup Initial Rooms

Use the management command to create your conference rooms:

```bash
# Create the default two conference rooms
python manage.py setup_rooms

# To reset and recreate all rooms
python manage.py setup_rooms --reset

# To update existing rooms with new details
python manage.py setup_rooms --update
```

### 3. Migrate Existing Data (If Applicable)

If you have existing booking data with room names, migrate it to use the new Room model:

```bash
# Preview what will be migrated
python manage.py migrate_room_data --dry-run

# Perform the migration with room creation
python manage.py migrate_room_data --create-rooms

# Force migration even if Room objects exist
python manage.py migrate_room_data --force
```

### 4. Admin Setup

The system includes a comprehensive admin interface. Access it at `/admin/` to:
- Manage rooms (add, edit, view real-time status)
- Monitor all bookings with advanced filtering
- View analytics and generate reports
- Handle maintenance scheduling

## 🏗️ System Architecture

### Models Overview

#### Room Model
```python
class Room(models.Model):
    name = models.CharField(max_length=100, unique=True)
    room_type = models.CharField(choices=RoomType.choices)
    capacity = models.PositiveIntegerField()
    location = models.CharField(max_length=100)
    facilities = models.TextField()
    status = models.CharField(choices=RoomStatus.choices)
    # ... analytics and cost fields
```

**Key Properties:**
- `is_available`: Check if room is bookable
- `current_booking`: Get active booking if any
- `next_booking`: Get next scheduled booking
- `is_occupied`: Real-time occupancy status

#### Enhanced ConferenceBooking Model
```python
class ConferenceBooking(models.Model):
    room = models.ForeignKey(Room)
    booked_by = models.ForeignKey(User)
    purpose = models.CharField(max_length=255)
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    
    # Enhanced fields
    attendees_count = models.PositiveIntegerField()
    meeting_type = models.CharField(choices=MEETING_TYPES)
    priority = models.CharField(choices=Priority.choices)
    checked_in = models.BooleanField()
    no_show = models.BooleanField()
    # ... status and tracking fields
```

**Key Properties:**
- `is_active`: Future confirmed booking
- `is_current`: Currently happening
- `can_be_cancelled`: Cancellation eligibility
- `can_check_in`: Check-in availability

## 🎯 Usage Guide

### Making a Booking

1. **Access the Booking Form**: Available through your dashboard
2. **Select Room**: Choose from available rooms with capacity information
3. **Set Details**: 
   - Purpose and description
   - Date and time
   - Number of attendees (internal + external)
   - Meeting type and priority
4. **Submit**: System automatically checks for conflicts
5. **Confirmation**: Receive confirmation email with room details

### Booking Validation

The system automatically validates:
- ✅ Time conflicts with existing bookings
- ✅ Room capacity vs. attendee count
- ✅ Working hours (9 AM - 6 PM, weekdays only)
- ✅ Maximum booking duration (8 hours)
- ✅ Minimum booking duration (15 minutes)
- ✅ Advance booking limits (30 days)
- ✅ User booking limits (3 bookings/day, 20 hours/week)

### Managing Your Bookings

#### View Your Bookings
```
/conf_booking/my-bookings/
```
- Filter by status, date range
- Pagination support
- Quick actions (cancel, check-in)

#### Cancel a Booking
- Click "Cancel" on any future booking
- Provide cancellation reason
- Automatic email notification sent

#### Check-in to Meeting
- Available 15 minutes before to 15 minutes after start time
- Click "Check In" button
- Prevents no-show marking

## 🔗 API Endpoints

### Get Available Slots
```
GET /conf_booking/api/available-slots/
Parameters:
- room_id: Specific room ID (optional)
- duration: Duration in minutes (default: 60)
- start_date: Search start date (YYYY-MM-DD)
- min_capacity: Minimum room capacity
```

**Response:**
```json
{
  "available_slots": [
    {
      "room_id": 1,
      "room_name": "Conference Room A",
      "start": "2024-01-15T09:00:00Z",
      "end": "2024-01-15T10:00:00Z",
      "capacity": 12,
      "facilities": "Projector, Whiteboard, Video Conferencing"
    }
  ]
}
```

### Get Room Details
```
GET /conf_booking/api/room/{room_id}/
```

**Response:**
```json
{
  "id": 1,
  "name": "Conference Room A",
  "capacity": 12,
  "current_booking": {
    "purpose": "Team Meeting",
    "end_time": "2024-01-15T11:00:00Z"
  },
  "today_bookings": [...],
  "availability_slots": [...],
  "utilization_today": 45.5
}
```

## 📊 Analytics & Reports

### Room Dashboard
```
/conf_booking/dashboard/
```
- Real-time room status
- Current occupancy
- Next bookings
- Daily utilization metrics

### Analytics Dashboard
```
/conf_booking/analytics/
```
- Weekly booking reports
- Popular time slots
- Room utilization trends
- User booking statistics

### Admin Management
```
/conf_booking/admin/manage/
```
- All bookings overview
- Filtering and search
- Bulk operations
- No-show management
- Reminder system

## 🔧 Utility Classes

### BookingAnalytics
```python
from trueAlign.models import BookingAnalytics

# Get daily utilization
daily_data = BookingAnalytics.get_daily_utilization()

# Generate weekly report
weekly_report = BookingAnalytics.get_weekly_report(start_date)

# User analytics
user_stats = BookingAnalytics.get_user_analytics(user, days=30)
```

### RoomManager
```python
from trueAlign.models import RoomManager

# Get available rooms for time slot
available = RoomManager.get_available_rooms_for_slot(start, end, capacity)

# Suggest alternative times
suggestions = RoomManager.suggest_alternative_slots(room, start, end, duration)

# Real-time dashboard data
dashboard = RoomManager.get_room_status_dashboard()
```

### BookingValidator
```python
from trueAlign.models import BookingValidator

# Validate booking time
errors = BookingValidator.validate_booking_time(start, end)

# Check room capacity
capacity_error = BookingValidator.validate_room_capacity(room, attendees)

# User booking limits
user_errors = BookingValidator.validate_user_booking_limits(user, start, end)
```

## 📧 Notification System

### Email Notifications
- **Booking Confirmation**: Sent immediately after successful booking
- **Booking Reminder**: 15 minutes before meeting start
- **Cancellation Notice**: When booking is cancelled
- **No-show Alert**: For admin when meetings are missed

### Notification Management
```python
from trueAlign.models import BookingNotification

# Get bookings needing reminders
reminders = BookingNotification.get_reminder_bookings(minutes_before=15)

# Get overdue check-ins
overdue = BookingNotification.get_overdue_checkins()

# Get no-show candidates
no_shows = BookingNotification.get_no_show_candidates()
```

## 🛡️ Security Features

- **User Authentication**: All endpoints require login
- **Permission Checks**: Users can only modify their own bookings
- **Admin Controls**: Staff-only access to admin functions
- **Data Validation**: Comprehensive input validation
- **Audit Trail**: Complete change history
- **Rate Limiting**: Prevents booking abuse

## ⚙️ Configuration

### Settings
Add to your Django settings:

```python
# Email configuration for notifications
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.your-email-provider.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'your-email@domain.com'
EMAIL_HOST_PASSWORD = 'your-password'
DEFAULT_FROM_EMAIL = 'Conference Booking System <booking@yourcompany.com>'

# Time zone (India Standard Time)
TIME_ZONE = 'Asia/Kolkata'
USE_TZ = True

# Optional: Redis for caching
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
    }
}
```

### Working Hours
The system is configured for:
- **Working Days**: Monday to Friday
- **Working Hours**: 9:00 AM to 6:00 PM (IST)
- **Minimum Booking**: 15 minutes
- **Maximum Booking**: 8 hours

## 🔍 Troubleshooting

### Common Issues

**1. Room not appearing in booking form**
- Check room status is "Active"
- Verify room capacity meets requirements
- Ensure room has no maintenance schedule

**2. Booking conflicts not detected**
- Check time zone settings
- Verify database migration completed
- Review booking status (only CONFIRMED bookings block slots)

**3. Notifications not sending**
- Verify email settings
- Check spam folder
- Review Django email configuration

**4. Analytics not updating**
- Run room analytics update: `Room.objects.get(name='Room Name').update_analytics()`
- Check for database performance issues
- Verify booking status consistency

### Debug Commands

```bash
# Check room status
python manage.py shell
>>> from trueAlign.models import Room
>>> Room.objects.all().values('name', 'status', 'total_bookings')

# Verify booking conflicts
>>> from trueAlign.models import ConferenceBooking
>>> ConferenceBooking.get_conflicting_bookings(room, start_time, end_time)

# Update analytics
>>> room = Room.objects.get(name='Conference Room A')
>>> room.update_analytics()
```

## 📈 Performance Optimization

### Database Indexes
The system includes optimized database indexes for:
- Room and time-based queries
- User booking lookups
- Status and date filtering

### Caching
Implement Redis caching for:
- Room availability checks
- Daily utilization data
- Popular time slots

### Query Optimization
- Use `select_related()` for room and user data
- Prefetch related bookings for analytics
- Database-level aggregations for reports

## 🤝 Contributing

To extend the system:

1. **Add New Meeting Types**: Update `MEETING_TYPE_CHOICES`
2. **Custom Validation**: Extend `BookingValidator` class
3. **New Reports**: Add methods to `BookingAnalytics`
4. **Integration**: Use provided utility classes and API endpoints

## 📝 License

This conference booking system is part of the TrueAlign people management system.

---

**Need Help?** Check the admin interface for real-time system status and detailed booking management options.