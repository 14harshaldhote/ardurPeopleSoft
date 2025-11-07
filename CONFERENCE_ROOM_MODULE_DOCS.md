# Conference Room Booking System - Complete Documentation

## 📋 Table of Contents
1. [Overview](#overview)
2. [Features](#features)
3. [Installation & Setup](#installation--setup)
4. [Database Models](#database-models)
5. [URL Endpoints](#url-endpoints)
6. [Business Rules](#business-rules)
7. [Usage Guide](#usage-guide)
8. [API Reference](#api-reference)
9. [Email Notifications](#email-notifications)
10. [Testing](#testing)

---

## 🎯 Overview

The Conference Room Booking System is a comprehensive Django-based module that allows employees to browse, book, and manage conference room reservations. Admin users can create and manage rooms, while all employees can make bookings with automatic conflict detection and email notifications.

### Tech Stack
- **Backend**: Django 5.1.4
- **Frontend**: Jinja2 Templates + Tailwind CSS
- **Database**: MySQL/PostgreSQL compatible
- **Email**: Django email backend

---

## ✨ Features

### For All Users (Employees)
- ✅ Browse available conference rooms
- ✅ Filter rooms by location, capacity, floor
- ✅ View room details with amenities
- ✅ Book conference rooms with validation
- ✅ View upcoming, active, and past bookings
- ✅ Cancel upcoming bookings
- ✅ Calendar view of all bookings
- ✅ Receive email confirmations
- ✅ Real-time availability checking

### For Admin/HR
- ✅ Create, edit, and delete conference rooms
- ✅ Activate/deactivate rooms
- ✅ Set booking rules (buffer time, max duration, lead time)
- ✅ Manage room amenities
- ✅ View all bookings across rooms
- ✅ Upload room images

### Smart Booking Features
- 🚫 **Conflict Prevention**: Automatic detection of overlapping bookings
- ⏱️ **Buffer Time**: Configurable cleaning/setup time between bookings
- 📅 **Lead Time**: Minimum advance booking requirements
- ⏰ **Duration Limits**: Maximum booking duration per room
- 👥 **Capacity Validation**: Ensures attendee count doesn't exceed room capacity
- 📧 **Email Notifications**: Automatic notifications for booking events

---

## 🚀 Installation & Setup

### Step 1: Database Migration

Run the following commands to create database tables:

```bash
# Create migrations for the new models
python manage.py makemigrations

# Apply migrations
python manage.py migrate
```

### Step 2: Create Sample Data (Optional)

Populate the system with sample conference rooms and bookings:

```bash
# Seed with sample data
python manage.py seed_conference_data

# Or clear existing data and reseed
python manage.py seed_conference_data --clear
```

### Step 3: Email Configuration

Add email settings to your `.env` file:

```env
# Email Configuration
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@example.com
EMAIL_HOST_PASSWORD=your-app-password
DEFAULT_FROM_EMAIL=noreply@company.com
```

### Step 4: Optional - Slack Notifications

To enable Slack notifications (optional), add to your `.env`:

```env
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

Then uncomment the Slack notification receiver in `trueAlign/confrence/signals.py`.

### Step 5: Collect Static Files

```bash
python manage.py collectstatic
```

---

## 📊 Database Models

### 1. OfficeLocation (Existing Model)
Represents physical office locations where conference rooms are located.

**Key Fields:**
- `name`: Office location name
- `code`: Short code (e.g., 'MUM', 'DEL')
- `is_active`: Whether location is active
- `timezone`: Location timezone
- `working_hours_start/end`: Office working hours

### 2. ConferenceRoom
Represents a conference room in an office location.

**Key Fields:**
- `name`: Room name (unique per office)
- `office_location`: Foreign key to OfficeLocation
- `floor`: Floor location
- `capacity`: Maximum occupancy
- `amenities`: JSON array of amenities
- `buffer_time_minutes`: Buffer between bookings (default: 15)
- `min_lead_time_minutes`: Minimum advance booking (default: 15)
- `max_booking_duration_hours`: Maximum duration (default: 3)
- `is_active`: Availability status
- `created_by`: Admin who created the room

**Model Methods:**
- `capacity_display`: Returns capacity as "X people"
- `amenities_display`: Returns comma-separated amenities
- `clean()`: Validates room data

### 3. RoomBooking
Represents a conference room booking.

**Key Fields:**
- `room`: Foreign key to ConferenceRoom
- `booked_by`: User who made the booking
- `title`: Meeting title
- `purpose`: Detailed purpose
- `attendees`: List of attendee names/emails
- `attendee_count`: Number of attendees
- `start_time`: Booking start datetime
- `end_time`: Booking end datetime
- `status`: PENDING, CONFIRMED, or CANCELLED
- `cancelled_at`: Cancellation timestamp
- `cancellation_reason`: Reason for cancellation

**Status Choices:**
- `PENDING`: Initial state (auto-confirms)
- `CONFIRMED`: Active booking
- `CANCELLED`: Cancelled booking

**Model Properties:**
- `duration_hours`: Calculated booking duration
- `is_upcoming`: Is in the future
- `is_past`: Has ended
- `is_active`: Currently ongoing

**Model Methods:**
- `clean()`: Comprehensive validation
- `save()`: Auto-confirms and validates
- `cancel(reason)`: Cancel the booking

---

## 🔗 URL Endpoints

### Public User Endpoints

| URL | View | Description |
|-----|------|-------------|
| `/conference/rooms/` | `room_list` | Browse available rooms |
| `/conference/rooms/<id>/` | `room_detail` | View room details |
| `/conference/bookings/create/` | `booking_create` | Create new booking |
| `/conference/bookings/create/<room_id>/` | `booking_create_room` | Book specific room |
| `/conference/bookings/my/` | `my_bookings` | User's bookings |
| `/conference/bookings/<id>/` | `booking_detail` | View booking details |
| `/conference/bookings/<id>/cancel/` | `booking_cancel` | Cancel a booking |
| `/conference/calendar/` | `booking_calendar` | Calendar view |

### Admin Endpoints (Admin/HR Only)

| URL | View | Description |
|-----|------|-------------|
| `/conference/admin/rooms/` | `room_list_admin` | Manage all rooms |
| `/conference/admin/rooms/create/` | `room_create` | Create new room |
| `/conference/admin/rooms/<id>/edit/` | `room_edit` | Edit room |
| `/conference/admin/rooms/<id>/delete/` | `room_delete` | Delete room |
| `/conference/admin/rooms/<id>/toggle/` | `room_toggle_active` | Toggle active status |

### API Endpoints

| URL | Method | Description |
|-----|--------|-------------|
| `/conference/api/check-availability/` | GET | Check room availability |

**Check Availability Parameters:**
- `room_id`: Room ID
- `date`: Booking date (YYYY-MM-DD)
- `start_time`: Start time (HH:MM)
- `end_time`: End time (HH:MM)

**Response:**
```json
{
  "available": true,
  "message": "Room is available for this time slot"
}
```

or

```json
{
  "available": false,
  "message": "Time slot conflicts with: Team Meeting",
  "conflict": {
    "title": "Team Meeting",
    "start": "14:00",
    "end": "15:30"
  }
}
```

---

## 📜 Business Rules & Validation

### Booking Validation Rules

1. **Past Booking Prevention**
   - Cannot book a room for past dates/times
   - Validation: `start_time >= timezone.now()`

2. **Lead Time Requirement**
   - Must book at least X minutes in advance (configurable per room)
   - Default: 15 minutes
   - Validation: `(start_time - now) >= room.min_lead_time_minutes`

3. **Maximum Duration**
   - Bookings cannot exceed maximum duration (configurable per room)
   - Default: 3 hours
   - Validation: `duration <= room.max_booking_duration_hours`

4. **Capacity Check**
   - Number of attendees cannot exceed room capacity
   - Validation: `attendee_count <= room.capacity`

5. **Buffer Time**
   - Mandatory buffer between consecutive bookings
   - Default: 15 minutes
   - Used for cleaning and setup

6. **Conflict Detection**
   - No overlapping bookings (including buffer time)
   - Checks existing PENDING and CONFIRMED bookings
   - Formula: `new_start < existing_end AND new_end > existing_start`

7. **Room Availability**
   - Room must be active (`is_active=True`)
   - Inactive rooms cannot be booked

### Booking Lifecycle

```
CREATE → PENDING → CONFIRMED → (optional) → CANCELLED
         (auto)
```

- New bookings are automatically confirmed (can be modified for approval workflow)
- Cancelled bookings cannot be reactivated
- Past bookings cannot be cancelled

---

## 📖 Usage Guide

### For Employees

#### 1. Browse Conference Rooms

```
Navigate to: /conference/rooms/
```

- View all active conference rooms
- Filter by office location, capacity, floor
- Search by room name or description
- See room amenities and upcoming bookings

#### 2. Book a Conference Room

```
Navigate to: /conference/bookings/create/
Or: Click "Book Now" on any room
```

**Steps:**
1. Select conference room
2. Enter meeting title and purpose
3. Choose date and time
4. Add attendee count and names
5. Optionally add special requirements
6. Submit booking

**Validation:**
- System checks availability in real-time
- Validates against all booking rules
- Shows clear error messages if validation fails

#### 3. Manage Your Bookings

```
Navigate to: /conference/bookings/my/
```

**View:**
- Active bookings (currently ongoing)
- Upcoming bookings
- Past bookings
- Cancelled bookings

**Actions:**
- View booking details
- Cancel upcoming bookings
- See booking status

#### 4. Cancel a Booking

```
Navigate to: /conference/bookings/<id>/cancel/
```

- Only upcoming bookings can be cancelled
- Optionally provide cancellation reason
- Confirmation required
- Email notification sent automatically

### For Admins/HR

#### 1. Create a Conference Room

```
Navigate to: /conference/admin/rooms/create/
```

**Required Information:**
- Room name (unique per office)
- Office location
- Floor
- Capacity (number of people)

**Booking Rules:**
- Buffer time between bookings (minutes)
- Minimum lead time (minutes)
- Maximum booking duration (hours)

**Optional:**
- Amenities (comma-separated)
- Room description
- Room image
- Active status

#### 2. Manage Existing Rooms

```
Navigate to: /conference/admin/rooms/
```

**Available Actions:**
- **Edit**: Modify room details
- **Activate/Deactivate**: Toggle room availability
- **Delete**: Remove room (warning if future bookings exist)

**Room Statistics:**
- Total bookings count
- Upcoming bookings count
- Active status

#### 3. Best Practices

- Deactivate rooms temporarily instead of deleting
- Set realistic buffer times (15-30 minutes)
- Keep amenities list updated
- Upload room images for better UX
- Review booking patterns regularly

---

## 📧 Email Notifications

### Automatic Notifications

Email notifications are sent automatically for:

1. **Booking Created** ✅
   - Trigger: New confirmed booking
   - Recipient: User who booked
   - Content: Full booking details

2. **Booking Cancelled** ❌
   - Trigger: Booking cancellation
   - Recipient: User who booked
   - Content: Cancellation details and reason

### Email Content

Each email includes:
- Meeting title and purpose
- Room name and location
- Date and time
- Duration
- Number of attendees
- Room amenities
- Booking status
- Cancellation reason (if applicable)

### Email Configuration

Emails are sent using Django's email backend. Configure in `settings.py`:

```python
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'your-email@example.com'
EMAIL_HOST_PASSWORD = 'your-app-password'
DEFAULT_FROM_EMAIL = 'noreply@company.com'
```

---

## 🧪 Testing

### Manual Testing Checklist

#### Room Management
- [ ] Create a new conference room
- [ ] Edit room details
- [ ] Deactivate/activate room
- [ ] Delete room with no bookings
- [ ] Try to delete room with future bookings
- [ ] Upload room image

#### Booking Flow
- [ ] Book a room for tomorrow
- [ ] Try to book past date (should fail)
- [ ] Try to book with insufficient lead time (should fail)
- [ ] Try to book beyond max duration (should fail)
- [ ] Try to book with attendees > capacity (should fail)
- [ ] Try to book overlapping time slot (should fail)
- [ ] View booking details
- [ ] Cancel upcoming booking
- [ ] Try to cancel past booking (should fail)

#### Email Notifications
- [ ] Receive confirmation email on booking
- [ ] Receive cancellation email when cancelled
- [ ] Check email formatting

#### Filters & Search
- [ ] Filter rooms by location
- [ ] Filter rooms by minimum capacity
- [ ] Search rooms by name
- [ ] View calendar of bookings

### Sample Test Data

Use the management command to create test data:

```bash
python manage.py seed_conference_data --clear
```

This creates:
- Office locations (if none exist)
- 6 conference rooms per office
- Random bookings for the next 7 days

---

## 🔧 Customization

### Modify Default Booking Rules

Edit model defaults in `trueAlign/models.py`:

```python
class ConferenceRoom(models.Model):
    buffer_time_minutes = models.PositiveIntegerField(
        default=15,  # Change this
    )
    min_lead_time_minutes = models.PositiveIntegerField(
        default=15,  # Change this
    )
    max_booking_duration_hours = models.PositiveIntegerField(
        default=3,  # Change this
    )
```

### Add Approval Workflow

Modify `save()` method in `RoomBooking`:

```python
def save(self, *args, **kwargs):
    if self.status != self.STATUS_CANCELLED:
        self.clean()
    
    # Change this line:
    # if self.status == self.STATUS_PENDING and not self.pk:
    #     self.status = self.STATUS_CONFIRMED
    
    # Keep bookings in PENDING state for approval
    
    super().save(*args, **kwargs)
```

### Enable Slack Notifications

Uncomment the signal receiver in `trueAlign/confrence/signals.py`:

```python
@receiver(post_save, sender=RoomBooking)
def send_slack_on_booking(sender, instance, created, **kwargs):
    if created:
        send_slack_notification(instance, 'created')
    elif instance.status == RoomBooking.STATUS_CANCELLED:
        send_slack_notification(instance, 'cancelled')
```

---

## 📝 Workflow Summary

### Employee Booking Flow
```
Browse Rooms → Select Room → Fill Booking Form → System Validates 
→ Auto-Confirm → Email Sent → Booking Created
```

### Admin Room Management Flow
```
Create Room → Set Booking Rules → Add Amenities → Activate 
→ Room Available for Booking
```

### Cancellation Flow
```
View Booking → Click Cancel → Confirm → Email Sent 
→ Booking Cancelled → Room Available Again
```

---

## 🎨 UI/UX Features

- **Tailwind CSS**: Modern, responsive design
- **Icons**: Consistent SVG icons throughout
- **Color Coding**: 
  - Green: Confirmed/Available/Active
  - Yellow: Pending/Warning
  - Red: Cancelled/Errors
  - Blue: Primary actions
- **Responsive**: Works on desktop, tablet, and mobile
- **Loading States**: Visual feedback on form submission
- **Error Messages**: Clear, user-friendly validation messages

---

## 🔐 Security & Permissions

### Access Control
- **Public Users**: Can book and manage own bookings
- **Admin/HR**: Can manage all rooms and view all bookings
- **Permission Check**: `is_admin_or_hr()` helper function

### Data Validation
- Server-side validation on all forms
- Model-level validation via `clean()` methods
- SQL injection protection (Django ORM)
- XSS protection (Django templates)

---

## 📦 File Structure

```
trueAlign/confrence/
├── __init__.py
├── apps.py                 # App configuration
├── forms.py                # All forms (Room, Booking, Cancel)
├── views.py                # All views and logic
├── urls.py                 # URL routing
├── signals.py              # Email/Slack notifications
├── management/
│   └── commands/
│       └── seed_conference_data.py  # Test data seeder
└── templates/conference/
    ├── room_list.html
    ├── room_detail.html
    ├── booking_form.html
    ├── my_bookings.html
    ├── booking_detail.html
    ├── booking_cancel.html
    ├── calendar.html
    └── admin/
        ├── room_list.html
        ├── room_form.html
        └── room_delete_confirm.html
```

---

## ✅ Completion Checklist

- [x] Models created and migrated
- [x] Forms with validation
- [x] Views for all features
- [x] URL routing configured
- [x] Templates with Tailwind UI
- [x] Email notifications
- [x] Management command for seeding
- [x] Settings updated
- [x] Documentation complete

---

## 🚀 Next Steps

1. Run migrations: `python manage.py migrate`
2. Seed test data: `python manage.py seed_conference_data`
3. Create admin user if needed: `python manage.py createsuperuser`
4. Start server: `python manage.py runserver`
5. Access at: `http://localhost:8000/conference/rooms/`

---

## 📞 Support

For issues or questions:
1. Check this documentation
2. Review model validations in `models.py`
3. Check form validations in `forms.py`
4. Review view logic in `views.py`

---

**Happy Booking! 🎉**
