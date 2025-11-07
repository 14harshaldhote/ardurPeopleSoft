# Conference Room Booking Module

A complete, production-ready conference room booking system for Django office intranet.

## 🎯 Features

- **Room Management**: Admin can create, edit, and manage conference rooms
- **Smart Booking**: Automatic conflict detection, buffer time, and capacity validation
- **User Interface**: Beautiful Tailwind CSS templates with responsive design
- **Email Notifications**: Automatic email confirmations and cancellation notices
- **Calendar View**: Visual representation of all bookings
- **Role-Based Access**: Different features for admins and employees

## 📂 Module Structure

```
confrence/
├── __init__.py
├── apps.py                 # App configuration with signal registration
├── admin.py                # Django admin interface
├── forms.py                # All forms (Room, Booking, Cancellation)
├── views.py                # Views for room & booking management
├── urls.py                 # URL routing
├── signals.py              # Email & Slack notifications
├── management/
│   └── commands/
│       └── seed_conference_data.py
└── README.md               # This file
```

## 🚀 Quick Start

### 1. Migrations
```bash
python manage.py makemigrations
python manage.py migrate
```

### 2. Create Sample Data
```bash
python manage.py seed_conference_data
```

### 3. Access
- Browse Rooms: `/conference/rooms/`
- Admin Panel: `/conference/admin/rooms/`
- My Bookings: `/conference/bookings/my/`

## 📋 Models

### ConferenceRoom
- Manages conference room details, capacity, and amenities
- Configurable booking rules (buffer time, lead time, max duration)
- Linked to OfficeLocation

### RoomBooking
- Tracks all room reservations
- Status: PENDING, CONFIRMED, CANCELLED
- Full validation with conflict detection

## 🔗 URL Endpoints

| URL Pattern | Description |
|-------------|-------------|
| `/conference/rooms/` | Browse available rooms |
| `/conference/bookings/create/` | Create new booking |
| `/conference/bookings/my/` | View user's bookings |
| `/conference/admin/rooms/` | Admin room management |

See `CONFERENCE_ROOM_MODULE_DOCS.md` for complete endpoint list.

## ⚙️ Configuration

### Email Setup
Add to your `.env`:
```env
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@example.com
EMAIL_HOST_PASSWORD=your-app-password
DEFAULT_FROM_EMAIL=noreply@company.com
```

### Optional: Slack Notifications
Add to `.env`:
```env
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

Then uncomment the Slack signal receiver in `signals.py`.

## 🎨 Templates

All templates use Tailwind CSS and follow the project's design standards:
- `room_list.html` - Browse rooms
- `room_detail.html` - Room details
- `booking_form.html` - Create booking
- `my_bookings.html` - User's bookings
- `booking_detail.html` - Booking details
- `booking_cancel.html` - Cancel booking
- `calendar.html` - Calendar view
- `admin/room_list.html` - Admin room management
- `admin/room_form.html` - Create/edit room
- `admin/room_delete_confirm.html` - Delete confirmation

## 🔐 Permissions

- **All Employees**: Browse rooms, create bookings, manage own bookings
- **Admin/HR**: All employee features + room management

Permission check: `is_admin_or_hr(user)` returns `user.is_superuser or user.is_staff`

## 📧 Notifications

Automatic email notifications sent for:
- ✅ Booking creation (confirmed)
- ❌ Booking cancellation

Email includes:
- Full booking details
- Room information and amenities
- Meeting purpose and attendees
- Booking status

## 🧪 Testing

### Create Test Data
```bash
# Create sample data
python manage.py seed_conference_data

# Clear existing and recreate
python manage.py seed_conference_data --clear
```

### Manual Testing
1. Create a conference room as admin
2. Book the room as a user
3. Try to book an overlapping slot (should fail)
4. Cancel a booking
5. Check email notifications

## 🛠️ Customization

### Modify Default Booking Rules
Edit in `trueAlign/models.py`, `ConferenceRoom` model:
- `buffer_time_minutes` (default: 15)
- `min_lead_time_minutes` (default: 15)
- `max_booking_duration_hours` (default: 3)

### Enable Approval Workflow
Modify `RoomBooking.save()` method to keep bookings in PENDING state instead of auto-confirming.

## 📚 Documentation

- **Quick Start**: `CONFERENCE_ROOM_QUICK_START.md`
- **Full Docs**: `CONFERENCE_ROOM_MODULE_DOCS.md`
- **Code Comments**: Extensive inline documentation

## 🐛 Troubleshooting

**Problem**: Bookings not saving
- Check model validations in browser console
- Review `clean()` method in `RoomBooking`

**Problem**: Email not sending
- Verify email settings in `.env`
- Check `signals.py` for email configuration

**Problem**: Conflicts not detected
- Ensure buffer time is set correctly
- Review overlap detection logic in `RoomBooking.clean()`

## 📝 License

Part of the ardurHome office intranet system.

## ✅ Checklist for Deployment

- [ ] Run migrations
- [ ] Create real office locations
- [ ] Create conference rooms
- [ ] Configure email settings
- [ ] Test booking flow
- [ ] Test cancellation flow
- [ ] Verify email notifications
- [ ] Set up production media storage for room images

---

**Version**: 1.0  
**Created**: November 2025  
**Django**: 5.1.4+  
**Python**: 3.8+
