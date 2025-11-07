# Conference Room Booking System - Quick Start Guide 🚀

## ⚡ 5-Minute Setup

### 1. Run Migrations
```bash
python manage.py makemigrations
python manage.py migrate
```

### 2. Seed Sample Data
```bash
python manage.py seed_conference_data
```

### 3. Start Server
```bash
python manage.py runserver
```

### 4. Access System
- **Browse Rooms**: http://localhost:8000/conference/rooms/
- **My Bookings**: http://localhost:8000/conference/bookings/my/
- **Admin Panel**: http://localhost:8000/conference/admin/rooms/ (Admin only)
- **Calendar**: http://localhost:8000/conference/calendar/

---

## 🔑 Key URLs

| Feature | URL | Access |
|---------|-----|--------|
| Browse Rooms | `/conference/rooms/` | All Users |
| Book Room | `/conference/bookings/create/` | All Users |
| My Bookings | `/conference/bookings/my/` | All Users |
| Calendar | `/conference/calendar/` | All Users |
| Manage Rooms | `/conference/admin/rooms/` | Admin/HR |
| Create Room | `/conference/admin/rooms/create/` | Admin/HR |

---

## 📦 What Was Installed

### 1. Models (in `trueAlign/models.py`)
- ✅ `ConferenceRoom` - Manages conference rooms
- ✅ `RoomBooking` - Manages bookings

### 2. Views (in `trueAlign/confrence/views.py`)
- ✅ Room management views (Admin)
- ✅ Room browsing views (Users)
- ✅ Booking management views
- ✅ Calendar view
- ✅ Availability API

### 3. Forms (in `trueAlign/confrence/forms.py`)
- ✅ `ConferenceRoomForm` - Create/edit rooms
- ✅ `RoomBookingForm` - Create bookings
- ✅ `BookingCancelForm` - Cancel bookings
- ✅ `RoomFilterForm` - Filter rooms

### 4. Templates (in `trueAlign/templates/conference/`)
- ✅ 8 Beautiful Tailwind CSS templates
- ✅ Responsive design
- ✅ Admin & user interfaces

### 5. Signals (in `trueAlign/confrence/signals.py`)
- ✅ Email notifications on booking create/cancel
- ✅ Optional Slack webhook support

### 6. Management Commands
- ✅ `seed_conference_data` - Creates sample data

---

## 🎯 Core Features at a Glance

### For Employees
1. **Browse** - View all available rooms with filters
2. **Book** - Reserve rooms with automatic validation
3. **Manage** - View and cancel your bookings
4. **Calendar** - See all bookings in calendar view

### For Admins
1. **Create** - Add new conference rooms
2. **Edit** - Modify room details and rules
3. **Activate/Deactivate** - Control room availability
4. **Delete** - Remove rooms (with safety checks)

---

## ⚙️ Default Booking Rules

- **Buffer Time**: 15 minutes between bookings
- **Lead Time**: 15 minutes advance booking required
- **Max Duration**: 3 hours per booking
- **Auto-Confirm**: Bookings are auto-confirmed

*Can be customized per room in admin panel*

---

## 🔄 Booking Workflow

```
User selects room
    ↓
Fills booking form
    ↓
System validates:
  • Not in past ✓
  • Lead time met ✓
  • Within max duration ✓
  • No conflicts ✓
  • Capacity okay ✓
    ↓
Auto-confirm
    ↓
Email sent
    ↓
✅ Booking Created
```

---

## 📧 Email Setup (Optional but Recommended)

Add to `.env` file:
```env
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@example.com
EMAIL_HOST_PASSWORD=your-app-password
DEFAULT_FROM_EMAIL=noreply@company.com
```

---

## 🧪 Test the System

### Quick Test Checklist
- [ ] Visit `/conference/rooms/` - See list of rooms
- [ ] Click on a room - View details
- [ ] Click "Book Now" - Fill form and submit
- [ ] Visit `/conference/bookings/my/` - See your booking
- [ ] Click "Cancel" on a booking - Confirm cancellation
- [ ] Visit `/conference/admin/rooms/` (as admin) - Manage rooms

---

## 📊 Sample Data Created

When you run `seed_conference_data`, you get:

- **Office Locations**: 2 offices (Mumbai, Delhi) if none exist
- **Conference Rooms**: 6 rooms per office
  - Board Room (20 capacity)
  - Meeting Room A (10 capacity)
  - Meeting Room B (8 capacity)
  - Conference Hall (50 capacity)
  - Innovation Lab (12 capacity)
  - Training Room (25 capacity)
- **Bookings**: Random bookings for next 7 days

---

## 🎨 UI Features

- **Modern Design**: Clean Tailwind CSS interface
- **Responsive**: Works on all devices
- **Color Coded**:
  - 🟢 Green = Available/Confirmed
  - 🟡 Yellow = Pending/Warning
  - 🔴 Red = Cancelled/Error
  - 🔵 Blue = Primary Actions
- **Icons**: Consistent SVG icons
- **Loading States**: Visual feedback

---

## 🔧 Common Customizations

### Change Buffer Time
Edit in Admin Panel → Select Room → Change "Buffer time (minutes)"

### Change Max Duration
Edit in Admin Panel → Select Room → Change "Max Duration (hours)"

### Disable Auto-Confirm
Edit `trueAlign/models.py` → `RoomBooking.save()` method

### Add Slack Notifications
1. Add `SLACK_WEBHOOK_URL` to `.env`
2. Uncomment signal in `signals.py`

---

## ❓ FAQ

**Q: Can I book a room right now?**
A: No, minimum 15 minutes lead time required (configurable).

**Q: What happens if someone else books my time slot?**
A: System prevents conflicts - you'll see an error if time is taken.

**Q: Can I cancel past bookings?**
A: No, only upcoming bookings can be cancelled.

**Q: How do I get room admin access?**
A: Contact your system administrator to get staff/admin permissions.

**Q: Can I extend my booking?**
A: No, create a new booking for extended time (if available).

**Q: What's the buffer time for?**
A: Cleaning and setup between meetings. Can't book during buffer.

---

## 📝 Quick Command Reference

```bash
# Run migrations
python manage.py migrate

# Create sample data
python manage.py seed_conference_data

# Clear and recreate sample data
python manage.py seed_conference_data --clear

# Create admin user
python manage.py createsuperuser

# Start development server
python manage.py runserver

# Collect static files
python manage.py collectstatic
```

---

## 🎉 You're All Set!

The Conference Room Booking System is now ready to use. 

**Next Steps:**
1. Log in as admin
2. Create real office locations (if needed)
3. Create real conference rooms
4. Share room list URL with your team
5. Start booking!

For detailed documentation, see: `CONFERENCE_ROOM_MODULE_DOCS.md`

---

**Need Help?** Check the full documentation or review the code comments!
