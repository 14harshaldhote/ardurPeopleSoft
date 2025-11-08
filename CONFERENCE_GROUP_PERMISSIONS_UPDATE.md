# Conference Room System - Group-Based Permissions & Dashboard Integration

## 🔄 Changes Implemented

### 1. Group-Based Permissions ✅

**Changed From**: `is_superuser` or `is_staff` checks  
**Changed To**: Django Groups (`Admin`, `HR`)

#### Updated Files:
- `/trueAlign/confrence/views.py` - Updated `is_admin_or_hr()` helper function

#### New Permission Logic:
```python
def is_admin_or_hr(user):
    """
    Check if user is admin or HR using Django Groups.
    Admin and HR groups have permission to manage conference rooms.
    """
    if not user.is_authenticated:
        return False
    user_groups = user.groups.values_list('name', flat=True)
    return 'Admin' in user_groups or 'HR' in user_groups
```

**Access Control**:
- **Admin Group**: Full room management (create, edit, delete, toggle active)
- **HR Group**: Full room management (create, edit, delete, toggle active)
- **All Authenticated Users**: Can browse rooms and create bookings

---

### 2. Dashboard Integration ✅

**Entry Point**: Dashboard card (no separate navigation menu)

#### Updated Files:
1. `/trueAlign/confrence/views.py` - Added `get_dashboard_conference_context()` function
2. `/trueAlign/core/views.py` - Enabled conference context in `dashboard_view()`
3. `/trueAlign/templates/dashboard/conferenceBooking_card_new.html` - New dynamic card

#### Dashboard Context Function:
```python
def get_dashboard_conference_context(user):
    """
    Get real-time conference booking data for dashboard card.
    Returns context data for displaying current status, next booking, and stats.
    """
```

**Real-time Data Provided**:
- `featured_room` - Primary conference room for user's office
- `current_booking` - Currently active booking (if any)
- `next_booking` - Next upcoming booking
- `is_currently_free` - Room availability status
- `free_until` - Time when room will be free/occupied
- `todays_bookings_count` - Number of bookings today
- `user_upcoming_bookings` - User's upcoming bookings count
- `total_active_rooms` - Total available conference rooms

---

### 3. Real-Time Dashboard Card ✅

#### Features:
1. **Live Room Status**
   - Green "Available" badge when room is free
   - Red "In Use" badge when room is occupied
   - Shows "Until X:XX AM/PM" for next state change

2. **Current Status Section**
   - Real-time availability indicator
   - Room capacity display
   - Number of amenities

3. **Next Booking Section**
   - Shows upcoming booking details (title, time, organizer)
   - Or displays "No upcoming bookings" message

4. **Action Buttons**
   - **"Book This Room"** - Direct link to booking form for featured room
   - **View icon** - Link to detailed room information

5. **Footer Stats**
   - Today's total bookings count
   - User's upcoming bookings with link to "My Bookings"

---

## 🚀 Setup Instructions

### Step 1: Create Django Groups

Run these commands to create the required groups:

```bash
python manage.py shell
```

```python
from django.contrib.auth.models import Group

# Create Admin group
admin_group, created = Group.objects.get_or_create(name='Admin')
if created:
    print("✓ Admin group created")
else:
    print("✓ Admin group already exists")

# Create HR group
hr_group, created = Group.objects.get_or_create(name='HR')
if created:
    print("✓ HR group created")
else:
    print("✓ HR group already exists")

exit()
```

### Step 2: Assign Users to Groups

**Via Django Admin**:
1. Go to: `/admin/auth/user/`
2. Select a user
3. Scroll to "Groups" section
4. Add user to `Admin` or `HR` group
5. Save

**Via Python Shell**:
```python
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group

User = get_user_model()

# Add user to Admin group
user = User.objects.get(username='admin_username')
admin_group = Group.objects.get(name='Admin')
user.groups.add(admin_group)
print(f"✓ {user.username} added to Admin group")

# Add user to HR group
hr_user = User.objects.get(username='hr_username')
hr_group = Group.objects.get(name='HR')
hr_user.groups.add(hr_group)
print(f"✓ {hr_user.username} added to HR group")
```

### Step 3: Replace Dashboard Card

Replace the old static card with the new dynamic version:

```bash
# Backup old card
mv /Users/harshalsmac/WORK/ardur/ardurHome/trueAlign/templates/dashboard/conferenceBooking_card.html /Users/harshalsmac/WORK/ardur/ardurHome/trueAlign/templates/dashboard/conferenceBooking_card_old.html

# Use new card
mv /Users/harshalsmac/WORK/ardur/ardurHome/trueAlign/templates/dashboard/conferenceBooking_card_new.html /Users/harshalsmac/WORK/ardur/ardurHome/trueAlign/templates/dashboard/conferenceBooking_card.html
```

### Step 4: Test the System

1. **Login as regular employee**:
   - Dashboard card shows real-time room status
   - Click "Book This Room" to create booking
   - Click "My Bookings" to view bookings
   - Cannot access `/conference/admin/rooms/` (403 error)

2. **Login as Admin/HR user**:
   - Dashboard card shows real-time room status
   - Click "Book This Room" to create booking
   - Can access `/conference/admin/rooms/` for management
   - Can create, edit, delete rooms

---

## 📋 Permission Matrix

| Feature | Employee | Admin Group | HR Group |
|---------|----------|-------------|----------|
| **View Dashboard Card** | ✅ | ✅ | ✅ |
| **Browse Rooms** | ✅ | ✅ | ✅ |
| **View Room Details** | ✅ | ✅ | ✅ |
| **Create Bookings** | ✅ | ✅ | ✅ |
| **View Own Bookings** | ✅ | ✅ | ✅ |
| **Cancel Own Bookings** | ✅ | ✅ | ✅ |
| **Create Rooms** | ❌ | ✅ | ✅ |
| **Edit Rooms** | ❌ | ✅ | ✅ |
| **Delete Rooms** | ❌ | ✅ | ✅ |
| **Activate/Deactivate Rooms** | ❌ | ✅ | ✅ |
| **Access Admin Panel** | ❌ | ✅ | ✅ |

---

## 🔗 Navigation Flow

### For All Users:
```
Dashboard
    ↓
Conference Card (Entry Point)
    ├─→ "Book This Room" → Booking Form → Confirmation
    ├─→ View Icon → Room Details → Book Button → Booking Form
    └─→ "My Bookings" → Bookings List → Booking Detail → Cancel (if upcoming)
```

### For Admin/HR Only:
```
Admin Panel: /conference/admin/rooms/
    ├─→ Create Room → Room Form → Save
    ├─→ Edit Room → Room Form → Update
    ├─→ Delete Room → Confirmation → Delete
    └─→ Toggle Active → Instant Update
```

---

## 🎨 Dashboard Card States

### State 1: Room Available
- **Badge**: Green "Available" with pulsing dot
- **Status**: "Currently Free" with green checkmark
- **Until**: Shows next booking time
- **Action**: "Book This Room" button enabled

### State 2: Room Occupied
- **Badge**: Red "In Use" with pulsing dot
- **Status**: "Currently Occupied" with red alert icon
- **Until**: Shows when room will be free
- **Action**: "Book This Room" button enabled (for future slots)

### State 3: No Next Booking
- **Next Booking Section**: Shows "No upcoming bookings"
- **Background**: Blue/info color scheme
- **Indicates**: Room is free for rest of day

### State 4: No Rooms Available
- **Card**: Shows placeholder message
- **Icon**: Gray conference room icon
- **Message**: "Contact admin to set up conference rooms"

---

## 🔧 Configuration

### Set Featured Room Priority

The dashboard shows rooms in this priority order:
1. **User's Office Location** - Room from user's office (via `user.userdetails.office_location`)
2. **Any Active Room** - First available active room

To customize, edit `/trueAlign/confrence/views.py`:
```python
def get_dashboard_conference_context(user):
    # Modify room selection logic here
    if user_office:
        featured_room = ConferenceRoom.objects.filter(
            office_location=user_office,
            is_active=True
        ).order_by('name').first()  # Add custom ordering
```

---

## 📊 Real-Time Data Updates

Dashboard data is **fetched on every page load** - no caching.

**Data refreshed**:
- Room availability status
- Next booking information
- Today's booking count
- User's upcoming bookings

**Auto-refresh**: To enable auto-refresh, add JavaScript to dashboard:
```javascript
// Refresh dashboard card every 60 seconds
setInterval(function() {
    location.reload();
}, 60000);
```

---

## 🐛 Troubleshooting

### Issue: Permission Denied (403) for Admin User

**Solution**:
1. Check if user is in `Admin` or `HR` group:
   ```python
   python manage.py shell
   from django.contrib.auth import get_user_model
   User = get_user_model()
   user = User.objects.get(username='your_username')
   print(list(user.groups.values_list('name', flat=True)))
   ```
2. Add user to group if missing

### Issue: Dashboard Card Not Showing

**Solution**:
1. Check if `featured_room` exists:
   - Create at least one active conference room
2. Check if dashboard card template is replaced
3. Check server logs for errors in `get_dashboard_conference_context()`

### Issue: Old Static Card Still Showing

**Solution**:
1. Clear browser cache (Ctrl+Shift+R / Cmd+Shift+R)
2. Restart Django server
3. Check if file was replaced correctly

### Issue: "My Bookings" Link Shows Wrong Count

**Solution**:
- Booking counts are real-time, check database:
  ```python
  from trueAlign.models import RoomBooking
  from django.utils import timezone
  
  # Check user's bookings
  bookings = RoomBooking.objects.filter(
      booked_by=user,
      status__in=['CONFIRMED', 'PENDING'],
      start_time__gte=timezone.now()
  )
  print(f"Upcoming bookings: {bookings.count()}")
  ```

---

## ✅ Testing Checklist

### Group Permissions
- [ ] Create `Admin` and `HR` groups
- [ ] Assign test users to groups
- [ ] Verify Admin/HR can access `/conference/admin/rooms/`
- [ ] Verify employees get 403 on admin URLs
- [ ] Verify all users can book rooms

### Dashboard Card
- [ ] Card displays on dashboard
- [ ] Shows correct room name and floor
- [ ] Status badge is green/red based on availability
- [ ] "Currently Free/Occupied" matches actual status
- [ ] "Until" time is correct
- [ ] Capacity and amenities count display
- [ ] Next booking shows if exists
- [ ] "Book This Room" button works
- [ ] View details button works
- [ ] "My Bookings" link works and shows correct count
- [ ] Today's booking count is accurate

### Real-Time Updates
- [ ] Create a booking → Refresh dashboard → Status updates
- [ ] Cancel a booking → Refresh dashboard → Status updates
- [ ] Booking starts → Status changes to "In Use"
- [ ] Booking ends → Status changes to "Available"

---

## 📝 Migration Notes

### Before Migration
- System used `is_superuser` and `is_staff` for permissions
- Dashboard card had static hardcoded data
- No integration with conference booking system

### After Migration
- System uses Django Groups (`Admin`, `HR`)
- Dashboard card shows real-time data
- Full integration with conference booking
- Users can book directly from dashboard

### Breaking Changes
- **None** - All existing functionality preserved
- **Groups Required** - Must create and assign groups for admin access

---

## 🎉 Benefits of Changes

1. **Better Security**
   - Granular permission control via Groups
   - Easy to manage user roles
   - Follows Django best practices

2. **Improved UX**
   - Single entry point (dashboard)
   - Real-time room status
   - Quick booking access
   - Clear navigation flow

3. **Maintainability**
   - Cleaner permission logic
   - Centralized access control
   - Easier to add new roles

4. **Scalability**
   - Can add more groups (e.g., `Manager`, `Team Lead`)
   - Can add group-specific features
   - Can implement per-group room access

---

**Implementation Date**: November 7, 2025  
**Status**: ✅ COMPLETE  
**Breaking Changes**: None  
**Required Actions**: Create Groups, Assign Users, Replace Dashboard Card
