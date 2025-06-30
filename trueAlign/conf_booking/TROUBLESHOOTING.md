# Conference Room Booking System - Troubleshooting Guide

## Quick Diagnostics

### 1. Run the verification script to check system health:
```bash
python manage.py verify_booking_system --verbose
```

### 2. Check for common issues:
```bash
# Verify migrations are applied
python manage.py showmigrations conf_booking

# Check for active rooms
python manage.py shell -c "from trueAlign.models import Room; print(f'Active rooms: {Room.objects.filter(status=\"ACTIVE\").count()}')"

# Verify API endpoints
curl http://localhost:8000/book/api/rooms/
```

## Common Issues and Solutions

### 🚫 Issue: "Cannot book properly" / Form submission fails

**Symptoms:**
- Booking form doesn't submit
- Page refreshes but no booking is created
- Error messages about form validation

**Solutions:**

1. **Check form data submission:**
   ```python
   # In Django shell
   from django.test import Client
   client = Client()
   # Test form submission with valid data
   ```

2. **Verify CSRF token:**
   - Ensure `{% csrf_token %}` is present in forms
   - Check browser developer tools for CSRF errors

3. **Check working hours validation:**
   - Bookings only allowed 9 AM - 6 PM, Monday-Friday
   - Verify timezone settings: `TIME_ZONE = 'Asia/Kolkata'`

4. **Debug form validation:**
   ```python
   # Add to views.py temporarily for debugging
   print(f"Form errors: {form.errors}")
   print(f"Form data: {request.POST}")
   ```

### 🏢 Issue: Room status not showing correctly

**Symptoms:**
- Rooms always show as "Available" 
- "Occupied" status not updating
- Next booking information missing

**Solutions:**

1. **Check Room model properties:**
   ```python
   # In Django shell
   from trueAlign.models import Room
   room = Room.objects.first()
   print(f"Current booking: {room.current_booking}")
   print(f"Next booking: {room.next_booking}")
   print(f"Is occupied: {room.is_occupied}")
   ```

2. **Verify booking relationships:**
   ```python
   # Check if foreign key relationship exists
   room = Room.objects.first()
   print(f"Total bookings: {room.bookings.count()}")
   print(f"Confirmed bookings: {room.bookings.filter(status='CONFIRMED').count()}")
   ```

3. **Check timezone handling:**
   ```python
   from django.utils import timezone
   print(f"Current time (UTC): {timezone.now()}")
   print(f"Current time (IST): {timezone.now().astimezone(timezone.get_current_timezone())}")
   ```

### 📅 Issue: Booking conflicts not detected

**Symptoms:**
- Double bookings allowed
- Conflict detection not working
- No alternative time suggestions

**Solutions:**

1. **Test conflict detection manually:**
   ```python
   from trueAlign.models import ConferenceBooking, Room
   from django.utils import timezone
   from datetime import timedelta
   
   room = Room.objects.first()
   now = timezone.now()
   start = now + timedelta(hours=1)
   end = start + timedelta(hours=1)
   
   conflicts = ConferenceBooking.get_conflicting_bookings(room, start, end)
   print(f"Conflicts found: {conflicts.count()}")
   ```

2. **Check booking status:**
   ```python
   # Only CONFIRMED bookings should block slots
   bookings = ConferenceBooking.objects.filter(status='CONFIRMED')
   print(f"Confirmed bookings: {bookings.count()}")
   ```

### 🔌 Issue: API endpoints not working

**Symptoms:**
- 404 errors on `/book/api/` URLs
- Empty responses from API
- JavaScript console errors

**Solutions:**

1. **Verify URL configuration:**
   ```python
   # Check urls.py includes
   # Main urls.py should have:
   path('book/', include('trueAlign.conf_booking.urls')),
   ```

2. **Test API endpoints directly:**
   ```bash
   # Test rooms API
   curl -H "Accept: application/json" http://localhost:8000/book/api/rooms/
   
   # Test available slots API
   curl -H "Accept: application/json" "http://localhost:8000/book/api/available-slots/?duration=60"
   ```

3. **Check permissions:**
   ```python
   # Ensure user is logged in for API access
   from django.contrib.auth.decorators import login_required
   # All booking views should have @login_required
   ```

### 📧 Issue: Email notifications not sending

**Symptoms:**
- No booking confirmation emails
- No cancellation notices
- Email errors in logs

**Solutions:**

1. **Check email settings:**
   ```python
   # In settings.py
   EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
   EMAIL_HOST = 'your-smtp-server.com'
   EMAIL_PORT = 587
   EMAIL_USE_TLS = True
   EMAIL_HOST_USER = 'your-email@domain.com'
   EMAIL_HOST_PASSWORD = 'your-password'
   DEFAULT_FROM_EMAIL = 'booking@yourcompany.com'
   ```

2. **Test email sending:**
   ```python
   # In Django shell
   from django.core.mail import send_mail
   send_mail(
       'Test Subject',
       'Test message',
       'from@example.com',
       ['to@example.com'],
       fail_silently=False,
   )
   ```

3. **For development, use console backend:**
   ```python
   EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
   ```

## Database Issues

### 🗃️ Issue: Migration errors

**Solutions:**

1. **Check migration status:**
   ```bash
   python manage.py showmigrations
   python manage.py migrate --dry-run
   ```

2. **Reset migrations if needed:**
   ```bash
   # CAUTION: Only for development
   python manage.py migrate conf_booking zero
   python manage.py makemigrations conf_booking
   python manage.py migrate
   ```

3. **Setup initial rooms:**
   ```bash
   python manage.py setup_rooms
   ```

### 🔄 Issue: Data inconsistency

**Solutions:**

1. **Update room analytics:**
   ```python
   # In Django shell
   from trueAlign.models import Room
   for room in Room.objects.all():
       room.update_analytics()
   ```

2. **Clean up old bookings:**
   ```python
   from trueAlign.models import ConferenceBooking
   from django.utils import timezone
   from datetime import timedelta
   
   # Mark old bookings as completed
   old_bookings = ConferenceBooking.objects.filter(
       end_time__lt=timezone.now() - timedelta(days=1),
       status='CONFIRMED'
   )
   print(f"Found {old_bookings.count()} old bookings to clean up")
   ```

## Frontend Issues

### 🖥️ Issue: Modal not opening

**Solutions:**

1. **Check JavaScript console for errors**
2. **Verify modal HTML is included:**
   ```html
   {% include 'components/simple_booking_modal.html' %}
   ```

3. **Test modal function:**
   ```javascript
   // In browser console
   if (typeof window.openSimpleBookingModal === 'function') {
       console.log('Modal function exists');
       window.openSimpleBookingModal();
   } else {
       console.log('Modal function missing');
   }
   ```

### 🎨 Issue: Styling problems

**Solutions:**

1. **Check CSS loading:**
   ```html
   <!-- Ensure Tailwind CSS is loaded -->
   <script src="https://cdn.tailwindcss.com"></script>
   ```

2. **Verify class names are correct:**
   ```html
   <!-- Check for typos in Tailwind classes -->
   <div class="bg-blue-500 text-white p-4 rounded-lg">
   ```

## Performance Issues

### 🐌 Issue: Slow loading

**Solutions:**

1. **Add database indexes:**
   ```python
   # In models.py
   class ConferenceBooking(models.Model):
       class Meta:
           indexes = [
               models.Index(fields=['room', 'start_time']),
               models.Index(fields=['booked_by', 'status']),
           ]
   ```

2. **Use select_related and prefetch_related:**
   ```python
   # In views.py
   bookings = ConferenceBooking.objects.select_related(
       'room', 'booked_by'
   ).prefetch_related('room__bookings')
   ```

3. **Enable query logging:**
   ```python
   # In settings.py for debugging
   LOGGING = {
       'version': 1,
       'handlers': {
           'console': {
               'class': 'logging.StreamHandler',
           },
       },
       'loggers': {
           'django.db.backends': {
               'level': 'DEBUG',
               'handlers': ['console'],
           },
       },
   }
   ```

## Testing & Debugging

### 🧪 Issue: How to test the system

**Testing Steps:**

1. **Run verification script:**
   ```bash
   python manage.py verify_booking_system --create-test-data --verbose
   ```

2. **Manual testing checklist:**
   - [ ] Create a booking for today
   - [ ] Create a booking for tomorrow
   - [ ] Try to book same time slot (should fail)
   - [ ] Check room status updates
   - [ ] Test cancellation
   - [ ] Test check-in functionality

3. **API testing:**
   ```bash
   # Test with curl or Postman
   curl -X GET "http://localhost:8000/book/api/rooms/" \
        -H "Cookie: sessionid=your-session-id"
   ```

### 🔍 Issue: How to debug booking issues

**Debugging Steps:**

1. **Enable debug logging:**
   ```python
   # Add to views.py
   import logging
   logger = logging.getLogger(__name__)
   logger.info(f"Booking attempt: {request.POST}")
   ```

2. **Check Django logs:**
   ```bash
   tail -f /path/to/django.log
   ```

3. **Use Django debug toolbar:**
   ```python
   # In settings.py for development
   INSTALLED_APPS += ['debug_toolbar']
   MIDDLEWARE += ['debug_toolbar.middleware.DebugToolbarMiddleware']
   ```

## Recovery Procedures

### 🚨 Emergency: System completely broken

1. **Rollback to previous version:**
   ```bash
   git checkout HEAD~1
   python manage.py migrate
   ```

2. **Reset to clean state:**
   ```bash
   python manage.py migrate conf_booking zero
   python manage.py migrate
   python manage.py setup_rooms
   ```

3. **Restore from backup:**
   ```bash
   python manage.py loaddata booking_backup.json
   ```

### 🔄 Issue: Need to reset all bookings

```python
# In Django shell - CAUTION: This deletes all booking data
from trueAlign.models import ConferenceBooking
ConferenceBooking.objects.all().delete()
```

## Getting Help

### 📞 When to escalate

- Database corruption
- Security vulnerabilities
- Performance issues affecting multiple users
- Data loss scenarios

### 📝 Information to collect before escalating

1. **Error messages and stack traces**
2. **Steps to reproduce the issue**
3. **Browser and device information**
4. **Time when issue occurred**
5. **Affected user accounts**
6. **System logs and database query logs**

### 🔧 Temporary workarounds

1. **Disable booking temporarily:**
   ```python
   # In views.py
   def booking_room(request):
       messages.info(request, "Booking system is temporarily unavailable")
       return redirect('core:dashboard')
   ```

2. **Use manual booking process:**
   - Direct admin interface booking
   - Email-based booking requests
   - Phone/chat booking assistance

---

## Quick Reference

### Useful Management Commands
```bash
# Setup rooms
python manage.py setup_rooms

# Migrate room data
python manage.py migrate_room_data --dry-run

# Verify system
python manage.py verify_booking_system

# Django shell
python manage.py shell
```

### Important Model Methods
```python
# Room status
room.is_occupied
room.current_booking
room.next_booking

# Booking conflicts
ConferenceBooking.get_conflicting_bookings(room, start, end)

# Room availability
RoomManager.get_available_rooms_for_slot(start, end, capacity)
```

### API Endpoints
```
GET /book/api/rooms/
GET /book/api/available-slots/
GET /book/api/room/{id}/
POST /book/book/
POST /book/cancel/{id}/
```

Remember: Always test changes in a development environment first!