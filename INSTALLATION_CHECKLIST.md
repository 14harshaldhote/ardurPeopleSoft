# Conference Room Booking System - Installation Checklist ✅

Use this checklist to ensure proper installation and configuration.

---

## 📋 Pre-Installation

- [ ] Django 5.1.4+ installed
- [ ] PostgreSQL or MySQL database configured
- [ ] Python 3.8+ installed
- [ ] Virtual environment activated
- [ ] All existing migrations applied

---

## 🔧 Installation Steps

### 1. Database Setup
- [ ] Backup existing database (if in production)
- [ ] Run `python manage.py makemigrations`
- [ ] Review migration file in `trueAlign/migrations/`
- [ ] Run `python manage.py migrate`
- [ ] Verify tables created:
  - [ ] `trueAlign_conferenceroom`
  - [ ] `trueAlign_roombooking`

### 2. Static Files
- [ ] Run `python manage.py collectstatic`
- [ ] Verify template files exist in `trueAlign/templates/conference/`
- [ ] Check that Tailwind CSS is loading properly

### 3. Email Configuration
- [ ] Add email settings to `.env` file
  ```env
  EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
  EMAIL_HOST=smtp.gmail.com
  EMAIL_PORT=587
  EMAIL_USE_TLS=True
  EMAIL_HOST_USER=your-email@example.com
  EMAIL_HOST_PASSWORD=your-app-password
  DEFAULT_FROM_EMAIL=noreply@company.com
  ```
- [ ] Test email sending with Django shell:
  ```python
  from django.core.mail import send_mail
  send_mail('Test', 'Test message', 'from@example.com', ['to@example.com'])
  ```

### 4. Sample Data (Optional)
- [ ] Run `python manage.py seed_conference_data`
- [ ] Verify office locations created
- [ ] Verify conference rooms created
- [ ] Verify sample bookings created
- [ ] Check data in Django admin

---

## 🧪 Testing Checklist

### Admin Functionality
- [ ] Login as admin/staff user
- [ ] Access `/conference/admin/rooms/`
- [ ] Create a new conference room
  - [ ] Fill all required fields
  - [ ] Add amenities
  - [ ] Upload an image (optional)
  - [ ] Set booking rules
  - [ ] Save successfully
- [ ] Edit an existing room
- [ ] Deactivate a room
- [ ] Activate a room
- [ ] Delete a room (with no bookings)

### User Booking Flow
- [ ] Login as regular user
- [ ] Access `/conference/rooms/`
- [ ] Browse rooms
- [ ] Use filters (location, capacity)
- [ ] Search for a room
- [ ] View room details
- [ ] Click "Book Now"
- [ ] Fill booking form:
  - [ ] Select date (tomorrow)
  - [ ] Select start time
  - [ ] Select end time
  - [ ] Add meeting title
  - [ ] Add purpose
  - [ ] Add attendees
  - [ ] Add attendee count
  - [ ] Add special requirements (optional)
- [ ] Submit booking
- [ ] Verify redirect to My Bookings
- [ ] Check email inbox for confirmation

### Validation Testing
- [ ] Try to book in the past (should fail)
- [ ] Try to book with insufficient lead time (should fail)
- [ ] Try to book for > 3 hours (should fail)
- [ ] Try to book with attendees > capacity (should fail)
- [ ] Try to book overlapping time slot (should fail)
- [ ] Try to book inactive room (should fail)

### Booking Management
- [ ] Access `/conference/bookings/my/`
- [ ] View active bookings section
- [ ] View upcoming bookings section
- [ ] View past bookings section
- [ ] Click on booking to view details
- [ ] Cancel an upcoming booking
  - [ ] Add cancellation reason
  - [ ] Confirm cancellation
  - [ ] Check email for cancellation notice
- [ ] Verify cannot cancel past booking

### Calendar View
- [ ] Access `/conference/calendar/`
- [ ] View all bookings
- [ ] Filter by room
- [ ] Change month
- [ ] Verify bookings display correctly

### API Endpoint
- [ ] Test availability check endpoint
  ```bash
  curl "http://localhost:8000/conference/api/check-availability/?room_id=1&date=2025-11-08&start_time=10:00&end_time=11:00"
  ```
- [ ] Verify JSON response

---

## 🔐 Security Checklist

- [ ] Only admin/staff can access admin URLs
- [ ] Users can only view/edit their own bookings
- [ ] Form validation works on both client and server
- [ ] CSRF tokens present in all forms
- [ ] SQL injection protection (Django ORM)
- [ ] XSS protection (Django templates)

---

## 📧 Email Notification Testing

- [ ] Create a booking → Check confirmation email
- [ ] Cancel a booking → Check cancellation email
- [ ] Verify email formatting (HTML)
- [ ] Check sender address
- [ ] Verify all booking details in email
- [ ] Test with different email providers

---

## 🎨 UI/UX Verification

- [ ] All pages load without errors
- [ ] Tailwind CSS styles applied
- [ ] Icons display correctly
- [ ] Forms are user-friendly
- [ ] Error messages are clear
- [ ] Success messages display
- [ ] Responsive on mobile devices
- [ ] Responsive on tablets
- [ ] Responsive on desktop
- [ ] Loading states work
- [ ] Pagination works (if applicable)

---

## 📱 Browser Compatibility

- [ ] Chrome (latest)
- [ ] Firefox (latest)
- [ ] Safari (latest)
- [ ] Edge (latest)
- [ ] Mobile browsers

---

## 🚀 Production Checklist (Before Deployment)

### Settings
- [ ] `DEBUG = False` in production
- [ ] `ALLOWED_HOSTS` configured
- [ ] Secret key secured
- [ ] Database credentials secured
- [ ] Email credentials secured

### Media Files
- [ ] Configure production media storage
- [ ] Set up CDN for room images (optional)
- [ ] Test image uploads in production

### Performance
- [ ] Database indexes created (automatic with migrations)
- [ ] Static files served efficiently
- [ ] Consider caching for room list
- [ ] Monitor query performance

### Monitoring
- [ ] Set up error logging
- [ ] Monitor email sending failures
- [ ] Track booking metrics
- [ ] Set up user analytics (optional)

### Backup
- [ ] Database backup configured
- [ ] Media files backup configured
- [ ] Document restoration procedure

---

## 📊 Post-Installation Tasks

- [ ] Create real office locations (if not using sample data)
- [ ] Create real conference rooms
- [ ] Configure booking rules per room
- [ ] Add room amenities
- [ ] Upload room images
- [ ] Train admin users on room management
- [ ] Train employees on booking system
- [ ] Share room list URL with team
- [ ] Monitor initial usage

---

## 🐛 Common Issues & Solutions

### Issue: Migrations fail
**Solution**: 
- Check database connection
- Ensure `trueAlign.confrence` is in `INSTALLED_APPS`
- Run `python manage.py showmigrations` to check status

### Issue: Templates not found
**Solution**:
- Verify template directory structure
- Check `TEMPLATES` setting in `settings.py`
- Ensure templates are in `trueAlign/templates/conference/`

### Issue: Email not sending
**Solution**:
- Verify email settings in `.env`
- Check SMTP credentials
- Test with Django shell
- Check spam folder

### Issue: Room images not displaying
**Solution**:
- Configure `MEDIA_URL` and `MEDIA_ROOT`
- Ensure media files are served in development
- Check file permissions

### Issue: Booking validation errors
**Solution**:
- Review error messages carefully
- Check room booking rules
- Verify date/time format
- Ensure room is active

---

## 📞 Support Resources

- **Full Documentation**: `CONFERENCE_ROOM_MODULE_DOCS.md`
- **Quick Start**: `CONFERENCE_ROOM_QUICK_START.md`
- **Module README**: `trueAlign/confrence/README.md`
- **Code Comments**: Inline documentation in all files

---

## ✅ Installation Complete!

Once all items are checked:
1. Share the room list URL with your team
2. Monitor initial usage and feedback
3. Adjust booking rules as needed
4. Add more rooms based on demand

**Congratulations! Your Conference Room Booking System is ready! 🎉**

---

**Last Updated**: November 7, 2025  
**Version**: 1.0  
**Module**: Conference Room Booking System
