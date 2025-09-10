# cPanel Cron Job Setup for Attendance System

This document provides complete instructions for setting up automated cron jobs for the TrueAlign Attendance System using cPanel's cron job interface.

## 📋 Overview

The attendance system requires automated tasks to run at specific intervals to:
- Create daily attendance records
- Auto-mark attendance based on user sessions
- Send notifications and reminders
- Perform system cleanup and maintenance

## 🚀 Quick Setup (TL;DR)

Add this single cron job in cPanel that runs every hour:
```bash
0 * * * * cd /home/yourusername/ardurHome && /usr/local/bin/python3.11 manage.py runcrons --force
```

## 📖 Detailed Setup Instructions

### Step 1: Access cPanel Cron Jobs

1. Log into your cPanel account
2. Navigate to **Advanced** section
3. Click on **Cron Jobs**

### Step 2: Set Up the Main Cron Job

**Recommended Schedule: Every Hour**

```
Minute: 0
Hour: * (Every hour)
Day: * (Every day)
Month: * (Every month)
Weekday: * (Every weekday)
```

**Command:**
```bash
cd /home/yourusername/ardurHome && /usr/local/bin/python3.11 manage.py runcrons --force
```

**Note:** Replace the following:
- `yourusername` with your actual cPanel username
- `/usr/local/bin/python3.11` with your server's Python path (check with `which python3`)

### Step 3: Alternative Schedules (Optional)

If you prefer more frequent updates during business hours:

#### Option A: Every 30 Minutes During Business Hours
```
Minute: 0,30
Hour: 9-18
Day: *
Month: *
Weekday: 1-5
Command: cd /home/yourusername/ardurHome && /usr/local/bin/python3.11 manage.py runcrons --force
```

#### Option B: Multiple Specific Times
Create separate cron jobs for different times:

**Morning Setup (6:00 AM):**
```
Minute: 0
Hour: 6
Day: *
Month: *
Weekday: 1-5
Command: cd /home/yourusername/ardurHome && /usr/local/bin/python3.11 manage.py runcrons trueAlign.attendance.cron.DailyAttendanceCreationCronJob
```

**Business Hours (Every 30 minutes, 9 AM - 6 PM):**
```
Minute: 0,30
Hour: 9-18
Day: *
Month: *
Weekday: 1-5
Command: cd /home/yourusername/ardurHome && /usr/local/bin/python3.11 manage.py runcrons trueAlign.attendance.cron.AttendanceAutoMarkingCronJob
```

**Evening Cleanup (11 PM, Sunday):**
```
Minute: 0
Hour: 23
Day: *
Month: *
Weekday: 0
Command: cd /home/yourusername/ardurHome && /usr/local/bin/python3.11 manage.py runcrons trueAlign.attendance.cron.AttendanceCleanupCronJob
```

## 🔧 Finding Your Python Path

If you're unsure about your Python path, SSH into your server and run:
```bash
which python3
which python3.11
which python3.10
```

Common paths include:
- `/usr/local/bin/python3.11`
- `/usr/bin/python3`
- `/opt/python311/bin/python3.11`
- `/home/yourusername/.local/bin/python3`

## 📧 Email Notifications Setup

### Option 1: Receive All Cron Output
Leave the email field in cPanel filled with your email address to receive all cron job output.

### Option 2: Suppress Output (Recommended)
Add `> /dev/null 2>&1` to suppress normal output but still get error emails:
```bash
cd /home/yourusername/ardurHome && /usr/local/bin/python3.11 manage.py runcrons --force > /dev/null 2>&1
```

### Option 3: Log to File
Create a log file for cron output:
```bash
cd /home/yourusername/ardurHome && /usr/local/bin/python3.11 manage.py runcrons --force >> /home/yourusername/logs/attendance_cron.log 2>&1
```

## 🧪 Testing Your Cron Job

### Method 1: Manual Test via SSH
```bash
cd /home/yourusername/ardurHome
/usr/local/bin/python3.11 manage.py runcrons --force
```

### Method 2: Test Specific Job
```bash
cd /home/yourusername/ardurHome
/usr/local/bin/python3.11 manage.py manage_attendance_cron run daily_creation --force
```

### Method 3: Check Cron Job Status
```bash
cd /home/yourusername/ardurHome
/usr/local/bin/python3.11 manage.py manage_attendance_cron status
```

## 📊 Monitoring Cron Jobs

### Check Cron Job Logs
```bash
cd /home/yourusername/ardurHome
/usr/local/bin/python3.11 manage.py manage_attendance_cron logs --days 7
```

### View System Health
```bash
cd /home/yourusername/ardurHome
/usr/local/bin/python3.11 manage.py manage_attendance_cron health_check
```

### Check Recent Job Runs
```bash
cd /home/yourusername/ardurHome
/usr/local/bin/python3.11 manage.py manage_attendance_cron status --json
```

## 🚨 Troubleshooting

### Common Issues and Solutions

#### Issue 1: Permission Denied
```
Error: Permission denied
```
**Solution:** Check file permissions:
```bash
chmod +x /home/yourusername/ardurHome/manage.py
```

#### Issue 2: Python Not Found
```
Error: /usr/local/bin/python3.11: No such file or directory
```
**Solution:** Find correct Python path:
```bash
which python3
# Use the output in your cron command
```

#### Issue 3: Django Settings Error
```
Error: No module named 'ardurTrueAlign.settings'
```
**Solution:** Ensure you're in the correct directory:
```bash
cd /home/yourusername/ardurHome && pwd
ls -la manage.py
```

#### Issue 4: Database Connection Error
```
Error: database connection failed
```
**Solution:** Check database settings and connectivity:
```bash
cd /home/yourusername/ardurHome
/usr/local/bin/python3.11 manage.py dbshell
```

#### Issue 5: Cron Job Not Running
**Check these:**
1. Verify cron job is saved in cPanel
2. Check email for error messages
3. Verify the command works manually via SSH
4. Check server timezone settings

### Debug Mode
Run with verbose output to debug issues:
```bash
cd /home/yourusername/ardurHome
/usr/local/bin/python3.11 manage.py runcrons --force --verbose
```

## 📝 Log File Management

### Create Log Directory
```bash
mkdir -p /home/yourusername/logs
```

### Cron Job with Logging
```bash
cd /home/yourusername/ardurHome && /usr/local/bin/python3.11 manage.py runcrons --force >> /home/yourusername/logs/attendance_cron.log 2>&1
```

### Log Rotation (Optional)
Add a weekly cleanup job:
```
Minute: 0
Hour: 2
Day: *
Month: *
Weekday: 0
Command: find /home/yourusername/logs -name "*.log" -mtime +30 -delete
```

## 🔄 Backup Recommendations

### Daily Database Backup
```
Minute: 0
Hour: 3
Day: *
Month: *
Weekday: *
Command: cd /home/yourusername/ardurHome && /usr/local/bin/python3.11 manage.py dbbackup
```

### Weekly Full Backup
```
Minute: 0
Hour: 1
Day: *
Month: *
Weekday: 0
Command: tar -czf /home/yourusername/backups/ardur_backup_$(date +\%Y\%m\%d).tar.gz /home/yourusername/ardurHome/
```

## 📋 Final Checklist

- [ ] cPanel cron job is saved and active
- [ ] Python path is correct for your server
- [ ] Directory path points to your project
- [ ] Test command works manually via SSH
- [ ] Email notifications are configured
- [ ] Log files are set up (optional)
- [ ] Monitoring is in place
- [ ] Backup jobs are configured (recommended)

## 🆘 Support

If you encounter issues:

1. **Check the logs:**
   ```bash
   cd /home/yourusername/ardurHome
   /usr/local/bin/python3.11 manage.py manage_attendance_cron logs --failures-only
   ```

2. **Run health check:**
   ```bash
   cd /home/yourusername/ardurHome
   /usr/local/bin/python3.11 manage.py manage_attendance_cron health_check --fix
   ```

3. **Emergency fix:**
   ```bash
   cd /home/yourusername/ardurHome
   /usr/local/bin/python3.11 manage.py manage_attendance_cron emergency_fix
   ```

## 📞 Contact Information

For technical support or questions about the attendance system setup, please contact your system administrator or refer to the main system documentation.

---

**Last Updated:** December 2024  
**Version:** 1.0  
**Compatible with:** TrueAlign Attendance System v2.0+