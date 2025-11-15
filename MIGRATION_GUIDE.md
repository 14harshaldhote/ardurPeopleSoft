# Django Migration Fix Guide

## Problem Analysis

Your migration is failing because there's a mismatch between:
1. **Old Database Structure**: Has `trueAlign_usersession` table with `id` as `bigint(20)` (auto-increment)
2. **Current models.py**: Has `UserSession` model with `id` as `UUIDField(primary_key=True)`

Additionally, your current models.py has many NEW models that don't exist in the old database:
- OfficeLocation
- ConferenceRoom
- RoomBooking
- Appraisal models
- SessionActivity
- And many others

## Solution Approach

### Option 1: Fake Initial Migration (RECOMMENDED)
Since your database already exists, you should fake the initial migration to tell Django that the database is already in sync.

```bash
# Step 1: Make sure you have the migration file
python manage.py makemigrations trueAlign

# Step 2: Fake apply the migration (tells Django the database is already migrated)
python manage.py migrate trueAlign --fake-initial

# Step 3: Create new migrations for any changes
python manage.py makemigrations trueAlign

# Step 4: Apply new migrations
python manage.py migrate trueAlign
```

### Option 2: Manual Migration Creation
If Option 1 doesn't work, follow these steps:

#### Step 1: Backup Your Database
```bash
# For MySQL
mysqldump -u username -p database_name > backup_$(date +%Y%m%d).sql
```

#### Step 2: Clear Migration History (if needed)
```bash
# Delete all migration files except __init__.py
rm trueAlign/migrations/0*.py

# Clear Django's migration history in database
python manage.py migrate trueAlign zero --fake
```

#### Step 3: Create Fresh Migrations
```bash
# Create initial migration
python manage.py makemigrations trueAlign

# Fake apply it (since database already exists)
python manage.py migrate trueAlign --fake-initial
```

### Option 3: Fix UserSession ID Field Mismatch

The main issue is the `UserSession.id` field type mismatch. You have two choices:

#### Choice A: Keep BigInt ID (Match Old Database)
Edit `trueAlign/models.py` line 543:
```python
# OLD (current):
id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

# NEW (to match old database):
id = models.BigAutoField(primary_key=True)
```

Then run:
```bash
python manage.py makemigrations trueAlign
python manage.py migrate trueAlign --fake-initial
```

#### Choice B: Migrate to UUID (Complex)
This requires data migration:
1. Add new UUID field
2. Populate UUIDs for existing records
3. Update foreign keys
4. Drop old ID field
5. Rename UUID field to id

This is complex and risky. **Not recommended** unless you have a specific reason.

## Recommended Steps

### For Your Situation:

1. **First, check what's in your database:**
```bash
python manage.py dbshell
```
Then in MySQL:
```sql
SHOW TABLES LIKE 'trueAlign_%';
DESCRIBE trueAlign_usersession;
```

2. **Check Django's migration state:**
```bash
python manage.py showmigrations trueAlign
```

3. **If migrations exist but aren't applied:**
```bash
# Fake the initial migration
python manage.py migrate trueAlign --fake-initial
```

4. **If no migrations exist:**
```bash
# Create initial migration
python manage.py makemigrations trueAlign

# Fake apply it
python manage.py migrate trueAlign --fake-initial
```

5. **For new models not in old database:**
After faking the initial migration, create a new migration for new models:
```bash
python manage.py makemigrations trueAlign
python manage.py migrate trueAlign
```

## Important Notes

### About UserSession Model
Your old database has these fields as TEXT/longtext:
- `click_events`
- `error_events`
- `keyboard_events`
- `network_events`
- `offline_data`
- `page_views`
- `performance_metrics`
- `scroll_events`
- `security_incidents`
- `tab_visibility_log`

But your current model uses `JSONField` for most of these. You may need to:
1. Keep them as TextField initially
2. Create a data migration to convert text to JSON
3. Then change field type to JSONField

### Models Not in Old Database
These models are NEW and need to be created:
- OfficeLocation
- ConferenceRoom
- RoomBooking
- SessionActivity
- Appraisal
- AppraisalItem
- AppraisalAttachment
- AppraisalWorkflow
- ShiftValidationRule
- ShiftConflict
- Notification
- And many others...

After faking the initial migration, create a new migration:
```bash
python manage.py makemigrations trueAlign --name add_new_models
python manage.py migrate trueAlign
```

## Quick Fix Command Sequence

```bash
# 1. Backup database first!
mysqldump -u your_user -p your_database > backup.sql

# 2. Check current state
python manage.py showmigrations trueAlign

# 3. If migrations exist, fake them
python manage.py migrate trueAlign --fake-initial

# 4. If no migrations, create and fake
python manage.py makemigrations trueAlign
python manage.py migrate trueAlign --fake-initial

# 5. Create migrations for new models
python manage.py makemigrations trueAlign
python manage.py migrate trueAlign
```

## Troubleshooting

### Error: "Table already exists"
```bash
python manage.py migrate trueAlign --fake-initial
```

### Error: "No migrations to apply"
```bash
# Delete migration files and start fresh
rm trueAlign/migrations/0*.py
python manage.py makemigrations trueAlign
python manage.py migrate trueAlign --fake-initial
```

### Error: "Field type mismatch"
Edit models.py to match your database structure, then:
```bash
python manage.py makemigrations trueAlign
python manage.py migrate trueAlign --fake-initial
```

## Contact

If you continue to have issues, provide:
1. Output of `python manage.py showmigrations trueAlign`
2. Output of `DESCRIBE trueAlign_usersession;` from MySQL
3. The exact error message you're getting
