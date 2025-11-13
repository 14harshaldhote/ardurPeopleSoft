"""
Management command to migrate existing shift data to new models
"""

from django.core.management.base import BaseCommand
from django.db import transaction
from django.contrib.auth.models import User
from datetime import time
from decimal import Decimal

from shift.models import ShiftMaster, ShiftAssignment


class Command(BaseCommand):
    help = 'Migrate existing shift data from main models to shift app'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be migrated without actually doing it',
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force migration even if data already exists',
        )
    
    def handle(self, *args, **options):
        dry_run = options['dry_run']
        force = options['force']
        
        if dry_run:
            self.stdout.write(
                self.style.WARNING('DRY RUN MODE - No data will be migrated')
            )
        
        try:
            # Import from main models
            from trueAlign.models import ShiftMaster as OldShiftMaster
            from trueAlign.models import ShiftAssignment as OldShiftAssignment
            
            with transaction.atomic():
                self.migrate_shifts(OldShiftMaster, dry_run, force)
                self.migrate_assignments(OldShiftAssignment, dry_run, force)
                
                if dry_run:
                    transaction.set_rollback(True)
            
            if not dry_run:
                self.stdout.write(
                    self.style.SUCCESS('Migration completed successfully!')
                )
            
        except ImportError:
            self.stdout.write(
                self.style.ERROR('Old models not found. Migration not needed.')
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Migration failed: {str(e)}')
            )
    
    def migrate_shifts(self, OldShiftMaster, dry_run, force):
        """Migrate shift master data"""
        old_shifts = OldShiftMaster.objects.all()
        
        if not force and ShiftMaster.objects.exists():
            self.stdout.write(
                self.style.WARNING('Shift data already exists. Use --force to overwrite.')
            )
            return
        
        migrated_count = 0
        
        for old_shift in old_shifts:
            # Map old fields to new fields
            shift_data = {
                'name': old_shift.name,
                'start_time': old_shift.start_time,
                'end_time': old_shift.end_time,
                'shift_duration': old_shift.shift_duration,
                'break_duration': old_shift.break_duration,
                'work_days': self.map_work_days(old_shift.work_days),
                'custom_work_days': old_shift.custom_work_days,
                'is_active': old_shift.is_active,
                'created_at': old_shift.created_at,
                'updated_at': old_shift.updated_at,
            }
            
            # Set grace periods
            if hasattr(old_shift, 'grace_period'):
                shift_data['grace_period_in'] = old_shift.grace_period
                shift_data['grace_period_out'] = old_shift.grace_period
            
            # Auto-detect shift type
            shift_data['shift_type'] = self.detect_shift_type(old_shift)
            
            if not dry_run:
                new_shift, created = ShiftMaster.objects.get_or_create(
                    name=shift_data['name'],
                    defaults=shift_data
                )
                if created:
                    migrated_count += 1
            else:
                migrated_count += 1
                self.stdout.write(f'Would migrate shift: {old_shift.name}')
        
        self.stdout.write(
            self.style.SUCCESS(f'Migrated {migrated_count} shifts')
        )
    
    def migrate_assignments(self, OldShiftAssignment, dry_run, force):
        """Migrate shift assignment data"""
        old_assignments = OldShiftAssignment.objects.all()
        
        if not force and ShiftAssignment.objects.exists():
            self.stdout.write(
                self.style.WARNING('Assignment data already exists. Use --force to overwrite.')
            )
            return
        
        migrated_count = 0
        
        for old_assignment in old_assignments:
            try:
                # Find corresponding new shift
                new_shift = ShiftMaster.objects.get(name=old_assignment.shift.name)
                
                assignment_data = {
                    'user': old_assignment.user,
                    'shift': new_shift,
                    'effective_from': old_assignment.effective_from,
                    'effective_to': old_assignment.effective_to,
                    'is_current': old_assignment.is_current,
                    'notes': getattr(old_assignment, 'notes', ''),
                    'created_at': old_assignment.created_at,
                    'updated_at': old_assignment.updated_at,
                    'created_by': getattr(old_assignment, 'created_by', None),
                }
                
                # Map status
                assignment_data['status'] = 'ACTIVE'  # Default status
                
                if not dry_run:
                    new_assignment, created = ShiftAssignment.objects.get_or_create(
                        user=assignment_data['user'],
                        shift=assignment_data['shift'],
                        effective_from=assignment_data['effective_from'],
                        defaults=assignment_data
                    )
                    if created:
                        migrated_count += 1
                else:
                    migrated_count += 1
                    self.stdout.write(
                        f'Would migrate assignment: {old_assignment.user.username} - {old_assignment.shift.name}'
                    )
                    
            except ShiftMaster.DoesNotExist:
                self.stdout.write(
                    self.style.WARNING(
                        f'Shift not found for assignment: {old_assignment.shift.name}'
                    )
                )
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(
                        f'Error migrating assignment {old_assignment.id}: {str(e)}'
                    )
                )
        
        self.stdout.write(
            self.style.SUCCESS(f'Migrated {migrated_count} assignments')
        )
    
    def map_work_days(self, old_work_days):
        """Map old work days format to new format"""
        mapping = {
            'Weekdays': 'WEEKDAYS',
            'All Days': 'ALL_DAYS',
            'Custom': 'CUSTOM'
        }
        return mapping.get(old_work_days, 'WEEKDAYS')
    
    def detect_shift_type(self, old_shift):
        """Auto-detect shift type based on timing"""
        if not old_shift.start_time:
            return 'CUSTOM'
        
        hour = old_shift.start_time.hour
        if 5 <= hour < 12:
            return 'MORNING'
        elif 12 <= hour < 18:
            return 'EVENING'
        elif hour >= 18 or hour < 5:
            return 'NIGHT'
        else:
            return 'CUSTOM'
