"""
Management command to create default shift configurations
"""

from django.core.management.base import BaseCommand
from django.db import transaction
from datetime import time
from decimal import Decimal

from shift.models import ShiftMaster, ShiftValidationRule
from django.contrib.auth.models import Group


class Command(BaseCommand):
    help = 'Create default shift configurations and validation rules'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--overwrite',
            action='store_true',
            help='Overwrite existing shifts if they exist',
        )
    
    def handle(self, *args, **options):
        overwrite = options['overwrite']
        
        try:
            with transaction.atomic():
                self.create_default_shifts(overwrite)
                self.create_validation_rules()
            
            self.stdout.write(
                self.style.SUCCESS('Default shifts and rules created successfully!')
            )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Failed to create defaults: {str(e)}')
            )
    
    def create_default_shifts(self, overwrite):
        """Create default shift configurations"""
        default_shifts = [
            {
                'name': 'Morning Shift',
                'shift_type': 'MORNING',
                'start_time': time(9, 0),
                'end_time': time(17, 30),
                'shift_duration': Decimal('8.5'),
                'work_days': 'WEEKDAYS',
                'color_code': '#10B981',
                'description': 'Standard morning shift for weekdays'
            },
            {
                'name': 'Evening Shift',
                'shift_type': 'EVENING',
                'start_time': time(14, 0),
                'end_time': time(22, 30),
                'shift_duration': Decimal('8.5'),
                'work_days': 'WEEKDAYS',
                'color_code': '#F59E0B',
                'description': 'Evening shift for weekdays'
            },
            {
                'name': 'Night Shift',
                'shift_type': 'NIGHT',
                'start_time': time(22, 0),
                'end_time': time(6, 30),
                'shift_duration': Decimal('8.5'),
                'work_days': 'WEEKDAYS',
                'color_code': '#6366F1',
                'description': 'Night shift crossing midnight'
            },
            {
                'name': 'Weekend Day Shift',
                'shift_type': 'MORNING',
                'start_time': time(10, 0),
                'end_time': time(18, 0),
                'shift_duration': Decimal('8.0'),
                'work_days': 'CUSTOM',
                'custom_work_days': 'Saturday,Sunday',
                'color_code': '#8B5CF6',
                'description': 'Weekend day shift'
            },
            {
                'name': 'Flexible Shift',
                'shift_type': 'CUSTOM',
                'start_time': time(10, 0),
                'end_time': time(19, 0),
                'shift_duration': Decimal('9.0'),
                'work_days': 'ALL_DAYS',
                'color_code': '#EF4444',
                'description': 'Flexible timing shift with longer hours'
            }
        ]
        
        created_count = 0
        
        for shift_data in default_shifts:
            if overwrite:
                shift, created = ShiftMaster.objects.update_or_create(
                    name=shift_data['name'],
                    defaults=shift_data
                )
                if created:
                    created_count += 1
                    self.stdout.write(f'Created shift: {shift.name}')
                else:
                    self.stdout.write(f'Updated shift: {shift.name}')
            else:
                shift, created = ShiftMaster.objects.get_or_create(
                    name=shift_data['name'],
                    defaults=shift_data
                )
                if created:
                    created_count += 1
                    self.stdout.write(f'Created shift: {shift.name}')
                else:
                    self.stdout.write(f'Shift already exists: {shift.name}')
        
        self.stdout.write(
            self.style.SUCCESS(f'Processed {len(default_shifts)} shifts, created {created_count} new ones')
        )
    
    def create_validation_rules(self):
        """Create default validation rules"""
        default_rules = [
            {
                'name': 'Minimum Rest Period',
                'rule_type': 'MIN_REST_HOURS',
                'value': Decimal('8.0'),
                'group': None  # Global rule
            },
            {
                'name': 'Maximum Daily Hours',
                'rule_type': 'MAX_DAILY_HOURS',
                'value': Decimal('12.0'),
                'group': None
            },
            {
                'name': 'Maximum Weekly Hours',
                'rule_type': 'MAX_WEEKLY_HOURS',
                'value': Decimal('48.0'),
                'group': None
            },
            {
                'name': 'Overtime Approval Required',
                'rule_type': 'OVERTIME_APPROVAL',
                'value': Decimal('8.0'),  # Hours threshold
                'group': None
            }
        ]
        
        created_count = 0
        
        for rule_data in default_rules:
            rule, created = ShiftValidationRule.objects.get_or_create(
                rule_type=rule_data['rule_type'],
                group=rule_data['group'],
                defaults=rule_data
            )
            if created:
                created_count += 1
                self.stdout.write(f'Created validation rule: {rule.name}')
            else:
                self.stdout.write(f'Validation rule already exists: {rule.name}')
        
        self.stdout.write(
            self.style.SUCCESS(f'Processed {len(default_rules)} validation rules, created {created_count} new ones')
        )
