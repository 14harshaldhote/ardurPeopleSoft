#!/usr/bin/env python
"""
Script to generate complete Django migration from old database structure.
This creates a migration file that matches your existing database exactly.

Run with: python create_complete_migration.py
"""

import os
from datetime import datetime

# Migration file header
MIGRATION_HEADER = '''# Generated migration to match existing database schema
# Created: {timestamp}
# This migration represents your OLD database structure

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('contenttypes', '0002_remove_content_type_name'),
    ]

    operations = [
'''

MIGRATION_FOOTER = '''    ]
'''

def parse_old_data(file_path):
    """Parse the old data.txt file and group by table"""
    tables = {}
    
    with open(file_path, 'r') as f:
        lines = f.readlines()
    
    for line in lines[1:]:  # Skip header
        if not line.strip():
            continue
            
        parts = line.strip().split("', '")
        if len(parts) < 7:
            continue
            
        table_name = parts[0].strip("'")
        column_name = parts[1]
        column_type = parts[2]
        is_nullable = parts[3]
        column_key = parts[4]
        extra = parts[5]
        default = parts[6].strip("'")
        
        if table_name not in tables:
            tables[table_name] = []
        
        tables[table_name].append({
            'name': column_name,
            'type': column_type,
            'nullable': is_nullable == 'YES',
            'key': column_key,
            'extra': extra,
            'default': default
        })
    
    return tables

def mysql_to_django_field(column):
    """Convert MySQL column type to Django field"""
    col_type = column['type'].lower()
    nullable = column['nullable']
    is_primary = column['key'] == 'PRI'
    is_unique = column['key'] == 'UNI'
    is_foreign = column['key'] == 'MUL'
    auto_increment = 'auto_increment' in column['extra']
    
    # Determine Django field type
    if is_primary and auto_increment:
        if 'bigint' in col_type:
            return "models.BigAutoField(primary_key=True)"
        else:
            return "models.AutoField(primary_key=True)"
    
    if 'bigint' in col_type:
        field = "models.BigIntegerField("
    elif 'int' in col_type and 'unsigned' in col_type:
        field = "models.PositiveIntegerField("
    elif 'int' in col_type:
        field = "models.IntegerField("
    elif 'smallint' in col_type and 'unsigned' in col_type:
        field = "models.PositiveSmallIntegerField("
    elif 'smallint' in col_type:
        field = "models.SmallIntegerField("
    elif 'varchar' in col_type:
        max_length = col_type.split('(')[1].split(')')[0]
        field = f"models.CharField(max_length={max_length}"
    elif 'char' in col_type:
        max_length = col_type.split('(')[1].split(')')[0]
        field = f"models.CharField(max_length={max_length}"
    elif 'longtext' in col_type:
        field = "models.TextField("
    elif 'text' in col_type:
        field = "models.TextField("
    elif 'decimal' in col_type:
        parts = col_type.split('(')[1].split(')')[0].split(',')
        field = f"models.DecimalField(max_digits={parts[0]}, decimal_places={parts[1]}"
    elif 'double' in col_type or 'float' in col_type:
        field = "models.FloatField("
    elif 'datetime' in col_type:
        field = "models.DateTimeField("
    elif 'date' in col_type:
        field = "models.DateField("
    elif 'time' in col_type:
        field = "models.TimeField("
    elif 'tinyint(1)' in col_type:
        field = "models.BooleanField("
    else:
        field = "models.CharField(max_length=255"
    
    # Add parameters
    params = []
    if nullable and not is_primary:
        params.append("null=True")
        params.append("blank=True")
    
    if is_unique and not is_primary:
        params.append("unique=True")
    
    if params:
        field += ", ".join(params)
    
    field += ")"
    return field

def generate_model_code(table_name, columns):
    """Generate Django model creation code"""
    model_name = ''.join(word.capitalize() for word in table_name.replace('trueAlign_', '').replace('truealign_', '').split('_'))
    
    code = f"        # {model_name}\n"
    code += f"        migrations.CreateModel(\n"
    code += f"            name='{model_name}',\n"
    code += f"            fields=[\n"
    
    # Generate fields
    for col in columns:
        if col['key'] == 'MUL' and col['name'].endswith('_id'):
            # This is a foreign key, skip for now (will add later)
            continue
        
        field_def = mysql_to_django_field(col)
        code += f"                ('{col['name']}', {field_def}),\n"
    
    code += f"            ],\n"
    
    # Add db_table if needed
    if table_name.startswith('truealign_'):
        code += f"            options={{\n"
        code += f"                'db_table': '{table_name}',\n"
        code += f"            }},\n"
    
    code += f"        ),\n\n"
    
    return code

def generate_foreign_keys(table_name, columns):
    """Generate foreign key additions"""
    model_name = ''.join(word.capitalize() for word in table_name.replace('trueAlign_', '').replace('truealign_', '').split('_'))
    
    code = ""
    for col in columns:
        if col['key'] == 'MUL' and col['name'].endswith('_id'):
            field_name = col['name'][:-3]  # Remove '_id'
            related_model = field_name.capitalize()
            
            # Determine related model
            if 'user_id' in col['name']:
                related_model = 'settings.AUTH_USER_MODEL'
                on_delete = 'models.CASCADE'
            elif 'group_id' in col['name'] and 'chat' not in table_name:
                related_model = "'auth.Group'"
                on_delete = 'models.CASCADE'
            else:
                # Try to infer from field name
                related_model = f"'{related_model.capitalize()}'"
                on_delete = 'models.CASCADE'
            
            nullable = ", null=True, blank=True" if col['nullable'] else ""
            
            code += f"        migrations.AddField(\n"
            code += f"            model_name='{model_name.lower()}',\n"
            code += f"            name='{field_name}',\n"
            code += f"            field=models.ForeignKey({related_model}, on_delete={on_delete}{nullable}, related_name='{table_name}_{field_name}'),\n"
            code += f"        ),\n\n"
    
    return code

def main():
    print("=" * 70)
    print("COMPLETE MIGRATION GENERATOR")
    print("=" * 70)
    print()
    
    old_data_file = '/Users/harshalsmac/WORK/ardur/ardurHome/old data.txt'
    output_file = '/Users/harshalsmac/WORK/ardur/ardurHome/trueAlign/migrations/0001_initial.py'
    
    print(f"Reading old database structure from: {old_data_file}")
    tables = parse_old_data(old_data_file)
    
    print(f"Found {len(tables)} tables")
    print()
    
    # Generate migration file
    migration_content = MIGRATION_HEADER.format(timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    
    # First pass: Create all models (without foreign keys)
    print("Generating model definitions...")
    for table_name in sorted(tables.keys()):
        print(f"  - {table_name}")
        migration_content += generate_model_code(table_name, tables[table_name])
    
    # Second pass: Add foreign keys
    print("\nGenerating foreign key relationships...")
    for table_name in sorted(tables.keys()):
        fk_code = generate_foreign_keys(table_name, tables[table_name])
        if fk_code:
            migration_content += fk_code
    
    migration_content += MIGRATION_FOOTER
    
    # Write to file
    print(f"\nWriting migration to: {output_file}")
    with open(output_file, 'w') as f:
        f.write(migration_content)
    
    print()
    print("=" * 70)
    print("MIGRATION FILE CREATED SUCCESSFULLY!")
    print("=" * 70)
    print()
    print("NEXT STEPS:")
    print("1. Review the generated migration file")
    print("2. Run: python manage.py migrate trueAlign --fake-initial")
    print("3. This will mark the migration as applied without creating tables")
    print()
    print("The --fake-initial flag is CRITICAL because your tables already exist!")
    print("=" * 70)

if __name__ == '__main__':
    main()
