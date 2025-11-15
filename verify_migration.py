#!/usr/bin/env python3
"""
Verification script to ensure all tables and columns from old data.txt
are present in the Django migration file.
"""

import re
from collections import defaultdict

# Parse old data.txt
old_schema = defaultdict(list)
with open('/Users/harshalsmac/WORK/ardur/ardurHome/old data.txt', 'r') as f:
    for line in f:
        if line.strip() and not line.startswith('#'):
            # Parse: 'table_name', 'column_name', ...
            parts = [p.strip().strip("'") for p in line.split(',')]
            if len(parts) >= 2:
                table_name = parts[0]
                column_name = parts[1]
                old_schema[table_name].append(column_name)

# Parse migration file
migration_tables = set()
migration_columns = defaultdict(set)

with open('/Users/harshalsmac/WORK/ardur/ardurHome/trueAlign/migrations/0001_initial.py', 'r') as f:
    content = f.read()
    
    # Find all CreateModel operations
    create_model_pattern = r"migrations\.CreateModel\(\s*name='(\w+)',"
    for match in re.finditer(create_model_pattern, content):
        model_name = match.group(1).lower()
        migration_tables.add(model_name)
    
    # Find all field definitions within CreateModel
    # Pattern: ('field_name', models.
    field_pattern = r"\('(\w+)',\s*models\."
    for match in re.finditer(field_pattern, content):
        field_name = match.group(1)
        # This is a simplification - we'd need more context to know which model
        # But we'll do a simpler check below

print("=" * 80)
print("VERIFICATION REPORT")
print("=" * 80)

# Convert old table names to model names (remove trueAlign_ prefix, convert to PascalCase)
def table_to_model(table_name):
    # Remove prefix
    if table_name.startswith('trueAlign_'):
        name = table_name[10:]
    elif table_name.startswith('truealign_'):
        name = table_name[10:]
    else:
        name = table_name
    
    # Convert to PascalCase
    parts = name.split('_')
    return ''.join(p.capitalize() for p in parts)

# Check each table
missing_tables = []
tables_to_check = set()

for table_name in old_schema.keys():
    model_name = table_to_model(table_name)
    tables_to_check.add((table_name, model_name))
    if model_name.lower() not in migration_tables:
        missing_tables.append(f"{table_name} -> {model_name}")

print(f"\n📊 Total tables in old schema: {len(old_schema)}")
print(f"📊 Total models in migration: {len(migration_tables)}")

if missing_tables:
    print(f"\n❌ MISSING TABLES ({len(missing_tables)}):")
    for table in sorted(missing_tables):
        print(f"   - {table}")
else:
    print(f"\n✅ ALL {len(old_schema)} TABLES PRESENT IN MIGRATION")

# Now check columns for each table
print("\n" + "=" * 80)
print("COLUMN VERIFICATION")
print("=" * 80)

# Read migration file again to check columns per model
with open('/Users/harshalsmac/WORK/ardur/ardurHome/trueAlign/migrations/0001_initial.py', 'r') as f:
    migration_content = f.read()

missing_columns = []
for table_name, columns in sorted(old_schema.items()):
    model_name = table_to_model(table_name)
    
    # Find the model definition in migration
    model_pattern = rf"migrations\.CreateModel\(\s*name='{model_name}',.*?options="
    model_match = re.search(model_pattern, migration_content, re.DOTALL | re.IGNORECASE)
    
    if model_match:
        model_section = model_match.group(0)
        
        # Check each column
        for column in columns:
            # Skip 'id' as it's auto-generated
            if column == 'id':
                continue
            
            # Convert column name (handle foreign keys)
            field_name = column.replace('_id', '') if column.endswith('_id') else column
            
            # Check if field exists in model section
            field_patterns = [
                rf"\('{field_name}',",
                rf"\('{column}',",
            ]
            
            found = any(re.search(pattern, model_section, re.IGNORECASE) for pattern in field_patterns)
            
            # If not found in model definition, check AddField operations
            if not found:
                addfield_patterns = [
                    rf"migrations\.AddField\(\s*model_name='{model_name.lower()}',\s*name='{field_name}'",
                    rf"migrations\.AddField\(\s*model_name='{model_name.lower()}',\s*name='{column}'"
                ]
                found = any(re.search(pattern, migration_content, re.IGNORECASE) for pattern in addfield_patterns)
            
            if not found:
                missing_columns.append(f"{table_name}.{column} (model: {model_name}.{field_name})")

if missing_columns:
    print(f"\n❌ MISSING COLUMNS ({len(missing_columns)}):")
    for col in missing_columns[:50]:  # Show first 50
        print(f"   - {col}")
    if len(missing_columns) > 50:
        print(f"   ... and {len(missing_columns) - 50} more")
else:
    print(f"\n✅ ALL COLUMNS VERIFIED")

print("\n" + "=" * 80)
print("SUMMARY")
print("=" * 80)
print(f"Tables: {'✅ PASS' if not missing_tables else '❌ FAIL'}")
print(f"Columns: {'✅ PASS' if not missing_columns else '❌ FAIL'}")
print("=" * 80)
