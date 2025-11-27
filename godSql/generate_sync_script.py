import csv
import ast
import os
import re

# Configuration
CSV_DIR = '/Users/harshalsmac/WORK/ardur/ardurHome/godSql'
MODELS_FILE = '/Users/harshalsmac/WORK/ardur/ardurHome/trueAlign/models.py'
OUTPUT_SQL = '/Users/harshalsmac/WORK/ardur/ardurHome/godSql/schema_synchronization.sql'
APP_PREFIX = 'trueAlign_'

def load_csv_schema():
    """Load schema from CSV files."""
    print("Loading CSV schema...")
    tables = set()
    columns = {} # {table: {col: {type, nullable, key, default}}}
    
    # 1.csv: Tables
    try:
        with open(os.path.join(CSV_DIR, '1.csv'), 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                if row: tables.add(row[0])
    except Exception as e:
        print(f"Error loading 1.csv: {e}")

    # 2.csv: Columns
    try:
        with open(os.path.join(CSV_DIR, '2.csv'), 'r') as f:
            reader = csv.reader(f)
            # Try to detect header
            header = next(reader, None)
            # If header line looks like header, skip. Else process.
            # Based on previous output: TABLE_NAME,COLUMN_NAME,COLUMN_TYPE,IS_NULLABLE...
            # If first row is header, it will have "TABLE_NAME"
            first_row_is_header = False
            if header and 'TABLE_NAME' in header[0].upper():
                first_row_is_header = True
            
            if not first_row_is_header and header:
                # Process header row as data if it wasn't a header
                row = header
                if len(row) >= 4:
                    table = row[0]
                    if table not in columns: columns[table] = {}
                    columns[table][row[1]] = {
                        'type': row[2],
                        'nullable': row[3],
                        'key': row[4] if len(row) > 4 else '',
                        'default': row[5] if len(row) > 5 else None
                    }

            for row in reader:
                if not row or len(row) < 4: continue
                table = row[0]
                if table not in columns: columns[table] = {}
                columns[table][row[1]] = {
                    'type': row[2],
                    'nullable': row[3],
                    'key': row[4] if len(row) > 4 else '',
                    'default': row[5] if len(row) > 5 else None
                }
    except Exception as e:
        print(f"Error loading 2.csv: {e}")
        
    return tables, columns

def parse_django_models():
    """Parse models.py using AST."""
    print("Parsing models.py...")
    with open(MODELS_FILE, 'r') as f:
        tree = ast.parse(f.read())
        
    models = {} # {model_name: {field_name: {type, options}}}
    
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            is_model = False
            for base in node.bases:
                if (isinstance(base, ast.Attribute) and base.attr == 'Model') or \
                   (isinstance(base, ast.Name) and base.id == 'Model'):
                    is_model = True
            
            if is_model:
                model_name = node.name
                fields = {}
                
                for item in node.body:
                    if isinstance(item, ast.Assign):
                        for target in item.targets:
                            if isinstance(target, ast.Name):
                                field_name = target.id
                                if field_name == 'objects': continue
                                
                                if isinstance(item.value, ast.Call):
                                    func = item.value.func
                                    field_type = None
                                    if isinstance(func, ast.Attribute):
                                        field_type = func.attr
                                    elif isinstance(func, ast.Name):
                                        field_type = func.id
                                        
                                    if field_type == 'GenericForeignKey': continue
                                    
                                    if field_type:
                                        options = {}
                                        for keyword in item.value.keywords:
                                            val = None
                                            if isinstance(keyword.value, ast.Constant):
                                                val = keyword.value.value
                                            elif isinstance(keyword.value, ast.NameConstant): # Py < 3.8
                                                val = keyword.value.value
                                            # Handle simple Attribute access like models.CASCADE
                                            elif isinstance(keyword.value, ast.Attribute):
                                                val = keyword.value.attr
                                            
                                            options[keyword.arg] = val
                                            
                                        fields[field_name] = {
                                            'type': field_type,
                                            'options': options
                                        }
                # Extract Meta.db_table if exists
                db_table = None
                for item in node.body:
                    if isinstance(item, ast.ClassDef) and item.name == 'Meta':
                        for meta_item in item.body:
                            if isinstance(meta_item, ast.Assign):
                                for target in meta_item.targets:
                                    if isinstance(target, ast.Name) and target.id == 'db_table':
                                        if isinstance(meta_item.value, ast.Constant):
                                            db_table = meta_item.value.value
                                        elif isinstance(meta_item.value, ast.Str): # Python < 3.8
                                            db_table = meta_item.value.s
                
                models[model_name] = {
                    'fields': fields,
                    'db_table': db_table
                }
    return models

def map_type_to_sql(field_type, options):
    """Map Django field to SQL type definition."""
    if field_type == 'CharField':
        length = options.get('max_length', 255)
        return f"varchar({length})"
    elif field_type == 'TextField':
        return "longtext"
    elif field_type == 'IntegerField':
        return "int"
    elif field_type == 'SmallIntegerField':
        return "smallint"
    elif field_type == 'BigIntegerField':
        return "bigint"
    elif field_type == 'PositiveIntegerField':
        return "int" # MySQL unsigned is optional, Django often maps to int
    elif field_type == 'PositiveSmallIntegerField':
        return "smallint"
    elif field_type == 'BooleanField':
        return "tinyint(1)"
    elif field_type == 'DateField':
        return "date"
    elif field_type == 'DateTimeField':
        return "datetime(6)"
    elif field_type == 'TimeField':
        return "time(6)"
    elif field_type == 'DecimalField':
        digits = options.get('max_digits', 10)
        places = options.get('decimal_places', 2)
        return f"decimal({digits},{places})"
    elif field_type == 'ForeignKey' or field_type == 'OneToOneField':
        return "int" # Default assumption
    elif field_type == 'AutoField':
        return "int AUTO_INCREMENT"
    elif field_type == 'BigAutoField':
        return "bigint AUTO_INCREMENT"
    elif field_type == 'UUIDField':
        return "char(32)"
    elif field_type == 'GenericIPAddressField':
        return "char(39)"
    elif field_type == 'JSONField':
        return "longtext"
    elif field_type == 'FileField' or field_type == 'ImageField':
        return "varchar(255)"
    elif field_type == 'DurationField':
        return "bigint"
    
    return "varchar(255)"

def normalize_sql_type(t):
    """Normalize SQL type string for comparison."""
    t = t.lower()
    # Remove ' unsigned'
    t = t.replace(' unsigned', '')
    # int(11) -> int
    t = re.sub(r'int\(\d+\)', 'int', t)
    # bigint(20) -> bigint
    t = re.sub(r'bigint\(\d+\)', 'bigint', t)
    # tinyint(1) -> tinyint(1) (keep boolean indicator)
    # but sometimes tinyint(4) -> tinyint
    if t.startswith('tinyint') and t != 'tinyint(1)':
        t = 'tinyint'
    return t

def generate_sql(existing_tables, existing_columns, models):
    statements = []
    
    for model_name, model_data in models.items():
        fields = model_data['fields']
        # Use explicit db_table if available, else default
        if model_data.get('db_table'):
            table_name = model_data['db_table']
        else:
            table_name = APP_PREFIX + model_name.lower()
        
        if table_name not in existing_tables:
            # CREATE TABLE
            lines = []
            lines.append(f"CREATE TABLE `{table_name}` (")
            lines.append("    `id` bigint AUTO_INCREMENT NOT NULL PRIMARY KEY,") # Default PK
            
            for fname, fdef in fields.items():
                col_name = fname
                if fdef['type'] in ['ForeignKey', 'OneToOneField']:
                    col_name += '_id'
                
                sql_type = map_type_to_sql(fdef['type'], fdef['options'])
                nullable = fdef['options'].get('null', False)
                null_str = "NULL" if nullable else "NOT NULL"
                
                lines.append(f"    `{col_name}` {sql_type} {null_str},")
            
            # Remove trailing comma from last line
            lines[-1] = lines[-1].rstrip(',')
            lines.append(");")
            statements.append('\n'.join(lines))
            
        else:
            # ALTER TABLE
            table_cols = existing_columns.get(table_name, {})
            
            for fname, fdef in fields.items():
                col_name = fname
                if fdef['type'] in ['ForeignKey', 'OneToOneField']:
                    col_name += '_id'
                
                sql_type = map_type_to_sql(fdef['type'], fdef['options'])
                nullable = fdef['options'].get('null', False)
                null_str = "NULL" if nullable else "NOT NULL"
                
                if col_name not in table_cols:
                    # ADD COLUMN
                    statements.append(f"ALTER TABLE `{table_name}` ADD COLUMN `{col_name}` {sql_type} {null_str};")
                else:
                    # MODIFY COLUMN if needed
                    curr = table_cols[col_name]
                    curr_type = normalize_sql_type(curr['type'])
                    target_type = normalize_sql_type(sql_type)
                    
                    curr_null = (curr['nullable'] == 'YES')
                    
                    # Compare
                    type_mismatch = (curr_type != target_type)
                    null_mismatch = (curr_null != nullable)
                    
                    # Special case: varchar length change
                    if 'varchar' in curr_type and 'varchar' in target_type:
                        if curr_type != target_type: type_mismatch = True
                        else: type_mismatch = False
                    
                    if type_mismatch or null_mismatch:
                        statements.append(f"-- Change {table_name}.{col_name}: Type {curr['type']}->{sql_type}, Null {curr['nullable']}->{null_str}")
                        statements.append(f"ALTER TABLE `{table_name}` MODIFY COLUMN `{col_name}` {sql_type} {null_str};")

    return statements

def main():
    tables, columns = load_csv_schema()
    models = parse_django_models()
    
    sqls = generate_sql(tables, columns, models)
    
    with open(OUTPUT_SQL, 'w') as f:
        f.write('\n\n'.join(sqls))
    
    print(f"Generated {len(sqls)} statements.")

if __name__ == '__main__':
    main()
