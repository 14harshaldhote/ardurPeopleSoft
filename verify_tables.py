import csv
import re
from pathlib import Path

# Paths (change if needed)
MIGRATION_FILE = Path("/Users/harshalsmac/WORK/ardur/ardurHome/trueAlign/migrations/0001_initial_.py")
CSV_FILE = Path("/Users/harshalsmac/WORK/ardur/ardurHome/godSql/1.csv")

def load_csv_table_names(csv_path: Path) -> set[str]:
    """Read TABLE_NAME column from CSV and return as a set."""
    tables = set()
    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        # expect a header column named TABLE_NAME
        for row in reader:
            name = (row.get("TABLE_NAME") or "").strip()
            if name:
                tables.add(name)
    return tables

def extract_db_table_names_from_migration(migration_path: Path) -> set[str]:
    """
    Parse migration file text and extract all values of:
        'db_table': 'trueAlign_xxx'
    using a regex.
    """
    text = migration_path.read_text(encoding="utf-8")

    # Regex to match: 'db_table': 'trueAlign_xxx'
    pattern = r"'db_table'\s*:\s*'([^']+)'"
    matches = re.findall(pattern, text)

    return set(matches)

def main():
    if not MIGRATION_FILE.exists():
        print(f"Migration file not found: {MIGRATION_FILE}")
        return

    if not CSV_FILE.exists():
        print(f"CSV file not found: {CSV_FILE}")
        return

    csv_tables = load_csv_table_names(CSV_FILE)
    migration_tables = extract_db_table_names_from_migration(MIGRATION_FILE)

    # Direct (case-sensitive) comparison
    only_in_csv = sorted(csv_tables - migration_tables)
    only_in_migration = sorted(migration_tables - csv_tables)
    in_both = sorted(csv_tables & migration_tables)

    print("=== SUMMARY (case-sensitive) ===")
    print(f"Total in CSV:        {len(csv_tables)}")
    print(f"Total in migration:  {len(migration_tables)}")
    print(f"Matched (both):      {len(in_both)}")
    print(f"Only in CSV:         {len(only_in_csv)}")
    print(f"Only in migration:   {len(only_in_migration)}")
    print()

    if in_both:
        print("✅ In BOTH CSV and migration:")
        for name in in_both:
            print(f"  - {name}")
        print()

    if only_in_csv:
        print("❌ In CSV but NOT in migration (missing in migration?):")
        for name in only_in_csv:
            print(f"  - {name}")
        print()

    if only_in_migration:
        print("❌ In migration but NOT in CSV (extra/unexpected?):")
        for name in only_in_migration:
            print(f"  - {name}")
        print()

    # Optional: case-insensitive comparison to catch small case differences
    print("=== OPTIONAL: Case-insensitive check ===")
    csv_lower = {t.lower(): t for t in csv_tables}
    mig_lower = {t.lower(): t for t in migration_tables}

    same_lower = set(csv_lower.keys()) & set(mig_lower.keys())
    diff_case = [
        (csv_lower[k], mig_lower[k])
        for k in sorted(same_lower)
        if csv_lower[k] != mig_lower[k]
    ]

    if diff_case:
        print("⚠ Same table name but different case (CSV vs Migration):")
        for csv_name, mig_name in diff_case:
            print(f"  CSV: {csv_name}   |   Migration: {mig_name}")
    else:
        print("No case-only differences detected.")

if __name__ == "__main__":
    main()
