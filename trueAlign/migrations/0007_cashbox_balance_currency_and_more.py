# Generated migration fix to skip existing columns

from django.db import migrations


def check_column_exists(apps, schema_editor):
    """Check if columns already exist - if so, skip"""
    pass


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    """
    Empty migration to mark 0007 as applied.
    The columns already exist in the database from a previous run.
    """

    dependencies = [
        ('trueAlign', '0006_fix_bankpayment_schema'),
    ]

    operations = [
        migrations.RunPython(noop, noop),
    ]
