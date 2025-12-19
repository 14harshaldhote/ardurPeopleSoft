# Generated migration fix to skip existing columns

from django.db import migrations


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    """
    Empty migration - columns already exist in database.
    """

    dependencies = [
        ('trueAlign', '0007_cashbox_balance_currency_and_more'),
    ]

    operations = [
        migrations.RunPython(noop, noop),
    ]
