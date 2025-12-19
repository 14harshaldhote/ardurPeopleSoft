# Generated migration fix - skip existing changes

from django.db import migrations


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    """
    Empty migration - schema already correct in database.
    """

    dependencies = [
        ('trueAlign', '0008_cashtransaction_nlp_data_and_more'),
    ]

    operations = [
        migrations.RunPython(noop, noop),
    ]
