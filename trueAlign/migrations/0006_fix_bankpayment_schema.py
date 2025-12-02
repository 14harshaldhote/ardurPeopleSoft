from django.db import migrations, models

class Migration(migrations.Migration):

    dependencies = [
        ('trueAlign', '0005_bankstatement_bankstatementline'),
    ]

    operations = [
        migrations.RunSQL(
            sql="ALTER TABLE trueAlign_bankpayment ADD COLUMN bank_account_id bigint NOT NULL DEFAULT 1, ADD COLUMN created_by_id int NOT NULL DEFAULT 1, ADD COLUMN verified_by_id int NULL, ADD COLUMN approved_by_id int NULL",
            reverse_sql="ALTER TABLE trueAlign_bankpayment DROP COLUMN bank_account_id, DROP COLUMN created_by_id, DROP COLUMN verified_by_id, DROP COLUMN approved_by_id"
        ),
    ]
