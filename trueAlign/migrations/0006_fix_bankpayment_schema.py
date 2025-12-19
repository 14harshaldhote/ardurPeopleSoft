from django.db import migrations, models

class Migration(migrations.Migration):

    dependencies = [
        ('trueAlign', '0005_bankstatement_bankstatementline'),
    ]

    operations = [
        migrations.RunSQL(
            # Check if column exists before adding
            sql="""
                SET @dbname = DATABASE();
                SET @tablename = 'trueAlign_bankpayment';
                SET @columnname = 'bank_account_id';
                SET @preparedStatement = (SELECT IF(
                  (
                    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
                    WHERE
                      (table_name = @tablename)
                      AND (table_schema = @dbname)
                      AND (column_name = @columnname)
                  ) > 0,
                  'SELECT 1',
                  CONCAT('ALTER TABLE ', @tablename, ' ADD COLUMN ', @columnname, ' bigint NULL;')
                ));
                PREPARE alterIfNotExists FROM @preparedStatement;
                EXECUTE alterIfNotExists;
                DEALLOCATE PREPARE alterIfNotExists;
            """,
            reverse_sql=migrations.RunSQL.noop
        ),
    ]
