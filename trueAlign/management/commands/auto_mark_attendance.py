import logging
from django.core.management.base import BaseCommand
from trueAlign.models import Attendance

# Configure logger
logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Auto mark attendance for all users'

    def handle(self, *args, **options):
        try:
            logger.info("Starting auto_mark_attendance cron job")
            
            # Call the auto_mark_attendance method from the Attendance model
            success = Attendance.auto_mark_attendance()
            
            if success:
                logger.info("Successfully processed attendance for all users")
                self.stdout.write(self.style.SUCCESS('Successfully processed attendance'))
            else:
                logger.warning("Auto mark attendance completed with some issues")
                self.stdout.write(self.style.WARNING('Completed with some issues'))
            
        except Exception as e:
            logger.error("Critical error in auto_mark_attendance", exc_info=True,
                        extra={
                            'error': str(e),
                            'command': 'auto_mark_attendance'
                        })
            self.stdout.write(self.style.ERROR(f'Error: {str(e)}'))
            raise