from django.core.management.base import BaseCommand
from trueAlign.models import Attendance

class Command(BaseCommand):
    help = 'Auto mark attendance for all users'

    def handle(self, *args, **options):
        try:
            self.stdout.write("Starting auto_mark_attendance cron job")
            
            # Call the auto_mark_attendance method from the Attendance model
            Attendance.auto_mark_attendance()
            
            self.stdout.write(self.style.SUCCESS('Successfully processed attendance'))
            
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error: {str(e)}'))
            raise