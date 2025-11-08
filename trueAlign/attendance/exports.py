# attendance/exports.py
import openpyxl
import csv
import logging
from io import BytesIO, StringIO
from datetime import datetime, date, timedelta
from django.http import HttpResponse, JsonResponse
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.db.models import Q, Count, Sum, Avg
from openpyxl.styles import Font, Alignment, PatternFill, Border, Side
from openpyxl.utils import get_column_letter
from openpyxl.chart import BarChart, Reference
import pytz

from trueAlign.models import Attendance, ShiftAssignment
from .decorators import role_required

logger = logging.getLogger(__name__)
User = get_user_model()
IST = pytz.timezone('Asia/Kolkata')


class AttendanceExportService:
    """
    Comprehensive service for exporting attendance data in various formats
    with role-based filtering and proper formatting.
    """

    def __init__(self, user, queryset=None):
        self.user = user
        self.user_role = self._get_user_role()
        self.base_queryset = queryset or self._get_base_queryset()

    def _get_user_role(self):
        """Determine user role"""
        if self.user.groups.filter(name='HR').exists():
            return 'HR'
        elif self.user.groups.filter(name='Manager').exists():
            return 'Manager'
        elif self.user.groups.filter(name='Admin').exists():
            return 'Admin'
        else:
            return 'Employee'

    def _get_base_queryset(self):
        """Get base queryset with role-based filtering"""
        queryset = Attendance.objects.select_related('user', 'user__profile', 'shift')

        if self.user_role in ['HR', 'Admin'] or self.user.is_superuser:
            return queryset
        elif self.user_role == 'Manager':
            # Managers can see their team members
            team_members = User.objects.filter(profile__manager=self.user).values_list('id', flat=True)
            return queryset.filter(user_id__in=list(team_members) + [self.user.id])
        else:
            # Employees can only see their own data
            return queryset.filter(user=self.user)

    def export_to_excel(self, start_date, end_date, user_ids=None, include_charts=False):
        """
        Export attendance data to Excel with advanced formatting and optional charts
        """
        try:
            # Filter queryset
            queryset = self._filter_queryset(start_date, end_date, user_ids)

            # Create workbook
            wb = openpyxl.Workbook()

            # Remove default sheet
            wb.remove(wb.active)

            # Create main data sheet
            ws_main = wb.create_sheet("Attendance Data")
            self._create_main_sheet(ws_main, queryset, start_date, end_date)

            # Create summary sheet
            ws_summary = wb.create_sheet("Summary")
            self._create_summary_sheet(ws_summary, queryset, start_date, end_date)

            # Add charts if requested
            if include_charts and self.user_role in ['HR', 'Admin', 'Manager']:
                self._add_charts(wb, queryset)

            # Save to BytesIO
            buffer = BytesIO()
            wb.save(buffer)
            buffer.seek(0)

            # Create response
            response = HttpResponse(
                buffer.read(),
                content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            )
            filename = f'attendance_report_{start_date.strftime("%Y%m%d")}_{end_date.strftime("%Y%m%d")}.xlsx'
            response['Content-Disposition'] = f'attachment; filename="{filename}"'

            logger.info(f"Excel export completed for user {self.user.username}: {queryset.count()} records")
            return response

        except Exception as e:
            logger.error(f"Excel export error for user {self.user.username}: {e}")
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

    def _create_main_sheet(self, ws, queryset, start_date, end_date):
        """Create main data sheet with attendance records"""
        # Headers
        headers = [
            'Date', 'Day', 'Employee ID', 'Employee Name',
            'Status', 'Clock In', 'Clock Out', 'Total Hours', 'Expected Hours',
            'Overtime Hours', 'Late Minutes', 'Early Departure', 'Break Time',
            'Shift', 'Regularization Status', 'Comments'
        ]

        # Style headers
        header_font = Font(bold=True, color='FFFFFF')
        header_fill = PatternFill(start_color='366092', end_color='366092', fill_type='solid')
        header_alignment = Alignment(horizontal='center', vertical='center')
        thin_border = Border(
            left=Side(style='thin'), right=Side(style='thin'),
            top=Side(style='thin'), bottom=Side(style='thin')
        )

        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col, value=header)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = header_alignment
            cell.border = thin_border

        # Data rows
        for row, attendance in enumerate(queryset.order_by('date', 'user__username'), 2):
            data = [
                attendance.date.strftime('%Y-%m-%d'),
                attendance.date.strftime('%A'),
                attendance.user.username,
                f"{attendance.user.first_name} {attendance.user.last_name}".strip(),
                attendance.status,
                attendance.clock_in_time.strftime('%H:%M:%S') if attendance.clock_in_time else '',
                attendance.clock_out_time.strftime('%H:%M:%S') if attendance.clock_out_time else '',
                str(attendance.total_hours) if attendance.total_hours else '',
                str(attendance.expected_hours) if attendance.expected_hours else '',
                str(attendance.overtime_hours) if attendance.overtime_hours else '',
                attendance.late_minutes or 0,
                attendance.early_departure_minutes or 0,
                str(attendance.break_time) if attendance.break_time else '',
                attendance.shift.shift_name if attendance.shift else 'No Shift',
                attendance.regularization_status or 'Not Requested',
                attendance.comments or ''
            ]

            for col, value in enumerate(data, 1):
                cell = ws.cell(row=row, column=col, value=value)
                cell.border = thin_border

                # Color coding for status
                if col == 7:  # Status column
                    if 'Present' in str(value):
                        if 'Late' in str(value):
                            cell.fill = PatternFill(start_color='FFF2CC', end_color='FFF2CC', fill_type='solid')  # Light yellow
                        else:
                            cell.fill = PatternFill(start_color='D5E8D4', end_color='D5E8D4', fill_type='solid')  # Light green
                    elif value == 'Absent':
                        cell.fill = PatternFill(start_color='F8CECC', end_color='F8CECC', fill_type='solid')  # Light red
                    elif value == 'On Leave':
                        cell.fill = PatternFill(start_color='E1D5E7', end_color='E1D5E7', fill_type='solid')  # Light purple

        # Auto-adjust column widths
        for column in ws.columns:
            max_length = 0
            column = list(column)
            for cell in column:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except:
                    pass
            adjusted_width = min(max_length + 2, 25)
            ws.column_dimensions[column[0].column_letter].width = adjusted_width

        # Add title
        ws.insert_rows(1)
        title_cell = ws.cell(row=1, column=1, value=f"Attendance Report ({start_date} to {end_date})")
        title_cell.font = Font(bold=True, size=14)
        ws.merge_cells(f'A1:{get_column_letter(len(headers))}1')

        # Freeze panes
        ws.freeze_panes = 'A3'

    def _create_summary_sheet(self, ws, queryset, start_date, end_date):
        """Create summary statistics sheet"""
        # Title
        ws.cell(row=1, column=1, value="Attendance Summary").font = Font(bold=True, size=14)
        ws.cell(row=2, column=1, value=f"Period: {start_date} to {end_date}")

        # Calculate statistics
        total_records = queryset.count()
        present_count = queryset.filter(status__icontains='Present').count()
        absent_count = queryset.filter(status='Absent').count()
        late_count = queryset.filter(status='Present & Late').count()
        leave_count = queryset.filter(status='On Leave').count()
        holiday_count = queryset.filter(status='Holiday').count()
        weekend_count = queryset.filter(status='Weekend').count()

        # Summary data
        summary_data = [
            ['Metric', 'Count', 'Percentage'],
            ['Total Records', total_records, '100.00%'],
            ['Present', present_count, f'{(present_count/total_records*100):.2f}%' if total_records > 0 else '0%'],
            ['Present & Late', late_count, f'{(late_count/total_records*100):.2f}%' if total_records > 0 else '0%'],
            ['Absent', absent_count, f'{(absent_count/total_records*100):.2f}%' if total_records > 0 else '0%'],
            ['On Leave', leave_count, f'{(leave_count/total_records*100):.2f}%' if total_records > 0 else '0%'],
            ['Holiday', holiday_count, f'{(holiday_count/total_records*100):.2f}%' if total_records > 0 else '0%'],
            ['Weekend', weekend_count, f'{(weekend_count/total_records*100):.2f}%' if total_records > 0 else '0%'],
        ]

        # Write summary data
        for row_idx, row_data in enumerate(summary_data, 4):
            for col_idx, value in enumerate(row_data, 1):
                cell = ws.cell(row=row_idx, column=col_idx, value=value)
                if row_idx == 4:  # Header row
                    cell.font = Font(bold=True)
                    cell.fill = PatternFill(start_color='CCCCCC', end_color='CCCCCC', fill_type='solid')

        # Employee-wise summary (if permission allows)
        if self.user_role in ['HR', 'Admin', 'Manager']:
            ws.cell(row=13, column=1, value="Employee Summary").font = Font(bold=True, size=12)

            employee_headers = ['Employee', 'Total Days', 'Present', 'Absent', 'Late', 'Attendance %']
            for col, header in enumerate(employee_headers, 1):
                cell = ws.cell(row=14, column=col, value=header)
                cell.font = Font(bold=True)
                cell.fill = PatternFill(start_color='CCCCCC', end_color='CCCCCC', fill_type='solid')

            # Get employee-wise data
            employees = queryset.values('user__username', 'user__first_name', 'user__last_name').distinct()
            row = 15
            for emp in employees:
                emp_queryset = queryset.filter(user__username=emp['user__username'])
                emp_total = emp_queryset.count()
                emp_present = emp_queryset.filter(status__icontains='Present').count()
                emp_absent = emp_queryset.filter(status='Absent').count()
                emp_late = emp_queryset.filter(status='Present & Late').count()
                emp_attendance_rate = (emp_present / emp_total * 100) if emp_total > 0 else 0

                emp_data = [
                    f"{emp['user__first_name']} {emp['user__last_name']}".strip() or emp['user__username'],
                    emp_total,
                    emp_present,
                    emp_absent,
                    emp_late,
                    f'{emp_attendance_rate:.2f}%'
                ]

                for col, value in enumerate(emp_data, 1):
                    ws.cell(row=row, column=col, value=value)
                row += 1

        # Auto-adjust column widths
        for column in ws.columns:
            max_length = 0
            column = list(column)
            for cell in column:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except:
                    pass
            adjusted_width = min(max_length + 2, 20)
            ws.column_dimensions[column[0].column_letter].width = adjusted_width


    def _add_charts(self, wb, queryset):
        """Add charts to workbook"""
        try:
            chart_sheet = wb.create_sheet("Charts")

            # Status distribution chart
            status_counts = {
                'Present': queryset.filter(status='Present').count(),
                'Present & Late': queryset.filter(status='Present & Late').count(),
                'Absent': queryset.filter(status='Absent').count(),
                'On Leave': queryset.filter(status='On Leave').count(),
            }

            # Write chart data
            chart_sheet.cell(row=1, column=1, value="Status Distribution")
            for row, (status, count) in enumerate(status_counts.items(), 2):
                chart_sheet.cell(row=row, column=1, value=status)
                chart_sheet.cell(row=row, column=2, value=count)

            # Create bar chart
            chart = BarChart()
            chart.title = "Attendance Status Distribution"
            chart.x_axis.title = "Status"
            chart.y_axis.title = "Count"

            data = Reference(chart_sheet, min_col=2, min_row=1, max_row=len(status_counts) + 1)
            cats = Reference(chart_sheet, min_col=1, min_row=2, max_row=len(status_counts) + 1)

            chart.add_data(data, titles_from_data=True)
            chart.set_categories(cats)
            chart_sheet.add_chart(chart, "D2")

        except Exception as e:
            logger.warning(f"Failed to add charts: {e}")

    def export_to_csv(self, start_date, end_date, user_ids=None):
        """Export attendance data to CSV"""
        try:
            # Filter queryset
            queryset = self._filter_queryset(start_date, end_date, user_ids)

            # Create CSV response
            response = HttpResponse(content_type='text/csv')
            filename = f'attendance_report_{start_date.strftime("%Y%m%d")}_{end_date.strftime("%Y%m%d")}.csv'
            response['Content-Disposition'] = f'attachment; filename="{filename}"'

            writer = csv.writer(response)

            # Headers
            headers = [
                'Date', 'Day', 'Employee ID', 'Employee Name',
                'Status', 'Clock In', 'Clock Out', 'Total Hours', 'Expected Hours',
                'Overtime Hours', 'Late Minutes', 'Shift', 'Regularization Status'
            ]
            writer.writerow(headers)

            # Data rows
            for attendance in queryset.select_related('user', 'shift').order_by('date', 'user__username'):
                row = [
                    attendance.date.strftime('%Y-%m-%d'),
                    attendance.date.strftime('%A'),
                    attendance.user.username,
                    f"{attendance.user.first_name} {attendance.user.last_name}".strip(),
                    attendance.status,
                    attendance.clock_in_time.strftime('%H:%M:%S') if attendance.clock_in_time else '',
                    attendance.clock_out_time.strftime('%H:%M:%S') if attendance.clock_out_time else '',
                    str(attendance.total_hours) if attendance.total_hours else '',
                    str(attendance.expected_hours) if attendance.expected_hours else '',
                    str(attendance.overtime_hours) if attendance.overtime_hours else '',
                    attendance.late_minutes or 0,
                    attendance.shift.shift_name if attendance.shift else 'No Shift',
                    attendance.regularization_status or 'Not Requested'
                ]
                writer.writerow(row)

            logger.info(f"CSV export completed for user {self.user.username}: {queryset.count()} records")
            return response

        except Exception as e:
            logger.error(f"CSV export error for user {self.user.username}: {e}")
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

    def export_to_pdf(self, start_date, end_date, user_ids=None):
        """Export attendance data to PDF (basic implementation)"""
        try:
            # For now, return a message about PDF implementation
            return JsonResponse({
                'status': 'info',
                'message': 'PDF export feature will be implemented in the next version. Please use Excel or CSV export.'
            })
        except Exception as e:
            logger.error(f"PDF export error for user {self.user.username}: {e}")
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

    def _filter_queryset(self, start_date, end_date, user_ids=None):
        """Apply filters to the base queryset"""
        queryset = self.base_queryset.filter(date__range=[start_date, end_date])

        if user_ids:
            queryset = queryset.filter(user_id__in=user_ids)

        return queryset

    def get_export_summary(self, start_date, end_date):
        """Get export summary statistics"""
        try:
            queryset = self.base_queryset.filter(date__range=[start_date, end_date])

            summary = {
                'total_records': queryset.count(),
                'date_range': {
                    'start': start_date.strftime('%Y-%m-%d'),
                    'end': end_date.strftime('%Y-%m-%d')
                },
                'user_permissions': {
                    'role': self.user_role,
                    'can_export_all': self.user_role in ['HR', 'Admin'] or self.user.is_superuser,
                    'can_export_team': self.user_role in ['Manager', 'HR', 'Admin'] or self.user.is_superuser
                },
                'available_formats': ['excel', 'csv'],
                'features': {
                    'charts': self.user_role in ['HR', 'Admin', 'Manager'],
                    'employee_summary': self.user_role in ['HR', 'Admin', 'Manager']
                }
            }

            return summary

        except Exception as e:
            logger.error(f"Export summary error: {e}")
            return {'error': str(e)}


# Utility functions for quick exports
def quick_excel_export(user, start_date, end_date, **filters):
    """Quick Excel export function"""
    service = AttendanceExportService(user)
    return service.export_to_excel(start_date, end_date, **filters)


def quick_csv_export(user, start_date, end_date, **filters):
    """Quick CSV export function"""
    service = AttendanceExportService(user)
    return service.export_to_csv(start_date, end_date, **filters)


def get_user_export_permissions(user):
    """Get user's export permissions"""
    service = AttendanceExportService(user)
    return {
        'role': service.user_role,
        'can_export': True,  # All authenticated users can export their data
        'can_export_all': service.user_role in ['HR', 'Admin'],
        'can_export_team': service.user_role in ['Manager', 'HR', 'Admin'],
        'available_formats': ['excel', 'csv']
    }
