"""
Utility functions for Finance Module
Includes Excel export, PDF generation, ID generation, and calculations
"""

import os
from decimal import Decimal
from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
from io import BytesIO
import openpyxl
from openpyxl.styles import Font, Alignment, PatternFill, Border, Side
from openpyxl.drawing.image import Image
from openpyxl.utils import get_column_letter


def generate_unique_id(prefix, model_class, field_name=''):
    """
    Generate unique ID with prefix for financial records
    Format: PREFIX-YYYYMMDD-####
    """
    today = timezone.now().date()
    date_str = today.strftime('%Y%m%d')
    base_id = f"{prefix}-{date_str}"
    
    # Get count of records created today
    if field_name:
        count = model_class.objects.filter(**{f"{field_name}__startswith": base_id}).count()
    else:
        count = model_class.objects.filter(pk__startswith=base_id).count()
    
    sequence = str(count + 1).zfill(4)
    return f"{base_id}-{sequence}"


def get_company_logo_path():
    """
    Get the path to company logo
    """
    logo_path = os.path.join(settings.STATIC_ROOT or settings.BASE_DIR, 'static', 'images', 'company_logo.png')
    if not os.path.exists(logo_path):
        # Try alternate locations
        logo_path = os.path.join(settings.BASE_DIR, 'trueAlign', 'static', 'images', 'company_logo.png')
    
    if os.path.exists(logo_path):
        return logo_path
    return None


def add_logo_to_excel(worksheet, logo_path=None):
    """
    Add company logo to Excel worksheet
    """
    if logo_path is None:
        logo_path = get_company_logo_path()
    
    if logo_path and os.path.exists(logo_path):
        try:
            img = Image(logo_path)
            # Resize logo to fit in header
            img.width = 100
            img.height = 50
            worksheet.add_image(img, 'A1')
            return True
        except Exception as e:
            print(f"Error adding logo: {e}")
            return False
    return False


def create_excel_with_logo(title, headers, data, filename, logo_path=None):
    """
    Create Excel file with company logo and formatted data
    
    Args:
        title: Title of the report
        headers: List of column headers
        data: List of lists containing row data
        filename: Name for the file
        logo_path: Optional path to logo file
    
    Returns:
        BytesIO object containing the Excel file
    """
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = title[:31]  # Excel sheet title max 31 chars
    
    # Add logo
    add_logo_to_excel(ws, logo_path)
    
    # Define styles
    header_font = Font(bold=True, size=12, color='FFFFFF')
    header_fill = PatternFill(start_color='366092', end_color='366092', fill_type='solid')
    title_font = Font(bold=True, size=14)
    border = Border(
        left=Side(style='thin'),
        right=Side(style='thin'),
        top=Side(style='thin'),
        bottom=Side(style='thin')
    )
    
    # Add title (offset for logo)
    ws.merge_cells('C1:E1')
    title_cell = ws['C1']
    title_cell.value = title
    title_cell.font = title_font
    title_cell.alignment = Alignment(horizontal='center', vertical='center')
    
    # Add metadata
    ws['C2'] = f"Generated on: {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}"
    ws['C2'].font = Font(size=9, italic=True)
    
    # Add headers (starting from row 4 to give space for logo and title)
    header_row = 4
    for col_num, header in enumerate(headers, 1):
        cell = ws.cell(row=header_row, column=col_num)
        cell.value = header
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = Alignment(horizontal='center', vertical='center')
        cell.border = border
    
    # Add data
    for row_num, row_data in enumerate(data, header_row + 1):
        for col_num, value in enumerate(row_data, 1):
            cell = ws.cell(row=row_num, column=col_num)
            cell.value = value
            cell.border = border
            cell.alignment = Alignment(horizontal='left', vertical='center')
            
            # Format numbers
            if isinstance(value, (int, float, Decimal)):
                cell.number_format = '#,##0.00'
                cell.alignment = Alignment(horizontal='right', vertical='center')
    
    # Auto-adjust column widths
    for col in range(1, len(headers) + 1):
        column_letter = get_column_letter(col)
        max_length = 0
        for row in ws[column_letter]:
            try:
                if len(str(row.value)) > max_length:
                    max_length = len(str(row.value))
            except:
                pass
        adjusted_width = min(max_length + 2, 50)
        ws.column_dimensions[column_letter].width = adjusted_width
    
    # Save to BytesIO
    output = BytesIO()
    wb.save(output)
    output.seek(0)
    
    return output


def export_expenses_to_excel(expenses, filename='expenses_report.xlsx'):
    """
    Export expenses to Excel with logo
    """
    headers = [
        'Expense ID', 'Date', 'Category', 'Description',
        'Amount', 'Paid By', 'Status', 'Approved By', 'Approved At'
    ]
    
    data = []
    for expense in expenses:
        data.append([
            expense.expense_id,
            expense.date.strftime('%Y-%m-%d'),
            expense.get_category_display(),
            expense.description,
            float(expense.amount),
            expense.paid_by.get_full_name() if hasattr(expense.paid_by, 'get_full_name') else expense.paid_by.username,
            expense.get_status_display(),
            expense.approved_by.get_full_name() if expense.approved_by and hasattr(expense.approved_by, 'get_full_name') else (expense.approved_by.username if expense.approved_by else ''),
            expense.approved_at.strftime('%Y-%m-%d %H:%M') if expense.approved_at else ''
        ])
    
    return create_excel_with_logo('Expense Report', headers, data, filename)


def export_vouchers_to_excel(vouchers, filename='vouchers_report.xlsx'):
    """
    Export vouchers to Excel with logo
    """
    headers = [
        'Voucher Number', 'Type', 'Date', 'Party Name', 'Purpose',
        'Amount', 'Status', 'Reference No', 'Created By'
    ]
    
    data = []
    for voucher in vouchers:
        data.append([
            voucher.voucher_number,
            voucher.get_type_display(),
            voucher.date.strftime('%Y-%m-%d'),
            voucher.party_name,
            voucher.purpose,
            float(voucher.amount),
            voucher.get_status_display(),
            voucher.reference_no or '',
            voucher.created_by.get_full_name() if hasattr(voucher.created_by, 'get_full_name') else voucher.created_by.username
        ])
    
    return create_excel_with_logo('Voucher Report', headers, data, filename)


def export_bank_payments_to_excel(payments, filename='bank_payments_report.xlsx'):
    """
    Export bank payments to Excel with logo
    """
    headers = [
        'Payment ID', 'Date', 'Bank Account', 'Party Name', 'Reason',
        'Amount', 'Status', 'Reference Number', 'Verified By', 'Approved By'
    ]
    
    data = []
    for payment in payments:
        data.append([
            payment.payment_id,
            payment.payment_date.strftime('%Y-%m-%d'),
            f"{payment.bank_account.bank_name} - {payment.bank_account.account_number}",
            payment.party_name,
            payment.payment_reason,
            float(payment.amount),
            payment.get_status_display(),
            payment.reference_number or '',
            payment.verified_by.get_full_name() if payment.verified_by and hasattr(payment.verified_by, 'get_full_name') else (payment.verified_by.username if payment.verified_by else ''),
            payment.approved_by.get_full_name() if payment.approved_by and hasattr(payment.approved_by, 'get_full_name') else (payment.approved_by.username if payment.approved_by else '')
        ])
    
    return create_excel_with_logo('Bank Payments Report', headers, data, filename)


def export_invoices_to_excel(invoices, filename='invoices_report.xlsx'):
    """
    Export invoices to Excel with logo
    """
    headers = [
        'Invoice Number', 'Client', 'Billing Model', 'Cycle Start', 'Cycle End',
        'Subtotal', 'Tax', 'Discount', 'Total', 'Due Date', 'Status'
    ]
    
    data = []
    for invoice in invoices:
        data.append([
            invoice.invoice_number,
            invoice.client.get_full_name() if hasattr(invoice.client, 'get_full_name') else invoice.client.username,
            invoice.get_billing_model_display(),
            invoice.billing_cycle_start.strftime('%Y-%m-%d'),
            invoice.billing_cycle_end.strftime('%Y-%m-%d'),
            float(invoice.subtotal),
            float(invoice.tax_amount),
            float(invoice.discount),
            float(invoice.total_amount),
            invoice.due_date.strftime('%Y-%m-%d'),
            invoice.get_status_display()
        ])
    
    return create_excel_with_logo('Invoices Report', headers, data, filename)


def export_subscriptions_to_excel(subscriptions, filename='subscriptions_report.xlsx'):
    """
    Export subscriptions to Excel with logo
    """
    headers = [
        'Name', 'Vendor', 'Type', 'Amount', 'Frequency',
        'Start Date', 'Next Payment', 'Status', 'Auto Renew'
    ]
    
    data = []
    for sub in subscriptions:
        data.append([
            sub.name,
            sub.vendor,
            sub.subscription_type,
            float(sub.amount),
            sub.get_frequency_display(),
            sub.start_date.strftime('%Y-%m-%d'),
            sub.next_payment_date.strftime('%Y-%m-%d'),
            sub.get_status_display(),
            'Yes' if sub.auto_renew else 'No'
        ])
    
    return create_excel_with_logo('Subscriptions Report', headers, data, filename)


def calculate_invoice_totals(billing_model, order_count, fte_count, rate, tax_rate, discount=0):
    """
    Calculate invoice totals based on billing model
    
    Returns:
        dict with keys: subtotal, tax_amount, total_amount
    """
    subtotal = Decimal('0')
    
    if billing_model == 'per_order':
        subtotal = Decimal(str(order_count)) * Decimal(str(rate))
    elif billing_model == 'per_fte':
        subtotal = Decimal(str(fte_count)) * Decimal(str(rate))
    elif billing_model == 'hybrid':
        # For hybrid, you might want to customize this
        order_amount = Decimal(str(order_count)) * Decimal(str(rate)) if order_count else Decimal('0')
        fte_amount = Decimal(str(fte_count)) * Decimal(str(rate)) if fte_count else Decimal('0')
        subtotal = order_amount + fte_amount
    
    discount_amount = Decimal(str(discount))
    subtotal_after_discount = subtotal - discount_amount
    tax_amount = subtotal_after_discount * Decimal(str(tax_rate))
    total_amount = subtotal_after_discount + tax_amount
    
    return {
        'subtotal': subtotal,
        'tax_amount': tax_amount,
        'total_amount': total_amount
    }


def get_upcoming_subscriptions(days=30):
    """
    Get subscriptions that are due for renewal in the next N days
    """
    from trueAlign.models import Subscription
    
    today = timezone.now().date()
    end_date = today + timedelta(days=days)
    
    return Subscription.objects.filter(
        status='active',
        next_payment_date__gte=today,
        next_payment_date__lte=end_date
    ).order_by('next_payment_date')


def get_overdue_invoices():
    """
    Get all overdue invoices
    """
    from trueAlign.models import ClientInvoice
    
    today = timezone.now().date()
    
    return ClientInvoice.objects.filter(
        status__in=['sent', 'approved'],
        due_date__lt=today
    ).order_by('due_date')


def update_subscription_next_payment(subscription):
    """
    Update next payment date for a subscription based on frequency
    """
    from dateutil.relativedelta import relativedelta
    
    if subscription.frequency == 'monthly':
        subscription.next_payment_date = subscription.next_payment_date + relativedelta(months=1)
    elif subscription.frequency == 'quarterly':
        subscription.next_payment_date = subscription.next_payment_date + relativedelta(months=3)
    elif subscription.frequency == 'yearly':
        subscription.next_payment_date = subscription.next_payment_date + relativedelta(years=1)
    
    subscription.save(update_fields=['next_payment_date'])


def validate_voucher_balance(voucher_details):
    """
    Validate that debit and credit amounts balance in voucher details
    
    Args:
        voucher_details: List or QuerySet of VoucherDetail objects
    
    Returns:
        tuple: (is_balanced, debit_total, credit_total)
    """
    debit_total = sum(detail.debit_amount for detail in voucher_details)
    credit_total = sum(detail.credit_amount for detail in voucher_details)
    
    is_balanced = debit_total == credit_total
    
    return is_balanced, debit_total, credit_total