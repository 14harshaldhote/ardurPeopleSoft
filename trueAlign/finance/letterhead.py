"""
Letterhead and PDF generation for Finance Module
Generates professional documents with company letterhead
"""

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib import colors
from django.conf import settings
from io import BytesIO
import os
from decimal import Decimal


def get_company_details():
    """
    Get company details from settings or database
    """
    return {
        'name': getattr(settings, 'COMPANY_NAME', 'Your Company Name'),
        'address_line1': getattr(settings, 'COMPANY_ADDRESS_LINE1', 'Address Line 1'),
        'address_line2': getattr(settings, 'COMPANY_ADDRESS_LINE2', 'City, State, PIN'),
        'phone': getattr(settings, 'COMPANY_PHONE', '+91 XXXXXXXXXX'),
        'email': getattr(settings, 'COMPANY_EMAIL', 'info@company.com'),
        'website': getattr(settings, 'COMPANY_WEBSITE', 'www.company.com'),
        'gstin': getattr(settings, 'COMPANY_GSTIN', 'GSTIN: XXXXXXXXXXXX'),
        'pan': getattr(settings, 'COMPANY_PAN', 'PAN: XXXXXXXXXX'),
    }


def get_logo_path():
    """Get company logo path"""
    logo_path = os.path.join(settings.STATIC_ROOT or settings.BASE_DIR, 'static', 'images', 'company_logo.png')
    if not os.path.exists(logo_path):
        logo_path = os.path.join(settings.BASE_DIR, 'trueAlign', 'static', 'images', 'company_logo.png')
    
    if os.path.exists(logo_path):
        return logo_path
    return None


def create_letterhead_header(story, styles):
    """
    Create letterhead header with logo and company details
    """
    company = get_company_details()
    logo_path = get_logo_path()
    
    # Create header table with logo and company info
    header_data = []
    
    if logo_path and os.path.exists(logo_path):
        # Logo and company name side by side
        logo = Image(logo_path, width=1.5*inch, height=0.75*inch)
        company_info = [
            Paragraph(f"<b>{company['name']}</b>", styles['Heading1']),
            Paragraph(company['address_line1'], styles['Normal']),
            Paragraph(company['address_line2'], styles['Normal']),
            Paragraph(f"Phone: {company['phone']} | Email: {company['email']}", styles['Normal']),
        ]
        header_data = [[logo, company_info]]
    else:
        # Just company info if no logo
        company_info = [
            [Paragraph(f"<b>{company['name']}</b>", styles['Heading1'])],
            [Paragraph(company['address_line1'], styles['Normal'])],
            [Paragraph(company['address_line2'], styles['Normal'])],
            [Paragraph(f"Phone: {company['phone']} | Email: {company['email']}", styles['Normal'])],
        ]
        header_table = Table(company_info, colWidths=[6*inch])
        story.append(header_table)
        story.append(Spacer(1, 0.2*inch))
        return
    
    # Create header table
    header_table = Table(header_data, colWidths=[2*inch, 4*inch])
    header_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (0, 0), 'LEFT'),
        ('ALIGN', (1, 0), (1, 0), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    
    story.append(header_table)
    
    # Add horizontal line
    line_data = [['']]
    line_table = Table(line_data, colWidths=[6.5*inch])
    line_table.setStyle(TableStyle([
        ('LINEABOVE', (0, 0), (-1, 0), 2, colors.HexColor('#366092')),
    ]))
    story.append(line_table)
    story.append(Spacer(1, 0.3*inch))


def generate_voucher_pdf(voucher):
    """
    Generate PDF for voucher with letterhead
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=0.75*inch, leftMargin=0.75*inch,
                           topMargin=0.75*inch, bottomMargin=0.75*inch)
    
    story = []
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=16,
        textColor=colors.HexColor('#366092'),
        spaceAfter=12,
        alignment=TA_CENTER
    )
    
    # Add letterhead
    create_letterhead_header(story, styles)
    
    # Add voucher title
    story.append(Paragraph(f"<b>{voucher.get_type_display()} VOUCHER</b>", title_style))
    story.append(Spacer(1, 0.2*inch))
    
    # Voucher details
    details_data = [
        ['Voucher Number:', voucher.voucher_number, 'Date:', voucher.date.strftime('%d-%m-%Y')],
        ['Party Name:', voucher.party_name, 'Reference No:', voucher.reference_no or '-'],
        ['Purpose:', {'colspan': 3, 'value': voucher.purpose}],
    ]
    
    details_table_data = [
        [Paragraph('<b>Voucher Number:</b>', styles['Normal']), 
         Paragraph(voucher.voucher_number, styles['Normal']),
         Paragraph('<b>Date:</b>', styles['Normal']), 
         Paragraph(voucher.date.strftime('%d-%m-%Y'), styles['Normal'])],
        [Paragraph('<b>Party Name:</b>', styles['Normal']), 
         Paragraph(voucher.party_name, styles['Normal']),
         Paragraph('<b>Reference No:</b>', styles['Normal']), 
         Paragraph(voucher.reference_no or '-', styles['Normal'])],
    ]
    
    details_table = Table(details_table_data, colWidths=[1.5*inch, 2*inch, 1.5*inch, 1.5*inch])
    details_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    
    story.append(details_table)
    story.append(Spacer(1, 0.15*inch))
    
    # Purpose
    story.append(Paragraph('<b>Purpose:</b>', styles['Normal']))
    story.append(Paragraph(voucher.purpose, styles['Normal']))
    story.append(Spacer(1, 0.2*inch))
    
    # Voucher details table
    story.append(Paragraph('<b>Accounting Entries:</b>', styles['Heading2']))
    story.append(Spacer(1, 0.1*inch))
    
    entry_data = [['Account', 'Description', 'Debit (₹)', 'Credit (₹)']]
    
    total_debit = Decimal('0')
    total_credit = Decimal('0')
    
    for detail in voucher.details.all():
        entry_data.append([
            detail.account.name,
            detail.description or '-',
            f"{detail.debit_amount:,.2f}" if detail.debit_amount else '-',
            f"{detail.credit_amount:,.2f}" if detail.credit_amount else '-',
        ])
        total_debit += detail.debit_amount
        total_credit += detail.credit_amount
    
    # Add totals
    entry_data.append(['TOTAL', '', f"{total_debit:,.2f}", f"{total_credit:,.2f}"])
    
    entry_table = Table(entry_data, colWidths=[2.5*inch, 2*inch, 1*inch, 1*inch])
    entry_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#366092')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (2, 0), (-1, -1), 'RIGHT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, -1), (-1, -1), colors.lightgrey),
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    
    story.append(entry_table)
    story.append(Spacer(1, 0.3*inch))
    
    # Amount in words (you might want to add a number-to-words converter)
    story.append(Paragraph(f"<b>Amount:</b> ₹ {voucher.amount:,.2f}", styles['Normal']))
    story.append(Spacer(1, 0.3*inch))
    
    # Status
    story.append(Paragraph(f"<b>Status:</b> {voucher.get_status_display()}", styles['Normal']))
    story.append(Spacer(1, 0.5*inch))
    
    # Signatures
    sig_data = [
        [Paragraph('<b>Prepared By</b>', styles['Normal']), 
         Paragraph('<b>Approved By</b>', styles['Normal']),
         Paragraph('<b>Authorized Signatory</b>', styles['Normal'])]
    ]
    
    sig_table = Table(sig_data, colWidths=[2*inch, 2*inch, 2*inch])
    sig_table.setStyle(TableStyle([
        ('LINEABOVE', (0, 0), (-1, 0), 1, colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
    ]))
    
    story.append(sig_table)
    
    # Build PDF
    doc.build(story)
    buffer.seek(0)
    
    return buffer


def generate_invoice_pdf(invoice):
    """
    Generate PDF for client invoice with letterhead
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=0.75*inch, leftMargin=0.75*inch,
                           topMargin=0.75*inch, bottomMargin=0.75*inch)
    
    story = []
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor('#366092'),
        spaceAfter=12,
        alignment=TA_CENTER
    )
    
    # Add letterhead
    create_letterhead_header(story, styles)
    
    # Add invoice title
    story.append(Paragraph("<b>INVOICE</b>", title_style))
    story.append(Spacer(1, 0.2*inch))
    
    # Invoice details
    client_name = invoice.client.get_full_name() if hasattr(invoice.client, 'get_full_name') else invoice.client.username
    
    details_table_data = [
        [Paragraph('<b>Invoice Number:</b>', styles['Normal']), 
         Paragraph(invoice.invoice_number, styles['Normal']),
         Paragraph('<b>Date:</b>', styles['Normal']), 
         Paragraph(invoice.created_at.strftime('%d-%m-%Y'), styles['Normal'])],
        [Paragraph('<b>Client:</b>', styles['Normal']), 
         Paragraph(client_name, styles['Normal']),
         Paragraph('<b>Due Date:</b>', styles['Normal']), 
         Paragraph(invoice.due_date.strftime('%d-%m-%Y'), styles['Normal'])],
        [Paragraph('<b>Billing Cycle:</b>', styles['Normal']), 
         Paragraph(f"{invoice.billing_cycle_start.strftime('%d-%m-%Y')} to {invoice.billing_cycle_end.strftime('%d-%m-%Y')}", styles['Normal']),
         Paragraph('<b>Billing Model:</b>', styles['Normal']), 
         Paragraph(invoice.get_billing_model_display(), styles['Normal'])],
    ]
    
    details_table = Table(details_table_data, colWidths=[1.5*inch, 2*inch, 1.5*inch, 1.5*inch])
    details_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
    ]))
    
    story.append(details_table)
    story.append(Spacer(1, 0.3*inch))
    
    # Billing details
    story.append(Paragraph('<b>Billing Details:</b>', styles['Heading2']))
    story.append(Spacer(1, 0.1*inch))
    
    billing_data = [['Description', 'Quantity', 'Rate (₹)', 'Amount (₹)']]
    
    if invoice.billing_model == 'per_order':
        billing_data.append([
            'Orders Processed',
            str(invoice.order_count),
            f"{invoice.rate:,.2f}",
            f"{invoice.subtotal:,.2f}"
        ])
    elif invoice.billing_model == 'per_fte':
        billing_data.append([
            'FTE Count',
            str(invoice.fte_count),
            f"{invoice.rate:,.2f}",
            f"{invoice.subtotal:,.2f}"
        ])
    else:  # hybrid
        if invoice.order_count:
            billing_data.append([
                'Orders Processed',
                str(invoice.order_count),
                f"{invoice.rate:,.2f}",
                f"{Decimal(str(invoice.order_count)) * invoice.rate:,.2f}"
            ])
        if invoice.fte_count:
            billing_data.append([
                'FTE Count',
                str(invoice.fte_count),
                f"{invoice.rate:,.2f}",
                f"{invoice.fte_count * invoice.rate:,.2f}"
            ])
    
    billing_table = Table(billing_data, colWidths=[3*inch, 1*inch, 1.25*inch, 1.25*inch])
    billing_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#366092')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (1, 0), (-1, -1), 'RIGHT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    
    story.append(billing_table)
    story.append(Spacer(1, 0.2*inch))
    
    # Summary
    summary_data = [
        ['Subtotal:', f"₹ {invoice.subtotal:,.2f}"],
        ['Tax:', f"₹ {invoice.tax_amount:,.2f}"],
        ['Discount:', f"₹ {invoice.discount:,.2f}"],
        ['<b>Total Amount:</b>', f"<b>₹ {invoice.total_amount:,.2f}</b>"],
    ]
    
    summary_table_data = []
    for label, value in summary_data:
        summary_table_data.append([
            Paragraph(label, styles['Normal']),
            Paragraph(value, styles['Normal'])
        ])
    
    summary_table = Table(summary_table_data, colWidths=[4.5*inch, 2*inch])
    summary_table.setStyle(TableStyle([
        ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
        ('LINEABOVE', (0, -1), (-1, -1), 2, colors.black),
        ('FONTSIZE', (0, -1), (-1, -1), 12),
    ]))
    
    story.append(summary_table)
    story.append(Spacer(1, 0.5*inch))
    
    # Payment terms
    story.append(Paragraph('<b>Payment Terms & Conditions:</b>', styles['Heading3']))
    story.append(Paragraph('Payment is due within 30 days of invoice date.', styles['Normal']))
    story.append(Paragraph('Please make payment to the bank account mentioned below.', styles['Normal']))
    story.append(Spacer(1, 0.3*inch))
    
    # Bank details
    company = get_company_details()
    bank_details = [
        ['Bank Details:', ''],
        ['Bank Name:', getattr(settings, 'COMPANY_BANK_NAME', 'Bank Name')],
        ['Account Number:', getattr(settings, 'COMPANY_BANK_ACCOUNT', 'XXXXXXXXXXXX')],
        ['IFSC Code:', getattr(settings, 'COMPANY_BANK_IFSC', 'XXXXXXXXXXX')],
    ]
    
    bank_table_data = []
    for label, value in bank_details:
        bank_table_data.append([
            Paragraph(f'<b>{label}</b>', styles['Normal']),
            Paragraph(value, styles['Normal'])
        ])
    
    bank_table = Table(bank_table_data, colWidths=[2*inch, 4*inch])
    story.append(bank_table)
    story.append(Spacer(1, 0.5*inch))
    
    # Authorized signature
    story.append(Paragraph('<b>Authorized Signatory</b>', styles['Normal']))
    
    # Build PDF
    doc.build(story)
    buffer.seek(0)
    
    return buffer


def generate_expense_pdf(expense):
    """
    Generate PDF for expense claim with letterhead
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=0.75*inch, leftMargin=0.75*inch,
                           topMargin=0.75*inch, bottomMargin=0.75*inch)
    
    story = []
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=16,
        textColor=colors.HexColor('#366092'),
        spaceAfter=12,
        alignment=TA_CENTER
    )
    
    # Add letterhead
    create_letterhead_header(story, styles)
    
    # Title
    story.append(Paragraph("<b>EXPENSE CLAIM</b>", title_style))
    story.append(Spacer(1, 0.2*inch))
    
    # Expense details
    employee_name = expense.paid_by.get_full_name() if hasattr(expense.paid_by, 'get_full_name') else expense.paid_by.username
    
    details_table_data = [
        [Paragraph('<b>Expense ID:</b>', styles['Normal']), 
         Paragraph(expense.expense_id, styles['Normal']),
         Paragraph('<b>Date:</b>', styles['Normal']), 
         Paragraph(expense.date.strftime('%d-%m-%Y'), styles['Normal'])],
        [Paragraph('<b>Employee:</b>', styles['Normal']), 
         Paragraph(employee_name, styles['Normal']),
         Paragraph('<b>Category:</b>', styles['Normal']), 
         Paragraph(expense.get_category_display(), styles['Normal'])],
        [Paragraph('<b>Status:</b>', styles['Normal']), 
         Paragraph(expense.get_status_display(), styles['Normal']),
         Paragraph('<b>Amount:</b>', styles['Normal']), 
         Paragraph(f"₹ {expense.amount:,.2f}", styles['Normal'])],
    ]
    
    details_table = Table(details_table_data, colWidths=[1.5*inch, 2*inch, 1.5*inch, 1.5*inch])
    details_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
    ]))
    
    story.append(details_table)
    story.append(Spacer(1, 0.2*inch))
    
    # Description and amount
    story.append(Paragraph('<b>Description:</b>', styles['Heading3']))
    story.append(Paragraph(expense.description, styles['Normal']))
    story.append(Spacer(1, 0.2*inch))
    
    story.append(Paragraph(f"<b>Amount Claimed:</b> ₹ {expense.amount:,.2f}", styles['Heading2']))
    story.append(Spacer(1, 0.3*inch))
    
    # Approval details
    if expense.approved_by:
        approved_by_name = expense.approved_by.get_full_name() if hasattr(expense.approved_by, 'get_full_name') else expense.approved_by.username
        story.append(Paragraph(f"<b>Approved By:</b> {approved_by_name}", styles['Normal']))
        if expense.approved_at:
            story.append(Paragraph(f"<b>Approved On:</b> {expense.approved_at.strftime('%d-%m-%Y %H:%M')}", styles['Normal']))
    
    if expense.rejection_reason:
        story.append(Paragraph(f"<b>Rejection Reason:</b> {expense.rejection_reason}", styles['Normal']))
    
    story.append(Spacer(1, 0.5*inch))
    
    # Signatures
    sig_data = [
        [Paragraph('<b>Employee Signature</b>', styles['Normal']), 
         Paragraph('<b>Approved By</b>', styles['Normal'])]
    ]
    
    sig_table = Table(sig_data, colWidths=[3*inch, 3*inch])
    sig_table.setStyle(TableStyle([
        ('LINEABOVE', (0, 0), (-1, 0), 1, colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
    ]))
    
    story.append(sig_table)
    
    # Build PDF
    doc.build(story)
    buffer.seek(0)
    
    return buffer