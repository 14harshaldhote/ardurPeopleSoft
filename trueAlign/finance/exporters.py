"""
Compliance-ready Data Exporters with PII Redaction
Export financial data with role-based PII controls
"""

import csv
from io import StringIO, BytesIO
from datetime import date
from decimal import Decimal
from typing import List, Optional
from django.http import HttpResponse
from django.db.models import QuerySet


class FinanceDataExporter:
    """
    Export financial data with PII redaction based on user permissions
    """
    
    def __init__(self, user, include_pii: bool = None):
        """
        Initialize exporter
        
        Args:
            user: Django User object
            include_pii: Override PII inclusion (if None, checks permissions)
        """
        self.user = user
        
        # Check PII permission
        if include_pii is None:
            self.include_pii = (
                user.is_superuser or
                user.has_perm('finance.view_sensitive_data') or
                user.groups.filter(name__in=['Finance Admin', 'HR']).exists()
            )
        else:
            self.include_pii = include_pii and (
                user.is_superuser or user.has_perm('finance.view_sensitive_data')
            )
    
    def export_expenses_csv(self, expenses: QuerySet, fy_filter: Optional[int] = None) -> HttpResponse:
        """
        Export expenses to CSV with PII redaction
        
        Args:
            expenses: QuerySet of DailyExpense objects
            fy_filter: Financial year to filter (optional)
            
        Returns:
            HttpResponse with CSV attachment
        """
        # Apply FY filter if provided
        if fy_filter:
            from trueAlign.finance.fy_utils import get_fy_by_year
            fy_start, fy_end, fy_string = get_fy_by_year(fy_filter)
            expenses = expenses.filter(date__range=[fy_start, fy_end])
        
        # Create CSV
        output = StringIO()
        writer = csv.writer(output)
        
        # Headers
        headers = [
            'Date', 'Expense ID', 'Category', 'Department', 
            'Amount', 'Currency', 'Status'
        ]
        
        if self.include_pii:
            headers.extend([
                'Description', 'Vendor', 'Paid By', 
                'Approved By', 'Payment Mode', 'Reference No'
            ])
        else:
            headers.extend([
                'Description (Redacted)', 'Category Type', 'Month'
            ])
        
        writer.writerow(headers)
        
        # Data
        for expense in expenses.select_related('paid_by', 'approved_by'):
            row = [
                expense.date.strftime('%Y-%m-%d'),
                expense.expense_id,
                expense.category or '[Uncategorized]',
                expense.department,
                str(expense.amount),
                expense.currency,
                expense.status,
            ]
            
            if self.include_pii:
                # Full data for authorized users
                row.extend([
                    expense.description,
                    expense.vendor or '',
                    expense.paid_by.get_full_name() if expense.paid_by else '',
                    expense.approved_by.get_full_name() if expense.approved_by else '',
                    expense.payment_mode or '',
                    expense.reference_no or '',
                ])
            else:
                # Redacted for non-authorized users
                desc = expense.description or ''
                redacted_desc = desc[:30] + '...' if len(desc) > 30 else desc
                
                row.extend([
                    redacted_desc,
                    expense.category or 'Other',
                    expense.date.strftime('%b %Y'),
                ])
            
            writer.writerow(row)
        
        # Add metadata footer
        writer.writerow([])
        writer.writerow(['Export Metadata'])
        writer.writerow(['Exported By', self.user.get_full_name()])
        writer.writerow(['Export Date', date.today().strftime('%Y-%m-%d')])
        writer.writerow(['Total Records', expenses.count()])
        writer.writerow(['PII Included', 'Yes' if self.include_pii else 'No'])
        if fy_filter:
            writer.writerow(['Financial Year', f'FY {fy_filter}-{str(fy_filter+1)[2:]}'])
        
        # Create response
        response = HttpResponse(output.getvalue(), content_type='text/csv')
        filename = f'expenses_export_{date.today()}.csv'
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        # Log export
        self._log_export('expenses', expenses.count(), self.include_pii)
        
        return response
    
    def export_bank_statements_csv(self, statements: QuerySet) -> HttpResponse:
        """
        Export bank statements to CSV with PII redaction
        
        Args:
            statements: QuerySet of BankStatementLine objects
            
        Returns:
            HttpResponse with CSV attachment
        """
        output = StringIO()
        writer = csv.writer(output)
        
        # Headers
        headers = ['Date', 'Type', 'Amount', 'Balance', 'Category', 'Reconciled']
        
        if self.include_pii:
            headers.extend(['Description', 'Reference', 'Vendor', 'Matched Payment'])
        else:
            headers.extend(['Summary', 'Month'])
        
        writer.writerow(headers)
        
        # Data
        for line in statements.select_related('matched_payment'):
            row = [
                line.date.strftime('%Y-%m-%d') if line.date else '',
                line.transaction_type,
                str(line.amount),
                str(line.balance) if line.balance else '',
                line.category or '',
                'Yes' if line.is_reconciled else 'No',
            ]
            
            if self.include_pii:
                row.extend([
                    line.description,
                    line.reference_no or '',
                    line.vendor or '',
                    line.matched_payment.payment_id if line.matched_payment else '',
                ])
            else:
                summary = f"{line.transaction_type} transaction"
                row.extend([
                    summary,
                    line.date.strftime('%b %Y') if line.date else '',
                ])
            
            writer.writerow(row)
        
        # Metadata
        writer.writerow([])
        writer.writerow(['Export Metadata'])
        writer.writerow(['Exported By', self.user.get_full_name()])
        writer.writerow(['Export Date', date.today().strftime('%Y-%m-%d')])
        writer.writerow(['Total Records', statements.count()])
        writer.writerow(['PII Included', 'Yes' if self.include_pii else 'No'])
        
        response = HttpResponse(output.getvalue(), content_type='text/csv')
        filename = f'bank_statements_export_{date.today()}.csv'
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        self._log_export('bank_statements', statements.count(), self.include_pii)
        
        return response
    
    def export_summary_report(self, expenses: QuerySet, fy_year: int) -> HttpResponse:
        """
        Export FY summary report (safe for all users - aggregated data only)
        
        Args:
            expenses: QuerySet of expenses
            fy_year: Financial year
            
        Returns:
            HttpResponse with CSV attachment
        """
        from trueAlign.finance.fy_utils import get_fy_by_year, get_fy_quarters
        from django.db.models import Sum, Count, Avg
        
        fy_start, fy_end, fy_string = get_fy_by_year(fy_year)
        expenses = expenses.filter(date__range=[fy_start, fy_end])
        
        output = StringIO()
        writer = csv.writer(output)
        
        # Title
        writer.writerow([f'Financial Summary Report - {fy_string}'])
        writer.writerow([])
        
        # Overall Summary
        writer.writerow(['Overall Summary'])
        writer.writerow(['Metric', 'Value'])
        
        total_expenses = expenses.aggregate(
            total=Sum('amount'),
            count=Count('id'),
            avg=Avg('amount')
        )
        
        writer.writerow(['Total Amount', f"₹{total_expenses['total'] or 0:,.2f}"])
        writer.writerow(['Total Transactions', total_expenses['count'] or 0])
        writer.writerow(['Average Amount', f"₹{total_expenses['avg'] or 0:,.2f}"])
        writer.writerow([])
        
        # By Category
        writer.writerow(['Category Breakdown'])
        writer.writerow(['Category', 'Amount', 'Count', 'Percentage'])
        
        by_category = expenses.values('category').annotate(
            total=Sum('amount'),
            count=Count('id')
        ).order_by('-total')
        
        total_amount = total_expenses['total'] or Decimal('0')
        
        for cat in by_category:
            percentage = (cat['total'] / total_amount * 100) if total_amount > 0 else 0
            writer.writerow([
                cat['category'] or 'Uncategorized',
                f"₹{cat['total']:,.2f}",
                cat['count'],
                f"{percentage:.1f}%"
            ])
        
        writer.writerow([])
        
        # By Department
        writer.writerow(['Department Breakdown'])
        writer.writerow(['Department', 'Amount', 'Count'])
        
        by_dept = expenses.values('department').annotate(
            total=Sum('amount'),
            count=Count('id')
        ).order_by('-total')
        
        for dept in by_dept:
            writer.writerow([
                dept['department'],
                f"₹{dept['total']:,.2f}",
                dept['count']
            ])
        
        writer.writerow([])
        
        # By Quarter
        writer.writerow(['Quarterly Breakdown'])
        writer.writerow(['Quarter', 'Amount', 'Count'])
        
        quarters = get_fy_quarters(fy_year)
        for q_start, q_end, q_name in quarters:
            q_expenses = expenses.filter(date__range=[q_start, q_end]).aggregate(
                total=Sum('amount'),
                count=Count('id')
            )
            writer.writerow([
                q_name,
                f"₹{q_expenses['total'] or 0:,.2f}",
                q_expenses['count'] or 0
            ])
        
        # Metadata
        writer.writerow([])
        writer.writerow(['Report Metadata'])
        writer.writerow(['Generated By', self.user.get_full_name()])
        writer.writerow(['Generation Date', date.today().strftime('%Y-%m-%d')])
        writer.writerow(['Financial Year', fy_string])
        writer.writerow(['Period', f'{fy_start} to {fy_end}'])
        writer.writerow(['Note', 'This report contains aggregated data only (no PII)'])
        
        response = HttpResponse(output.getvalue(), content_type='text/csv')
        filename = f'summary_report_{fy_string.replace(" ", "_")}_{date.today()}.csv'
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        self._log_export('summary_report', 1, False)
        
        return response
    
    def _log_export(self, export_type: str, record_count: int, pii_included: bool):
        """
        Log data export for audit trail
        
        Args:
            export_type: Type of export
            record_count: Number of records exported
            pii_included: Whether PII was included
        """
        # Create audit log entry
        try:
            from trueAlign.models import AuditLog
            
            AuditLog.objects.create(
                user=self.user,
                action='DATA_EXPORT',
                model_name=export_type,
                description=f"Exported {record_count} {export_type} records (PII: {pii_included})",
                ip_address=None,  # Set from request if available
                metadata={
                    'export_type': export_type,
                    'record_count': record_count,
                    'pii_included': pii_included,
                    'timestamp': date.today().isoformat(),
                }
            )
        except Exception as e:
            # Fail silently if audit log not set up yet
            print(f"Audit log not available: {e}")


# Convenience functions for views

def export_expenses(request, queryset, fy_year=None):
    """
    Convenience function to export expenses from view
    
    Args:
        request: Django request object
        queryset: Expense queryset
        fy_year: Optional FY year filter
        
    Returns:
        HttpResponse with CSV
    """
    exporter = FinanceDataExporter(request.user)
    return exporter.export_expenses_csv(queryset, fy_filter=fy_year)


def export_bank_statements(request, queryset):
    """
    Convenience function to export bank statements from view
    """
    exporter = FinanceDataExporter(request.user)
    return exporter.export_bank_statements_csv(queryset)


def export_fy_summary(request, expenses_queryset, fy_year):
    """
    Convenience function to export FY summary report
    """
    exporter = FinanceDataExporter(request.user)
    return exporter.export_summary_report(expenses_queryset, fy_year)


# ============================================
# USAGE EXAMPLES
# ============================================

if __name__ == '__main__':
    print("Finance Data Exporter - Usage Examples\n")
    
    print("1. Export expenses with PII:")
    print("   exporter = FinanceDataExporter(user, include_pii=True)")
    print("   response = exporter.export_expenses_csv(expenses)")
    print()
    
    print("2. Export expenses without PII (redacted):")
    print("   exporter = FinanceDataExporter(user, include_pii=False)")
    print("   response = exporter.export_expenses_csv(expenses)")
    print()
    
    print("3. Export FY summary report:")
    print("   exporter = FinanceDataExporter(user)")
    print("   response = exporter.export_summary_report(expenses, fy_year=2024)")
    print()
    
    print("4. From Django view:")
    print("   return export_expenses(request, DailyExpense.objects.all(), fy_year=2024)")
