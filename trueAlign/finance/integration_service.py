"""
Finance Module - Integration Service
Unified service that integrates all finance modules:
- PDF parsing
- Fuzzy matching
- Analytics
- Rules engine
- Auto-categorization  
- Duplicate detection
"""

import logging
from typing import Dict, List, Optional
from decimal import Decimal
from datetime import date

logger = logging.getLogger('finance')

# Import all our modules
try:
    from .pdf_parsers import BankStatementParser, InvoiceParser
    from .matchers import VendorMatcher, DescriptionMatcher, TransactionMatcher, CommonMatchers
    from .analytics import ExpenseAnalyzer, CashFlowForecaster
    from .rules_engine import ExpenseRuleEngine
    from .auto_categorization import AutoCategorizer
    from .duplicate_detection import DuplicateDetector, RecurringExpenseDetector
    MODULES_AVAILABLE = True
except ImportError as e:
    MODULES_AVAILABLE = False
    logger.error(f"Module import failed: {e}")


class FinanceIntegrationService:
    """
    Main integration service for all finance automation
    Single entry point for all smart finance features
    """
    
    def __init__(self):
        """Initialize all sub-modules"""
        if not MODULES_AVAILABLE:
            raise ImportError("Finance modules not available")
        
        # Initialize modules
        self.vendor_matcher = CommonMatchers.indian_vendor_matcher()
        self.category_matcher = CommonMatchers.expense_category_matcher()
        self.rules_engine = ExpenseRuleEngine()
        self.auto_categorizer = AutoCategorizer(use_nlp=True, use_fuzzy=True, use_rules=True)
        self.duplicate_detector = DuplicateDetector()
        self.recurring_detector = RecurringExpenseDetector()
        
        logger.info("Finance Integration Service initialized")
    
    # ============================================
    # PDF PROCESSING
    # ============================================
    
    def process_bank_statement_pdf(self, pdf_path: str) -> Dict:
        """
        Process bank statement PDF end-to-end
        
        Args:
            pdf_path: Path to PDF file
            
        Returns:
            dict: {transactions, duplicates, summary}
        """
        logger.info(f"Processing bank statement: {pdf_path}")
        
        try:
            # Parse PDF
            parser = BankStatementParser(pdf_path)
            transactions = parser.parse()
            
            logger.info(f"Extracted {len(transactions)} transactions from PDF")
            
            # Enrich transactions
            enriched = []
            for txn in transactions:
                enriched_txn = self.enrich_transaction(txn)
                enriched.append(enriched_txn)
            
            # Detect duplicates
            duplicates = self.duplicate_detector.find_duplicates(enriched)
            
            return {
                'transactions': enriched,
                'duplicates': duplicates,
                'total_transactions': len(enriched),
                'duplicate_groups': len(duplicates),
            }
            
        except Exception as e:
            logger.error(f"Error processing PDF: {e}", exc_info=True)
            raise
    
    def process_invoice_pdf(self, pdf_path: str) -> Dict:
        """Process invoice PDF"""
        logger.info(f"Processing invoice: {pdf_path}")
        
        parser = InvoiceParser(pdf_path)
        invoice_data = parser.parse()
        
        # Normalize vendor name
        if invoice_data.get('vendor_name'):
            vendor_match = self.vendor_matcher.find_best_match(invoice_data['vendor_name'])
            if vendor_match:
                invoice_data['vendor_normalized'] = vendor_match[0]
                invoice_data['vendor_confidence'] = vendor_match[1]
        
        return invoice_data
    
    # ============================================
    # TRANSACTION ENRICHMENT
    # ============================================
    
    def enrich_transaction(self, transaction: Dict) -> Dict:
        """
        Enrich transaction with auto-categorization, vendor matching, etc.
        
        Args:
            transaction: Raw transaction dict
            
        Returns:
            dict: Enriched transaction
        """
        enriched = transaction.copy()
        
        # Normalize vendor name
        vendor_description = transaction.get('vendor') or transaction.get('description', '')
        if vendor_description:
            vendor_match = self.vendor_matcher.find_best_match(vendor_description)
            if vendor_match:
                enriched['vendor_normalized'] = vendor_match[0]
                enriched['vendor_confidence'] = vendor_match[1]
        
        # Auto-categorize
        categorization = self.auto_categorizer.categorize(transaction)
        enriched['category'] = categorization['category']
        enriched['category_confidence'] = categorization['confidence']
        enriched['category_method'] = categorization['method']
        
        # Apply business rules
        rules_result = self.rules_engine.process_expense(enriched)
        
        # Merge rules results
        enriched.update({
            'auto_status': rules_result.get('auto_status'),
            'auto_approved': rules_result.get('auto_approved', False),
            'flagged': rules_result.get('flagged', False),
            'flag_reason': rules_result.get('flag_reason'),
            'priority': rules_result.get('priority', 'normal'),
            'rules_applied': rules_result.get('rules_applied', []),
        })
        
        logger.debug(f"Enriched transaction: {enriched.get('description')} -> {enriched.get('category')}")
        
        return enriched
    
    # ============================================
    # EXPENSE PROCESSING
    # ============================================
    
    def process_new_expense(self, expense: Dict) -> Dict:
        """
        Process new expense end-to-end
        
        Args:
            expense: Expense data dict
            
        Returns:
            dict: Processed expense with recommendations
        """
        logger.info(f"Processing expense: {expense.get('description')}")
        
        # Enrich
        enriched = self.enrich_transaction(expense)
        
        # Check for duplicates (requires existing expenses)
        # This would need to query database in real implementation
        # enriched['duplicate_check'] = {...}
        
        return enriched
    
    def batch_process_expenses(self, expenses: List[Dict]) -> Dict:
        """
        Process multiple expenses in batch
        
        Args:
            expenses: List of expense dicts
            
        Returns:
            dict: Processing results
        """
        logger.info(f"Batch processing {len(expenses)} expenses")
        
        # Enrich all
        enriched = [self.enrich_transaction(exp) for exp in expenses]
        
        # Detect duplicates
        duplicates = self.duplicate_detector.find_duplicates(enriched)
        
        # Detect recurring
        recurring = self.recurring_detector.find_recurring(enriched)
        
        # Categorization summary
        categories = {}
        for exp in enriched:
            cat = exp.get('category', 'uncategorized')
            categories[cat] = categories.get(cat, 0) + 1
        
        return {
            'processed_expenses': enriched,
            'duplicates': duplicates,
            'recurring_patterns': recurring,
            'category_summary': categories,
            'total_processed': len(enriched),
        }
    
    # ============================================
    # RECONCILIATION
    # ============================================
    
    def match_bank_to_internal(self, bank_transactions: List[Dict], internal_records: List[Dict]) -> Dict:
        """
        Match bank transactions to internal expense records
        
        Args:
            bank_transactions: Bank statement transactions
            internal_records: Internal expense/payment records
            
        Returns:
            dict: Matching results
        """
        logger.info(f"Matching {len(bank_transactions)} bank txns to {len(internal_records)} internal records")
        
        matcher = TransactionMatcher(internal_records)
        
        matches = []
        unmatched_bank = []
        
        for bank_txn in bank_transactions:
            txn_matches = matcher.find_matches(bank_txn, date_tolerance=3)
            
            if txn_matches:
                matches.append({
                    'bank_transaction': bank_txn,
                    'internal_matches': txn_matches,
                    'best_match': txn_matches[0] if txn_matches else None,
                })
            else:
                unmatched_bank.append(bank_txn)
        
        # Find unmatched internal records
        matched_internal_ids = set()
        for match_info in matches:
            if match_info['best_match']:
                matched_internal_ids.add(id(match_info['best_match'][0]))
        
        unmatched_internal = [
            rec for rec in internal_records
            if id(rec) not in matched_internal_ids
        ]
        
        return {
            'matches': matches,
            'unmatched_bank': unmatched_bank,
            'unmatched_internal': unmatched_internal,
            'match_rate': len(matches) / len(bank_transactions) * 100 if bank_transactions else 0,
        }
    
    # ============================================
    # ANALYTICS
    # ============================================
    
    def generate_expense_analytics(self, expenses: List[Dict]) -> Dict:
        """
        Generate comprehensive expense analytics
        
        Args:
            expenses: List of expense dicts
            
        Returns:
            dict: Analytics results
        """
        logger.info(f"Generating analytics for {len(expenses)} expenses")
        
        analyzer = ExpenseAnalyzer(expenses)
        
        return {
            'monthly_summary': analyzer.monthly_summary().to_dict() if not analyzer.df.empty else {},
            'category_breakdown': analyzer.category_breakdown('this_year').to_dict() if not analyzer.df.empty else {},
            'department_breakdown': analyzer.department_breakdown('this_month').to_dict() if not analyzer.df.empty else {},
            'anomalies': analyzer.detect_anomalies(threshold=2.0).to_dict(orient='records') if not analyzer.df.empty else [],
            'trends': analyzer.trend_analysis(),
            'charts': {
                'monthly_chart_html': analyzer.create_monthly_chart(),
                'category_pie_html': analyzer.create_category_pie_chart('this_month'),
            }
        }
    
    def forecast_cash_flow(self, historical_data: List[Dict], method: str = 'moving_average') -> Dict:
        """Generate cash flow forecast"""
        logger.info("Generating cash flow forecast")
        
        forecaster = CashFlowForecaster(historical_data)
        return forecaster.forecast_next_month(method=method)


# ============================================
# CONVENIENCE FUNCTIONS
# ============================================

def quick_categorize(description: str, amount: float = 0) -> str:
    """
    Quick categorization for a single expense
    
    Args:
        description: Expense description
        amount: Amount (optional)
        
    Returns:
        str: Category name
    """
    service = FinanceIntegrationService()
    result = service.auto_categorizer.categorize({
        'description': description,
        'amount': amount,
    })
    return result['category']


def quick_vendor_match(vendor_text: str) -> Optional[str]:
    """
    Quick vendor normalization
    
    Args:
        vendor_text: Vendor name/description
        
    Returns:
        str: Normalized vendor name or None
    """
    service = FinanceIntegrationService()
    match = service.vendor_matcher.find_best_match(vendor_text)
    return match[0] if match else None


# ============================================
# USAGE EXAMPLES
# ============================================

if __name__ == '__main__':
    # Example: Process new expense
    service = FinanceIntegrationService()
    
    expense = {
        'description': 'Office rent payment December',
        'amount': Decimal('50000'),
        'date': date.today(),
        'department': 'Operations',
    }
    
    processed = service.process_new_expense(expense)
    
    print("Processed Expense:")
    print(f"  Category: {processed['category']} (confidence: {processed['category_confidence']}%)")
    print(f"  Auto-approved: {processed['auto_approved']}")
    print(f"  Priority: {processed['priority']}")
    print(f"  Rules applied: {processed['rules_applied']}")
    
    # Example: Quick functions
    category = quick_categorize("Google Ads campaign")
    print(f"\nQuick categorize 'Google Ads campaign': {category}")
    
    vendor = quick_vendor_match("AMZN INDIA")
    print(f"Quick vendor match 'AMZN INDIA': {vendor}")
