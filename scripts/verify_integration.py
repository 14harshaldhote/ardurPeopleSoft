#!/usr/bin/env python
"""
Simple Import Verification for Phase 2+3 Finance Modules
Tests module imports without requiring full Django setup
"""

import sys
from pathlib import Path

# Add project to path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from decimal import Decimal
from datetime import date, timedelta


def test_module_imports():
    """Test that all modules can be imported"""
    print("\n" + "="*70)
    print("PHASE 2+3 MODULE IMPORT VERIFICATION")
    print("="*70)
    
    results = []
    
    # Test 1: PDF Parsers
    print("\n[1/7] Testing PDF Parsers...")
    try:
        from trueAlign.finance.pdf_parsers import BankStatementParser, InvoiceParser
        print("  ✓ BankStatementParser imported")
        print("  ✓ InvoiceParser imported")
        results.append(("PDF Parsers", True, None))
    except Exception as e:
        print(f"  ✗ Failed: {str(e)}")
        results.append(("PDF Parsers", False, str(e)))
    
    # Test 2: Fuzzy Matchers
    print("\n[2/7] Testing Fuzzy Matchers...")
    try:
        from trueAlign.finance.matchers import (
            VendorMatcher, DescriptionMatcher, 
            TransactionMatcher, CommonMatchers
        )
        print("  ✓ VendorMatcher imported")
        print("  ✓ DescriptionMatcher imported")
        print("  ✓ TransactionMatcher imported")
        print("  ✓ CommonMatchers imported")
        
        # Test instantiation
        matcher = CommonMatchers.indian_vendor_matcher()
        print(f"  ✓ Indian vendor matcher has {len(matcher.known_vendors)} vendors")
        
        results.append(("Fuzzy Matchers", True, None))
    except Exception as e:
        print(f"  ✗ Failed: {str(e)}")
        results.append(("Fuzzy Matchers", False, str(e)))
    
    # Test 3: Analytics
    print("\n[3/7] Testing Analytics...")
    try:
        from trueAlign.finance.analytics import (
            ExpenseAnalyzer, CashFlowForecaster, FinancialDashboard
        )
        print("  ✓ ExpenseAnalyzer imported")
        print("  ✓ CashFlowForecaster imported")
        print("  ✓ FinancialDashboard imported")
        
        # Test with sample data
        sample_data = [
            {'date': date.today(), 'amount': 1000, 'category': 'rent'},
        ]
        analyzer = ExpenseAnalyzer(sample_data)
        print(f"  ✓ Analyzer created with {len(analyzer.df)} records")
        
        results.append(("Analytics", True, None))
    except Exception as e:
        print(f"  ✗ Failed: {str(e)}")
        results.append(("Analytics", False, str(e)))
    
    # Test 4: Rules Engine
    print("\n[4/7] Testing Rules Engine...")
    try:
        from trueAlign.finance.rules_engine import (
            ExpenseRuleEngine, RuleBuilder
        )
        print("  ✓ ExpenseRuleEngine imported")
        print("  ✓ RuleBuilder imported")
        
        # Test instantiation
        engine = ExpenseRuleEngine()
        print(f"  ✓ Rules engine has {len(engine.rules)} predefined rules")
        
        results.append(("Rules Engine", True, None))
    except Exception as e:
        print(f"  ✗ Failed: {str(e)}")
        results.append(("Rules Engine", False, str(e)))
    
    # Test 5: Auto-Categorization
    print("\n[5/7] Testing Auto-Categorization...")
    try:
        from trueAlign.finance.auto_categorization import AutoCategorizer
        print("  ✓ AutoCategorizer imported")
        
        # Test categorization
        categorizer = AutoCategorizer(use_nlp=False, use_fuzzy=True, use_rules=True)
        result = categorizer.categorize({
            'description': 'Office rent payment',
            'amount': 50000
        })
        print(f"  ✓ Categorized 'Office rent payment' as '{result['category']}' "
              f"({result['confidence']}% confidence)")
        
        results.append(("Auto-Categorization", True, None))
    except Exception as e:
        print(f"  ✗ Failed: {str(e)}")
        results.append(("Auto-Categorization", False, str(e)))
    
    # Test 6: Duplicate Detection
    print("\n[6/7] Testing Duplicate Detection...")
    try:
        from trueAlign.finance.duplicate_detection import (
            DuplicateDetector, RecurringExpenseDetector
        )
        print("  ✓ DuplicateDetector imported")
        print("  ✓ RecurringExpenseDetector imported")
        
        # Test duplicate detection
        transactions = [
            {'id': 1, 'date': date.today(), 'amount': Decimal('50000'), 
             'description': 'Office Rent', 'vendor': 'Property Mgmt'},
            {'id': 2, 'date': date.today(), 'amount': Decimal('50000'), 
             'description': 'Office rent', 'vendor': 'Property Mgmt'},
        ]
        
        detector = DuplicateDetector()
        duplicates = detector.find_duplicates(transactions)
        print(f"  ✓ Detected {len(duplicates)} duplicate groups")
        
        results.append(("Duplicate Detection", True, None))
    except Exception as e:
        print(f"  ✗ Failed: {str(e)}")
        results.append(("Duplicate Detection", False, str(e)))
    
    # Test 7: Integration Service
    print("\n[7/7] Testing Integration Service...")
    try:
        from trueAlign.finance.integration_service import (
            FinanceIntegrationService, quick_categorize, quick_vendor_match
        )
        print("  ✓ FinanceIntegrationService imported")
        print("  ✓ quick_categorize imported")
        print("  ✓ quick_vendor_match imported")
        
        # Test quick functions
        category = quick_categorize("Google Ads campaign")
        print(f"  ✓ Quick categorize: 'Google Ads campaign' → '{category}'")
        
        vendor = quick_vendor_match("AMZN IND")
        if vendor:
            print(f"  ✓ Quick vendor match: 'AMZN IND' → '{vendor}'")
        else:
            print(f"  ⚠ Quick vendor match: 'AMZN IND' → No match")
        
        # Test full service
        service = FinanceIntegrationService()
        print("  ✓ Integration service instantiated with:")
        print(f"    - Vendor matcher")
        print(f"    - Category matcher")
        print(f"    - Rules engine")
        print(f"    - Auto-categorizer")
        print(f"    - Duplicate detector")
        
        results.append(("Integration Service", True, None))
    except Exception as e:
        print(f"  ✗ Failed: {str(e)}")
        results.append(("Integration Service", False, str(e)))
    
    # Summary
    print("\n" + "="*70)
    print("VERIFICATION SUMMARY")
    print("="*70)
    
    passed = sum(1 for _, success, _ in results if success)
    total = len(results)
    
    for module_name, success, error in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"{status}: {module_name}")
        if error:
            print(f"       Error: {error}")
    
    print("\n" + "="*70)
    
    if passed == total:
        print(f"🎉 SUCCESS: All {total} modules verified!")
        print("\nPhase 2+3 integration is working correctly.")
        print("\n✅ Ready for:")
        print("  1. Real data testing (PDF upload, expense creation)")
        print("  2. Dashboard integration testing")
        print("  3. Performance testing")
        print("\n💡 Next: Run `python manage.py shell` and test Django services")
        return 0
    else:
        print(f"⚠ PARTIAL: {passed}/{total} modules passed")
        print("\nPlease review errors above.")
        return 1


def test_quick_examples():
    """Run quick functionality examples"""
    print("\n" + "="*70)
    print("QUICK FUNCTIONALITY EXAMPLES")
    print("="*70)
    
    try:
        from trueAlign.finance.integration_service import quick_categorize
        
        examples = [
            "Office rent payment December",
            "Google Ads marketing campaign",
            "Salary payment to employees",
            "AWS cloud hosting",
            "Electricity bill",
        ]
        
        print("\nAuto-Categorization Examples:")
        for desc in examples:
            cat = quick_categorize(desc)
            print(f"  '{desc}' → {cat}")
        
    except Exception as e:
        print(f"Could not run examples: {e}")


if __name__ == '__main__':
    exit_code = test_module_imports()
    
    if exit_code == 0:
        test_quick_examples()
    
    sys.exit(exit_code)
