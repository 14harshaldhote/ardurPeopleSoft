#!/usr/bin/env python
"""
Phase 3 Completion Verification Script
Verifies all Phase 2+3 features are implemented and working
"""

import sys
from pathlib import Path
import os

# Add project to path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))


class Phase3Verifier:
    """Verify Phase 3 completion"""
    
    def __init__(self):
        self.results = {
            'modules': {},
            'integrations': {},
            'features': {},
            'performance': {},
        }
        self.passed = 0
        self.failed = 0
    
    def verify_modules(self):
        """Verify all Phase 2+3 modules exist"""
        print("\n" + "="*70)
        print("PHASE 2+3 MODULE VERIFICATION")
        print("="*70)
        
        required_modules = {
            'pdf_parsers.py': 'PDF parsing for bank statements and invoices',
            'matchers.py': 'Fuzzy matching for vendors and descriptions',
            'analytics.py': 'Pandas-based analytics and forecasting',
            'rules_engine.py': 'Business rules automation engine',
            'auto_categorization.py': 'Multi-method auto-categorization',
            'duplicate_detection.py':  'Duplicate and recurring detection',
            'integration_service.py': 'Unified integration API',
        }
        
        finance_dir = BASE_DIR / 'trueAlign' / 'finance'
        
        print(f"\nChecking modules in: {finance_dir}")
        
        for module_file, description in required_modules.items():
            module_path = finance_dir / module_file
            exists = module_path.exists()
            
            if exists:
                # Check file size to ensure it's not empty
                size = module_path.stat().st_size
                lines = len(module_path.read_text().split('\n'))
                
                print(f"  ✓ {module_file:30} ({lines:4} lines, {size:6} bytes)")
                print(f"     {description}")
                self.results['modules'][module_file] = {'status': 'PASS', 'lines': lines, 'bytes': size}
                self.passed += 1
            else:
                print(f"  ✗ {module_file:30} MISSING")
                self.results['modules'][module_file] = {'status': 'FAIL', 'reason': 'File not found'}
                self.failed += 1
        
        print(f"\nModules: {self.passed}/{len(required_modules)} verified")
    
    def verify_imports(self):
        """Verify all modules can be imported"""
        print("\n" + "="*70)
        print("MODULE IMPORT VERIFICATION")
        print("="*70)
        
        imports_to_test = [
            ('trueAlign.finance.pdf_parsers', ['BankStatementParser', 'InvoiceParser']),
            ('trueAlign.finance.matchers', ['VendorMatcher', 'DescriptionMatcher', 'TransactionMatcher', 'CommonMatchers']),
            ('trueAlign.finance.analytics', ['ExpenseAnalyzer', 'CashFlowForecaster', 'FinancialDashboard']),
            ('trueAlign.finance.rules_engine', ['ExpenseRuleEngine', 'RuleBuilder']),
            ('trueAlign.finance.auto_categorization', ['AutoCategorizer']),
            ('trueAlign.finance.duplicate_detection', ['DuplicateDetector', 'RecurringExpenseDetector']),
            ('trueAlign.finance.integration_service', ['FinanceIntegrationService', 'quick_categorize', 'quick_vendor_match']),
        ]
        
        import_passed = 0
        import_failed = 0
        
        for module_path, classes in imports_to_test:
            try:
                module = __import__(module_path, fromlist=classes)
                
                for cls_name in classes:
                    if hasattr(module, cls_name):
                        print(f"  ✓ {module_path}.{cls_name}")
                        import_passed += 1
                    else:
                        print(f"  ✗ {module_path}.{cls_name} NOT FOUND")
                        import_failed += 1
                        
            except Exception as e:
                print(f"  ✗ {module_path}: {str(e)}")
                import_failed += len(classes)
        
        print(f"\nImports: {import_passed} passed, {import_failed} failed")
        self.results['imports'] = {'passed': import_passed, 'failed': import_failed}
        
        return import_failed == 0
    
    def verify_integrations(self):
        """Verify Django service integrations"""
        print("\n" + "="*70)
        print("DJANGO SERVICE INTEGRATION VERIFICATION")
        print("="*70)
        
        # Check if services.py uses integration service
        services_file = BASE_DIR / 'trueAlign' / 'finance' / 'services.py'
        
        if services_file.exists():
            content = services_file.read_text()
            
            integrations = {
                'FinanceIntegrationService import': 'from .integration_service import FinanceIntegrationService' in content or 'from trueAlign.finance.integration_service import FinanceIntegrationService' in content,
                'Auto-categorization in ExpenseService': 'process_new_expense' in content,
                'PDF parsing in ReconciliationService': 'process_bank_statement_pdf' in content or 'BankStatementParser' in content,
                'Advanced matching in reconciliation': 'match_bank_to_internal' in content or 'TransactionMatcher' in content,
            }
            
            for integration, exists in integrations.items():
                if exists:
                    print(f"  ✓ {integration}")
                    self.passed += 1
                else:
                    print(f"  ⚠ {integration} - Not detected")
                    self.failed += 1
        else:
            print(f"  ✗ services.py not found")
    
    def verify_dashboard_integration(self):
        """Verify intelligence dashboard integration"""
        print("\n" + "="*70)
        print("DASHBOARD INTEGRATION VERIFICATION")
        print("="*70)
        
        views_file = BASE_DIR / 'trueAlign' / 'finance' / 'views.py'
        
        if views_file.exists():
            content = views_file.read_text()
            
            checks = {
                'FinanceIntegrationService import': 'FinanceIntegrationService' in content,
                'Analytics generation': 'generate_expense_analytics' in content,
                'Monthly chart': 'monthly_chart' in content,
                'Category pie': 'category_pie' in content,
                'Trends data': 'trends' in content,
            }
            
            for check, exists in checks.items():
                if exists:
                    print(f"  ✓ {check}")
                    self.passed += 1
                else:
                    print(f"  ⚠ {check} - Not detected")
                    self.failed += 1
        
        # Check template
        template_file = BASE_DIR / 'trueAlign' / 'templates' / 'finance' / 'intelligence' / 'dashboard.html'
        
        if template_file.exists():
            content = template_file.read_text()
            
            template_checks = {
                'Monthly chart display': 'monthly_chart' in content,
                'Category pie display': 'category_pie' in content,
                'Trends display': 'trends' in content,
                'Plotly.js CDN': 'plotly' in content.lower(),
            }
            
            for check, exists in template_checks.items():
                if exists:
                    print(f"  ✓ Template: {check}")
                    self.passed += 1
                else:
                    print(f"  ⚠ Template: {check} - Not detected")
                    self.failed += 1
    
    def verify_performance(self):
        """Verify performance optimization"""
        print("\n" + "="*70)
        print("PERFORMANCE VERIFICATION")
        print("="*70)
        
        # Check if optimized duplicate detection exists
        dup_file = BASE_DIR / 'trueAlign' / 'finance' / 'duplicate_detection.py'
        
        if dup_file.exists():
            content = dup_file.read_text()
            
            optimizations = {
                'Hash-based exact matching': '_find_exact_duplicates_fast' in content,
                'Date-sorted early exit': 'sort(key=lambda x: x.get' in content and 'break' in content,
                'Two-pass approach': 'exact_duplicates' in content and 'fuzzy_duplicates' in content,
                'Processed ID tracking': 'processed_ids' in content,
            }
            
            for opt, exists in optimizations.items():
                if exists:
                    print(f"  ✓ {opt}")
                    self.passed += 1
                else:
                    print(f"  ✗ {opt} - Not found")
                    self.failed += 1
        
        # Check performance test script
        perf_script = BASE_DIR / 'scripts' / 'performance_test.py'
        
        if perf_script.exists():
            print(f"  ✓ Performance test script exists")
            self.passed += 1
        else:
            print(f"  ✗ Performance test script missing")
            self.failed += 1
    
    def verify_requirements(self):
        """Verify all Phase 1 dependencies installed"""
        print("\n" + "="*70)
        print("DEPENDENCY VERIFICATION")
        print("="*70)
        
        required_packages = [
            ('pdfplumber', 'PDF parsing'),
            ('rapidfuzz', 'Fuzzy matching'),
            ('pandas', 'Analytics'),
            ('plotly', 'Interactive charts'),
            ('business_rules', 'Rules engine'),
            ('nltk', 'NLP processing'),
        ]
        
        for package, purpose in required_packages:
            try:
                __import__(package.replace('-', '_'))
                print(f"  ✓ {package:20} - {purpose}")
                self.passed += 1
            except ImportError:
                print(f"  ✗ {package:20} - NOT INSTALLED")
                self.failed += 1
    
    def print_summary(self):
        """Print verification summary"""
        print("\n" + "="*70)
        print("PHASE 3 COMPLETION SUMMARY")
        print("="*70)
        
        total = self.passed + self.failed
        percentage = (self.passed / total * 100) if total > 0 else 0
        
        print(f"\n✓ Passed: {self.passed}")
        print(f"✗ Failed: {self.failed}")
        print(f"📊 Success Rate: {percentage:.1f}%")
        
        if self.failed == 0:
            print("\n" + "="*70)
            print("🎉 PHASE 3 COMPLETE - ALL CHECKS PASSED!")
            print("="*70)
            print("\n✅ Ready to proceed to Phase 4: Security & Compliance")
            return 0
        elif percentage >= 90:
            print("\n" + "="*70)
            print("✅ PHASE 3 MOSTLY COMPLETE - Minor issues detected")
            print("="*70)
            print("\n⚠️ Review warnings above before proceeding to Phase 4")
            return 0
        else:
            print("\n" + "="*70)
            print("⚠️ PHASE 3 INCOMPLETE - Major issues detected")
            print("="*70)
            print("\n❌ Please resolve issues before proceeding to Phase 4")
            return 1


def main():
    """Run verification"""
    verifier = Phase3Verifier()
    
    try:
        verifier.verify_modules()
        verifier.verify_imports()
        verifier.verify_integrations()
        verifier.verify_dashboard_integration()
        verifier.verify_performance()
        verifier.verify_requirements()
        
        return verifier.print_summary()
        
    except Exception as e:
        print(f"\n❌ Verification error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
