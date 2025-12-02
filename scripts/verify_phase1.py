#!/usr/bin/env python
"""
Finance Module - Phase 1 Verification Script
Verify that all Phase 1 setup is complete before proceeding
"""

import sys
import os
import django

# Setup Django environment
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from django.conf import settings
from django.core.cache import cache
import importlib.util

def check_color(passed):
    """Return colored status"""
    return "✅ PASS" if passed else "❌ FAIL"

def main():
    print("=" * 60)
    print("Finance Module - Phase 1 Verification")
    print("=" * 60)
    print()
    
    results = []
    
    # 1. Check django-money in INSTALLED_APPS
    print("1. Checking django-money installation...")
    djmoney_installed = 'djmoney' in settings.INSTALLED_APPS
    results.append(djmoney_installed)
    print(f"   {check_color(djmoney_installed)} django-money in INSTALLED_APPS")
    
    # 2. Check django_iban
    print("\n2. Checking django-iban installation...")
    iban_installed = 'django_iban' in settings.INSTALLED_APPS
    results.append(iban_installed)
    print(f"   {check_color(iban_installed)} django_iban in INSTALLED_APPS")
    
    # 3. Check Finance config
    print("\n3. Checking Finance configuration...")
    has_config = hasattr(settings, 'FINANCE_CONFIG')
    results.append(has_config)
    print(f"   {check_color(has_config)} FINANCE_CONFIG exists")
    
    if has_config:
        print(f"   - Default Currency: {settings.FINANCE_CONFIG.get('DEFAULT_CURRENCY')}")
        print(f"   - Multi-Currency: {settings.FINANCE_CONFIG.get('ENABLE_MULTI_CURRENCY')}")
        print(f"   - NLP Analysis: {settings.FINANCE_CONFIG.get('ENABLE_NLP_ANALYSIS')}")
    
    # 4. Check Django-Money settings
    print("\n4. Checking Django-Money settings...")
    has_currencies = hasattr(settings, 'CURRENCIES')
    has_default_currency = hasattr(settings, 'DEFAULT_CURRENCY')
    results.append(has_currencies and has_default_currency)
    print(f"   {check_color(has_currencies)} CURRENCIES defined")
    print(f"   {check_color(has_default_currency)} DEFAULT_CURRENCY defined")
    
    if has_currencies:
        print(f"   - Supported: {list(settings.CURRENCIES)}")
    
    # 5. Check cache configuration
    print("\n5. Checking cache configuration...")
    cache_backend = settings.CACHES['default']['BACKEND']
    is_cached = cache_backend != 'django.core.cache.backends.dummy.DummyCache'
    results.append(is_cached)
    print(f"   {check_color(is_cached)} Cache backend: {cache_backend}")
    
    # Test cache
    try:
        cache.set('test_key', 'test_value', 10)
        cached_value = cache.get('test_key')
        cache_works = cached_value == 'test_value'
        results.append(cache_works)
        print(f"   {check_color(cache_works)} Cache read/write test")
    except Exception as e:
        results.append(False)
        print(f"   ❌ FAIL Cache test: {e}")
    
    # 6. Check logging configuration
    print("\n6. Checking finance logging...")
    has_finance_logger = 'finance' in settings.LOGGING.get('loggers', {})
    has_trueAlign_finance = 'trueAlign.finance' in settings.LOGGING.get('loggers', {})
    results.append(has_finance_logger and has_trueAlign_finance)
    print(f"   {check_color(has_finance_logger)} 'finance' logger configured")
    print(f"   {check_color(has_trueAlign_finance)} 'trueAlign.finance' logger configured")
    
    # 7. Check important libraries can be imported
    print("\n7. Checking library imports...")
    
    libs_to_check = [
        ('djmoney', 'django-money'),
        ('babel', 'Babel'),
        ('arrow', 'arrow'),
        ('stdnum', 'python-stdnum'),
        ('pdfplumber', 'pdfplumber'),
        ('pandas', 'pandas'),
    ]
    
    for module_name, lib_name in libs_to_check:
        try:
            spec = importlib.util.find_spec(module_name)
            imported = spec is not None
            results.append(imported)
            print(f"   {check_color(imported)} {lib_name}")
        except Exception as e:
            results.append(False)
            print(f"   ❌ FAIL {lib_name}: {e}")
    
    # 8. Check finance module files exist
    print("\n8. Checking finance module files...")
    
    base_dir = settings.BASE_DIR
    files_to_check = [
        'trueAlign/finance/validators.py',
        'trueAlign/finance/currency_converter.py',
        'trueAlign/finance/formatters.py',
        'requirements/finance-production.txt',
        'requirements/finance-dev.txt',
    ]
    
    for file_path in files_to_check:
        full_path = os.path.join(base_dir, file_path)
        exists = os.path.exists(full_path)
        results.append(exists)
        print(f"   {check_color(exists)} {file_path}")
    
    # 9. Check logs directory
    print("\n9. Checking logs directory...")
    logs_dir = os.path.join(base_dir, 'logs')
    logs_exist = os.path.exists(logs_dir)
    results.append(logs_exist)
    print(f"   {check_color(logs_exist)} logs/ directory exists")
    
    # Summary
    print("\n" + "=" * 60)
    total = len(results)
    passed = sum(results)
    failed = total - passed
    
    print(f"Total Checks: {total}")
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    
    if failed == 0:
        print("\n🎉 All checks passed! Ready for Phase 1 library installation.")
        print("\nNext steps:")
        print("1. Run: ./scripts/install_phase1.sh")
        print("2. If using cPanel, run: python manage.py createcachetable finance_cache")
        print("3. Start model migration to MoneyField")
        return 0
    else:
        print("\n⚠️  Some checks failed. Please review configuration.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
