#!/usr/bin/env python
"""
Performance Testing Script (Module Level)
Tests performance without requiring full Django setup
"""

import sys
import time
from pathlib import Path
from decimal import Decimal
from datetime import date, timedelta
import random

# Add project to path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))


class PerformanceTimer:
    """Context manager for timing operations"""
    
    def __init__(self, name):
        self.name = name
        self.start_time = None
        self.duration = None
        
    def __enter__(self):
        self.start_time = time.time()
        return self
        
    def __exit__(self, *args):
        self.duration = time.time() - self.start_time
        print(f"\n{'='*70}")
        print(f"⏱  {self.name}")
        print(f"{'='*70}")
        print(f"Duration: {self.duration:.3f} seconds")
        print(f"{'='*70}\n")


def generate_sample_data(count=10000):
    """Generate sample expense data"""
    categories = ['rent', 'salary', 'utilities', 'software', 'marketing', 
                 'travel', 'food', 'supplies', 'consulting', 'legal']
    departments = ['Operations', 'Marketing', 'Technology', 'HR', 'Finance']
    
    descriptions = {
        'rent': ['Office rent payment', 'Monthly lease', 'Property rent'],
        'salary': ['Salary payment', 'Payroll processing', 'Monthly salary'],
        'utilities': ['Electricity bill', 'Internet charges', 'Water bill'],
        'software': ['AWS hosting', 'Office 365', 'Software license'],
        'marketing': ['Google Ads', 'Facebook campaign', 'LinkedIn ads'],
        'travel': ['Flight booking', 'Hotel stay', 'Cab fare'],
        'food': ['Team lunch', 'Client dinner', 'Office refreshments'],
        'supplies': ['Office stationery', 'Printer supplies', 'Furniture'],
        'consulting': ['Consultant fees', 'Advisory services'],
        'legal': ['Legal fees', 'Compliance charges'],
    }
    
    expenses = []
    start_date = date.today() - timedelta(days=365)
    
    print(f"\n📊 Generating {count:,} sample expenses...")
    
    for i in range(count):
        category = random.choice(categories)
        dept = random.choice(departments)
        desc_template = random.choice(descriptions[category])
        
        expense = {
            'id': i + 1,
            'expense_id': f'PERF{10000+i}',
            'department': dept,
            'date': start_date + timedelta(days=random.randint(0, 365)),
            'category': category if random.random() > 0.2 else '',  # 20% uncategorized
            'description': f"{desc_template} {random.randint(1, 100)}",
            'amount': Decimal(str(random.randint(1000, 100000))),
            'vendor': '',
        }
        expenses.append(expense)
        
        if (i + 1) % 1000 == 0:
            print(f"  Generated {i+1:,}/{count:,} expenses", end='\r')
    
    print(f"✓ Generated {count:,} expenses      ")
    return expenses


def test_auto_categorization(expenses, sample_size=1000):
    """Test auto-categorization performance"""
    print(f"\n🎯 Testing Auto-Categorization ({sample_size:,} expenses)")
    
    try:
        from trueAlign.finance.integration_service import quick_categorize
        
        # Get uncategorized expenses
        uncategorized = [e for e in expenses if not e['category']][:sample_size]
        
        categorized_count = 0
        
        with PerformanceTimer(f"Auto-Categorize {len(uncategorized):,} Expenses") as timer:
            for expense in uncategorized:
                try:
                    category = quick_categorize(expense['description'])
                    if category:
                        categorized_count += 1
                except Exception as e:
                    pass  # Skip errors
        
        # Calculate metrics
        rate = sample_size / timer.duration if timer.duration > 0 else 0
        success_rate = (categorized_count / len(uncategorized) * 100) if uncategorized else 0
        
        print(f"✓ Processed {rate:.1f} expenses/second")
        print(f"✓ Success rate: {success_rate:.1f}%")
        
        return {
            'sample_size': sample_size,
            'duration': timer.duration,
            'rate_per_second': rate,
            'categorized': categorized_count,
            'success_rate': success_rate,
        }
        
    except ImportError as e:
        print(f"✗ Could not import integration service: {e}")
        return None


def test_duplicate_detection(expenses, sample_size=10000):
    """Test duplicate detection performance"""
    print(f"\n🔍 Testing Duplicate Detection ({sample_size:,} transactions)")
    
    try:
        from trueAlign.finance.duplicate_detection import DuplicateDetector
        
        # Limit to sample size
        sample = expenses[:sample_size]
        
        detector = DuplicateDetector()
        
        with PerformanceTimer(f"Detect Duplicates in {len(sample):,} Records") as timer:
            duplicates = detector.find_duplicates(sample)
        
        # Calculate metrics
        rate = sample_size / timer.duration if timer.duration > 0 else 0
        
        print(f"✓ Processed {rate:.1f} transactions/second")
        print(f"✓ Found {len(duplicates)} duplicate groups")
        
        return {
            'sample_size': sample_size,
            'duration': timer.duration,
            'rate_per_second': rate,
            'duplicates_found': len(duplicates),
        }
        
    except ImportError as e:
        print(f"✗ Could not import duplicate detector: {e}")
        return None


def test_analytics_generation(expenses):
    """Test analytics generation performance"""
    print(f"\n📈 Testing Analytics Generation")
    
    try:
        from trueAlign.finance.analytics import ExpenseAnalyzer
        
        print(f"  Analyzing {len(expenses):,} expenses")
        
        with PerformanceTimer(f"Generate Analytics for {len(expenses):,} Records") as timer:
            analyzer = ExpenseAnalyzer(expenses)
            
            # Generate various analytics
            monthly = analyzer.monthly_summary()
            categories = analyzer.category_breakdown()
            anomalies = analyzer.detect_anomalies()
        
        print(f"✓ Generated in {timer.duration:.2f}s for {len(expenses):,} records")
        print(f"✓ Months analyzed: {len(monthly)}")
        print(f"✓ Categories: {len(categories)}")
        print(f"✓ Anomalies detected: {len(anomalies)}")
        
        return {
            'sample_size': len(expenses),
            'duration': timer.duration,
            'anomalies_found': len(anomalies),
        }
        
    except ImportError as e:
        print(f"✗ Could not import analytics: {e}")
        return None


def test_vendor_matching(sample_size=1000):
    """Test vendor matching performance"""
    print(f"\n🏢 Testing Vendor Matching ({sample_size:,} matches)")
    
    try:
        from trueAlign.finance.matchers import CommonMatchers
        
        matcher = CommonMatchers.indian_vendor_matcher()
        
        # Sample vendor names to match
        test_vendors = [
            'AMZN IND', 'GOOGLE ADS', 'MSFT', 'AWS', 'FLIPKRT',
            'ICICI BNK', 'HDFC BANK', 'AIRTEL', 'JIO', 'PAYTM'
        ] * (sample_size // 10)
        
        matches_found = 0
        
        with PerformanceTimer(f"Match {len(test_vendors):,} Vendor Names") as timer:
            for vendor in test_vendors:
                match = matcher.find_best_match(vendor)
                if match:
                    matches_found += 1
        
        rate = len(test_vendors) / timer.duration if timer.duration > 0 else 0
        
        print(f"✓ Processed {rate:.1f} matches/second")
        print(f"✓ Successful matches: {matches_found}/{len(test_vendors)}")
        
        return {
            'sample_size': len(test_vendors),
            'duration': timer.duration,
            'rate_per_second': rate,
            'matches_found': matches_found,
        }
        
    except ImportError as e:
        print(f"✗ Could not import matchers: {e}")
        return None


def print_summary(results):
    """Print performance summary"""
    print("\n" + "="*70)
    print("PERFORMANCE TEST SUMMARY")
    print("="*70)
    
    if results['auto_categorization']:
        r = results['auto_categorization']
        print(f"\n📊 Auto-Categorization:")
        print(f"  Rate: {r['rate_per_second']:.1f} expenses/second")
        print(f"  Success: {r['success_rate']:.1f}%")
        print(f"  Verdict: {'✓ GOOD' if r['rate_per_second'] > 50 else '⚠ NEEDS OPTIMIZATION'}")
    
    if results['duplicate_detection']:
        r = results['duplicate_detection']
        print(f"\n🔍 Duplicate Detection:")
        print(f"  Rate: {r['rate_per_second']:.1f} transactions/second")
        print(f"  Duplicates: {r['duplicates_found']} groups")
        print(f"  Verdict: {'✓ GOOD' if r['rate_per_second'] > 200 else '⚠ NEEDS OPTIMIZATION'}")
    
    if results['analytics']:
        r = results['analytics']
        print(f"\n📈 Analytics Generation:")
        print(f"  Duration: {r['duration']:.2f} seconds")
        print(f"  Records: {r['sample_size']:,}")
        print(f"  Verdict: {'✓ GOOD' if r['duration'] < 5 else '⚠ NEEDS OPTIMIZATION'}")
    
    if results['vendor_matching']:
        r = results['vendor_matching']
        print(f"\n🏢 Vendor Matching:")
        print(f"  Rate: {r['rate_per_second']:.1f} matches/second")
        print(f"  Success: {r['matches_found']}/{r['sample_size']}")
        print(f"  Verdict: {'✓ GOOD' if r['rate_per_second'] > 1000 else '⚠ NEEDS OPTIMIZATION'}")
    
    print("\n" + "="*70)
    print("\n💡 Recommendations:")
    print("  1. Apply database indexes: python manage.py migrate finance")
    print("  2. Implement caching for matchers")
    print("  3. Use batch processing where possible")
    print("  4. Monitor with Django Debug Toolbar in development")
    print("\n" + "="*70)


def main():
    """Main test execution"""
    print("\n" + "="*70)
    print("FINANCE MODULE PERFORMANCE TESTING (MODULE LEVEL)")
    print("="*70)
    
    results = {
        'auto_categorization': None,
        'duplicate_detection': None,
        'analytics': None,
        'vendor_matching': None,
    }
    
    try:
        # Generate test data
        print("\nGenerating test data...")
        expenses = generate_sample_data(10000)
        
        # Run tests
        results['auto_categorization'] = test_auto_categorization(expenses, 1000)
        results['duplicate_detection'] = test_duplicate_detection(expenses, 10000)
        results['analytics'] = test_analytics_generation(expenses)
        results['vendor_matching'] = test_vendor_matching(1000)
        
        # Print summary
        print_summary(results)
        
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
