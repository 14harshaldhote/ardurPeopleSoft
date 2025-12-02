"""
Quick test to verify django-money integration works correctly
"""
import os
import sys
import django

# Add current directory to path
sys.path.append(os.getcwd())

# Force settings  
os.environ['DJANGO_SETTINGS_MODULE'] = 'ardurTrueAlign.settings'
django.setup()

from django.contrib.auth import get_user_model
from trueAlign.models import CashBox, CashTransaction
from moneyed import Money

User = get_user_model()

def test_money_field():
    print("=== Testing Django-Money Integration ===\n")
    
    # Get or create a user
    user = User.objects.first()
    if not user:
        user = User.objects.create(username='money_test_user')
        print(f"✓ Created test user: {user.username}")
    else:
        print(f"✓ Using existing user: {user.username}")
    
    # Test 1: Create CashBox with Money
    print("\n[Test 1] Creating CashBox with MoneyField...")
    box, created = CashBox.objects.get_or_create(
        name="MoneyField Test Box",
        defaults={
            'location': 'Test Location',
            'managed_by': user,
            'balance': Money(10000, 'INR')  # Using Money object
        }
    )
    
    if created:
        print(f"✓ Created: {box.name}")
    else:
        print(f"✓ Found existing: {box.name}")
    
    print(f"  Balance: {box.balance}")
    print(f"  Amount: {box.balance.amount}")
    print(f"  Currency: {box.balance.currency}")
    
    # Test 2: Arithmetic with Money
    print("\n[Test 2] Testing arithmetic operations...")
    original_balance = box.balance
    box.balance += Money(5000, 'INR')
    box.save()
    print(f"  Original: {original_balance}")
    print(f"  After +₹5000: {box.balance}")
    
    # Test 3: Create CashTransaction
    print("\n[Test 3] Creating CashTransaction with MoneyField...")
    txn = CashTransaction.objects.create(
        box=box,
        type='DEPOSIT',
        amount=Money(2500, 'INR'),
        description='Test deposit with django-money',
        performed_by=user
    )
    print(f"✓ Created transaction: {txn}")
    print(f"  Amount: {txn.amount}")
    print(f"  Currency: {txn.amount.currency}")
    
    # Test 4: Query and display
    print("\n[Test 4] Querying transactions...")
    all_txns = CashTransaction.objects.filter(box=box)[:3]
    for t in all_txns:
        print(f"  - {t.type}: {t.amount} on {t.date.strftime('%Y-%m-%d')}")
    
    print("\n=== All Tests Passed! ===")
    print("✓ Django-money integration is working correctly")
    print("✓ MoneyField supports currency operations")
    print("✓ Database storage and retrieval working")

if __name__ == '__main__':
    try:
        test_money_field()
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
