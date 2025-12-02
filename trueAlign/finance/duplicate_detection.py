"""
Finance Module - Duplicate Detection
Detect duplicate expenses and transactions using multiple strategies
"""

import logging
from typing import List, Dict, Tuple, Optional
from datetime import timedelta
from decimal import Decimal

logger = logging.getLogger('finance')

# Import fuzzy matching
try:
    from rapidfuzz import fuzz
    FUZZY_AVAILABLE = True
except ImportError:
    FUZZY_AVAILABLE = False


class DuplicateDetector:
    """
    Detect potential duplicate expenses/transactions
    Uses multiple strategies for high accuracy
    """
    
    def __init__(self, date_tolerance_days: int = 7, amount_tolerance_percent: float = 5.0):
        """
        Initialize detector
        
        Args:
            date_tolerance_days: Days within which to check for duplicates
            amount_tolerance_percent: Percentage difference allowed in amounts
        """
        self.date_tolerance = date_tolerance_days
        self.amount_tolerance = amount_tolerance_percent
    
    def find_duplicates(self, transactions: List[Dict]) -> List[Dict]:
        """
        Find all potential duplicates in transaction list
        Optimized with hash-based exact matching for 10-100x performance
        
        Args:
            transactions: List of transaction dicts with:
                - id, date, amount, description, vendor
                
        Returns:
            list: List of duplicate groups
        """
        # OPTIMIZATION 1: Hash-based exact duplicate detection (O(n) instead of O(n²))
        exact_duplicates = self._find_exact_duplicates_fast(transactions)
        
        # Track IDs already in exact duplicate groups
        processed_ids = set()
        for dup_group in exact_duplicates:
            processed_ids.add(dup_group['original']['id'])
            for dup in dup_group['duplicates']:
                processed_ids.add(dup['transaction']['id'])
        
        # OPTIMIZATION 2: For fuzzy matching, only check unprocessed transactions
        # and use early exit conditions
        fuzzy_duplicates = []
        processed = set()
        
        # Filter out already-processed transactions
        remaining_txns = [txn for txn in transactions if txn.get('id') not in processed_ids]
        
        # Sort by date to enable early exit
        remaining_txns.sort(key=lambda x: x.get('date'))
        
        for i, txn1 in enumerate(remaining_txns):
            txn_id = txn1.get('id')
            if txn_id in processed:
                continue
            
            # Find potential duplicates for this transaction
            matches = []
            
            for j in range(i + 1, len(remaining_txns)):
                txn2 = remaining_txns[j]
                txn2_id = txn2.get('id')
                
                if txn2_id in processed:
                    continue
                
                # EARLY EXIT: If dates are too far apart, break (since sorted by date)
                date_diff = abs((txn1.get('date') - txn2.get('date')).days) if txn1.get('date') and txn2.get('date') else 999
                if date_diff > self.date_tolerance:
                    break  # No point checking further
                
                # Check if duplicate (fuzzy matching)
                is_dup, confidence = self._is_duplicate_fuzzy(txn1, txn2)
                
                if is_dup:
                    matches.append({
                        'transaction': txn2,
                        'confidence': confidence,
                        'id': txn2_id,
                    })
            
            # If matches found, create duplicate group
            if matches:
                processed.add(txn_id)
                for match in matches:
                    processed.add(match['id'])
                
                fuzzy_duplicates.append({
                    'original': txn1,
                    'duplicates': matches,
                    'group_size': len(matches) + 1,
                })
        
        # Combine exact and fuzzy duplicates
        all_duplicates = exact_duplicates + fuzzy_duplicates
        
        # Sort by confidence
        for dup_group in all_duplicates:
            dup_group['duplicates'].sort(key=lambda x: x['confidence'], reverse=True)
        
        return all_duplicates
    
    def _find_exact_duplicates_fast(self, transactions: List[Dict]) -> List[Dict]:
        """
        Fast exact duplicate detection using hash-based approach
        O(n) complexity instead of O(n²)
        
        Args:
            transactions: List of transactions
            
        Returns:
            list: Exact duplicate groups
        """
        from collections import defaultdict
        
        # Create hash keys for exact matching
        by_hash = defaultdict(list)
        
        for txn in transactions:
            # Hash key: date + amount + normalized description
            date = txn.get('date')
            amount = txn.get('amount')
            description = txn.get('description', '').lower().strip()
            
            # Create tuple key
            key = (date, amount, description)
            by_hash[key].append(txn)
        
        # Find groups with >1 transaction
        duplicates = []
        for group in by_hash.values():
            if len(group) > 1:
                duplicates.append({
                    'original': group[0],
                    'duplicates': [
                        {'transaction': txn, 'confidence': 100.0, 'id': txn.get('id')}
                        for txn in group[1:]
                    ],
                    'group_size': len(group),
                })
        
        return duplicates
    
    def _is_duplicate_fuzzy(self, txn1: Dict, txn2: Dict) -> Tuple[bool, float]:
        """
        Check if two transactions are fuzzy duplicates (renamed from _is_duplicate)
        
        Returns:
            tuple: (is_duplicate, confidence_score)
        """
        # Strategy 1: Near match (date + amount similar + description similar)
        near_match_score = self._near_match(txn1, txn2)
        if near_match_score >= 80:
            return (True, near_match_score)
        
        # Strategy 2: Same vendor + same amount within tolerance
        vendor_amount_score = self._vendor_amount_match(txn1, txn2)
        if vendor_amount_score >= 75:
            return (True, vendor_amount_score)
        
        return (False, 0.0)
    
    def _is_duplicate(self, txn1: Dict, txn2: Dict) -> Tuple[bool, float]:
        """
        Check if two transactions are duplicates
        
        Returns:
            tuple: (is_duplicate, confidence_score)
        """
        # Strategy 1: Exact match (date + amount + description)
        if self._exact_match(txn1, txn2):
            return (True, 100.0)
        
        # Strategy 2: Near match (date + amount similar + description similar)
        near_match_score = self._near_match(txn1, txn2)
        if near_match_score >= 80:
            return (True, near_match_score)
        
        # Strategy 3: Same vendor + same amount within tolerance
        vendor_amount_score = self._vendor_amount_match(txn1, txn2)
        if vendor_amount_score >= 75:
            return (True, vendor_amount_score)
        
        return (False, 0.0)
    
    def _exact_match(self, txn1: Dict, txn2: Dict) -> bool:
        """Check for exact duplicate"""
        return (
            txn1.get('date') == txn2.get('date') and
            txn1.get('amount') == txn2.get('amount') and
            txn1.get('description', '').lower().strip() == txn2.get('description', '').lower().strip()
        )
    
    def _near_match(self, txn1: Dict, txn2: Dict) -> float:
        """
        Check for near match
        
        Returns:
            float: Confidence score (0-100)
        """
        # Check date proximity
        date1 = txn1.get('date')
        date2 = txn2.get('date')
        
        if not date1 or not date2:
            return 0.0
        
        date_diff = abs((date1 - date2).days)
        if date_diff > self.date_tolerance:
            return 0.0
        
        # Check amount proximity
        amount1 = txn1.get('amount', 0)
        amount2 = txn2.get('amount', 0)
        
        if amount1 == 0 or amount2 == 0:
            return 0.0
        
        amount_diff_percent = abs(float(amount1 - amount2)) / float(amount1) * 100
        
        if amount_diff_percent > self.amount_tolerance:
            return 0.0
        
        # Check description similarity
        desc1 = txn1.get('description', '')
        desc2 = txn2.get('description', '')
        
        if FUZZY_AVAILABLE and desc1 and desc2:
            desc_similarity = fuzz.token_set_ratio(desc1, desc2)
        else:
            # Fallback: simple check
            desc_similarity = 100 if desc1.lower() == desc2.lower() else 0
        
        # Calculate overall confidence
        # Weights: date (20%), amount (40%), description (40%)
        date_score = max(0, 100 - (date_diff / self.date_tolerance) * 100) * 0.2
        amount_score = max(0, 100 - (amount_diff_percent / self.amount_tolerance) * 100) * 0.4
        desc_score = desc_similarity * 0.4
        
        confidence = date_score + amount_score + desc_score
        
        return round(confidence, 2)
    
    def _vendor_amount_match(self, txn1: Dict, txn2: Dict) -> float:
        """
        Check vendor + amount match
        Useful for recurring expenses
        """
        vendor1 = txn1.get('vendor', '')
        vendor2 = txn2.get('vendor', '')
        
        if not vendor1 or not vendor2:
            return 0.0
        
        # Check vendor similarity
        if FUZZY_AVAILABLE:
            vendor_similarity = fuzz.ratio(vendor1, vendor2)
        else:
            vendor_similarity = 100 if vendor1.lower() == vendor2.lower() else 0
        
        if vendor_similarity < 80:
            return 0.0
        
        # Check amount match
        amount1 = txn1.get('amount', 0)
        amount2 = txn2.get('amount', 0)
        
        if amount1 == 0 or amount2 == 0:
            return 0.0
        
        amount_diff_percent = abs(float(amount1 - amount2)) / float(amount1) * 100
        
        if amount_diff_percent > self.amount_tolerance:
            return 0.0
        
        # Check date (within tolerance)
        date1 = txn1.get('date')
        date2 = txn2.get('date')
        
        if date1 and date2:
            date_diff = abs((date1 - date2).days)
            if date_diff > self.date_tolerance:
                return 0.0
            
            date_score = max(0, 100 - (date_diff / self.date_tolerance) * 100) * 0.3
        else:
            date_score = 0
        
        # Calculate confidence
        # Weights: vendor (50%), amount (30%), date (20%)
        vendor_score = vendor_similarity * 0.5
        amount_score = max(0, 100 - (amount_diff_percent / self.amount_tolerance) * 100) * 0.3
        
        confidence = vendor_score + amount_score + date_score
        
        return round(confidence, 2)
    
    def check_single_transaction(self, new_transaction: Dict, existing_transactions: List[Dict]) -> Optional[Dict]:
        """
        Check if a single new transaction is duplicate of existing ones
        
        Args:
            new_transaction: New transaction to check
            existing_transactions: List of existing transactions
            
        Returns:
            dict: Best match if duplicate found, None otherwise
        """
        best_match = None
        best_confidence = 0
        
        for existing_txn in existing_transactions:
            is_dup, confidence = self._is_duplicate(new_transaction, existing_txn)
            
            if is_dup and confidence > best_confidence:
                best_confidence = confidence
                best_match = {
                    'transaction': existing_txn,
                    'confidence': confidence,
                }
        
        return best_match if best_match and best_confidence >= 75 else None


class RecurringExpenseDetector:
    """
    Detect recurring expenses (monthly rent, subscriptions, etc.)
    """
    
    def __init__(self, min_occurrences: int = 3, amount_tolerance: float = 5.0):
        """
        Initialize detector
        
        Args:
            min_occurrences: Minimum occurrences to be considered recurring
            amount_tolerance: Percentage difference allowed
        """
        self.min_occurrences = min_occurrences
        self.amount_tolerance = amount_tolerance
    
    def find_recurring(self, transactions: List[Dict]) -> List[Dict]:
        """
        Find recurring expenses
        
        Args:
            transactions: List of transactions sorted by date
            
        Returns:
            list: Recurring expense patterns
        """
        # Group by vendor
        vendor_groups = {}
        
        for txn in transactions:
            vendor = txn.get('vendor', 'Unknown')
            if vendor not in vendor_groups:
                vendor_groups[vendor] = []
            vendor_groups[vendor].append(txn)
        
        recurring_patterns = []
        
        # Analyze each vendor's transactions
        for vendor, txns in vendor_groups.items():
            if len(txns) < self.min_occurrences:
                continue
            
            # Check if amounts are similar
            amounts = [float(t.get('amount', 0)) for t in txns]
            avg_amount = sum(amounts) / len(amounts)
            
            # Check variance
            variance = max(amounts) - min(amounts)
            variance_percent = (variance / avg_amount * 100) if avg_amount > 0 else 100
            
            if variance_percent <= self.amount_tolerance:
                # Potentially recurring
                # Check date intervals
                dates = [t.get('date') for t in txns if t.get('date')]
                dates.sort()
                
                if len(dates) >= 2:
                    intervals = [(dates[i+1] - dates[i]).days for i in range(len(dates)-1)]
                    avg_interval = sum(intervals) / len(intervals)
                    
                    # Check if intervals are consistent (monthly, quarterly, etc.)
                    interval_variance = max(intervals) - min(intervals)
                    
                    if interval_variance <= 7:  # Within a week
                        # Determine frequency
                        if 25 <= avg_interval <= 35:
                            frequency = 'monthly'
                        elif 85 <= avg_interval <= 95:
                            frequency = 'quarterly'
                        elif 175 <= avg_interval <= 190:
                            frequency = 'semi-annual'
                        elif 350 <= avg_interval <= 380:
                            frequency = 'annual'
                        else:
                            frequency = f'every {int(avg_interval)} days'
                        
                        recurring_patterns.append({
                            'vendor': vendor,
                            'frequency': frequency,
                            'avg_amount': round(Decimal(str(avg_amount)), 2),
                            'occurrences': len(txns),
                            'avg_interval_days': int(avg_interval),
                            'transactions': txns,
                        })
        
        # Sort by occurrences
        recurring_patterns.sort(key=lambda x: x['occurrences'], reverse=True)
        
        return recurring_patterns


# ============================================
# USAGE EXAMPLES
# ============================================

if __name__ == '__main__':
    from datetime import date
    
    # Example transactions
    transactions = [
        {'id': 1, 'date': date(2024, 12, 1), 'amount': Decimal('50000'), 'description': 'Office Rent December', 'vendor': 'Property Mgmt'},
        {'id': 2, 'date': date(2024, 12, 1), 'amount': Decimal('50000'), 'description': 'Office rent dec', 'vendor': 'Property Management'},  # Duplicate!
        {'id': 3, 'date': date(2024, 12, 5), 'amount': Decimal('15000'), 'description': 'Google Ads Campaign', 'vendor': 'Google'},
        {'id': 4, 'date': date(2024, 12, 6), 'amount': Decimal('15200'), 'description': 'Google Ads', 'vendor': 'Google'},  # Near duplicate
        {'id': 5, 'date': date(2024, 11, 1), 'amount': Decimal('50000'), 'description': 'Office Rent November', 'vendor': 'Property Mgmt'},
        {'id': 6, 'date': date(2024, 10, 1), 'amount': Decimal('50000'), 'description': 'Office Rent October', 'vendor': 'Property Mgmt'},
    ]
    
    # Find duplicates
    detector = DuplicateDetector()
    duplicates = detector.find_duplicates(transactions)
    
    print("Duplicate Groups Found:")
    for idx, dup_group in enumerate(duplicates, 1):
        print(f"\nGroup {idx}:")
        print(f"  Original: {dup_group['original']['description']}")
        for dup in dup_group['duplicates']:
            print(f"  Duplicate: {dup['transaction']['description']} (confidence: {dup['confidence']}%)")
    
    # Find recurring
    recurring_detector = RecurringExpenseDetector(min_occurrences=3)
    recurring = recurring_detector.find_recurring(transactions)
    
    print("\n\nRecurring Expenses Found:")
    for pattern in recurring:
        print(f"\nVendor: {pattern['vendor']}")
        print(f"  Frequency: {pattern['frequency']}")
        print(f"  Average Amount: ₹{pattern['avg_amount']}")
        print(f"  Occurrences: {pattern['occurrences']}")
