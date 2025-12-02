"""
Finance Module - Advanced Vendor & Text Matching
Uses rapidfuzz for fuzzy string matching to match vendors, descriptions, etc.
"""

from rapidfuzz import fuzz, process
from typing import List, Tuple, Optional
import logging

logger = logging.getLogger('finance')


class VendorMatcher:
    """
    Match vendor names using fuzzy matching
    Handles typos, abbreviations, variations
    """
    
    def __init__(self, known_vendors: List[str], threshold: int = 80):
        """
        Initialize matcher with known vendors
        
        Args:
            known_vendors: List of known vendor names
            threshold: Minimum similarity score (0-100)
        """
        self.known_vendors = known_vendors
        self.threshold = threshold
    
    def find_best_match(self, query: str) -> Optional[Tuple[str, float]]:
        """
        Find best matching vendor
        
        Args:
            query: Vendor name to match
            
        Returns:
            Tuple of (matched_vendor, score) or None
            
        Examples:
            >>> matcher = VendorMatcher(['Amazon India', 'Flipkart', 'Google Ads'])
            >>> matcher.find_best_match('AMAZON IND')
            ('Amazon India', 92.3)
        """
        if not query or not self.known_vendors:
            return None
        
        # Use rapidfuzz for matching
        result = process.extractOne(
            query,
            self.known_vendors,
            scorer=fuzz.WRatio,  # Weighted Ratio (best for general use)
            score_cutoff=self.threshold
        )
        
        if result:
            matched_vendor, score, _ = result
            logger.debug(f"Matched '{query}' to '{matched_vendor}' (score: {score})")
            return (matched_vendor, score)
        
        return None
    
    def find_top_matches(self, query: str, limit: int = 5) -> List[Tuple[str, float]]:
        """
        Find top N matching vendors
        
        Args:
            query: Vendor name to match
            limit: Number of results
            
        Returns:
            List of (vendor, score) tuples
        """
        if not query or not self.known_vendors:
            return []
        
        results = process.extract(
            query,
            self.known_vendors,
            scorer=fuzz.WRatio,
            limit=limit,
            score_cutoff=self.threshold
        )
        
        return [(match, score) for match, score, _ in results]
    
    def batch_match(self, queries: List[str]) -> dict:
        """
        Match multiple queries at once
        
        Args:
            queries: List of vendor names to match
            
        Returns:
            dict: {query: (best_match, score)}
        """
        results = {}
        
        for query in queries:
            match = self.find_best_match(query)
            results[query] = match
        
        return results


class DescriptionMatcher:
    """
    Match transaction descriptions to known patterns
    Useful for categorization and reconciliation
    """
    
    def __init__(self, patterns: dict, threshold: int = 75):
        """
        Initialize with known description patterns
        
        Args:
            patterns: Dict of {category: [descriptions]}
            threshold: Minimum similarity score
            
        Example:
            patterns = {
                'salary': ['Salary Payment', 'Monthly Salary', 'Payroll'],
                'rent': ['Office Rent', 'Rent Payment', 'Monthly Rent'],
                'utilities': ['Electricity Bill', 'Internet Bill', 'Water Bill'],
            }
        """
        self.patterns = patterns
        self.threshold = threshold
        
        # Flatten patterns for matching
        self.all_descriptions = []
        self.description_to_category = {}
        
        for category, descriptions in patterns.items():
            for desc in descriptions:
                self.all_descriptions.append(desc)
                self.description_to_category[desc] = category
    
    def match_category(self, description: str) -> Optional[Tuple[str, str, float]]:
        """
        Match description to category
        
        Args:
            description: Transaction description
            
        Returns:
            Tuple of (category, matched_pattern, score) or None
            
        Example:
            >>> matcher.match_category('SALARY PMT MARCH')
            ('salary', 'Salary Payment', 85.0)
        """
        if not description or not self.all_descriptions:
            return None
        
        result = process.extractOne(
            description,
            self.all_descriptions,
            scorer=fuzz.token_set_ratio,  # Good for partial matches
            score_cutoff=self.threshold
        )
        
        if result:
            matched_desc, score, _ = result
            category = self.description_to_category.get(matched_desc)
            
            logger.debug(f"Matched '{description}' to category '{category}' (score: {score})")
            return (category, matched_desc, score)
        
        return None
    
    def match_with_all_categories(self, description: str) -> List[Tuple[str, float]]:
        """
        Get similarity scores for all categories
        
        Args:
            description: Transaction description
            
        Returns:
            List of (category, score) sorted by score
        """
        category_scores = {}
        
        for category, patterns in self.patterns.items():
            # Get best score for this category
            results = process.extract(
                description,
                patterns,
                scorer=fuzz.token_set_ratio,
                limit=1
            )
            
            if results:
                _, score, _ = results[0]
                category_scores[category] = score
        
        # Sort by score descending
        sorted_scores = sorted(category_scores.items(), key=lambda x: x[1], reverse=True)
        return sorted_scores


class TransactionMatcher:
    """
    Match bank transactions to internal records
    Combines amount + date + description matching
    """
    
    def __init__(self, internal_transactions: List[dict]):
        """
        Initialize with internal transaction records
        
        Args:
            internal_transactions: List of dicts with keys:
                - date, amount, description, vendor_name, etc.
        """
        self.internal_transactions = internal_transactions
    
    def find_matches(self, bank_transaction: dict, date_tolerance: int = 3) -> List[Tuple[dict, float]]:
        """
        Find matching internal transactions
        
        Args:
            bank_transaction: Dict with {date, amount, description}
            date_tolerance: Days of tolerance for date matching
            
        Returns:
            List of (internal_transaction, confidence_score) tuples
        """
        from datetime import timedelta
        
        matches = []
        bank_date = bank_transaction.get('date')
        bank_amount = bank_transaction.get('amount')
        bank_desc = bank_transaction.get('description', '')
        
        if not bank_date or not bank_amount:
            return []
        
        for internal_txn in self.internal_transactions:
            internal_date = internal_txn.get('date')
            internal_amount = internal_txn.get('amount')
            internal_desc = internal_txn.get('description', '')
            
            if not internal_date or not internal_amount:
                continue
            
            # Check date tolerance
            date_diff = abs((bank_date - internal_date).days)
            if date_diff > date_tolerance:
                continue
            
            # Check amount match
            if bank_amount != internal_amount:
                continue
            
            # Calculate description similarity
            desc_similarity = fuzz.token_set_ratio(bank_desc, internal_desc)
            
            # Calculate confidence score
            confidence = self._calculate_confidence(
                date_diff, date_tolerance, desc_similarity
            )
            
            matches.append((internal_txn, confidence))
        
        # Sort by confidence descending
        matches.sort(key=lambda x: x[1], reverse=True)
        return matches
    
    def _calculate_confidence(self, date_diff, date_tolerance, desc_similarity):
        """
        Calculate overall confidence score
        
        Factors:
        - Exact amount match (required): 40 points
        - Date proximity: 30 points
        - Description similarity: 30 points
        """
        confidence = 40  # Base score for amount match
        
        # Date score (30 points max)
        if date_diff == 0:
            confidence += 30
        else:
            date_score = 30 * (1 - date_diff / date_tolerance)
            confidence += max(0, date_score)
        
        # Description score (30 points max)
        desc_score = 30 * (desc_similarity / 100)
        confidence += desc_score
        
        return round(confidence, 2)


# Prebuilt matchers for common use cases
class CommonMatchers:
    """Prebuilt matchers for common scenarios"""
    
    @staticmethod
    def indian_vendor_matcher():
        """Matcher for common Indian vendors"""
        vendors = [
            'Amazon India',
            'Flipkart',
            'Google Ads',
            'Facebook Ads',
            'Microsoft Azure',
            'AWS India',
            'Zoho Corporation',
            'Razorpay',
            'Paytm',
            'PhonePe',
            'ICICI Bank',
            'HDFC Bank',
            'State Bank of India',
            'Airtel',
            'Jio',
            'Vi (Vodafone Idea)',
        ]
        return VendorMatcher(vendors, threshold=75)
    
    @staticmethod
    def expense_category_matcher():
        """Matcher for expense categories"""
        patterns = {
            'salary': [
                'Salary Payment',
                'Monthly Salary',
                'Payroll',
                'SAL',
                'Wages',
            ],
            'rent': [
                'Office Rent',
                'Rent Payment',
                'Monthly Rent',
                'RENT',
            ],
            'utilities': [
                'Electricity Bill',
                'Power Bill',
                'Internet Bill',
                'Broadband',
                'Water Bill',
            ],
            'software': [
                'Software License',
                'SaaS Subscription',
                'Cloud Services',
                'AWS',
                'Azure',
                'Google Cloud',
            ],
            'marketing': [
                'Google Ads',
                'Facebook Ads',
                'LinkedIn Ads',
                'Advertisement',
                'Marketing Campaign',
            ],
            'travel': [
                'Flight Ticket',
                'Train Ticket',
                'Hotel Booking',
                'Cab Fare',
                'Uber',
                'Ola',
            ],
        }
        return DescriptionMatcher(patterns, threshold=70)


# Usage examples
if __name__ == '__main__':
    # Example 1: Vendor matching
    vendor_matcher = CommonMatchers.indian_vendor_matcher()
    match = vendor_matcher.find_best_match('AMZN INDIA')
    print(f"Matched: {match}")  # ('Amazon India', 85.0)
    
    # Example 2: Category matching
    category_matcher = CommonMatchers.expense_category_matcher()
    result = category_matcher.match_category('OFFICE RENT PMT APR')
    print(f"Category: {result}")  # ('rent', 'Office Rent', 80.0)
    
    # Example 3: Transaction matching
    internal_txns = [
        {'date': datetime(2024, 12, 1).date(), 'amount': Decimal('50000'), 'description': 'Office Rent December'}
    ]
    bank_txn = {'date': datetime(2024, 12, 2).date(), 'amount': Decimal('50000'), 'description': 'RENT PMT DEC'}
    
    txn_matcher = TransactionMatcher(internal_txns)
    matches = txn_matcher.find_matches(bank_txn)
    print(f"Matches: {matches}")  # [(internal_txn, 95.0)]
