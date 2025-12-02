"""
Finance Module - Auto-Categorization System
Combines fuzzy matching, NLP, and rules for intelligent categorization
"""

import logging
from typing import Dict, Optional, List
from decimal import Decimal

logger = logging.getLogger('finance')

# Import our modules
try:
    from .matchers import DescriptionMatcher, CommonMatchers
    from .rules_engine import ExpenseRuleEngine, FinanceRules
    MATCHERS_AVAILABLE = True
except ImportError:
    MATCHERS_AVAILABLE = False
    logger.warning("Matchers or rules not available")

# Import NLTK if available (Phase 3)
try:
    import nltk
    from nltk.tokenize import word_tokenize
    from nltk.corpus import stopwords
    from nltk.stem import PorterStemmer
    NLTK_AVAILABLE = True
except ImportError:
    NLTK_AVAILABLE = False
    logger.warning("NLTK not available")


class AutoCategorizer:
    """
    Intelligent auto-categorization system
    Combines multiple approaches for best accuracy
    """
    
    # Category keywords (expanded)
    CATEGORY_KEYWORDS = {
        'salary': ['salary', 'payroll', 'wages', 'compensation', 'sal', 'emp'],
        'rent': ['rent', 'lease', 'property', 'premises', 'office space'],
        'utilities': ['electricity', 'power', 'internet', 'broadband', 'water', 'gas', 'bill'],
        'software': ['license', 'saas', 'subscription', 'software', 'cloud', 'aws', 'azure', 'google cloud'],
        'hardware': ['laptop', 'computer', 'server', 'equipment', 'device', 'hardware'],
        'marketing': ['ads', 'advertisement', 'marketing', 'campaign', 'seo', 'google ads', 'facebook ads'],
        'travel': ['flight', 'hotel', 'train', 'cab', 'uber', 'ola', 'travel', 'airfare'],
        'food': ['lunch', 'dinner', 'catering', 'food', 'restaurant', 'meal'],
        'supplies': ['stationery', 'supplies', 'office supplies', 'printing', 'paper'],
        'consulting': ['consulting', 'consultant', 'professional services', 'advisory'],
        'legal': ['legal', 'attorney', 'lawyer', 'compliance', 'audit'],
        'training': ['training', 'course', 'workshop', 'seminar', 'certification'],
    }
    
    def __init__(self, use_nlp=True, use_fuzzy=True, use_rules=True):
        """
        Initialize categorizer
        
        Args:
            use_nlp: Use NLTK for text processing
            use_fuzzy: Use fuzzy matching
            use_rules: Use business rules
        """
        self.use_nlp = use_nlp and NLTK_AVAILABLE
        self.use_fuzzy = use_fuzzy and MATCHERS_AVAILABLE
        self.use_rules = use_rules and MATCHERS_AVAILABLE
        
        # Initialize components
        if self.use_fuzzy:
            self.fuzzy_matcher = CommonMatchers.expense_category_matcher()
        
        if self.use_rules:
            self.rules_engine = ExpenseRuleEngine()
        
        if self.use_nlp:
            try:
                # Download required NLTK data (do once)
                nltk.download('punkt', quiet=True)
                nltk.download('stopwords', quiet=True)
                self.stemmer = PorterStemmer()
                self.stop_words = set(stopwords.words('english'))
            except:
                self.use_nlp = False
                logger.warning("NLTK data download failed")
    
    def categorize(self, expense: Dict) -> Dict:
        """
        Auto-categorize expense using all available methods
        
        Args:
            expense: Dict with {description, amount, vendor, etc.}
            
        Returns:
            dict: {category, confidence, method, details}
        """
        description = expense.get('description', '')
        amount = expense.get('amount', 0)
        
        if not description:
            return {'category': None, 'confidence': 0, 'method': 'none'}
        
        # Try different methods
        results = []
        
        # Method 1: Fuzzy matching (fastest, good accuracy)
        if self.use_fuzzy:
            fuzzy_result = self._fuzzy_categorize(description)
            if fuzzy_result:
                results.append(fuzzy_result)
        
        # Method 2: Keyword matching (simple, reliable)
        keyword_result = self._keyword_categorize(description)
        if keyword_result:
            results.append(keyword_result)
        
        # Method 3: NLP-based (most intelligent)
        if self.use_nlp:
            nlp_result = self._nlp_categorize(description)
            if nlp_result:
                results.append(nlp_result)
        
        # Method 4: Rules engine
        if self.use_rules:
            rules_result = self._rules_categorize(expense)
            if rules_result:
                results.append(rules_result)
        
        # Combine results (weighted voting)
        if results:
            return self._combine_results(results)
        
        return {'category': 'uncategorized', 'confidence': 0, 'method': 'fallback'}
    
    def _fuzzy_categorize(self, description: str) -> Optional[Dict]:
        """Categorize using fuzzy matching"""
        match = self.fuzzy_matcher.match_category(description)
        
        if match:
            category, pattern, score = match
            return {
                'category': category,
                'confidence': score,
                'method': 'fuzzy',
                'matched_pattern': pattern,
            }
        return None
    
    def _keyword_categorize(self, description: str) -> Optional[Dict]:
        """Categorize using keyword matching"""
        desc_lower = description.lower()
        
        best_category = None
        best_score = 0
        matched_keywords = []
        
        for category, keywords in self.CATEGORY_KEYWORDS.items():
            matches = [kw for kw in keywords if kw in desc_lower]
            
            if matches:
                # Score based on number and length of matches
                score = sum(len(kw) for kw in matches)
                
                if score > best_score:
                    best_score = score
                    best_category = category
                    matched_keywords = matches
        
        if best_category:
            # Normalize confidence to 0-100
            confidence = min(100, best_score * 10)
            return {
                'category': best_category,
                'confidence': confidence,
                'method': 'keyword',
                'matched_keywords': matched_keywords,
            }
        return None
    
    def _nlp_categorize(self, description: str) -> Optional[Dict]:
        """Categorize using NLP (token analysis)"""
        # Tokenize and stem
        tokens = word_tokenize(description.lower())
        tokens = [self.stemmer.stem(t) for t in tokens if t.isalnum() and t not in self.stop_words]
        
        # Create stemmed keyword dict
        stemmed_categories = {}
        for category, keywords in self.CATEGORY_KEYWORDS.items():
            stemmed_categories[category] = [
                self.stemmer.stem(kw.split()[-1])  # Stem last word of keyword
                for kw in keywords
            ]
        
        # Match tokens to categories
        best_category = None
        best_score = 0
        
        for category, stemmed_kws in stemmed_categories.items():
            matches = [t for t in tokens if t in stemmed_kws]
            score = len(matches)
            
            if score > best_score:
                best_score = score
                best_category = category
        
        if best_category and best_score > 0:
            confidence = min(100, best_score * 30)  # Up to 100
            return {
                'category': best_category,
                'confidence': confidence,
                'method': 'nlp',
            }
        return None
    
    def _rules_categorize(self, expense: Dict) -> Optional[Dict]:
        """Categorize using business rules"""
        processed = self.rules_engine.process_expense(expense)
        
        auto_category = processed.get('auto_category')
        
        if auto_category:
            return {
                'category': auto_category,
                'confidence': 90,  # High confidence for rules
                'method': 'rules',
            }
        return None
    
    def _combine_results(self, results: List[Dict]) -> Dict:
        """
        Combine multiple categorization results using weighted voting
        
        Weights:
        - Rules: 1.2 (most reliable)
        - Fuzzy: 1.0
        - NLP: 0.9
        - Keyword: 0.8
        """
        METHOD_WEIGHTS = {
            'rules': 1.2,
            'fuzzy': 1.0,
            'nlp': 0.9,
            'keyword': 0.8,
        }
        
        # Calculate weighted scores for each category
        category_scores = {}
        
        for result in results:
            category = result['category']
            confidence = result['confidence']
            method = result['method']
            weight = METHOD_WEIGHTS.get(method, 1.0)
            
            weighted_score = confidence * weight
            
            if category in category_scores:
                category_scores[category] += weighted_score
            else:
                category_scores[category] = weighted_score
        
        # Get best category
        best_category = max(category_scores, key=category_scores.get)
        best_score = category_scores[best_category]
        
        # Normalize confidence
        total_possible = sum(100 * METHOD_WEIGHTS.get(r['method'], 1.0) for r in results)
        confidence = min(100, (best_score / total_possible) * 100) if total_possible > 0 else 0
        
        # Find which methods agreed
        methods_used = [r['method'] for r in results if r['category'] == best_category]
        
        return {
            'category': best_category,
            'confidence': round(confidence, 2),
            'method': 'combined',
            'methods_agreed': methods_used,
            'all_results': results,
        }
    
    def batch_categorize(self, expenses: List[Dict]) -> List[Dict]:
        """
        Categorize multiple expenses
        
        Args:
            expenses: List of expense dicts
            
        Returns:
            list: Expenses with categorization added
        """
        categorized = []
        
        for expense in expenses:
            result = self.categorize(expense)
            
            # Add categorization to expense
            expense_with_category = expense.copy()
            expense_with_category['auto_category'] = result['category']
            expense_with_category['category_confidence'] = result['confidence']
            expense_with_category['categorization_method'] = result['method']
            
            categorized.append(expense_with_category)
        
        return categorized


# ============================================
# USAGE EXAMPLES
# ============================================

if __name__ == '__main__':
    # Create categorizer
    categorizer = AutoCategorizer(use_nlp=True, use_fuzzy=True, use_rules=True)
    
    # Test expenses
    test_expenses = [
        {'description': 'Office Rent December 2024', 'amount': 50000},
        {'description': 'Google Ads Campaign Q4', 'amount': 25000},
        {'description': 'AWS Cloud Services - Monthly', 'amount': 15000},
        {'description': 'Employee Salary - Tech Team', 'amount': 500000},
        {'description': 'Laptop Purchase for Developer', 'amount': 80000},
    ]
    
    for expense in test_expenses:
        result = categorizer.categorize(expense)
        print(f"\nDescription: {expense['description']}")
        print(f"Category: {result['category']} (confidence: {result['confidence']}%)")
        print(f"Method: {result['method']}")
        if 'methods_agreed' in result:
            print(f"Methods agreed: {result['methods_agreed']}")
