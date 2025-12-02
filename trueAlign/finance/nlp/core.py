"""
Core NLP Processor (Orchestrator)
"""
from .cleaners import normalize_text
from .classifiers import TransactionClassifier
from .risk import RiskEngine

class FinanceNLPProcessor:
    
    @staticmethod
    def analyze_transaction(description, amount):
        """
        Run full analysis on a transaction description.
        Returns a dict with all analysis results.
        """
        # 1. Normalization
        normalized_text = normalize_text(description)
        
        # 2. Classification
        txn_type = TransactionClassifier.classify_type(description)
        mode = TransactionClassifier.detect_mode(description)
        category = TransactionClassifier.predict_category(description)
        
        # 3. Risk Analysis
        risk_score, risk_factors = RiskEngine.calculate_risk_score(description, amount)
        
        # 4. Construct Result
        return {
            'normalized_text': normalized_text,
            'type': txn_type,
            'mode': mode,
            'predicted_category': category,
            'risk_score': risk_score,
            'risk_factors': risk_factors,
            'tags': [x for x in [txn_type, mode, category] if x]
        }
