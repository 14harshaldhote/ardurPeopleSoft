"""
Risk Scoring Engine
"""
from .constants import RISK_VAGUE, RISK_SUSPICIOUS
from .cleaners import normalize_text

class RiskEngine:
    
    @staticmethod
    def calculate_risk_score(description, amount):
        """
        Calculate risk score (0-100) and identify risk factors.
        """
        score = 0
        factors = []
        text = normalize_text(description)
        
        # 1. Vagueness Check
        for kw in RISK_VAGUE:
            if kw in text:
                score += 20
                factors.append(f"Vague keyword: '{kw}'")
                
        # 2. Suspicious Keywords
        for kw in RISK_SUSPICIOUS:
            if kw in text:
                score += 30
                factors.append(f"Suspicious keyword: '{kw}'")
                
        # 3. Round Number Check (High Value)
        if amount and amount > 5000:
            if amount % 1000 == 0: # Multiple of 1000
                score += 15
                factors.append(f"Round number > 5000: {amount}")
            if amount % 500 == 0 and amount % 1000 != 0:
                score += 10
                factors.append(f"Round number (500s): {amount}")

        # 4. Cash + Adjustment Combination
        if 'cash' in text and 'adjustment' in text:
            score += 40
            factors.append("Suspicious combination: 'cash' + 'adjustment'")
            
        # Cap score at 100
        return min(score, 100), factors
