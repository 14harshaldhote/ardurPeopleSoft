"""
Heuristic Matchers for Reconciliation
"""
from datetime import timedelta

class SmartMatcher:
    
    @staticmethod
    def find_potential_matches(statement_line, candidates, threshold_days=3):
        """
        Find potential matches for a statement line from a list of candidates 
        (Expenses or Payments).
        
        Logic:
        1. Amount Match (Exact)
        2. Date Match (Within threshold)
        3. Text Similarity (Bonus)
        """
        matches = []
        
        target_amount = abs(statement_line.amount)
        target_date = statement_line.date
        
        for candidate in candidates:
            # Check Amount
            # Handle Money object vs Decimal vs Float
            cand_amount = candidate.amount.amount if hasattr(candidate.amount, 'amount') else candidate.amount
            
            if cand_amount == target_amount:
                # Check Date
                cand_date = candidate.date.date() if hasattr(candidate.date, 'date') else candidate.date
                delta = abs((cand_date - target_date).days)
                
                if delta <= threshold_days:
                    matches.append({
                        'candidate': candidate,
                        'score': 100 - (delta * 10), # Higher score for closer date
                        'reason': f"Exact amount match, date diff: {delta} days"
                    })
                    
        return sorted(matches, key=lambda x: x['score'], reverse=True)
