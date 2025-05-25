# views_modules package
"""
Django views modules for trueAlign application
"""

__version__ = '1.0.0'
__author__ = 'TrueAlign Team'

# Import session views for easy access
from . import session_views

__all__ = [
    'session_views',
]