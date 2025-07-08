"""
Support Module
==============

This module provides a comprehensive support ticket system with the following features:

- Ticket creation, management, and tracking
- SLA monitoring and breach detection
- Comment system with file attachments
- User role-based permissions
- Bulk operations on tickets
- Email notifications
- Dashboard and reporting
- Advanced search and filtering

Components:
-----------
- views.py: HTTP request handlers for all support functionality
- services.py: Business logic layer for ticket operations
- forms.py: Django forms for user input validation
- utils.py: Utility functions for SLA, file handling, notifications, etc.
- urls.py: URL routing configuration

The system integrates with the main trueAlign models and provides a complete
ticketing solution for organizational support needs.
"""

__version__ = '1.0.0'
__author__ = 'Support System Team'

# Module metadata
default_app_config = 'trueAlign.support.apps.SupportConfig'
