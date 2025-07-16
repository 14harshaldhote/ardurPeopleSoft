"""
Support Ticket System
====================

A comprehensive support ticket management system for handling customer and internal support requests.

Core Features:
- Ticket creation and management
- Intelligent priority and assignment
- SLA monitoring and tracking
- Comments and attachments
- Dashboard and reporting
- Advanced search and filtering

Architecture:
- views/: Request handlers organized by functionality
- services/: Core business logic and automation
- utils/: Utility functions and helpers
- forms/: Input validation and form handling
- management/: Django management commands
- templates/: HTML templates for UI

Version: 2.1.0
"""

__version__ = '2.1.0'
__author__ = 'Support System Team'

# Default app configuration
default_app_config = 'trueAlign.support.apps.SupportConfig'
