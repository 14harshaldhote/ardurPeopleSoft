"""
Global Updates (Notes) Module

This module handles company-wide global updates and announcements.
Provides CRUD operations for HR to manage updates and allows
employees and managers to view them based on their roles.

Features:
- Role-based access control (HR can manage, others can view)
- Status-based visibility (upcoming, released, scheduled)
- Rich form handling with validation
- AJAX endpoints for dynamic functionality
- Responsive templates with Bootstrap styling

Models:
- GlobalUpdate: Main model for storing global updates

Views:
- global_update_list: List all updates with filtering
- global_update_detail: View specific update details
- global_update_create: Create new updates (HR only)
- global_update_edit: Edit existing updates (HR only)
- global_update_delete: Delete updates (HR only)
- AJAX endpoints for status and read tracking

Forms:
- GlobalUpdateForm: Main form for create/edit operations
- GlobalUpdateFilterForm: Filter form for list view
- GlobalUpdateQuickCreateForm: Simplified creation form

Templates:
- base.html: Base template with common styling
- global_update_list.html: List view with filtering and pagination
- global_update_detail.html: Detail view with full content
- global_update_form.html: Create/edit form with validation
"""

default_app_config = 'trueAlign.notes.apps.NotesConfig'
