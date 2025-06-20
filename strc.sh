#!/bin/bash

# This script creates the new, updated directory structure for the ardurPeopleSoft project.
# Run this script from the root of your project (the directory containing manage.py).

echo "Creating the new ardurPeopleSoft project structure..."

# 1. ardurTrueAlign/ (Project config directory)
mkdir -p ardurTrueAlign
touch ardurTrueAlign/__init__.py
touch ardurTrueAlign/asgi.py
# settings.py should be left as is initially, but ensure it's there
[ -f ardurTrueAlign/settings.py ] || touch ardurTrueAlign/settings.py
# urls.py should be left as is initially, but ensure it's there
[ -f ardurTrueAlign/urls.py ] || touch ardurTrueAlign/urls.py
touch ardurTrueAlign/wsgi.py

# 2. trueAlign/ (Your main Django App)
mkdir -p trueAlign
touch trueAlign/__init__.py
touch trueAlign/admin.py
touch trueAlign/apps.py
# models.py and migrations/ should exist from your current setup
[ -f trueAlign/models.py ] || touch trueAlign/models.py
mkdir -p trueAlign/migrations
touch trueAlign/urls.py # NEW: Becomes a simple "router"

# 3. Feature Packages within trueAlign/

# attendance/
mkdir -p trueAlign/attendance
touch trueAlign/attendance/__init__.py
touch trueAlign/attendance/forms.py
touch trueAlign/attendance/services.py
touch trueAlign/attendance/urls.py
touch trueAlign/attendance/views.py
mkdir -p trueAlign/attendance/management/commands
touch trueAlign/attendance/management/commands/auto_mark_attendance.py
mkdir -p trueAlign/attendance/templates/attendance
touch trueAlign/attendance/templates/attendance/analytics.html
touch trueAlign/attendance/templates/attendance/dashboard.html
touch trueAlign/attendance/templates/attendance/regularization_requests.html
touch trueAlign/attendance/templates/attendance/report.html
mkdir -p trueAlign/attendance/templatetags
touch trueAlign/attendance/templatetags/__init__.py
touch trueAlign/attendance/templatetags/attendance_filters.py

# leave/
mkdir -p trueAlign/leave
touch trueAlign/leave/__init__.py
touch trueAlign/leave/forms.py
touch trueAlign/leave/services.py
touch trueAlign/leave/urls.py
touch trueAlign/leave/views.py
mkdir -p trueAlign/leave/templates/leave
touch trueAlign/leave/templates/leave/dashboard.html
touch trueAlign/leave/templates/leave/request_form.html
touch trueAlign/leave/templates/leave/policy_list.html
touch trueAlign/leave/templates/leave/balance_report.html

# sessions/
mkdir -p trueAlign/sessions
touch trueAlign/sessions/__init__.py
touch trueAlign/sessions/urls.py
touch trueAlign/sessions/views.py
mkdir -p trueAlign/sessions/management/commands
touch trueAlign/sessions/management/commands/__init__.py
touch trueAlign/sessions/management/commands/manage_sessions.py
mkdir -p trueAlign/sessions/templates/sessions
touch trueAlign/sessions/templates/sessions/user_sessions_dashboard.html
touch trueAlign/sessions/templates/sessions/user_session_detail.html

# finance/
mkdir -p trueAlign/finance
touch trueAlign/finance/__init__.py
touch trueAlign/finance/forms.py
touch trueAlign/finance/services.py
touch trueAlign/finance/urls.py
touch trueAlign/finance/views.py
mkdir -p trueAlign/finance/templates/finance
touch trueAlign/finance/templates/finance/dashboard.html
touch trueAlign/finance/templates/finance/invoice_generation.html
touch trueAlign/finance/templates/finance/invoice_print.html
touch trueAlign/finance/templates/finance/voucher_entry.html
mkdir -p trueAlign/finance/templatetags
touch trueAlign/finance/templatetags/__init__.py
touch trueAlign/finance/templatetags/finance_extras.py

# support/
mkdir -p trueAlign/support
touch trueAlign/support/__init__.py
touch trueAlign/support/forms.py
touch trueAlign/support/services.py
touch trueAlign/support/urls.py
touch trueAlign/support/views.py
mkdir -p trueAlign/support/templates/support
touch trueAlign/support/templates/support/dashboard.html
touch trueAlign/support/templates/support/create_ticket.html
touch trueAlign/support/templates/support/ticket_list.html
touch trueAlign/support/templates/support/ticket_detail.html

# chat/
mkdir -p trueAlign/chat
touch trueAlign/chat/__init__.py
touch trueAlign/chat/consumers.py
touch trueAlign/chat/routing.py
touch trueAlign/chat/urls.py
touch trueAlign/chat/views.py
mkdir -p trueAlign/chat/templates/chat
touch trueAlign/chat/templates/chat/chat_home.html
touch trueAlign/chat/templates/chat/chat_detail.html

# games/
mkdir -p trueAlign/games
touch trueAlign/games/__init__.py
touch trueAlign/games/urls.py
touch trueAlign/games/views.py
mkdir -p trueAlign/games/management/commands
touch trueAlign/games/management/commands/__init__.py
touch trueAlign/games/management/commands/create_game_icons.py
mkdir -p trueAlign/games/templates/games/ttt
touch trueAlign/games/templates/games/dashboard.html
touch trueAlign/games/templates/games/ttt/game_detail.html

# core/ (CORE PACKAGE: Shared logic, main dashboard)
mkdir -p trueAlign/core
touch trueAlign/core/__init__.py
touch trueAlign/core/context_processors.py
touch trueAlign/core/middleware.py
touch trueAlign/core/signals.py
touch trueAlign/core/urls.py
touch trueAlign/core/utils.py
touch trueAlign/core/views.py
mkdir -p trueAlign/core/templates/core
touch trueAlign/core/templates/core/base.html
touch trueAlign/core/templates/core/navbar.html
touch trueAlign/core/templates/core/dashboard.html
touch trueAlign/core/templates/core/login.html
touch trueAlign/core/templates/core/error.html
mkdir -p trueAlign/core/templatetags
touch trueAlign/core/templatetags/__init__.py
touch trueAlign/core/templatetags/custom_filters.py

# Project-wide static and media (ensure these base directories exist)
mkdir -p static/css
mkdir -p static/images
mkdir -p media/comment_attachments
mkdir -p media/ticket_attachments

echo "New project structure created successfully!"
echo "Remember to move your existing code into these new locations incrementally."
echo "Also, update import paths and URL configurations as you refactor."