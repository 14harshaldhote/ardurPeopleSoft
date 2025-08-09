#!/usr/bin/env python
"""
Simple script to check ALLOWED_HOSTS configuration
"""

import os
import sys
import django

# Add the project path
sys.path.append('/Users/harshalsmac/WORK/ardur/ardurHome')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from django.conf import settings

print("=== ALLOWED_HOSTS Configuration Check ===")
print(f"ALLOWED_HOSTS: {settings.ALLOWED_HOSTS}")
print(f"DEBUG: {settings.DEBUG}")

# Check environment variables
print("\n=== Environment Variables ===")
print(f"ALLOWED_HOSTS env var: {os.environ.get('ALLOWED_HOSTS', 'NOT SET')}")
print(f"DEBUG env var: {os.environ.get('DEBUG', 'NOT SET')}")

# Test if testserver is in ALLOWED_HOSTS
if 'testserver' in settings.ALLOWED_HOSTS:
    print("\n✓ testserver is in ALLOWED_HOSTS")
else:
    print("\n✗ testserver is NOT in ALLOWED_HOSTS")
    print("Current ALLOWED_HOSTS:", settings.ALLOWED_HOSTS)
