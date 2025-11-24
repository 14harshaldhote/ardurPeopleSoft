#!/usr/bin/env python3
"""
Automated batch updater for finance templates
Converts all remaining templates to use Heroicons and modern Tailwind CSS
"""

import re
import os
from pathlib import Path

# Base directory
FINANCE_TEMPLATES = Path("/Users/harshalsmac/WORK/ardur/ardurHome/trueAlign/templates/finance")

# Icon replacements mapping
ICON_MAPPINGS = {
    'ri-add-line': '''<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
                </svg>''',
    'ri-search-line': '''<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>''',
    'ri-eye-line': '''<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                </svg>''',
    'ri-printer-line': '''<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 17h2a2 2 0 002-2v-4a2 2 0 00-2-2H5a2 2 0 00-2 2v4a2 2 0 002 2h2m2 4h6a2 2 0 002-2v-4a2 2 0 00-2-2H9a2 2 0 00-2 2v4a2 2 0 002 2zm8-12V5a2 2 0 00-2-2H9a2 2 0 00-2 2v4h10z" />
                </svg>''',
    'ri-edit-line': '''<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                </svg>''',
    'ri-check-line': '''<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                </svg>''',
    'ri-refresh-line': '''<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>''',
}

def update_template(file_path):
    """Update a single template file"""
    print(f"Updating: {file_path}")
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    original = content
    
    # Replace Remix Icons
    for icon_class, svg in ICON_MAPPINGS.items():
        pattern = rf'<i class="{icon_class}[^"]*"></i>'
        content = re.sub(pattern, svg.strip(), content)
    
    # Update colors
    content = content.replace('text-zinc-', 'text-gray-')
    content = content.replace('bg-zinc-', 'bg-gray-')
    content = content.replace('border-zinc-', 'border-gray-')
    
    # Update borders
    content = content.replace('border-black/10', 'border-gray-200/50')
    content = content.replace('border-white/20', 'border-gray-300')
    content = content.replace('border-white/30', 'border-gray-300')
    
    # Update rounded corners
    content = content.replace('rounded-[16px]', 'rounded-2xl')
    
    # Update shadows
    content = content.replace('shadow-inner', 'shadow-lg')
    
    # Update table headers
    content = content.replace('bg-white/30 border-b border-white/20', 'bg-gray-50 border-b border-gray-200')
    
    # Update table cells - be careful with spacing
    content = re.sub(r'px-4 py-3', 'px-6 py-4', content)  
     
    # Update badges
    content = re.sub(r'bg-(\w+)-500/20', r'bg-\1-100', content)
    content = re.sub(r'border-(\w+)-500/30', r'border-\1-300', content)
    content = re.sub(r'px-2 py-1', 'px-3 py-1', content)
    content = re.sub(r'font-medium', 'font-semibold', content)
    
    # Update dividers
    content = content.replace('divide-white/10', 'divide-gray-100')
    
    # Update hover states
    content = content.replace('hover:bg-white/10', 'hover:bg-gray-50')
    content = content.replace('hover:bg-white/25', 'hover:bg-white/30')
    
    # Add container wrapper if missing
    if '<div class="space-y-6">' in content and 'container mx-auto px-4 py-6' not in content:
        content = content.replace('<div class="space-y-6">', 
                                '<div class="container mx-auto px-4 py-6">\n    <div class="space-y-6">')
        # Find the last closing div and add another one
        last_div = content.rfind('</div>\n{% endblock %}')
        if last_div > 0:
            content = content[:last_div] + '    </div>\n</div>\n{% endblock %}'
    
    # Only write if changed
    if content != original:
        with open(file_path, 'w') as f:
            f.write(content)
        print(f"  ✓ Updated {file_path.name}")
        return True
    else:
        print(f"  - No changes needed for {file_path.name}")
        return False

# Files to update
files_to_update = [
    "vouchers/list.html",
    "vouchers/detail.html",
    "vouchers/form.html",
    "bank_payments/list.html",
    "bank_payments/detail.html",
    "bank_payments/form.html",
    "chart_of_accounts/list.html",
    "chart_of_accounts/form.html",
    "parameters/list.html",
    "parameters/form.html",
    "parameters/approve.html",
    "subscriptions/list.html",
    "subscriptions/form.html",
]

if __name__ == "__main__":
    print("Starting batch update of finance templates...")
    print("=" * 60)
    
    updated_count = 0
    for file_rel_path in files_to_update:
        file_path = FINANCE_TEMPLATES / file_rel_path
        if file_path.exists():
            if update_template(file_path):
                updated_count += 1
        else:
            print(f"  ✗ File not found: {file_path}")
    
    print("=" * 60)
    print(f"Batch update complete! Updated {updated_count} files.")
