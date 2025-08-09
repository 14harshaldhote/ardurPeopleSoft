#!/usr/bin/env python
"""
Debug script to check role choices in forms
"""

import os
import sys
import django

# Setup Django environment
sys.path.append('/Users/harshalsmac/WORK/ardur/ardurHome')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from trueAlign.models import UserDetails
from trueAlign.profile.forms import UserDetailsCreateForm, UserDetailsUpdateForm

def debug_role_choices():
    print("🔍 Debugging Role Choices")
    print("=" * 50)

    # Check model choices
    print("\n1. Role choices from UserDetails model:")
    for value, label in UserDetails.ROLE_CHOICES:
        print(f"   '{value}' → '{label}'")

    # Check create form
    print("\n2. Role choices in UserDetailsCreateForm:")
    try:
        form = UserDetailsCreateForm()
        role_field = form.fields.get('role')

        if role_field:
            print(f"   Field type: {type(role_field)}")
            print(f"   Field choices:")
            if hasattr(role_field, 'choices') and role_field.choices:
                for value, label in role_field.choices:
                    print(f"     '{value}' → '{label}'")
            else:
                print("     No choices found!")
        else:
            print("   ❌ Role field not found in form!")

    except Exception as e:
        print(f"   ❌ Error with create form: {e}")

    # Check update form
    print("\n3. Role choices in UserDetailsUpdateForm:")
    try:
        form = UserDetailsUpdateForm()
        role_field = form.fields.get('role')

        if role_field:
            print(f"   Field type: {type(role_field)}")
            print(f"   Field choices:")
            if hasattr(role_field, 'choices') and role_field.choices:
                for value, label in role_field.choices:
                    print(f"     '{value}' → '{label}'")
            else:
                print("     No choices found!")
        else:
            print("   ❌ Role field not found in form!")

    except Exception as e:
        print(f"   ❌ Error with update form: {e}")

    # Test form rendering
    print("\n4. Testing form rendering:")
    try:
        form = UserDetailsCreateForm()
        role_widget = form['role']
        print(f"   Widget type: {type(role_widget.field.widget)}")
        print(f"   Widget attrs: {role_widget.field.widget.attrs}")

        # Try to render the widget
        rendered = str(role_widget)
        if 'admin' in rendered.lower() or 'developer' in rendered.lower():
            print("   ✅ Role options are being rendered in HTML")
            # Count options
            option_count = rendered.lower().count('<option')
            print(f"   Number of options found: {option_count}")
        else:
            print("   ❌ Role options not found in rendered HTML")
            print("   First 200 chars of rendered HTML:")
            print(f"   {rendered[:200]}...")

    except Exception as e:
        print(f"   ❌ Error rendering form: {e}")

def debug_form_fields():
    print("\n🔧 Debugging All Form Fields")
    print("=" * 50)

    try:
        form = UserDetailsCreateForm()

        print("All fields in UserDetailsCreateForm:")
        for field_name, field in form.fields.items():
            field_type = type(field).__name__
            print(f"  • {field_name:25s} → {field_type}")

            # Special check for choice fields
            if hasattr(field, 'choices') and field.choices:
                choice_count = len(list(field.choices))
                print(f"    ↳ Has {choice_count} choices")

    except Exception as e:
        print(f"❌ Error listing form fields: {e}")

def test_template_context():
    print("\n🌐 Testing Template Context")
    print("=" * 50)

    try:
        from django.template import Context, Template

        # Create a form
        form = UserDetailsCreateForm()

        # Simple template to test role field rendering
        template_str = """
        Role field test:
        {% for value, label in form.role.field.choices %}
        - {{ value }}: {{ label }}
        {% endfor %}
        """

        template = Template(template_str)
        context = Context({'form': form})
        rendered = template.render(context)

        print("Template rendering result:")
        print(rendered)

        # Count how many roles were rendered
        role_count = rendered.count(':')
        print(f"Number of roles rendered: {role_count}")

        if role_count > 0:
            print("✅ Role choices are available to templates")
        else:
            print("❌ Role choices not available to templates")

    except Exception as e:
        print(f"❌ Error testing template context: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    debug_role_choices()
    debug_form_fields()
    test_template_context()
