from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Field

class CrispyFormMixin:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.form_tag = False
        
        # Apply custom classes to all fields
        for field_name, field in self.fields.items():
            field.widget.attrs.update({
                'class': 'block w-full px-4 py-3 rounded-xl bg-white/50 border border-white/40 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500'
            })
