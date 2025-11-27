import os
from io import BytesIO
from django.http import HttpResponse
from django.template.loader import get_template
try:
    from xhtml2pdf import pisa
except ImportError:
    pisa = None

def render_to_pdf(template_src, context_dict={}):
    """
    Render a Django template into a PDF file.
    """
    if not pisa:
        return None
        
    template = get_template(template_src)
    html = template.render(context_dict)
    result = BytesIO()
    
    # Convert HTML to PDF
    # Use UTF-8 encoding to handle special characters
    pdf = pisa.pisaDocument(BytesIO(html.encode("UTF-8")), result, encoding='UTF-8')
    
    if not pdf.err:
        return result.getvalue()
    return None
