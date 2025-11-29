import os
from io import BytesIO
from django.http import HttpResponse
from django.template.loader import get_template
try:
    from xhtml2pdf import pisa
except ImportError:
    pisa = None

from django.conf import settings
from django.contrib.staticfiles import finders

def link_callback(uri, rel):
    """
    Convert HTML URIs to absolute system paths so xhtml2pdf can access those resources
    """
    sUrl = settings.STATIC_URL        # Typically /static/
    mUrl = settings.MEDIA_URL         # Typically /media/
    
    # Ensure sUrl starts with / for matching if uri starts with /
    if not sUrl.startswith('/'):
        sUrl = '/' + sUrl

    if uri.startswith(mUrl):
        path = os.path.join(settings.MEDIA_ROOT, uri.replace(mUrl, ""))
    elif uri.startswith(sUrl):
        # It's a static file
        relative_path = uri.replace(sUrl, "")
        
        # Try finders first with the relative path
        result = finders.find(relative_path)
        if result:
            if isinstance(result, (list, tuple)):
                result = result[0]
            path = result
        else:
            # Fallback to manual search in STATICFILES_DIRS
            # This handles cases where finders might miss or if we want to be explicit
            path = os.path.join(settings.BASE_DIR, 'static', relative_path)
    else:
        return uri

    return path

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
    pdf = pisa.pisaDocument(
        BytesIO(html.encode("UTF-8")), 
        result, 
        encoding='UTF-8',
        link_callback=link_callback
    )
    
    if not pdf.err:
        return result.getvalue()
    return None
