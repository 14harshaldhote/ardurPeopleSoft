from django.utils import timezone
from django.template import Template, Context
from trueAlign.models import LetterTemplate, GeneratedLetter
from .utils import render_to_pdf
from django.core.files.base import ContentFile

class LetterService:
    @staticmethod
    def get_active_templates():
        """
        Fetch all active letter templates.
        """
        return LetterTemplate.objects.filter(is_active=True)

    @staticmethod
    def get_template_by_id(template_id):
        """
        Fetch a specific template by ID.
        """
        try:
            return LetterTemplate.objects.get(id=template_id)
        except LetterTemplate.DoesNotExist:
            return None

    @staticmethod
    def render_letter_preview(template_content, context_data):
        """
        Render the letter HTML with dynamic data for preview.
        """
        template = Template(template_content)
        context = Context(context_data)
        return template.render(context)

    @staticmethod
    def generate_and_save_letter(user, employee, template, context_data, custom_content=None):
        """
        Generate the final PDF, save the record, and return the GeneratedLetter instance.
        """
        # 1. Render HTML content
        if custom_content:
            # If user manually edited, use that content directly
            # Note: We might want to sanitize this in a real app
            html_content = custom_content
        else:
            html_content = LetterService.render_letter_preview(template.content, context_data)
        
        # 2. Prepare context for PDF (including letterhead, etc.)
        # We might want to wrap the content in a base template for PDF
        pdf_context = {
            'content': html_content,
            'employee': employee,
            'generated_at': timezone.now(),
            # Add other context variables needed for the base PDF template
        }
        
        # 3. Generate PDF
        # Assuming we have a base PDF template that includes the letterhead
        pdf_file_content = render_to_pdf('letter/pdf_base.html', pdf_context)
        
        if not pdf_file_content:
            # If PDF generation fails, we can't save the file.
            # We'll just save the record without the file.
            generated_letter = GeneratedLetter(
                template=template,
                employee=employee,
                generated_by=user,
                content=html_content,
            )
            generated_letter.save()
            return generated_letter

        # 4. Save GeneratedLetter record
        generated_letter = GeneratedLetter(
            template=template,
            employee=employee,
            generated_by=user,
            content=html_content,
        )
        
        # Save PDF file
        filename = f"{template.type}_{employee.username}_{timezone.now().strftime('%Y%m%d%H%M%S')}.pdf"
        generated_letter.pdf_file.save(filename, ContentFile(pdf_file_content), save=False)
        generated_letter.save()
        
        return generated_letter
        
        generated_letter.save()
        
        return generated_letter
