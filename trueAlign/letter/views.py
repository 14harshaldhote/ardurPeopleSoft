from django.shortcuts import render, get_object_or_404, redirect
from django.views.generic import ListView, DetailView, View
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from django.contrib import messages
from trueAlign.models import LetterTemplate, GeneratedLetter
from .services import LetterService
from .forms import LetterGenerationForm
import json

class HRRequiredMixin(UserPassesTestMixin):
    def test_func(self):
        return self.request.user.groups.filter(name='HR').exists() or self.request.user.is_superuser

class LetterDashboardView(LoginRequiredMixin, HRRequiredMixin, ListView):
    model = LetterTemplate
    template_name = 'letter/dashboard.html'
    context_object_name = 'templates'

    def get_queryset(self):
        queryset = LetterService.get_active_templates()
        
        # Search by name
        query = self.request.GET.get('q')
        if query:
            queryset = queryset.filter(name__icontains=query)
            
        # Filter by type
        type_filter = self.request.GET.get('type')
        if type_filter:
            queryset = queryset.filter(type=type_filter)
            
        return queryset

class LetterDetailView(LoginRequiredMixin, HRRequiredMixin, DetailView):
    model = LetterTemplate
    template_name = 'letter/form.html'
    context_object_name = 'template'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        template = self.get_object()
        context['form'] = LetterGenerationForm(template=template)
        return context

class GenerateLetterView(LoginRequiredMixin, HRRequiredMixin, View):
    def post(self, request, pk):
        template = get_object_or_404(LetterTemplate, pk=pk)
        form = LetterGenerationForm(request.POST, template=template)
        
        if form.is_valid():
            employee = form.cleaned_data['employee']
            # Prepare context data from form and employee details
            # Prepare context data from form and employee details
            context_data = {
                'employee_name': employee.get_full_name() or employee.username,
                'designation': getattr(employee.profile, 'designation', 'N/A') if hasattr(employee, 'profile') else 'N/A',
                'department': getattr(employee.profile, 'department', 'N/A') if hasattr(employee, 'profile') else 'N/A',
                'date': form.cleaned_data.get('date_of_generation', timezone.now().date()).strftime('%d %B, %Y'),
                'joining_date': getattr(employee.profile, 'joining_date', 'N/A') if hasattr(employee, 'profile') else 'N/A',
                'recipient_name': employee.get_full_name(), # Keep for backward compatibility if needed
                'current_date': timezone.now().strftime('%d %B, %Y'),
                'subject_line': f"{template.name} - {employee.get_full_name()}",
                # Add other dynamic fields from form
                **form.cleaned_data
            }
            
            # Check for custom content (manual edits)
            custom_content = request.POST.get('custom_content')
            
            try:
                generated_letter = LetterService.generate_and_save_letter(
                    user=request.user,
                    employee=employee,
                    template=template,
                    context_data=context_data,
                    custom_content=custom_content
                )
                messages.success(request, "Letter generated successfully.")
                return redirect('letter:download_pdf', pk=generated_letter.pk)
            except Exception as e:
                messages.error(request, f"Error generating letter: {str(e)}")
                return redirect('letter:detail', pk=pk)
        
        messages.error(request, "Invalid form data.")
        return redirect('letter:detail', pk=pk)

class PreviewLetterView(LoginRequiredMixin, HRRequiredMixin, View):
    def post(self, request, pk):
        template = get_object_or_404(LetterTemplate, pk=pk)
        data = json.loads(request.body)
        
        # Fetch employee details if provided
        employee_id = data.get('employee')
        employee = None
        if employee_id:
            from django.contrib.auth import get_user_model
            User = get_user_model()
            try:
                employee = User.objects.get(pk=employee_id)
            except User.DoesNotExist:
                pass

        # Prepare context data similar to GenerateLetterView
        context_data = {
            'employee_name': employee.get_full_name() if employee else data.get('employee_name', '[Employee Name]'),
            'designation': getattr(employee.profile, 'designation', 'N/A') if employee and hasattr(employee, 'profile') else data.get('designation', '[Designation]'),
            'department': getattr(employee.profile, 'department', 'N/A') if employee and hasattr(employee, 'profile') else data.get('department', '[Department]'),
            'date': data.get('date_of_generation', timezone.now().strftime('%d %B, %Y')),
            'joining_date': getattr(employee.profile, 'joining_date', 'N/A') if employee and hasattr(employee, 'profile') else data.get('joining_date', '[Joining Date]'),
            'current_date': timezone.now().strftime('%d %B, %Y'),
            'subject_line': f"{template.name}",
            **data
        }
        
        # Render the inner content first
        inner_html = LetterService.render_letter_preview(template.content, context_data)
        
        # Wrap in the base preview template
        from django.template.loader import render_to_string
        full_html = render_to_string('letter/letter_preview_base.html', {'content': inner_html})
        
        return JsonResponse({'html': full_html})

class DownloadLetterPDFView(LoginRequiredMixin, HRRequiredMixin, View):
    def get(self, request, pk):
        generated_letter = get_object_or_404(GeneratedLetter, pk=pk)
        if generated_letter.pdf_file:
            response = HttpResponse(generated_letter.pdf_file, content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="{generated_letter.pdf_file.name}"'
            return response
        else:
            messages.error(request, "PDF file not found.")
            return redirect('letter:dashboard')
