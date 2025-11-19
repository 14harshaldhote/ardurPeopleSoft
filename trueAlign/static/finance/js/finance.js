// Finance Module JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Confirmation dialogs for destructive actions
    const confirmButtons = document.querySelectorAll('[data-confirm]');
    confirmButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            const message = this.getAttribute('data-confirm');
            if (!confirm(message)) {
                e.preventDefault();
            }
        });
    });
    
    // Auto-hide alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
    alerts.forEach(alert => {
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert); 
            bsAlert.close();
        }, 5000);
    });
    
    // Date picker initialization (if using Date Picker library)
    const datePickers = document.querySelectorAll('input[type="date"]');
    datePickers.forEach(picker => {
        // Can add flatpickr or other date picker library here
        picker.max = new Date().toISOString().split("T")[0];
    });
    
    // Number formatting
    const currencyInputs = document.querySelectorAll('.currency-input');
    currencyInputs.forEach(input => {
        input.addEventListener('blur', function() {
            const value = parseFloat(this.value);
            if (!isNaN(value)) {
                this.value = value.toFixed(2);
            }
        });
    });
    
    // Dynamic formset handling for voucher details
    const addFormBtn = document.querySelector('.add-form-row');
    if (addFormBtn) {
        addFormBtn.addEventListener('click', function() {
            const formset = document.querySelector('.formset-container');
            const totalForms = document.querySelector('#id_form-TOTAL_FORMS');
            const formIdx = parseInt(totalForms.value);
            
            // Clone empty form
            const emptyForm = document.querySelector('.empty-form').cloneNode(true);
            emptyForm.classList.remove('empty-form');
            emptyForm.classList.add('formset-form');
            emptyForm.innerHTML = emptyForm.innerHTML.replace(/__prefix__/g, formIdx);
            
            formset.appendChild(emptyForm);
            totalForms.value = formIdx + 1;
        });
    }
    
    // Delete form row
    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('delete-form-row')) {
            e.preventDefault();
            const row = e.target.closest('.formset-form');
            row.remove();
            updateFormIndices();
        }
    });
    
    function updateFormIndices() {
        const forms = document.querySelectorAll('.formset-form');
        const totalForms = document.querySelector('#id_form-TOTAL_FORMS');
        totalForms.value = forms.length;
        
        forms.forEach((form, index) => {
            const inputs = form.querySelectorAll('input, select, textarea');
            inputs.forEach(input => {
                const name = input.name.replace(/form-\d+-/, `form-${index}-`);
                const id = input.id.replace(/id_form-\d+-/, `id_form-${index}-`);
                input.name = name;
                input.id = id;
            });
        });
    }
    
    // Sidebar active state
    const currentPath = window.location.pathname;
    const sidebarLinks = document.querySelectorAll('.sidebar-menu a');
    sidebarLinks.forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.parentElement.classList.add('active');
        }
    });
    
    // Table row click to navigate
    const clickableRows = document.querySelectorAll('tr[data-href]');
    clickableRows.forEach(row => {
        row.style.cursor = 'pointer';
        row.addEventListener('click', function(e) {
            if (!e.target.closest('a, button')) {
                window.location.href = this.getAttribute('data-href');
            }
        });
    });
    
    // Real-time invoice calculation
    const invoiceForm = document.querySelector('#invoice-form');
    if (invoiceForm) {
        const billingModel = invoiceForm.querySelector('#id_billing_model');
        const orderCount = invoiceForm.querySelector('#id_order_count');
        const fteCount = invoiceForm.querySelector('#id_fte_count');
        const rate = invoiceForm.querySelector('#id_rate');
        const discount = invoiceForm.querySelector('#id_discount');
        const subtotal = invoiceForm.querySelector('#id_subtotal');
        const taxAmount = invoiceForm.querySelector('#id_tax_amount');
        const totalAmount = invoiceForm.querySelector('#id_total_amount');
        
        function calculateInvoice() {
            const model = billingModel.value;
            const rateVal = parseFloat(rate.value) || 0;
            const orderVal = parseFloat(orderCount.value) || 0;
            const fteVal = parseFloat(fteCount.value) || 0;
            const discountVal = parseFloat(discount.value) || 0;
            
            let subtotalVal = 0;
            if (model === 'per_order') {
                subtotalVal = orderVal * rateVal;
            } else if (model === 'per_fte') {
                subtotalVal = fteVal * rateVal;
            } else if (model === 'hybrid') {
                subtotalVal = (orderVal * rateVal) + (fteVal * rateVal);
            }
            
            const subtotalAfterDiscount = subtotalVal - discountVal;
            const taxVal = subtotalAfterDiscount * 0.18; // Default GST 18%
            const totalVal = subtotalAfterDiscount + taxVal;
            
            subtotal.value = subtotalVal.toFixed(2);
            taxAmount.value = taxVal.toFixed(2);
            totalAmount.value = totalVal.toFixed(2);
        }
        
        [billingModel, orderCount, fteCount, rate, discount].forEach(field => {
            if (field) {
                field.addEventListener('input', calculateInvoice);
                field.addEventListener('change', calculateInvoice);
            }
        });
    }
    
    // Filter form auto-submit
    const filterForms = document.querySelectorAll('.filter-form-auto');
    filterForms.forEach(form => {
        const selects = form.querySelectorAll('select');
        selects.forEach(select => {
            select.addEventListener('change', () => form.submit());
        });
    });
});
