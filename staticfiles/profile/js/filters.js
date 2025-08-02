/**
 * filters.js - User list filtering and search functionality
 */

document.addEventListener('DOMContentLoaded', function() {
    // Auto-submit form when filter selections change
    const filterForm = document.querySelector('form[data-filter-form]') || document.querySelector('form');
    if (filterForm) {
        const filterSelects = filterForm.querySelectorAll('select[name="status"], select[name="location"], select[name="employee_type"]');

        filterSelects.forEach(select => {
            select.addEventListener('change', function() {
                filterForm.submit();
            });
        });

        // Handle search input (submit after delay)
        const searchInput = filterForm.querySelector('input[name="search"]');
        let searchTimeout;

        if (searchInput) {
            searchInput.addEventListener('input', function() {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(function() {
                    if (searchInput.value.length >= 3 || searchInput.value.length === 0) {
                        filterForm.submit();
                    }
                }, 500);
            });

            // Clear search button functionality
            const clearSearchBtn = document.getElementById('clearSearch');
            if (clearSearchBtn) {
                clearSearchBtn.addEventListener('click', function() {
                    searchInput.value = '';
                    filterForm.submit();
                });
            }
        }
    }

    // Handle date range filters
    const startDateInput = document.getElementById('start_date');
    const endDateInput = document.getElementById('end_date');

    if (startDateInput && endDateInput) {
        endDateInput.addEventListener('change', function() {
            if (startDateInput.value && endDateInput.value) {
                const startDate = new Date(startDateInput.value);
                const endDate = new Date(endDateInput.value);

                if (endDate < startDate) {
                    alert('End date cannot be earlier than start date');
                    endDateInput.value = '';
                }
            }
        });

        // Auto-submit when dates change
        [startDateInput, endDateInput].forEach(input => {
            input.addEventListener('change', function() {
                if (startDateInput.value || endDateInput.value) {
                    const form = input.closest('form');
                    if (form) form.submit();
                }
            });
        });
    }

    // Toggle advanced filters
    const advancedFiltersToggle = document.getElementById('toggleAdvancedFilters');
    const advancedFiltersSection = document.getElementById('advancedFilters');

    if (advancedFiltersToggle && advancedFiltersSection) {
        advancedFiltersToggle.addEventListener('click', function() {
            advancedFiltersSection.classList.toggle('hidden');

            // Update button text
            if (advancedFiltersSection.classList.contains('hidden')) {
                advancedFiltersToggle.innerHTML = '<i class="fas fa-plus-circle mr-1"></i> Show Advanced Filters';
            } else {
                advancedFiltersToggle.innerHTML = '<i class="fas fa-minus-circle mr-1"></i> Hide Advanced Filters';
            }
        });
    }

    // User detail page tabs
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabContents = document.querySelectorAll('.tab-content');

    if (tabButtons.length && tabContents.length) {
        tabButtons.forEach(button => {
            button.addEventListener('click', function() {
                const tabId = this.dataset.tab;

                // Update active tab button
                tabButtons.forEach(btn => {
                    btn.classList.remove('border-blue-500', 'text-blue-600', 'bg-white');
                    btn.classList.add('border-transparent', 'text-gray-500');
                });

                this.classList.remove('border-transparent', 'text-gray-500');
                this.classList.add('border-blue-500', 'text-blue-600', 'bg-white');

                // Show active tab content
                tabContents.forEach(content => {
                    content.classList.add('hidden');
                });

                document.getElementById(tabId).classList.remove('hidden');

                // Save active tab to session storage
                sessionStorage.setItem('activeUserTab', tabId);
            });
        });

        // Restore active tab from session storage
        const activeTab = sessionStorage.getItem('activeUserTab');
        if (activeTab) {
            const activeButton = document.querySelector(`.tab-button[data-tab="${activeTab}"]`);
            if (activeButton) {
                activeButton.click();
            }
        }
    }

    // Handle modal functionality
    const modalTriggers = document.querySelectorAll('[data-modal-target]');
    const modalCloseButtons = document.querySelectorAll('.modal-close');

    modalTriggers.forEach(trigger => {
        trigger.addEventListener('click', function() {
            const modalId = this.dataset.modalTarget;
            const modal = document.getElementById(modalId);

            if (modal) {
                modal.classList.remove('hidden');
                document.body.classList.add('overflow-hidden');
            }
        });
    });

    modalCloseButtons.forEach(button => {
        button.addEventListener('click', function() {
            const modal = this.closest('[id]');
            if (modal) {
                modal.classList.add('hidden');
                document.body.classList.remove('overflow-hidden');
            }
        });
    });

    // Close modals when clicking outside
    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('fixed') && e.target.classList.contains('inset-0')) {
            e.target.classList.add('hidden');
            document.body.classList.remove('overflow-hidden');
        }
    });

    // Password validation
    const passwordField = document.getElementById('password');
    const confirmPasswordField = document.getElementById('confirm_password');
    const passwordForm = document.getElementById('passwordResetForm');

    if (passwordField && confirmPasswordField && passwordForm) {
        passwordForm.addEventListener('submit', function(e) {
            if (passwordField.value !== confirmPasswordField.value) {
                e.preventDefault();
                alert('Passwords do not match');
            }

            if (passwordField.value.length < 8) {
                e.preventDefault();
                alert('Password must be at least 8 characters long');
            }
        });
    }
});
