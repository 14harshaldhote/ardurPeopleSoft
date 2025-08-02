export function initializeDashboard(config) {
    const filterForm = document.getElementById(config.filterFormId);
    const dateRangeSelect = document.getElementById(config.dateRangeSelectId);
    const customDateInputs = document.getElementById(config.customDateInputsId);
    const loadingIndicator = document.getElementById(config.dashboardLoadingId);
    const activeFilters = document.getElementById(config.activeFiltersId);
    const resetFilters = document.getElementById(config.resetFiltersId);

    // Handle date range changes
    dateRangeSelect.addEventListener('change', (e) => {
        customDateInputs.classList.toggle('hidden', e.target.value !== 'custom');
    });

    // Handle filter form submission
    filterForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        await updateDashboard(new FormData(filterForm));
    });

    // Reset filters
    resetFilters.addEventListener('click', () => {
        filterForm.reset();
        updateDashboard(new FormData(filterForm));
    });

    // Update active filters display
    function updateActiveFilters(formData) {
        const chips = [];
        for (const [key, value] of formData.entries()) {
            if (value) {
                chips.push(createFilterChip(key, value));
            }
        }
        activeFilters.innerHTML = chips.join('');
        
        // Add click handlers for removing filters
        document.querySelectorAll('.filter-chip-remove').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const filterName = e.currentTarget.dataset.filter;
                const input = filterForm.querySelector(`[name="${filterName}"]`);
                if (input) {
                    input.value = '';
                    filterForm.dispatchEvent(new Event('submit'));
                }
            });
        });
    }

    // Create filter chip HTML
    function createFilterChip(key, value) {
        const label = key.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
        return `
            <span class="inline-flex items-center space-x-1 px-3 py-1 rounded-full text-sm bg-blue-50 text-blue-700 border border-blue-100">
                <span>${label}: ${value}</span>
                <button type="button" class="filter-chip-remove ml-2 text-blue-500 hover:text-blue-700" data-filter="${key}">
                    <svg class="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd" />
                    </svg>
                </button>
            </span>
        `;
    }

    // Update dashboard with new data
    async function updateDashboard(formData) {
        try {
            loadingIndicator.classList.remove('hidden');
            loadingIndicator.classList.add('flex');

            const response = await fetch(window.location.pathname + '?' + new URLSearchParams(formData), {
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            });

            const data = await response.json();
            
            // Update dashboard sections
            updateDashboardSections(data);
            updateActiveFilters(formData);
            
            // Update URL with new filters
            const url = new URL(window.location);
            for (const [key, value] of formData.entries()) {
                if (value) {
                    url.searchParams.set(key, value);
                } else {
                    url.searchParams.delete(key);
                }
            }
            window.history.pushState({}, '', url);

        } catch (error) {
            console.error('Error updating dashboard:', error);
            // Show error notification
            showNotification('Error updating dashboard. Please try again.');
        } finally {
            loadingIndicator.classList.add('hidden');
            loadingIndicator.classList.remove('flex');
        }
    }

    // Start auto-refresh interval
    if (config.updateInterval) {
        setInterval(() => {
            updateDashboard(new FormData(filterForm));
        }, config.updateInterval);
    }
}
