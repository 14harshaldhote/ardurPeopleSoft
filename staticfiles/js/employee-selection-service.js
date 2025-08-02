/**
 * EmployeeSelectionService
 * A comprehensive service for managing employee selection in shift assignment workflows
 *
 * Features:
 * - Manages selection state with efficient Set data structure
 * - Provides methods for selecting, deselecting, and toggling
 * - Syncs UI with selection state
 * - Publishes events when selection changes
 * - Persists selection state across page refreshes (optional)
 * - Optimized for performance with large datasets
 */
class EmployeeSelectionService {
    constructor(options = {}) {
        // Initialize selection Set
        this.selectedEmployees = new Set();

        // Configuration options with defaults
        this.config = {
            persistSelection: options.persistSelection || false,
            storageKey: options.storageKey || 'trueAlign_selectedEmployees',
            cardSelector: options.cardSelector || '.employee-card',
            selectedClass: options.selectedClass || 'selected',
            checkboxSelector: options.checkboxSelector || 'input[type="checkbox"]',
            countSelector: options.countSelector || '#selected-count',
            summarySelector: options.summarySelector || '#selection-summary',
            previewSelector: options.previewSelector || '#selected-employees-preview',
            previewListSelector: options.previewListSelector || '#selected-employees-list',
            bulkActionSelector: options.bulkActionSelector || '#bulk-assign-btn',
            onSelectionChange: options.onSelectionChange || null,
            maxPreviewItems: options.maxPreviewItems || 5,
            debug: options.debug || false,
        };

        // Event listeners
        this.eventListeners = {
            change: [],
            clear: [],
            selectAll: [],
        };

        // Employee data cache for quick lookups
        this.employeeCache = new Map();

        // Initialize
        if (this.config.persistSelection) {
            this._loadFromStorage();
        }

        this._setupEventDelegation();
        this.log('EmployeeSelectionService initialized');
    }

    /**
     * Add an employee to the selection
     * @param {number|string} employeeId - ID of the employee to select
     * @param {boolean} updateUI - Whether to update the UI (default: true)
     * @returns {boolean} - Whether the operation changed the selection
     */
    select(employeeId, updateUI = true) {
        employeeId = parseInt(employeeId, 10);
        const changed = !this.selectedEmployees.has(employeeId);

        if (changed) {
            this.selectedEmployees.add(employeeId);
            this.log(`Selected employee ${employeeId}`);

            if (updateUI) {
                this._updateCardState(employeeId, true);
                this._updateSelectionUI();
            }

            this._triggerEvent('change', {
                type: 'select',
                employeeId,
                count: this.selectedEmployees.size
            });

            if (this.config.persistSelection) {
                this._saveToStorage();
            }
        }

        return changed;
    }

    /**
     * Remove an employee from the selection
     * @param {number|string} employeeId - ID of the employee to deselect
     * @param {boolean} updateUI - Whether to update the UI (default: true)
     * @returns {boolean} - Whether the operation changed the selection
     */
    deselect(employeeId, updateUI = true) {
        employeeId = parseInt(employeeId, 10);
        const changed = this.selectedEmployees.has(employeeId);

        if (changed) {
            this.selectedEmployees.delete(employeeId);
            this.log(`Deselected employee ${employeeId}`);

            if (updateUI) {
                this._updateCardState(employeeId, false);
                this._updateSelectionUI();
            }

            this._triggerEvent('change', {
                type: 'deselect',
                employeeId,
                count: this.selectedEmployees.size
            });

            if (this.config.persistSelection) {
                this._saveToStorage();
            }
        }

        return changed;
    }

    /**
     * Toggle an employee's selection state
     * @param {number|string} employeeId - ID of the employee to toggle
     * @param {boolean} updateUI - Whether to update the UI (default: true)
     * @returns {boolean} - The new selection state (true = selected, false = deselected)
     */
    toggle(employeeId, updateUI = true) {
        employeeId = parseInt(employeeId, 10);
        const newState = !this.selectedEmployees.has(employeeId);

        if (newState) {
            this.select(employeeId, updateUI);
        } else {
            this.deselect(employeeId, updateUI);
        }

        return newState;
    }

    /**
     * Check if an employee is selected
     * @param {number|string} employeeId - ID of the employee to check
     * @returns {boolean} - Whether the employee is selected
     */
    isSelected(employeeId) {
        return this.selectedEmployees.has(parseInt(employeeId, 10));
    }

    /**
     * Get the number of selected employees
     * @returns {number} - The count of selected employees
     */
    getCount() {
        return this.selectedEmployees.size;
    }

    /**
     * Get the IDs of all selected employees
     * @returns {number[]} - Array of selected employee IDs
     */
    getSelectedIds() {
        return Array.from(this.selectedEmployees);
    }

    /**
     * Get the comma-separated list of selected employee IDs
     * @returns {string} - Comma-separated IDs for API calls
     */
    getSelectedIdsString() {
        return this.getSelectedIds().join(',');
    }

    /**
     * Select all visible employees
     * @returns {number} - Number of newly selected employees
     */
    selectAllVisible() {
        const cards = document.querySelectorAll(`${this.config.cardSelector}[data-selectable="true"]`);
        let newlySelected = 0;

        cards.forEach(card => {
            const employeeId = parseInt(card.dataset.employeeId, 10);
            if (!this.isSelected(employeeId)) {
                this.select(employeeId, false); // Don't update UI yet for performance
                newlySelected++;
            }
        });

        if (newlySelected > 0) {
            this._updateAllCardsUI();
            this._updateSelectionUI();

            this._triggerEvent('selectAll', {
                count: this.selectedEmployees.size,
                newlySelected
            });

            if (this.config.persistSelection) {
                this._saveToStorage();
            }

            this.log(`Selected all visible employees (${newlySelected} new selections)`);
        }

        return newlySelected;
    }

    /**
     * Clear all selections
     * @returns {number} - Number of employees that were deselected
     */
    clearSelection() {
        const count = this.selectedEmployees.size;

        if (count > 0) {
            this.selectedEmployees.clear();
            this._updateAllCardsUI();
            this._updateSelectionUI();

            this._triggerEvent('clear', { previousCount: count });

            if (this.config.persistSelection) {
                this._saveToStorage();
            }

            this.log(`Cleared selection of ${count} employees`);
        }

        return count;
    }

    /**
     * Register an employee in the cache
     * @param {Object} employeeData - Employee data object
     */
    registerEmployee(employeeData) {
        if (employeeData && employeeData.id) {
            this.employeeCache.set(parseInt(employeeData.id, 10), employeeData);
        }
    }

    /**
     * Register multiple employees in the cache
     * @param {Array} employees - Array of employee data objects
     */
    registerEmployees(employees) {
        if (Array.isArray(employees)) {
            employees.forEach(employee => this.registerEmployee(employee));
        }
    }

    /**
     * Get employee data from cache
     * @param {number|string} employeeId - ID of the employee
     * @returns {Object|null} - Employee data or null if not found
     */
    getEmployeeData(employeeId) {
        return this.employeeCache.get(parseInt(employeeId, 10)) || null;
    }

    /**
     * Update selection UI elements
     */
    updateUI() {
        this._updateAllCardsUI();
        this._updateSelectionUI();
    }

    /**
     * Add event listener
     * @param {string} event - Event name ('change', 'clear', or 'selectAll')
     * @param {Function} callback - Callback function
     */
    on(event, callback) {
        if (typeof callback !== 'function') return;

        if (this.eventListeners[event]) {
            this.eventListeners[event].push(callback);
        }
    }

    /**
     * Remove event listener
     * @param {string} event - Event name
     * @param {Function} callback - Callback function to remove
     */
    off(event, callback) {
        if (this.eventListeners[event]) {
            this.eventListeners[event] = this.eventListeners[event]
                .filter(cb => cb !== callback);
        }
    }

    /**
     * Update card state in the UI
     * @private
     * @param {number|string} employeeId - ID of the employee
     * @param {boolean} selected - Whether the employee is selected
     */
    _updateCardState(employeeId, selected) {
        const card = document.querySelector(`${this.config.cardSelector}[data-employee-id="${employeeId}"]`);
        if (!card) return;

        const checkbox = card.querySelector(this.config.checkboxSelector);

        if (selected) {
            card.classList.add(this.config.selectedClass);
            card.classList.add('border-blue-500');
            card.classList.add('bg-blue-50');
            card.classList.remove('border-gray-200');
            if (checkbox) checkbox.checked = true;
        } else {
            card.classList.remove(this.config.selectedClass);
            card.classList.remove('border-blue-500');
            card.classList.remove('bg-blue-50');
            card.classList.add('border-gray-200');
            if (checkbox) checkbox.checked = false;
        }
    }

    /**
     * Update all cards in the UI based on current selection state
     * @private
     */
    _updateAllCardsUI() {
        // First reset all cards
        document.querySelectorAll(this.config.cardSelector).forEach(card => {
            card.classList.remove(this.config.selectedClass);
            card.classList.remove('border-blue-500');
            card.classList.remove('bg-blue-50');
            card.classList.add('border-gray-200');
            const checkbox = card.querySelector(this.config.checkboxSelector);
            if (checkbox) checkbox.checked = false;
        });

        // Then mark selected ones
        this.selectedEmployees.forEach(id => {
            this._updateCardState(id, true);
        });
    }

    /**
     * Update selection UI components (count, summary, preview)
     * @private
     */
    _updateSelectionUI() {
        // Update count
        const countElement = document.querySelector(this.config.countSelector);
        if (countElement) {
            countElement.textContent = this.selectedEmployees.size;
        }

        // Update summary visibility
        const summaryElement = document.querySelector(this.config.summarySelector);
        if (summaryElement) {
            if (this.selectedEmployees.size > 0) {
                summaryElement.classList.remove('hidden');
            } else {
                summaryElement.classList.add('hidden');
            }
        }

        // Update preview
        this._updatePreview();

        // Update bulk action button state
        const bulkActionBtn = document.querySelector(this.config.bulkActionSelector);
        if (bulkActionBtn) {
            bulkActionBtn.disabled = this.selectedEmployees.size === 0;
        }

        // Call custom handler if provided
        if (typeof this.config.onSelectionChange === 'function') {
            this.config.onSelectionChange({
                count: this.selectedEmployees.size,
                ids: this.getSelectedIds()
            });
        }
    }

    /**
     * Update the selection preview
     * @private
     */
    _updatePreview() {
        const preview = document.querySelector(this.config.previewSelector);
        const list = document.querySelector(this.config.previewListSelector);

        if (!preview || !list) return;

        if (this.selectedEmployees.size === 0) {
            preview.classList.add('hidden');
            return;
        }

        preview.classList.remove('hidden');

        // Generate list HTML
        let previewHTML = '';
        let displayCount = 0;
        const maxItems = this.config.maxPreviewItems;

        // Get first few selected employees
        const selectedIds = this.getSelectedIds();
        const displayIds = selectedIds.slice(0, maxItems);

        displayIds.forEach(id => {
            const employee = this.getEmployeeData(id);
            if (employee) {
                displayCount++;
                previewHTML += `
                    <div class="flex items-center justify-between py-2 border-b border-gray-100 last:border-0">
                        <div class="flex items-center">
                            <div class="flex-shrink-0 mr-3">
                                ${employee.avatar
                                    ? `<img class="h-8 w-8 rounded-full" src="${employee.avatar}" alt="${employee.name}">`
                                    : `<div class="h-8 w-8 rounded-full bg-gray-300 flex items-center justify-center">
                                        <span class="text-xs font-medium text-gray-700">${employee.name.charAt(0)}</span>
                                      </div>`
                                }
                            </div>
                            <div>
                                <p class="text-sm font-medium text-gray-900">${employee.name}</p>
                                <p class="text-xs text-gray-500">${employee.current_shift ? employee.current_shift.name : 'No current shift'}</p>
                            </div>
                        </div>
                        <button class="text-gray-400 hover:text-red-500"
                                onclick="event.preventDefault(); window.employeeSelectionService.deselect(${id});">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                            </svg>
                        </button>
                    </div>
                `;
            }
        });

        // Add "and X more" if not all employees are shown
        if (selectedIds.length > maxItems) {
            const moreCount = selectedIds.length - maxItems;
            previewHTML += `
                <div class="py-2 text-center text-sm text-gray-500">
                    And ${moreCount} more employee${moreCount > 1 ? 's' : ''}
                </div>
            `;
        }

        list.innerHTML = previewHTML;
    }

    /**
     * Set up event delegation for handling clicks on employee cards
     * @private
     */
    _setupEventDelegation() {
        document.addEventListener('click', (e) => {
            // Handle checkbox clicks
            if (e.target.matches(`${this.config.cardSelector} ${this.config.checkboxSelector}`)) {
                e.stopPropagation();
                const card = e.target.closest(this.config.cardSelector);
                if (card && card.dataset.employeeId) {
                    const employeeId = parseInt(card.dataset.employeeId, 10);
                    if (e.target.checked) {
                        this.select(employeeId);
                    } else {
                        this.deselect(employeeId);
                    }
                }
                return;
            }

            // Handle card clicks
            const card = e.target.closest(`${this.config.cardSelector}[data-selectable="true"]`);
            if (card && card.dataset.employeeId) {
                const employeeId = parseInt(card.dataset.employeeId, 10);
                this.toggle(employeeId);
            }
        });
    }

    /**
     * Trigger an event
     * @private
     * @param {string} event - Event name
     * @param {Object} data - Event data
     */
    _triggerEvent(event, data) {
        if (this.eventListeners[event]) {
            this.eventListeners[event].forEach(callback => {
                try {
                    callback(data);
                } catch (err) {
                    console.error(`Error in ${event} event handler:`, err);
                }
            });
        }
    }

    /**
     * Save selection to localStorage
     * @private
     */
    _saveToStorage() {
        if (typeof localStorage !== 'undefined') {
            try {
                localStorage.setItem(
                    this.config.storageKey,
                    JSON.stringify(Array.from(this.selectedEmployees))
                );
            } catch (err) {
                console.error('Failed to save selection to localStorage:', err);
            }
        }
    }

    /**
     * Load selection from localStorage
     * @private
     */
    _loadFromStorage() {
        if (typeof localStorage !== 'undefined') {
            try {
                const stored = localStorage.getItem(this.config.storageKey);
                if (stored) {
                    const ids = JSON.parse(stored);
                    if (Array.isArray(ids)) {
                        ids.forEach(id => this.selectedEmployees.add(parseInt(id, 10)));
                        this.log(`Loaded ${ids.length} selections from storage`);
                    }
                }
            } catch (err) {
                console.error('Failed to load selection from localStorage:', err);
            }
        }
    }

    /**
     * Log debug message
     * @private
     * @param {string} message - Message to log
     */
    log(message) {
        if (this.config.debug) {
            console.log(`[EmployeeSelectionService] ${message}`);
        }
    }
}

// Create a global instance if window is available
if (typeof window !== 'undefined') {
    window.employeeSelectionService = new EmployeeSelectionService({
        debug: true,
        persistSelection: true,
    });

    // Log when initialized on page
    document.addEventListener('DOMContentLoaded', () => {
        console.log('EmployeeSelectionService ready', window.employeeSelectionService);
    });
}
