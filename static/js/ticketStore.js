class TicketStore {
    constructor() {
        this.state = {
            view: localStorage.getItem('preferredView') || 'table',
            filters: this.loadFilters(),
            selectedTickets: new Set(),
            searchQuery: '',
            isLoading: false,
            showFilters: window.innerWidth >= 768,
            errors: []
        };
        this.subscribers = new Set();
    }

    loadFilters() {
        try {
            return JSON.parse(localStorage.getItem('ticketFilters')) || {};
        } catch {
            return {};
        }
    }

    subscribe(callback) {
        this.subscribers.add(callback);
        callback(this.state);
        return () => this.subscribers.delete(callback);
    }

    setState(newState) {
        this.state = { ...this.state, ...newState };
        this.subscribers.forEach(callback => callback(this.state));
        this.persistState();
    }

    persistState() {
        localStorage.setItem('preferredView', this.state.view);
        localStorage.setItem('ticketFilters', JSON.stringify(this.state.filters));
    }

    async performSearch(query) {
        this.setState({ isLoading: true, searchQuery: query });
        try {
            // Implement actual search logic here
            await new Promise(resolve => setTimeout(resolve, 300));
            this.setState({ isLoading: false });
        } catch (error) {
            this.setState({ 
                isLoading: false, 
                errors: [...this.state.errors, error.message]
            });
        }
    }
}
