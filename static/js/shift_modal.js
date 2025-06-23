document.addEventListener('DOMContentLoaded', function () {
    const modalPlaceholder = document.getElementById('modal-placeholder');

    // Function to get CSRF token from cookies (required for POST requests)
    function getCookie(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }
    const csrftoken = getCookie('csrftoken');

    // --- Main Function to Open the Modal ---
    async function openModal(url) {
        try {
            // Fetch the modal's HTML content from the server
            const response = await fetch(url);
            const html = await response.text();
            
            // Inject the HTML into the placeholder
            modalPlaceholder.innerHTML = html;
            
            // Add animations for a smooth entry
            const modal = document.getElementById('shift-modal');
            const modalContent = document.getElementById('modal-content');
            setTimeout(() => {
                modal.classList.remove('opacity-0');
                modalContent.classList.remove('scale-95', 'opacity-0');
                modalContent.classList.add('scale-100', 'opacity-100');
            }, 10); // Small delay to allow CSS transitions to work

            // Attach event listeners for the new modal content
            attachModalEventListeners();

        } catch (error) {
            console.error("Failed to load modal:", error);
        }
    }
    
    // --- Function to Close the Modal ---
    function closeModal() {
        const modal = document.getElementById('shift-modal');
        const modalContent = document.getElementById('modal-content');

        if (modal && modalContent) {
            // Reverse animations for a smooth exit
            modalContent.classList.add('scale-95', 'opacity-0');
            modal.classList.add('opacity-0');
            
            // Remove from DOM after transition
            setTimeout(() => {
                modalPlaceholder.innerHTML = '';
            }, 300); // Must match transition duration
        }
    }

    // --- Function to Handle Form Submission via AJAX ---
    async function handleFormSubmit(event) {
        event.preventDefault(); // Stop the default page reload
        const form = event.target;
        const url = form.action;
        const formData = new FormData(form);

        try {
            const response = await fetch(url, {
                method: 'POST',
                body: formData,
                headers: {
                    'X-CSRFToken': csrftoken,
                    'X-Requested-With': 'XMLHttpRequest', // Often used to identify AJAX requests
                },
            });

            if (response.ok) {
                // SUCCESS: Server returned a 2xx status (e.g., 200 OK)
                const data = await response.json();
                if (data.success) {
                    closeModal();
                    // Reload the page to show the new shift in the list
                    window.location.reload(); 
                }
            } else {
                // ERROR: Server returned a 4xx or 5xx status (e.g., 400 Bad Request)
                // This means there were validation errors.
                const errorHtml = await response.text();
                // Replace the form content with the new HTML which includes error messages
                const modalContent = document.getElementById('modal-content');
                if(modalContent) {
                   modalContent.innerHTML = errorHtml;
                   // We need to re-attach listeners to the new content
                   attachModalEventListeners(true);
                }
            }
        } catch (error) {
            console.error("Form submission failed:", error);
        }
    }

    // --- Function to attach all necessary event listeners inside the modal ---
    function attachModalEventListeners(isFormOnly = false) {
        const form = document.getElementById('shift-form');
        if (form) {
            form.addEventListener('submit', handleFormSubmit);
        }

        // if isFormOnly is true, we are re-attaching after a validation error
        // and don't need to re-attach the close/cancel button listeners
        if(!isFormOnly) {
            const closeModalButton = document.getElementById('modal-close-btn');
            const cancelModalButton = document.getElementById('modal-cancel-btn');
            if(closeModalButton) closeModalButton.addEventListener('click', closeModal);
            if(cancelModalButton) cancelModalButton.addEventListener('click', closeModal);
        }
    }

    // --- Attach listener to the main "Create Shift" button on the page ---
    const createShiftButton = document.getElementById('create-shift-btn');
    if (createShiftButton) {
        createShiftButton.addEventListener('click', () => {
            const url = createShiftButton.dataset.url;
            openModal(url);
        });
    }
});