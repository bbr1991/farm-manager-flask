// static/js/form-disable.js

document.addEventListener('DOMContentLoaded', function() {
    // Find all forms in the document
    const allForms = document.querySelectorAll('form');

    allForms.forEach(form => {
        form.addEventListener('submit', function(event) {
            // Find the submit button(s) within this specific form
            const submitButtons = form.querySelectorAll('button[type="submit"]');

            if (submitButtons.length > 0) {
                submitButtons.forEach(button => {
                    // Disable the button
                    button.disabled = true;
                    
                    // Optional: Change the text to show it's working
                    button.innerHTML = `
                        <span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>
                        Processing...
                    `;
                });
            }
        });
    });
});