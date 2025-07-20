document.addEventListener('DOMContentLoaded', function () {
    
    const sidebar = document.getElementById('sidebar');
    const sidebarCollapse = document.getElementById('sidebarCollapse');

    if (sidebarCollapse) {
        sidebarCollapse.addEventListener('click', function () {
            // Toggle the 'active' class on the sidebar
            sidebar.classList.toggle('active');
            
            // Toggle the aria-expanded attribute for accessibility
            const isExpanded = sidebarCollapse.getAttribute('aria-expanded') === 'true';
            sidebarCollapse.setAttribute('aria-expanded', !isExpanded);
        });
    }

});