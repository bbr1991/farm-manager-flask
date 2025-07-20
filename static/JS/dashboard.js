document.addEventListener('DOMContentLoaded', function () {
    // A helper function to safely parse data from the data-* attribute
    const getChartData = (canvasId) => {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return null;
        try {
            return JSON.parse(canvas.dataset.chartData);
        } catch (e) {
            console.error('Error parsing chart data for:', canvasId, e);
            return null;
        }
    };

    // --- Chart Initialization ---

    function initFinancialBarChart() {
        const data = getChartData('financialBarChart');
        if (!data) return;
        
        const ctx = document.getElementById('financialBarChart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: data.map(item => item.month),
                datasets: [
                    {
                        label: 'Monthly Income',
                        data: data.map(item => item.monthly_income),
                        backgroundColor: 'rgba(39, 174, 96, 0.7)', // Theme Green
                        borderColor: 'rgba(39, 174, 96, 1)',
                        borderWidth: 1
                    },
                    {
                        label: 'Monthly Expenses',
                        data: data.map(item => item.monthly_expenses),
                        backgroundColor: 'rgba(231, 74, 59, 0.7)', // Red
                        borderColor: 'rgba(231, 74, 59, 1)',
                        borderWidth: 1
                    }
                ]
            },
            options: { 
                maintainAspectRatio: false,
                scales: { y: { beginAtZero: true } },
                plugins: { legend: { display: true, position: 'top' } } 
            }
        });
    }

    function initExpensePieChart() {
        const data = getChartData('expensePieChart');
        if (!data) return;

        const ctx = document.getElementById('expensePieChart').getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: data.map(item => item.category),
                datasets: [{
                    data: data.map(item => item.total),
                    backgroundColor: ['#e74a3b', '#fd7e14', '#f6c23e', '#20c997', '#34495e', '#6f42c1'],
                    hoverOffset: 4
                }]
            },
            options: {
                maintainAspectRatio: false,
                plugins: { legend: { display: true, position: 'bottom' } }
            }
        });
    }

    function initProductionLineChart(canvasId, label, color) {
        const data = getChartData(canvasId);
        if (!data) return;

        const ctx = document.getElementById(canvasId).getContext('2d');
        new Chart(ctx, {
            type: 'line',
            data: {
                labels: data.map(item => item.log_date),
                datasets: [{
                    label: label,
                    data: data.map(item => item.total_eggs || item.total_water), // Works for both
                    fill: true,
                    backgroundColor: `rgba(${color}, 0.1)`,
                    borderColor: `rgba(${color}, 1)`,
                    tension: 0.3,
                    pointRadius: 2
                }]
            },
            options: { 
                scales: { y: { beginAtZero: true } },
                plugins: { legend: { display: false } }
            }
        });
    }

    // --- Run All Initializations ---
    initFinancialBarChart();
    initExpensePieChart();
    initProductionLineChart('eggLineChart', 'Eggs Collected', '78, 115, 223'); // Blue
    initProductionLineChart('waterLineChart', 'Water Produced', '39, 174, 96'); // Theme Green
});