// dashboard_charts.js - Enhanced Attendance Dashboard JavaScript
function enhancedAttendanceDashboard() {
    return {
        isLoading: false,
        dashboardData: {},
        chartPeriod: '7',
        departmentViewMode: 'chart',
        lastUpdated: new Date().toLocaleTimeString(),
        dailyTrendChart: null,
        statusDistributionChart: null,
        departmentChart: null,
        userRole: window.userRole || 'Employee',

        init() {
            this.loadDashboardData();
            this.initializeCharts();

            // Auto-refresh every 5 minutes
            setInterval(() => {
                this.refreshData();
            }, 300000);

            // Handle window resize
            window.addEventListener('resize', this.handleResize.bind(this));
        },

        async loadDashboardData() {
            this.isLoading = true;
            try {
                const response = await fetch('/api/attendance/dashboard/', {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': this.getCSRFToken()
                    }
                });

                if (response.ok) {
                    const data = await response.json();
                    this.dashboardData = data.data;
                    this.updateCharts();
                    this.lastUpdated = new Date().toLocaleTimeString();
                } else {
                    console.error('Failed to load dashboard data');
                    this.showError('Failed to load dashboard data');
                }
            } catch (error) {
                console.error('Error loading dashboard data:', error);
                this.showError('Network error while loading dashboard data');
            } finally {
                this.isLoading = false;
            }
        },

        initializeCharts() {
            // Initialize ECharts instances
            this.dailyTrendChart = echarts.init(document.getElementById('dailyTrendChart'));
            this.statusDistributionChart = echarts.init(document.getElementById('statusDistributionChart'));

            if (this.userRole === 'HR' || this.userRole === 'Admin') {
                const departmentChartEl = document.getElementById('departmentChart');
                if (departmentChartEl) {
                    this.departmentChart = echarts.init(departmentChartEl);
                }
            }

            // Set loading states
            this.dailyTrendChart.showLoading();
            this.statusDistributionChart.showLoading();
            if (this.departmentChart) {
                this.departmentChart.showLoading();
            }
        },

        async updateCharts() {
            if (!this.dashboardData) return;

            // Load chart data
            await this.loadChartData();

            // Update all charts
            this.updateDailyTrendChart();
            this.updateStatusDistributionChart();

            if (this.userRole === 'HR' || this.userRole === 'Admin') {
                this.updateDepartmentChart();
            }
        },

        async loadChartData() {
            try {
                const response = await fetch(`/api/attendance/dashboard/charts/?days=${this.chartPeriod}`, {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': this.getCSRFToken()
                    }
                });

                if (response.ok) {
                    const data = await response.json();
                    this.dashboardData.charts = data.data;
                }
            } catch (error) {
                console.error('Error loading chart data:', error);
            }
        },

        updateDailyTrendChart() {
            if (!this.dailyTrendChart || !this.dashboardData.charts?.daily_trend) {
                this.dailyTrendChart?.hideLoading();
                return;
            }

            const chartData = this.dashboardData.charts.daily_trend;

            const option = {
                title: {
                    text: 'Daily Attendance Trend',
                    left: 'left',
                    textStyle: {
                        fontSize: 16,
                        fontWeight: '600',
                        color: '#374151'
                    }
                },
                tooltip: {
                    trigger: 'axis',
                    axisPointer: { type: 'cross' },
                    backgroundColor: '#fff',
                    borderColor: '#e5e7eb',
                    borderWidth: 1,
                    textStyle: { color: '#374151' }
                },
                legend: {
                    data: ['Present', 'Absent', 'Late', 'On Leave'],
                    bottom: 10,
                    textStyle: { color: '#6b7280' }
                },
                grid: {
                    left: '3%',
                    right: '4%',
                    bottom: '15%',
                    containLabel: true
                },
                xAxis: {
                    type: 'category',
                    data: chartData.map(item => {
                        const date = new Date(item.date);
                        return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
                    }),
                    axisLine: { lineStyle: { color: '#e5e7eb' } },
                    axisTick: { lineStyle: { color: '#e5e7eb' } },
                    axisLabel: { color: '#6b7280' }
                },
                yAxis: {
                    type: 'value',
                    axisLine: { lineStyle: { color: '#e5e7eb' } },
                    axisTick: { lineStyle: { color: '#e5e7eb' } },
                    axisLabel: { color: '#6b7280' },
                    splitLine: { lineStyle: { color: '#f3f4f6' } }
                },
                series: [
                    {
                        name: 'Present',
                        type: 'line',
                        data: chartData.map(item => item.present),
                        smooth: true,
                        lineStyle: { color: '#10b981', width: 3 },
                        itemStyle: { color: '#10b981' },
                        areaStyle: {
                            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
                                { offset: 0, color: 'rgba(16, 185, 129, 0.3)' },
                                { offset: 1, color: 'rgba(16, 185, 129, 0.1)' }
                            ])
                        }
                    },
                    {
                        name: 'Absent',
                        type: 'line',
                        data: chartData.map(item => item.absent),
                        smooth: true,
                        lineStyle: { color: '#ef4444', width: 3 },
                        itemStyle: { color: '#ef4444' }
                    },
                    {
                        name: 'Late',
                        type: 'line',
                        data: chartData.map(item => item.late),
                        smooth: true,
                        lineStyle: { color: '#f59e0b', width: 3 },
                        itemStyle: { color: '#f59e0b' }
                    },
                    {
                        name: 'On Leave',
                        type: 'line',
                        data: chartData.map(item => item.on_leave),
                        smooth: true,
                        lineStyle: { color: '#8b5cf6', width: 3 },
                        itemStyle: { color: '#8b5cf6' }
                    }
                ]
            };

            this.dailyTrendChart.hideLoading();
            this.dailyTrendChart.setOption(option, true);
        },

        updateStatusDistributionChart() {
            if (!this.statusDistributionChart || !this.dashboardData.charts?.status_distribution) {
                this.statusDistributionChart?.hideLoading();
                return;
            }

            const statusData = this.dashboardData.charts.status_distribution;

            const data = Object.entries(statusData).map(([status, count]) => ({
                name: status,
                value: count
            }));

            const colorMap = {
                'Present': '#10b981',
                'Present & Late': '#f59e0b',
                'Absent': '#ef4444',
                'On Leave': '#8b5cf6',
                'Holiday': '#6b7280',
                'Weekend': '#9ca3af'
            };

            const option = {
                title: {
                    text: 'Status Distribution',
                    left: 'left',
                    textStyle: {
                        fontSize: 16,
                        fontWeight: '600',
                        color: '#374151'
                    }
                },
                tooltip: {
                    trigger: 'item',
                    formatter: '{a} <br/>{b}: {c} ({d}%)',
                    backgroundColor: '#fff',
                    borderColor: '#e5e7eb',
                    borderWidth: 1,
                    textStyle: { color: '#374151' }
                },
                legend: {
                    orient: 'vertical',
                    left: 'right',
                    top: 'middle',
                    textStyle: { color: '#6b7280' }
                },
                series: [
                    {
                        name: 'Attendance Status',
                        type: 'pie',
                        radius: ['40%', '70%'],
                        center: ['40%', '50%'],
                        data: data,
                        emphasis: {
                            itemStyle: {
                                shadowBlur: 10,
                                shadowOffsetX: 0,
                                shadowColor: 'rgba(0, 0, 0, 0.5)'
                            }
                        },
                        itemStyle: {
                            color: function(params) {
                                return colorMap[params.name] || '#6b7280';
                            }
                        },
                        label: {
                            formatter: '{b}\n{c} ({d}%)',
                            color: '#374151'
                        }
                    }
                ]
            };

            this.statusDistributionChart.hideLoading();
            this.statusDistributionChart.setOption(option, true);
        },

        updateDepartmentChart() {
            if (!this.departmentChart || !this.dashboardData.department_breakdown) {
                this.departmentChart?.hideLoading();
                return;
            }

            const deptData = this.dashboardData.department_breakdown;
            const departments = Object.keys(deptData);
            const presentData = departments.map(dept => deptData[dept].present);
            const absentData = departments.map(dept => deptData[dept].absent);

            const option = {
                title: {
                    text: 'Department-wise Attendance',
                    left: 'left',
                    textStyle: {
                        fontSize: 16,
                        fontWeight: '600',
                        color: '#374151'
                    }
                },
                tooltip: {
                    trigger: 'axis',
                    axisPointer: { type: 'shadow' },
                    backgroundColor: '#fff',
                    borderColor: '#e5e7eb',
                    borderWidth: 1,
                    textStyle: { color: '#374151' }
                },
                legend: {
                    data: ['Present', 'Absent'],
                    bottom: 10,
                    textStyle: { color: '#6b7280' }
                },
                grid: {
                    left: '3%',
                    right: '4%',
                    bottom: '15%',
                    containLabel: true
                },
                xAxis: {
                    type: 'category',
                    data: departments,
                    axisLine: { lineStyle: { color: '#e5e7eb' } },
                    axisTick: { lineStyle: { color: '#e5e7eb' } },
                    axisLabel: {
                        color: '#6b7280',
                        rotate: 45,
                        interval: 0
                    }
                },
                yAxis: {
                    type: 'value',
                    axisLine: { lineStyle: { color: '#e5e7eb' } },
                    axisTick: { lineStyle: { color: '#e5e7eb' } },
                    axisLabel: { color: '#6b7280' },
                    splitLine: { lineStyle: { color: '#f3f4f6' } }
                },
                series: [
                    {
                        name: 'Present',
                        type: 'bar',
                        data: presentData,
                        itemStyle: { color: '#10b981' }
                    },
                    {
                        name: 'Absent',
                        type: 'bar',
                        data: absentData,
                        itemStyle: { color: '#ef4444' }
                    }
                ]
            };

            this.departmentChart.hideLoading();
            this.departmentChart.setOption(option, true);
        },

        async refreshData() {
            await this.loadDashboardData();
        },

        toggleDepartmentView() {
            this.departmentViewMode = this.departmentViewMode === 'chart' ? 'table' : 'chart';

            if (this.departmentViewMode === 'chart') {
                this.$nextTick(() => {
                    if (this.departmentChart) {
                        this.departmentChart.resize();
                        this.updateDepartmentChart();
                    }
                });
            }
        },

        async exportData(format) {
            this.isLoading = true;

            try {
                const today = new Date();
                const firstDay = new Date(today.getFullYear(), today.getMonth(), 1);
                const lastDay = new Date(today.getFullYear(), today.getMonth() + 1, 0);

                const params = new URLSearchParams({
                    start_date: firstDay.toISOString().split('T')[0],
                    end_date: lastDay.toISOString().split('T')[0],
                    format: format
                });

                const url = format === 'excel'
                    ? '/api/attendance/export/excel/'
                    : '/api/attendance/export/csv/';

                const response = await fetch(`${url}?${params}`, {
                    method: 'GET',
                    headers: {
                        'X-CSRFToken': this.getCSRFToken()
                    }
                });

                if (response.ok) {
                    const blob = await response.blob();
                    const downloadUrl = window.URL.createObjectURL(blob);
                    const link = document.createElement('a');
                    link.href = downloadUrl;

                    const contentDisposition = response.headers.get('content-disposition');
                    let filename = `attendance_report_${new Date().toISOString().split('T')[0]}.${format}`;

                    if (contentDisposition) {
                        const filenameMatch = contentDisposition.match(/filename="(.+)"/);
                        if (filenameMatch) {
                            filename = filenameMatch[1];
                        }
                    }

                    link.download = filename;
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);
                    window.URL.revokeObjectURL(downloadUrl);

                    this.showSuccess(`Successfully exported ${format.toUpperCase()} file`);
                } else {
                    throw new Error(`Failed to export ${format} file`);
                }
            } catch (error) {
                console.error('Export error:', error);
                this.showError(`Failed to export ${format} file`);
            } finally {
                this.isLoading = false;
            }
        },

        handleResize() {
            // Debounce resize events
            clearTimeout(this.resizeTimeout);
            this.resizeTimeout = setTimeout(() => {
                this.dailyTrendChart?.resize();
                this.statusDistributionChart?.resize();
                this.departmentChart?.resize();
            }, 250);
        },

        getCSRFToken() {
            const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]');
            return csrfToken ? csrfToken.value : '';
        },

        showSuccess(message) {
            // Create a simple toast notification
            const toast = document.createElement('div');
            toast.className = 'fixed top-4 right-4 bg-green-500 text-white px-6 py-3 rounded-lg shadow-lg z-50 transition-opacity duration-300';
            toast.innerHTML = `
                <div class="flex items-center">
                    <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                    </svg>
                    ${message}
                </div>
            `;
            document.body.appendChild(toast);

            setTimeout(() => {
                toast.style.opacity = '0';
                setTimeout(() => {
                    document.body.removeChild(toast);
                }, 300);
            }, 3000);
        },

        showError(message) {
            // Create a simple error toast notification
            const toast = document.createElement('div');
            toast.className = 'fixed top-4 right-4 bg-red-500 text-white px-6 py-3 rounded-lg shadow-lg z-50 transition-opacity duration-300';
            toast.innerHTML = `
                <div class="flex items-center">
                    <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                    </svg>
                    ${message}
                </div>
            `;
            document.body.appendChild(toast);

            setTimeout(() => {
                toast.style.opacity = '0';
                setTimeout(() => {
                    document.body.removeChild(toast);
                }, 300);
            }, 3000);
        },

        // Utility function to format numbers
        formatNumber(num) {
            return new Intl.NumberFormat().format(num);
        },

        // Utility function to format percentages
        formatPercentage(num) {
            return `${(num || 0).toFixed(1)}%`;
        },

        // Utility function to get status color
        getStatusColor(status) {
            const colorMap = {
                'Present': 'text-green-600',
                'Present & Late': 'text-yellow-600',
                'Absent': 'text-red-600',
                'On Leave': 'text-purple-600',
                'Holiday': 'text-gray-600',
                'Weekend': 'text-gray-500'
            };
            return colorMap[status] || 'text-gray-600';
        }
    }
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // Set user role globally for Alpine.js
    window.userRole = document.querySelector('meta[name="user-role"]')?.content || 'Employee';

    // Initialize auto-refresh for real-time updates
    setInterval(() => {
        const event = new CustomEvent('refresh-dashboard');
        document.dispatchEvent(event);
    }, 60000); // Refresh every minute for real-time feel
});

// Handle live updates via WebSocket (if available)
if (typeof window.WebSocket !== 'undefined') {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/attendance/`;

    try {
        const socket = new WebSocket(wsUrl);

        socket.onmessage = function(e) {
            const data = JSON.parse(e.data);
            if (data.type === 'attendance_update') {
                // Trigger dashboard refresh
                const event = new CustomEvent('refresh-dashboard');
                document.dispatchEvent(event);
            }
        };

        socket.onclose = function(e) {
            console.log('WebSocket connection closed');
        };

        socket.onerror = function(e) {
            console.log('WebSocket error:', e);
        };
    } catch (error) {
        console.log('WebSocket not available, using polling for updates');
    }
}

// Export for global use
window.enhancedAttendanceDashboard = enhancedAttendanceDashboard;
