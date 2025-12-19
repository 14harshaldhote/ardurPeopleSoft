/**
 * Dashboard Charts for Attendance Module
 * Provides chart initialization and data visualization utilities
 */

// Chart color palette
const CHART_COLORS = {
    present: '#10B981',      // Green
    absent: '#EF4444',       // Red
    late: '#F59E0B',         // Yellow/Amber
    leave: '#8B5CF6',        // Purple
    holiday: '#3B82F6',      // Blue
    weekend: '#6B7280',      // Gray
    primary: '#4F46E5',      // Indigo
    secondary: '#9CA3AF'     // Gray
};

// Initialize attendance pie chart
function initAttendancePieChart(containerId, data) {
    const container = document.getElementById(containerId);
    if (!container || typeof echarts === 'undefined') {
        console.warn('ECharts not loaded or container not found:', containerId);
        return null;
    }

    const chart = echarts.init(container);

    const option = {
        tooltip: {
            trigger: 'item',
            formatter: '{b}: {c} ({d}%)'
        },
        legend: {
            orient: 'horizontal',
            bottom: '0%',
            itemGap: 10,
            textStyle: {
                fontSize: 11
            }
        },
        series: [{
            type: 'pie',
            radius: ['40%', '70%'],
            center: ['50%', '45%'],
            avoidLabelOverlap: true,
            itemStyle: {
                borderRadius: 6,
                borderColor: '#fff',
                borderWidth: 2
            },
            label: {
                show: false
            },
            emphasis: {
                label: {
                    show: true,
                    fontSize: 14,
                    fontWeight: 'bold'
                }
            },
            data: [
                { value: data.present || 0, name: 'Present', itemStyle: { color: CHART_COLORS.present } },
                { value: data.absent || 0, name: 'Absent', itemStyle: { color: CHART_COLORS.absent } },
                { value: data.late || 0, name: 'Late', itemStyle: { color: CHART_COLORS.late } },
                { value: data.leave || 0, name: 'Leave', itemStyle: { color: CHART_COLORS.leave } }
            ].filter(item => item.value > 0)
        }]
    };

    chart.setOption(option);

    // Handle resize
    window.addEventListener('resize', () => chart.resize());

    return chart;
}

// Initialize weekly trend line chart
function initWeeklyTrendChart(containerId, data) {
    const container = document.getElementById(containerId);
    if (!container || typeof echarts === 'undefined') {
        console.warn('ECharts not loaded or container not found:', containerId);
        return null;
    }

    const chart = echarts.init(container);

    const days = data.days || ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    const hours = data.hours || [0, 0, 0, 0, 0, 0, 0];

    const option = {
        tooltip: {
            trigger: 'axis',
            formatter: '{b}: {c} hours'
        },
        grid: {
            left: '3%',
            right: '4%',
            bottom: '3%',
            top: '10%',
            containLabel: true
        },
        xAxis: {
            type: 'category',
            data: days,
            axisLine: {
                lineStyle: { color: '#E5E7EB' }
            },
            axisLabel: {
                color: '#6B7280',
                fontSize: 11
            }
        },
        yAxis: {
            type: 'value',
            name: 'Hours',
            nameTextStyle: {
                color: '#9CA3AF',
                fontSize: 11
            },
            axisLine: {
                show: false
            },
            axisTick: {
                show: false
            },
            splitLine: {
                lineStyle: {
                    color: '#F3F4F6',
                    type: 'dashed'
                }
            },
            axisLabel: {
                color: '#6B7280',
                fontSize: 11
            }
        },
        series: [{
            data: hours,
            type: 'line',
            smooth: true,
            symbol: 'circle',
            symbolSize: 8,
            lineStyle: {
                color: CHART_COLORS.primary,
                width: 3
            },
            itemStyle: {
                color: CHART_COLORS.primary,
                borderColor: '#fff',
                borderWidth: 2
            },
            areaStyle: {
                color: {
                    type: 'linear',
                    x: 0, y: 0, x2: 0, y2: 1,
                    colorStops: [
                        { offset: 0, color: 'rgba(79, 70, 229, 0.3)' },
                        { offset: 1, color: 'rgba(79, 70, 229, 0.05)' }
                    ]
                }
            }
        }]
    };

    chart.setOption(option);

    // Handle resize
    window.addEventListener('resize', () => chart.resize());

    return chart;
}

// Initialize monthly bar chart
function initMonthlyBarChart(containerId, data) {
    const container = document.getElementById(containerId);
    if (!container || typeof echarts === 'undefined') {
        console.warn('ECharts not loaded or container not found:', containerId);
        return null;
    }

    const chart = echarts.init(container);

    const option = {
        tooltip: {
            trigger: 'axis',
            axisPointer: { type: 'shadow' }
        },
        grid: {
            left: '3%',
            right: '4%',
            bottom: '3%',
            top: '10%',
            containLabel: true
        },
        xAxis: {
            type: 'category',
            data: data.labels || [],
            axisLine: {
                lineStyle: { color: '#E5E7EB' }
            },
            axisLabel: {
                color: '#6B7280',
                fontSize: 10,
                rotate: 45
            }
        },
        yAxis: {
            type: 'value',
            axisLine: { show: false },
            axisTick: { show: false },
            splitLine: {
                lineStyle: {
                    color: '#F3F4F6',
                    type: 'dashed'
                }
            },
            axisLabel: {
                color: '#6B7280',
                fontSize: 11
            }
        },
        series: [{
            data: data.values || [],
            type: 'bar',
            barWidth: '60%',
            itemStyle: {
                color: {
                    type: 'linear',
                    x: 0, y: 0, x2: 0, y2: 1,
                    colorStops: [
                        { offset: 0, color: CHART_COLORS.primary },
                        { offset: 1, color: '#818CF8' }
                    ]
                },
                borderRadius: [4, 4, 0, 0]
            }
        }]
    };

    chart.setOption(option);

    // Handle resize
    window.addEventListener('resize', () => chart.resize());

    return chart;
}

// Auto-initialize charts on page load
document.addEventListener('DOMContentLoaded', function () {
    // Look for chart containers with data attributes
    const pieChartContainers = document.querySelectorAll('[data-chart-type="attendance-pie"]');
    const trendChartContainers = document.querySelectorAll('[data-chart-type="weekly-trend"]');
    const barChartContainers = document.querySelectorAll('[data-chart-type="monthly-bar"]');

    pieChartContainers.forEach(container => {
        const data = JSON.parse(container.dataset.chartData || '{}');
        initAttendancePieChart(container.id, data);
    });

    trendChartContainers.forEach(container => {
        const data = JSON.parse(container.dataset.chartData || '{}');
        initWeeklyTrendChart(container.id, data);
    });

    barChartContainers.forEach(container => {
        const data = JSON.parse(container.dataset.chartData || '{}');
        initMonthlyBarChart(container.id, data);
    });
});

// Export for module usage if needed
if (typeof window !== 'undefined') {
    window.AttendanceCharts = {
        CHART_COLORS,
        initAttendancePieChart,
        initWeeklyTrendChart,
        initMonthlyBarChart
    };
}
