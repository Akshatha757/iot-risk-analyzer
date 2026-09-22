document.addEventListener('DOMContentLoaded', () => {
    // App State
    let riskDoughnutChart = null;
    let deviceBarChart = null;
    let currentScans = [];
    let currentThreats = [];
    let activeReport = null; // Store current viewed report for download

    // DOM Elements
    const views = document.querySelectorAll('.content-view');
    const navItems = document.querySelectorAll('.nav-item');
    const globalSearch = document.getElementById('global-search');
    const threatSearch = document.getElementById('threat-search');
    const filterRisk = document.getElementById('filter-risk');
    const historyTableBody = document.getElementById('history-table-body');
    const threatDbContainer = document.getElementById('threat-db-container');
    const auditForm = document.getElementById('audit-form');
    const submitBtn = document.getElementById('submit-audit-btn');
    
    // Modal Elements
    const reportModal = document.getElementById('report-modal');
    const modalReportContent = document.getElementById('modal-report-content');
    const closeModalBtn = document.getElementById('close-modal-btn');
    const dismissModalBtn = document.getElementById('dismiss-modal-btn');
    const downloadReportBtn = document.getElementById('download-report-btn');
    const quickAnalyzeBtn = document.getElementById('quick-analyze-btn');
    const downloadProjectZipBtn = document.getElementById('download-project-zip-btn');

    // 1. Clock Initialization
    function updateClock() {
        const clockEl = document.getElementById('clock');
        if (clockEl) {
            const now = new Date();
            clockEl.textContent = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        }
    }
    setInterval(updateClock, 1000);
    updateClock();

    // 2. Navigation System
    function switchView(targetId) {
        views.forEach(view => {
            view.classList.remove('active');
            if (view.id === targetId) {
                view.classList.add('active');
            }
        });

        navItems.forEach(item => {
            item.classList.remove('active');
            if (item.getAttribute('data-target') === targetId) {
                item.classList.add('active');
            }
        });

        // Trigger view-specific loads
        if (targetId === 'dashboard') {
            loadDashboardData();
        } else if (targetId === 'threat-db') {
            loadThreatLibrary();
        }
    }

    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const target = item.getAttribute('data-target');
            switchView(target);
        });
    });

    if (quickAnalyzeBtn) {
        quickAnalyzeBtn.addEventListener('click', () => {
            switchView('analyzer');
        });
    }

    if (downloadProjectZipBtn) {
        downloadProjectZipBtn.addEventListener('click', () => {
            const downloadAnchor = document.createElement('a');
            downloadAnchor.href = '/api/download-zip';
            downloadAnchor.setAttribute('download', 'iot-risk-analyzer.zip');
            document.body.appendChild(downloadAnchor);
            downloadAnchor.click();
            downloadAnchor.remove();
        });
    }

    // 3. Dashboard Charts and Stats Loader
    async function loadDashboardData() {
        try {
            const response = await fetch('/api/dashboard-stats');
            const data = await response.json();

            if (response.ok) {
                // Update statistic cards
                document.getElementById('stat-total-scans').textContent = data.total_scans;
                document.getElementById('stat-avg-score').textContent = data.avg_score;
                document.getElementById('stat-high-risk').textContent = data.risk_breakdown.High;

                // Update Stats Colors
                const avgScoreEl = document.getElementById('stat-avg-score');
                if (data.avg_score > 70) {
                    avgScoreEl.className = 'text-danger';
                } else if (data.avg_score > 30) {
                    avgScoreEl.className = 'text-warning';
                } else {
                    avgScoreEl.className = 'text-success';
                }

                // Render Charts
                renderRiskChart(data.risk_breakdown);
                renderDeviceChart(data.device_breakdown);

                // Fetch history
                loadHistoryTable();
            }
        } catch (error) {
            console.error('Error fetching dashboard stats:', error);
        }
    }

    function renderRiskChart(breakdown) {
        const ctx = document.getElementById('riskChart').getContext('2d');
        
        if (riskDoughnutChart) {
            riskDoughnutChart.destroy();
        }

        const isEmpty = breakdown.Low === 0 && breakdown.Medium === 0 && breakdown.High === 0;
        
        riskDoughnutChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: isEmpty ? ['No Data'] : ['Low Risk', 'Medium Risk', 'High Risk'],
                datasets: [{
                    data: isEmpty ? [1] : [breakdown.Low, breakdown.Medium, breakdown.High],
                    backgroundColor: isEmpty ? ['rgba(255, 255, 255, 0.05)'] : ['#10b981', '#f59e0b', '#ef4444'],
                    borderColor: 'rgba(22, 24, 38, 0.9)',
                    borderWidth: 2,
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#9ca3af',
                            font: { family: 'Outfit', size: 12 },
                            padding: 15
                        }
                    },
                    tooltip: {
                        enabled: !isEmpty
                    }
                },
                cutout: '70%'
            }
        });
    }

    function renderDeviceChart(breakdown) {
        const ctx = document.getElementById('deviceChart').getContext('2d');

        if (deviceBarChart) {
            deviceBarChart.destroy();
        }

        const labels = Object.keys(breakdown);
        const data = Object.values(breakdown);

        deviceBarChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels.length === 0 ? ['No Data'] : labels,
                datasets: [{
                    label: 'Audited Devices',
                    data: data.length === 0 ? [0] : data,
                    backgroundColor: 'rgba(99, 102, 241, 0.65)',
                    borderColor: '#6366f1',
                    borderWidth: 1.5,
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { color: '#9ca3af', font: { family: 'Outfit' } }
                    },
                    y: {
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#9ca3af', stepSize: 1, font: { family: 'Outfit' } }
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    }

    // 4. Scan History Table Populator
    async function loadHistoryTable() {
        try {
            const response = await fetch('/api/scans');
            currentScans = await response.json();

            if (response.ok) {
                applyTableFilters();
            }
        } catch (error) {
            console.error('Error listing scan history:', error);
            historyTableBody.innerHTML = '<tr><td colspan="7" class="text-center text-danger py-4">Failed to load scan history.</td></tr>';
        }
    }

    function applyTableFilters() {
        const riskFilter = filterRisk.value;
        const searchVal = globalSearch.value.toLowerCase().trim();

        let filtered = currentScans;

        // Filter by Risk Level
        if (riskFilter !== 'all') {
            filtered = filtered.filter(scan => scan.risk_level === riskFilter);
        }

        // Filter by global search term
        if (searchVal) {
            filtered = filtered.filter(scan => {
                const name = (scan.device_name || '').toLowerCase();
                const type = (scan.device_type || '').toLowerCase();
                const brand = (scan.manufacturer || '').toLowerCase();
                return name.includes(searchVal) || type.includes(searchVal) || brand.includes(searchVal);
            });
        }

        // Render Table Body
        if (filtered.length === 0) {
            historyTableBody.innerHTML = '<tr><td colspan="7" class="text-center text-muted py-4">No audits match your criteria.</td></tr>';
            return;
        }

        historyTableBody.innerHTML = filtered.map(scan => {
            const date = new Date(scan.timestamp);
            const formattedDate = date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            const riskClass = `badge-${scan.risk_level.toLowerCase()}`;
            const scoreClass = scan.risk_level.toLowerCase();
            const deviceIcon = getDeviceIcon(scan.device_type);

            return `
                <tr>
                    <td class="text-muted" style="font-size:12px;">${formattedDate}</td>
                    <td>
                        <div style="display:flex; align-items:center; gap:10px;">
                            <i class="${deviceIcon}" style="color:var(--color-primary); font-size:16px;"></i>
                            <strong>${escapeHtml(scan.device_name || 'Device')}</strong>
                        </div>
                    </td>
                    <td>${escapeHtml(scan.device_type.replace('_', ' ').toUpperCase())}</td>
                    <td>${escapeHtml(scan.manufacturer || 'Unknown')}</td>
                    <td><span class="score-badge ${scoreClass}">${scan.risk_score}/100</span></td>
                    <td><span class="badge ${riskClass}">${scan.risk_level}</span></td>
                    <td class="text-right">
                        <button class="btn btn-secondary btn-sm view-report-btn" data-id="${scan.id}" title="View Details">
                            <i class="fa-solid fa-file-contract"></i> View Report
                        </button>
                        <button class="btn btn-secondary btn-sm btn-icon-only delete-scan-btn" data-id="${scan.id}" style="color:var(--color-danger); margin-left: 6px;" title="Delete Record">
                            <i class="fa-solid fa-trash-can"></i>
                        </button>
                    </td>
                </tr>
            `;
        }).join('');

        // Attach event listeners to dynamic buttons
        document.querySelectorAll('.view-report-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const scanId = btn.getAttribute('data-id');
                const scan = currentScans.find(s => s.id == scanId);
                if (scan) {
                    showReportModal(scan);
                }
            });
        });

        document.querySelectorAll('.delete-scan-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const scanId = btn.getAttribute('data-id');
                if (confirm('Are you sure you want to permanently delete this audit record?')) {
                    try {
                        const response = await fetch(`/api/scans/${scanId}`, { method: 'DELETE' });
                        if (response.ok) {
                            loadDashboardData();
                        }
                    } catch (err) {
                        console.error('Delete action failed:', err);
                    }
                }
            });
        });
    }

    // 5. Threat Intelligence Library Loader
    async function loadThreatLibrary() {
        try {
            const response = await fetch('/api/threat-intelligence');
            currentThreats = await response.json();

            if (response.ok) {
                applyThreatFilters();
            }
        } catch (error) {
            console.error('Error fetching threats list:', error);
            threatDbContainer.innerHTML = '<div class="text-center text-danger w-100 py-4">Failed to fetch threat database.</div>';
        }
    }

    function applyThreatFilters() {
        const query = threatSearch.value.toLowerCase().trim();
        let filtered = currentThreats;

        if (query) {
            filtered = currentThreats.filter(t => 
                t.title.toLowerCase().includes(query) ||
                t.description.toLowerCase().includes(query) ||
                t.remediation.toLowerCase().includes(query) ||
                t.device_type.toLowerCase().includes(query)
            );
        }

        if (filtered.length === 0) {
            threatDbContainer.innerHTML = '<div class="text-center text-muted w-100 py-4">No threat definitions matching your search.</div>';
            return;
        }

        threatDbContainer.innerHTML = filtered.map(t => {
            const impactBadgeClass = `badge-${t.impact.toLowerCase() === 'critical' ? 'high' : t.impact.toLowerCase()}`;
            return `
                <div class="card glass threat-card">
                    <div class="threat-header">
                        <h3>${escapeHtml(t.title)}</h3>
                        <span class="badge ${impactBadgeClass}">${t.impact}</span>
                    </div>
                    <p>${escapeHtml(t.description)}</p>
                    <div class="threat-mitigation">
                        <strong>Defense Checklist:</strong>
                        <span>${escapeHtml(t.remediation)}</span>
                    </div>
                </div>
            `;
        }).join('');
    }

    // 6. Form Submission handler (Executing Security Audit)
    if (auditForm) {
        auditForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            // Toggle spinner
            submitBtn.disabled = true;
            submitBtn.querySelector('.btn-text').textContent = 'Analyzing Configurations...';
            submitBtn.querySelector('.spinner').classList.remove('hidden');

            const payload = {
                device_name: document.getElementById('device_name').value.trim(),
                manufacturer: document.getElementById('manufacturer').value.trim(),
                device_type: document.getElementById('device_type').value,
                connection_type: document.getElementById('connection_type').value,
                firmware_version: document.getElementById('firmware_version').value.trim(),
                default_creds_changed: document.getElementById('default_creds_changed').checked,
                firmware_outdated: document.getElementById('firmware_outdated').checked,
                network_isolated: document.getElementById('network_isolated').checked,
                cloud_connected: document.getElementById('cloud_connected').checked,
                physical_access: document.getElementById('physical_access').checked,
                open_ports: document.getElementById('open_ports').value
            };

            try {
                const response = await fetch('/api/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const result = await response.json();

                if (response.ok) {
                    auditForm.reset();
                    // Set default checkboxes
                    document.getElementById('default_creds_changed').checked = true;
                    document.getElementById('cloud_connected').checked = true;

                    // Show Report Modal
                    showReportModal(result);
                } else {
                    alert(`Audit failed: ${result.error || 'Unknown Error'}`);
                }
            } catch (err) {
                console.error('API Post failed:', err);
                alert('Connection error occurred while attempting the analysis.');
            } finally {
                // Restore button
                submitBtn.disabled = false;
                submitBtn.querySelector('.btn-text').textContent = 'Execute Security Audit';
                submitBtn.querySelector('.spinner').classList.add('hidden');
            }
        });
    }

    // 7. Report Modal Rendering Engine
    function showReportModal(report) {
        activeReport = report;
        
        // Compute circular gauge offset
        // 2 * PI * r = circumference of circle. Radius = 40. Circumference = ~251.3
        const radius = 40;
        const circumference = 2 * Math.PI * radius;
        const offset = circumference - (report.risk_score / 100) * circumference;

        // Score theme coloring
        let strokeColor = '#10b981'; // Low
        if (report.risk_score > 70) {
            strokeColor = '#ef4444'; // High
        } else if (report.risk_score > 30) {
            strokeColor = '#f59e0b'; // Medium
        }

        // Build Threats List HTML
        let threatsHtml = '';
        if (report.threats && report.threats.length > 0) {
            threatsHtml = report.threats.map(t => {
                const severity = (t.impact || 'medium').toLowerCase();
                const labelColor = severity === 'critical' || severity === 'high' ? 'critical' : severity;
                return `
                    <div class="report-threat-item ${labelColor}">
                        <div class="threat-item-meta">
                            <span class="threat-item-title">${escapeHtml(t.title)}</span>
                            <span class="badge badge-${labelColor}">${t.impact}</span>
                        </div>
                        <p>${escapeHtml(t.description)}</p>
                    </div>
                `;
            }).join('');
        } else {
            threatsHtml = '<div class="text-center text-success py-3"><i class="fa-solid fa-circle-check"></i> No critical vulnerabilities detected. Device complies with safety directives.</div>';
        }

        // Build Mitigations List HTML
        let mitigationsHtml = '';
        if (report.mitigations && report.mitigations.length > 0) {
            mitigationsHtml = `
                <div class="report-mitigations-box">
                    <ul>
                        ${report.mitigations.map(m => `
                            <li>
                                <i class="fa-solid fa-circle-info"></i>
                                <span>${escapeHtml(m)}</span>
                            </li>
                        `).join('')}
                    </ul>
                </div>
            `;
        } else {
            mitigationsHtml = '<div class="text-center text-success py-2">No remediations required.</div>';
        }

        // Inject Content into Modal
        modalReportContent.innerHTML = `
            <div class="report-header">
                <div class="report-gauge-container">
                    <svg class="gauge-svg" width="100" height="100">
                        <circle class="gauge-bg" cx="50" cy="50" r="${radius}"></circle>
                        <circle class="gauge-fill" cx="50" cy="50" r="${radius}" 
                                style="stroke-dasharray: ${circumference}; stroke-dashoffset: ${offset}; stroke: ${strokeColor};">
                        </circle>
                    </svg>
                    <div class="report-gauge-value" style="color: ${strokeColor}">${report.risk_score}</div>
                </div>
                <div class="report-summary-text">
                    <h3>${escapeHtml(report.device_name || 'Device Audit')}</h3>
                    <p>Type: <strong>${escapeHtml(report.device_type.replace('_', ' ').toUpperCase())}</strong> | Manufacturer: <strong>${escapeHtml(report.manufacturer || 'Unknown')}</strong></p>
                    <p>Security Index Evaluation: <strong style="color: ${strokeColor}">${report.risk_level.toUpperCase()} RISK PROFILE</strong></p>
                </div>
            </div>

            <div class="report-section-title">
                <i class="fa-solid fa-skull-crossbones"></i> Identified Cyber Threats
            </div>
            <div class="report-threats-list">
                ${threatsHtml}
            </div>

            <div class="report-section-title">
                <i class="fa-solid fa-screwdriver-wrench"></i> Suggested Remediations
            </div>
            ${mitigationsHtml}
        `;

        // Open Modal
        reportModal.classList.add('active');
    }

    // Modal Close Triggers
    function closeModal() {
        reportModal.classList.remove('active');
        activeReport = null;
        // Auto-refresh Dashboard on close of a newly completed audit
        switchView('dashboard');
    }

    closeModalBtn.addEventListener('click', closeModal);
    dismissModalBtn.addEventListener('click', closeModal);
    reportModal.addEventListener('click', (e) => {
        if (e.target === reportModal) {
            closeModal();
        }
    });

    // 8. Download Report Trigger
    if (downloadReportBtn) {
        downloadReportBtn.addEventListener('click', () => {
            if (!activeReport) return;
            
            const filename = `IoT_Shield_Report_${activeReport.device_name.replace(/\s+/g, '_')}_${activeReport.id}.json`;
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(activeReport, null, 4));
            const downloadAnchor = document.createElement('a');
            downloadAnchor.setAttribute("href", dataStr);
            downloadAnchor.setAttribute("download", filename);
            document.body.appendChild(downloadAnchor);
            downloadAnchor.click();
            downloadAnchor.remove();
        });
    }

    // 9. Input & Global Searches Key Listening
    if (globalSearch) {
        globalSearch.addEventListener('input', () => {
            // If in threat-db, search threats, else search history table
            const activeView = document.querySelector('.content-view.active');
            if (activeView.id === 'threat-db') {
                threatSearch.value = globalSearch.value;
                applyThreatFilters();
            } else {
                applyTableFilters();
            }
        });
    }

    if (threatSearch) {
        threatSearch.addEventListener('input', applyThreatFilters);
    }

    if (filterRisk) {
        filterRisk.addEventListener('change', applyTableFilters);
    }

    // Escape HTML Helper
    function escapeHtml(str) {
        if (!str) return '';
        return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    // Device Icons Helper
    function getDeviceIcon(deviceType) {
        const icons = {
            'camera': 'fa-solid fa-video',
            'router': 'fa-solid fa-server',
            'smart_lock': 'fa-solid fa-key',
            'smart_bulb': 'fa-solid fa-lightbulb',
            'thermostat': 'fa-solid fa-temperature-half',
            'voice_assistant': 'fa-solid fa-microphone-lines',
            'smart_plug': 'fa-solid fa-plug',
            'smart_tv': 'fa-solid fa-tv',
            'other': 'fa-solid fa-circle-nodes'
        };
        return icons[deviceType] || 'fa-solid fa-network-wired';
    }

    // 10. Auto-Detect IP Ports Handler
    const autoScanIpBtn = document.getElementById('auto-scan-ip-btn');
    const targetIpInput = document.getElementById('target_ip_scan');
    const openPortsInput = document.getElementById('open_ports');
    const portScanStatus = document.getElementById('port-scan-status');

    if (autoScanIpBtn) {
        autoScanIpBtn.addEventListener('click', async () => {
            const ip = targetIpInput ? targetIpInput.value.trim() || '127.0.0.1' : '127.0.0.1';
            autoScanIpBtn.disabled = true;
            autoScanIpBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Probing ${ip}...`;
            if (portScanStatus) portScanStatus.textContent = `Probing ports on ${ip}... Please wait.`;

            try {
                const response = await fetch('/api/scan-ip', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target_ip: ip })
                });

                if (response.ok) {
                    const data = await response.json();
                    if (openPortsInput) {
                        openPortsInput.value = data.open_ports_str || '';
                    }
                    if (portScanStatus) {
                        if (data.open_ports && data.open_ports.length > 0) {
                            portScanStatus.innerHTML = `<strong style="color: #ef4444;">Found open ports on ${data.target_ip}: ${data.open_ports_str}</strong>`;
                        } else {
                            portScanStatus.innerHTML = `<strong style="color: #10b981;">No common open ports detected on ${data.target_ip}</strong>`;
                        }
                    }
                } else {
                    if (portScanStatus) portScanStatus.textContent = 'Scan failed. Ensure target IP is reachable.';
                }
            } catch (err) {
                console.error('Scan error:', err);
                if (portScanStatus) portScanStatus.textContent = 'Error connecting to port scanner service.';
            } finally {
                autoScanIpBtn.disabled = false;
                autoScanIpBtn.innerHTML = `<i class="fa-solid fa-radar"></i> Auto-Detect Ports`;
            }
        });
    }

    // Initial load
    loadDashboardData();
});
