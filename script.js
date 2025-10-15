document.addEventListener('DOMContentLoaded', () => {

    // ===== DUMMY DATA =====
    const dummyData = [
        {
            id: 1,
            ip_address: '203.0.113.101',
            make: 'Hikvision',
            model: 'DS-2CD2142FWD-I',
            firmware: '5.4.0',
            location: { city: 'Mumbai', country: 'IN', lat: 19.0760, lon: 72.8777 },
            status: 'High',
            open_ports: [80, 443, 554, 8000],
            last_scanned: '2025-10-15 10:30 UTC',
            vulnerabilities: [
                { cve: 'CVE-2017-7921', description: 'Hikvision IP Camera Access Bypass', severity: 'High', remediation: 'Update firmware to version 5.4.5 or later. Ensure the camera is not exposed directly to the internet.' },
                { cve: 'CVE-2021-36260', description: 'Command Injection Vulnerability', severity: 'High', remediation: 'Apply the latest security patches from the vendor immediately.' }
            ]
        },
        {
            id: 2,
            ip_address: '198.51.100.22',
            make: 'Dahua',
            model: 'IPC-HFW4431R-Z',
            firmware: '2.800.0000000.6.R',
            location: { city: 'London', country: 'GB', lat: 51.5074, lon: -0.1278 },
            status: 'Medium',
            open_ports: [80, 554],
            last_scanned: '2025-10-15 11:05 UTC',
            vulnerabilities: [
                { cve: 'CVE-2019-3943', description: 'Default credentials are in use (admin/admin).', severity: 'Medium', remediation: 'Change the default administrator password immediately. Use a strong, unique password.' }
            ]
        },
        {
            id: 3,
            ip_address: '192.0.2.55',
            make: 'Axis',
            model: 'P1365-E',
            firmware: '6.50.5.5',
            location: { city: 'Tokyo', country: 'JP', lat: 35.6895, lon: 139.6917 },
            status: 'Low',
            open_ports: [443, 554],
            last_scanned: '2025-10-15 12:15 UTC',
            vulnerabilities: [
                { cve: 'N/A', description: 'No critical vulnerabilities found. Device is up-to-date.', severity: 'Low', remediation: 'Continue to monitor for new firmware updates and security advisories.' }
            ]
        },
        {
            id: 4,
            ip_address: '203.0.113.14',
            make: 'Hikvision',
            model: 'DS-2DE4225IW-DE',
            firmware: '5.5.80',
            location: { city: 'New York', country: 'US', lat: 40.7128, lon: -74.0060 },
            status: 'High',
            open_ports: [80, 443, 554, 8000],
            last_scanned: '2025-10-15 09:45 UTC',
            vulnerabilities: [
                { cve: 'CVE-2017-7921', description: 'Hikvision IP Camera Access Bypass (Outdated Firmware)', severity: 'High', remediation: 'Update firmware to the latest available version.' },
                { cve: 'N/A', description: 'RTSP stream accessible without authentication.', severity: 'Medium', remediation: 'Enable RTSP authentication in the camera settings and use a strong password.' }
            ]
        }
    ];

    // ===== DOM ELEMENTS =====
    const scanBtn = document.getElementById('scanBtn');
    const loader = document.getElementById('loader');
    const deviceTableBody = document.querySelector('#deviceTable tbody');
    const filterRisk = document.getElementById('filterRisk');
    const map = document.getElementById('map');
    const totalDevicesEl = document.getElementById('totalDevices');
    const highRiskDevicesEl = document.getElementById('highRiskDevices');
    const mediumRiskDevicesEl = document.getElementById('mediumRiskDevices');
    const lowRiskDevicesEl = document.getElementById('lowRiskDevices');

    // Modal
    const modal = document.getElementById('deviceModal');
    const closeModalBtn = document.getElementById('closeModalBtn');
    const modalTitle = document.getElementById('modalTitle');
    const modalSummary = document.querySelector('.device-summary');
    const modalVulnerabilities = document.getElementById('modalVulnerabilities');

    // ===== FUNCTIONS =====

    function showLoader() { loader.classList.add('active'); }
    function hideLoader() { loader.classList.remove('active'); }

    function updateStats(devices) {
        totalDevicesEl.textContent = devices.length;
        highRiskDevicesEl.textContent = devices.filter(d => d.status === 'High').length;
        mediumRiskDevicesEl.textContent = devices.filter(d => d.status === 'Medium').length;
        lowRiskDevicesEl.textContent = devices.filter(d => d.status === 'Low').length;
    }

    function renderTable(devices) {
        deviceTableBody.innerHTML = '';
        if (devices.length === 0) {
            deviceTableBody.innerHTML = `<tr class="placeholder"><td colspan="6">No devices match the current filter.</td></tr>`;
            return;
        }

        devices.forEach(device => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><span class="risk-indicator risk-${device.status}"></span>${device.status}</td>
                <td>${device.ip_address}</td>
                <td>${device.make} ${device.model}</td>
                <td>${device.location.city}, ${device.location.country}</td>
                <td>${device.last_scanned}</td>
                <td><button class="action-btn" data-id="${device.id}">View Details</button></td>
            `;
            deviceTableBody.appendChild(row);
        });
    }

    function renderMapPins(devices) {
        map.querySelectorAll('.map-pin').forEach(pin => pin.remove());
        const mapWidth = map.clientWidth;
        const mapHeight = map.clientHeight;

        devices.forEach(device => {
            const pin = document.createElement('div');
            pin.className = `map-pin pin-${device.status.toLowerCase()}`;

            const x = (device.location.lon + 180) * (mapWidth / 360);
            const y = (mapHeight / 2) - (mapWidth * Math.log(Math.tan((Math.PI / 4) + (device.location.lat * Math.PI / 180) / 2)) / (2 * Math.PI));

            pin.style.left = `${x}px`;
            pin.style.top = `${y}px`;
            pin.title = `${device.ip_address} - ${device.location.city}`;
            map.appendChild(pin);
        });
    }

    function populateDashboard(data) {
        updateStats(data);
        renderTable(data);
        renderMapPins(data);
    }

    function filterDevices() {
        const riskLevel = filterRisk.value;
        const filtered = (riskLevel === 'all') ? dummyData : dummyData.filter(d => d.status === riskLevel);
        renderTable(filtered);
    }

    function showModal(deviceId) {
        const device = dummyData.find(d => d.id === parseInt(deviceId));
        if (!device) return;

        modalTitle.textContent = `Details for ${device.ip_address}`;

        modalSummary.innerHTML = `
            <div class="summary-item"><strong>Make & Model</strong><span>${device.make} ${device.model}</span></div>
            <div class="summary-item"><strong>Firmware</strong><span>${device.firmware}</span></div>
            <div class="summary-item"><strong>Location</strong><span>${device.location.city}, ${device.location.country}</span></div>
            <div class="summary-item"><strong>Risk Level</strong><span><span class="risk-indicator risk-${device.status}"></span>${device.status}</span></div>
            <div class="summary-item"><strong>Open Ports</strong><span>${device.open_ports.join(', ')}</span></div>
            <div class="summary-item"><strong>Last Scanned</strong><span>${device.last_scanned}</span></div>
        `;

        modalVulnerabilities.innerHTML = '';
        if (device.vulnerabilities.length > 0) {
            device.vulnerabilities.forEach(vuln => {
                const vulnEl = document.createElement('div');
                vulnEl.className = `vuln-item ${vuln.severity.toLowerCase()}`;
                vulnEl.innerHTML = `
                    <div class="vuln-header">
                        <div>
                            <strong>${vuln.cve}</strong>
                            <p>${vuln.description}</p>
                        </div>
                        <span class="severity ${vuln.severity}">${vuln.severity}</span>
                    </div>
                    <div class="vuln-content">
                        <strong>Remediation Steps:</strong>
                        <p>${vuln.remediation}</p>
                    </div>
                `;
                modalVulnerabilities.appendChild(vulnEl);
            });
        } else {
            modalVulnerabilities.innerHTML = `<p>No specific vulnerabilities found for this device.</p>`;
        }

        modal.classList.add('active');
    }

    function hideModal() { modal.classList.remove('active'); }

    scanBtn.addEventListener('click', () => {
        showLoader();
        setTimeout(() => {
            populateDashboard(dummyData);
            hideLoader();
        }, 2000);
    });

    filterRisk.addEventListener('change', filterDevices);

    deviceTableBody.addEventListener('click', e => {
        if (e.target.classList.contains('action-btn')) {
            const deviceId = e.target.getAttribute('data-id');
            showModal(deviceId);
        }
    });

    modalVulnerabilities.addEventListener('click', e => {
        const header = e.target.closest('.vuln-header');
        if (header) {
            const vulnItem = header.parentElement;
            vulnItem.classList.toggle('active');
        }
    });

    closeModalBtn.addEventListener('click', hideModal);
    modal.addEventListener('click', e => {
        if (e.target === modal) hideModal();
    });
});
