/**
 * ThreatTrace AI - Popup Controller Script
 */

document.addEventListener('DOMContentLoaded', async () => {
    const healthStatusEl = document.getElementById('health-status');
    const healthTextEl = document.getElementById('health-text');
    const roleBadgeEl = document.getElementById('role-badge');
    const userEmailEl = document.getElementById('user-email');
    const btnLogout = document.getElementById('btn-logout');
    const btnScanTab = document.getElementById('btn-scan-tab');
    const inputApiUrl = document.getElementById('input-api-url');
    const btnSaveUrl = document.getElementById('btn-save-url');
    const recentListEl = document.getElementById('recent-list');

    // Demo Buttons
    const btnAdmin = document.getElementById('btn-demo-admin');
    const btnAnalyst = document.getElementById('btn-demo-analyst');
    const btnAuditor = document.getElementById('btn-demo-auditor');

    // 1. Load Stored Settings & User Profile
    await refreshState();

    // 2. Health Check
    chrome.runtime.sendMessage({ type: 'CHECK_HEALTH' }, (response) => {
        if (response && response.data?.online) {
            healthStatusEl.className = 'status-indicator online';
            healthTextEl.innerText = 'Connected';
        } else {
            healthStatusEl.className = 'status-indicator offline';
            healthTextEl.innerText = 'Disconnected';
        }
    });

    // 3. Demo Login Handlers
    btnAdmin.addEventListener('click', () => switchDemoRole('admin'));
    btnAnalyst.addEventListener('click', () => switchDemoRole('analyst'));
    btnAuditor.addEventListener('click', () => switchDemoRole('auditor'));

    // 4. Logout Handler
    btnLogout.addEventListener('click', () => {
        chrome.runtime.sendMessage({ type: 'LOGOUT' }, () => {
            refreshState();
        });
    });

    // 5. Save API URL Handler
    btnSaveUrl.addEventListener('click', () => {
        const newUrl = inputApiUrl.value.trim() || 'http://localhost:5000';
        chrome.runtime.sendMessage({ type: 'SAVE_CONFIG', apiUrl: newUrl }, () => {
            alert('API URL saved.');
            refreshState();
        });
    });

    // 6. Scan Current Tab Handler
    btnScanTab.addEventListener('click', async () => {
        btnScanTab.disabled = true;
        btnScanTab.innerText = '⏳ Triggering scan on active tab...';

        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab && tab.id) {
            chrome.tabs.sendMessage(tab.id, { type: 'TRIGGER_SCAN' }, (res) => {
                btnScanTab.disabled = false;
                btnScanTab.innerText = '⚡ Scan Current Active Email';
                window.close(); // Close popup so user sees injected overlay
            });
        } else {
            btnScanTab.disabled = false;
            btnScanTab.innerText = '⚡ Scan Current Active Email';
        }
    });

    async function switchDemoRole(role) {
        chrome.runtime.sendMessage({ type: 'DEMO_LOGIN', role }, (res) => {
            if (res && res.success) {
                refreshState();
            } else {
                alert(`Demo Login Error: ${res?.error || 'Failed to authenticate'}`);
            }
        });
    }

    async function refreshState() {
        chrome.runtime.sendMessage({ type: 'GET_CONFIG' }, (res) => {
            if (!res || !res.config) return;
            const { apiUrl, userProfile, recentScans = [] } = res.config;

            if (apiUrl) inputApiUrl.value = apiUrl;

            if (userProfile && userProfile.email) {
                userEmailEl.innerText = userProfile.email;
                roleBadgeEl.innerText = (userProfile.role || 'ANALYST').toUpperCase();
                roleBadgeEl.className = `role-badge ${userProfile.role || 'analyst'}`;
            } else {
                userEmailEl.innerText = 'Not Signed In';
                roleBadgeEl.innerText = 'GUEST';
                roleBadgeEl.className = 'role-badge';
            }

            renderRecentScans(recentScans);
        });
    }

    function renderRecentScans(scans) {
        if (!scans || scans.length === 0) {
            recentListEl.innerHTML = '<div class="empty-state">No recent email scans logged yet.</div>';
            return;
        }

        recentListEl.innerHTML = scans.map(s => {
            const scoreClass = s.threatScore >= 70 ? 'high' : 'safe';
            return `
                <div class="recent-item">
                    <div class="recent-subject" title="${s.subject}">${s.subject}</div>
                    <div class="recent-score ${scoreClass}">${s.threatScore}/100</div>
                </div>
            `;
        }).join('');
    }
});
