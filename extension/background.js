/**
 * ThreatTrace AI Browser Extension - Background Service Worker (Manifest V3)
 * Handles API communication, JWT authentication, storage, and badge telemetry.
 */

const DEFAULT_API_URL = 'http://localhost:5000';

// Initialize default storage on install
chrome.runtime.onInstalled.addListener(async () => {
    const existing = await chrome.storage.local.get(['apiUrl', 'recentScans']);
    if (!existing.apiUrl) {
        await chrome.storage.local.set({ apiUrl: DEFAULT_API_URL, recentScans: [] });
    }
    console.log("🛡️ ThreatTrace AI Extension Service Worker initialized.");
});

// Main Message Dispatcher
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    (async () => {
        try {
            switch (message.type) {
                case 'SCAN_EMAIL':
                    const scanResult = await handleScanEmail(message.data);
                    sendResponse({ success: true, data: scanResult });
                    break;

                case 'CHECK_HEALTH':
                    const healthResult = await handleCheckHealth();
                    sendResponse({ success: true, data: healthResult });
                    break;

                case 'LOGIN':
                    const loginResult = await handleLogin(message.email, message.password);
                    sendResponse(loginResult);
                    break;

                case 'DEMO_LOGIN':
                    const demoResult = await handleDemoLogin(message.role);
                    sendResponse(demoResult);
                    break;

                case 'LOGOUT':
                    await chrome.storage.local.remove(['jwtToken', 'userProfile']);
                    await chrome.action.setBadgeText({ text: '' });
                    sendResponse({ success: true });
                    break;

                case 'GET_CONFIG':
                    const config = await chrome.storage.local.get(['apiUrl', 'jwtToken', 'userProfile', 'recentScans']);
                    sendResponse({ success: true, config });
                    break;

                case 'SAVE_CONFIG':
                    await chrome.storage.local.set({ apiUrl: message.apiUrl || DEFAULT_API_URL });
                    sendResponse({ success: true });
                    break;

                default:
                    sendResponse({ success: false, error: `Unknown message type: ${message.type}` });
            }
        } catch (error) {
            console.error("Background Worker Error:", error);
            sendResponse({ success: false, error: error.message || "Background execution failure" });
        }
    })();
    return true; // Keep message channel open for async response
});

/**
 * Handle scan email request by forwarding to backend /api/analyze
 */
async function handleScanEmail(emailPayload) {
    const { apiUrl = DEFAULT_API_URL, jwtToken, recentScans = [] } = await chrome.storage.local.get(['apiUrl', 'jwtToken', 'recentScans']);

    // Construct rawEmail string if payload is an object
    let rawEmail = '';
    if (typeof emailPayload === 'string') {
        rawEmail = emailPayload;
    } else if (emailPayload && typeof emailPayload === 'object') {
        rawEmail = [
            emailPayload.headersRaw || '',
            `From: ${emailPayload.from || 'Unknown Sender'}`,
            `To: ${emailPayload.to || 'Unknown Recipient'}`,
            `Subject: ${emailPayload.subject || 'No Subject'}`,
            `Date: ${emailPayload.date || new Date().toUTCString()}`,
            '',
            emailPayload.body || ''
        ].filter(Boolean).join('\n');
    }

    if (!rawEmail.trim()) {
        throw new Error("No readable email content could be extracted.");
    }

    // Auto-login with default analyst demo if no token is present
    let token = jwtToken;
    if (!token) {
        const autoAuth = await handleDemoLogin('analyst');
        if (autoAuth.success) {
            token = autoAuth.token;
        }
    }

    const headers = { 'Content-Type': 'application/json' };
    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    const response = await fetch(`${apiUrl}/api/analyze`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ rawEmail })
    });

    if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.error || `Analysis failed with HTTP ${response.status}`);
    }

    const report = await response.json();

    // Update Extension Badge
    const threatScore = report.aiThreatAnalysis?.threatScore || 0;
    if (threatScore >= 70) {
        await chrome.action.setBadgeText({ text: `${threatScore}` });
        await chrome.action.setBadgeBackgroundColor({ color: '#ef4444' });
    } else if (threatScore >= 40) {
        await chrome.action.setBadgeText({ text: `${threatScore}` });
        await chrome.action.setBadgeBackgroundColor({ color: '#f59e0b' });
    } else {
        await chrome.action.setBadgeText({ text: 'OK' });
        await chrome.action.setBadgeBackgroundColor({ color: '#10b981' });
    }

    // Cache recent scan
    const scanSummary = {
        caseId: report.caseId,
        subject: report.emailDetails?.subject || 'Email Scan',
        sender: report.emailDetails?.from || 'Unknown',
        threatScore,
        category: report.aiThreatAnalysis?.threatCategory || 'General',
        timestamp: new Date().toISOString(),
        txHash: report.blockchain?.txHash || null
    };

    const updatedRecent = [scanSummary, ...recentScans.slice(0, 9)];
    await chrome.storage.local.set({ recentScans: updatedRecent });

    return report;
}

/**
 * Check backend health status
 */
async function handleCheckHealth() {
    const { apiUrl = DEFAULT_API_URL } = await chrome.storage.local.get(['apiUrl']);
    try {
        const res = await fetch(`${apiUrl}/api/health`, { method: 'GET' });
        if (res.ok) {
            const data = await res.json();
            return { online: true, details: data };
        }
        return { online: false, error: `HTTP ${res.status}` };
    } catch (err) {
        return { online: false, error: err.message };
    }
}

/**
 * Handle manual login
 */
async function handleLogin(email, password) {
    const { apiUrl = DEFAULT_API_URL } = await chrome.storage.local.get(['apiUrl']);
    try {
        const res = await fetch(`${apiUrl}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });

        const data = await res.json();
        if (!res.ok) {
            return { success: false, error: data.error || 'Authentication failed' };
        }

        await chrome.storage.local.set({
            jwtToken: data.token,
            userProfile: { email: data.email || email, role: data.role, userId: data.userId }
        });

        return { success: true, token: data.token, role: data.role };
    } catch (err) {
        return { success: false, error: err.message || 'Login network error' };
    }
}

/**
 * Handle 1-click Demo profile login (auto-register if missing)
 */
async function handleDemoLogin(role = 'analyst') {
    const { apiUrl = DEFAULT_API_URL } = await chrome.storage.local.get(['apiUrl']);
    const email = `${role}@threatintel.soc`;
    const password = `${role}123!`;

    try {
        let res = await fetch(`${apiUrl}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });

        if (!res.ok) {
            // Auto register demo profile
            await fetch(`${apiUrl}/auth/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password, role })
            });

            res = await fetch(`${apiUrl}/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            });
        }

        const data = await res.json();
        if (res.ok && data.token) {
            await chrome.storage.local.set({
                jwtToken: data.token,
                userProfile: { email, role: data.role || role, userId: data.userId }
            });
            return { success: true, token: data.token, role: data.role || role };
        }

        return { success: false, error: data.error || 'Failed demo authentication' };
    } catch (err) {
        return { success: false, error: err.message };
    }
}
