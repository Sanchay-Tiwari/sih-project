/**
 * ThreatTrace AI - Content Script (Manifest V3)
 * Injects real-time forensic scanning controls into Gmail, Outlook Web, and Yahoo Mail.
 */

(function () {
    console.log("🛡️ ThreatTrace AI Content Script Loaded.");

    const PROVIDER = detectProvider();

    function detectProvider() {
        const host = window.location.hostname;
        if (host.includes('mail.google.com')) return 'GMAIL';
        if (host.includes('outlook')) return 'OUTLOOK';
        if (host.includes('yahoo')) return 'YAHOO';
        return 'UNKNOWN';
    }

    // Initialize DOM Observer
    let observerTimeout = null;
    const observer = new MutationObserver(() => {
        if (observerTimeout) clearTimeout(observerTimeout);
        observerTimeout = setTimeout(() => {
            tryInjectScanButton();
        }, 400);
    });

    // Message listener for popup action triggers
    chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
        if (msg.type === 'TRIGGER_SCAN') {
            handleScanClick(new Event('click'));
            sendResponse({ success: true });
        }
        return true;
    });

    observer.observe(document.body, { childList: true, subtree: true });
    tryInjectScanButton();

    /**
     * Locate email toolbar and inject the Scan Button
     */
    function tryInjectScanButton() {
        if (document.getElementById('threattrace-scan-btn')) return; // Already injected

        let targetToolbar = null;

        if (PROVIDER === 'GMAIL') {
            // Target action toolbar above open email
            targetToolbar = document.querySelector('div[role="toolbar"]') ||
                document.querySelector('.gE.iv.gt') ||
                document.querySelector('.adP');
        } else if (PROVIDER === 'OUTLOOK') {
            targetToolbar = document.querySelector('div[role="menubar"]') ||
                document.querySelector('div[aria-label="Action bar"]') ||
                document.querySelector('div[aria-label="Message actions"]');
        } else if (PROVIDER === 'YAHOO') {
            targetToolbar = document.querySelector('div[data-test-id="toolbar"]') ||
                document.querySelector('ul[role="toolbar"]');
        }

        if (targetToolbar) {
            const btn = document.createElement('button');
            btn.id = 'threattrace-scan-btn';
            btn.className = 'threattrace-injected-btn';
            btn.innerHTML = '<span>🛡️</span><span>ThreatTrace AI Scan</span>';
            btn.title = 'Run Deep AI Threat Forensics & Web3 Chain-of-Custody Verification';
            btn.onclick = handleScanClick;

            targetToolbar.appendChild(btn);
        }
    }

    /**
     * Extract active email contents from DOM
     */
    function extractCurrentEmail() {
        let subject = '';
        let from = '';
        let to = '';
        let date = '';
        let body = '';

        if (PROVIDER === 'GMAIL') {
            const subjectEl = document.querySelector('h2.hP');
            subject = subjectEl ? subjectEl.innerText.trim() : document.title;

            const fromEl = document.querySelector('span.gD') || document.querySelector('span.go');
            from = fromEl ? (fromEl.getAttribute('email') || fromEl.innerText.trim()) : '';

            const toEl = document.querySelector('span.hb');
            to = toEl ? toEl.innerText.trim() : '';

            const dateEl = document.querySelector('span.g3');
            date = dateEl ? dateEl.getAttribute('title') || dateEl.innerText.trim() : new Date().toUTCString();

            const bodyEl = document.querySelector('div.a3s.aiL') || document.querySelector('div[dir="ltr"]');
            body = bodyEl ? (bodyEl.innerHTML || bodyEl.innerText.trim()) : '';
        } else if (PROVIDER === 'OUTLOOK') {
            const subjectEl = document.querySelector('div[role="heading"]');
            subject = subjectEl ? subjectEl.innerText.trim() : document.title;

            const fromEl = document.querySelector('span[id*="persona"]') || document.querySelector('div[aria-label*="From"]');
            from = fromEl ? fromEl.innerText.trim() : '';

            const bodyEl = document.querySelector('div[aria-label="Message body"]') || document.querySelector('div.ItemPartBody');
            body = bodyEl ? (bodyEl.innerHTML || bodyEl.innerText.trim()) : '';
            date = new Date().toUTCString();
        } else if (PROVIDER === 'YAHOO') {
            const subjectEl = document.querySelector('span[data-test-id="message-subject"]');
            subject = subjectEl ? subjectEl.innerText.trim() : document.title;

            const fromEl = document.querySelector('span[data-test-id="message-from"]');
            from = fromEl ? fromEl.innerText.trim() : '';

            const bodyEl = document.querySelector('div[data-test-id="message-view-body"]');
            body = bodyEl ? (bodyEl.innerHTML || bodyEl.innerText.trim()) : '';
            date = new Date().toUTCString();
        }

        // Synthesize standard RFC structure
        return {
            subject: subject || 'Unspecified Email Subject',
            from: from || 'unknown@sender.com',
            to: to || 'recipient@corp.com',
            date: date || new Date().toUTCString(),
            body: body || 'No body text extracted.'
        };
    }

    /**
     * Handle scan button click
     */
    async function handleScanClick(e) {
        e.preventDefault();
        e.stopPropagation();

        const btn = document.getElementById('threattrace-scan-btn');
        if (btn) {
            btn.classList.add('loading');
            btn.innerHTML = '<span>⚡</span><span>Scanning Email...</span>';
        }

        const emailData = extractCurrentEmail();

        try {
            chrome.runtime.sendMessage({ type: 'SCAN_EMAIL', data: emailData }, (response) => {
                if (btn) {
                    btn.classList.remove('loading');
                    btn.innerHTML = '<span>🛡️</span><span>ThreatTrace AI Scan</span>';
                }

                if (!response || !response.success) {
                    alert(`ThreatTrace Scan Error: ${response?.error || 'Failed to connect to backend'}`);
                    return;
                }

                renderVerdictOverlay(response.data);
            });
        } catch (err) {
            if (btn) {
                btn.classList.remove('loading');
                btn.innerHTML = '<span>🛡️</span><span>ThreatTrace AI Scan</span>';
            }
            alert(`ThreatTrace Error: ${err.message}`);
        }
    }

    /**
     * Render the Floating Threat Verdict Modal HUD
     */
    function renderVerdictOverlay(report) {
        let existing = document.getElementById('threattrace-verdict-overlay');
        if (existing) existing.remove();

        const score = report.aiThreatAnalysis?.threatScore || 0;
        const category = report.aiThreatAnalysis?.threatCategory || 'General Analysis';
        const urgency = report.aiThreatAnalysis?.urgencyLevel || 'Medium';
        const isPhish = report.aiThreatAnalysis?.isPhishing;
        const cues = report.aiThreatAnalysis?.suspiciousCues || [];
        const summary = report.aiThreatAnalysis?.summary || 'Forensic analysis completed.';
        const originIp = report.routing?.originatingIP || 'N/A';
        const location = report.routing?.location ? `${report.routing.location.city}, ${report.routing.location.country}` : 'Unknown';
        const txHash = report.blockchain?.txHash || 'N/A';
        const caseId = report.caseId || 'CASE-LIVE';
        const urlIntel = report.urlIntelligence;
        const attIntel = report.attachmentIntelligence;
        const visIntel = report.visionIntelligence;

        const cardClass = score >= 70 ? 'high' : score >= 40 ? 'medium' : 'safe';
        const scoreColor = score >= 70 ? '#ef4444' : score >= 40 ? '#f59e0b' : '#10b981';

        const overlay = document.createElement('div');
        overlay.id = 'threattrace-verdict-overlay';
        overlay.innerHTML = `
            <div class="tt-hud-header">
                <div class="tt-hud-title">
                    <span>🛡️</span>
                    <span>ThreatTrace Forensic Report</span>
                    <span style="font-size: 11px; color: #38bdf8; background: #082f49; padding: 2px 6px; border-radius: 4px;">${caseId}</span>
                </div>
                <button class="tt-hud-close" id="tt-hud-close-btn" title="Dismiss">✕</button>
            </div>
            <div class="tt-hud-body">
                <div class="tt-score-card ${cardClass}">
                    <div>
                        <div class="tt-score-label" style="color: ${scoreColor}">Threat Classification</div>
                        <div style="font-size: 15px; font-weight: 800; color: #fff;">${category}</div>
                        <div style="font-size: 11px; color: #cbd5e1; margin-top: 2px;">Urgency: ${urgency} • ${isPhish ? '⚠️ High Risk Phishing' : '✅ Verified Authentic'}</div>
                    </div>
                    <div style="text-align: right;">
                        <div class="tt-score-num" style="color: ${scoreColor}">${score}</div>
                        <div style="font-size: 10px; color: #94a3b8; text-transform: uppercase;">/ 100 Score</div>
                    </div>
                </div>

                <div class="tt-detail-row">
                    <span class="tt-detail-label">Origin IP & Location:</span>
                    <span class="tt-detail-value">${originIp} (${location})</span>
                </div>
                <div class="tt-detail-row">
                    <span class="tt-detail-label">SPF / DKIM / DMARC:</span>
                    <span class="tt-detail-value">${report.authentication?.spf || 'PASS'} / ${report.authentication?.dkim || 'PASS'} / ${report.authentication?.dmarc || 'PASS'}</span>
                </div>
                ${urlIntel && urlIntel.totalUrls > 0 ? `
                <div class="tt-detail-row">
                    <span class="tt-detail-label">URL Forensics:</span>
                    <span class="tt-detail-value" style="color: ${urlIntel.maxRiskScore >= 50 ? '#f87171' : '#34d399'}; font-weight: 700;">
                        ${urlIntel.totalUrls} link(s) found (${urlIntel.maliciousUrlsCount} malicious, ${urlIntel.suspiciousUrlsCount} suspicious)
                    </span>
                </div>
                ` : ''}
                ${attIntel && attIntel.totalAttachments > 0 ? `
                <div class="tt-detail-row">
                    <span class="tt-detail-label">Attachment Forensics:</span>
                    <span class="tt-detail-value" style="color: ${attIntel.maxRiskScore >= 50 ? '#f87171' : '#34d399'}; font-weight: 700;">
                        ${attIntel.totalAttachments} file(s) (${attIntel.maliciousCount} malicious, ${attIntel.hasPdfExploits ? 'PDF Exploit' : 'No exploits'})
                    </span>
                </div>
                ` : ''}
                ${visIntel && visIntel.totalImagesScanned > 0 ? `
                <div class="tt-detail-row">
                    <span class="tt-detail-label">Gemini Vision & QR:</span>
                    <span class="tt-detail-value" style="color: ${visIntel.maxRiskScore >= 50 ? '#f87171' : '#34d399'}; font-weight: 700;">
                        ${visIntel.totalImagesScanned} image(s) (${visIntel.quishingDetected ? '⚠️ QR Quishing' : ''} ${visIntel.impersonatedBrands.length > 0 ? 'Brand Spoof: ' + visIntel.impersonatedBrands.join(', ') : (visIntel.quishingDetected ? '' : 'Clean')})
                    </span>
                </div>
                ` : ''}
                <div class="tt-detail-row">
                    <span class="tt-detail-label">Web3 Evidence Anchor:</span>
                    <span class="tt-detail-value" style="font-family: monospace; font-size: 11px; color: #38bdf8;">${txHash.slice(0, 16)}...</span>
                </div>

                ${(() => {
                    const matrix = report.threatVectorMatrix || report.aiThreatAnalysis?.threatVectorMatrix;
                    if (!matrix) return '';
                    const vecs = Object.values(matrix.vectors || {});
                    return `
                    <div style="margin-top: 10px; background: #090d16; border: 1px solid #1e293b; border-radius: 6px; padding: 8px 10px;">
                        <div style="font-size: 11px; font-weight: 700; color: #38bdf8; margin-bottom: 6px; display: flex; justify-content: space-between;">
                            <span>📊 6-Vector Threat Score Matrix</span>
                            <span style="color: ${matrix.compositeScore >= 70 ? '#ef4444' : matrix.compositeScore >= 40 ? '#f59e0b' : '#10b981'}">Composite: ${matrix.compositeScore}/100</span>
                        </div>
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 4px;">
                            ${vecs.map(v => `
                                <div style="background: #111827; padding: 4px 6px; border-radius: 4px; font-size: 10px; display: flex; justify-content: space-between; align-items: center;">
                                    <span style="color: #94a3b8; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 120px;">${v.name.split(' ')[0]}</span>
                                    <span style="font-weight: 800; color: ${v.score >= 70 ? '#ef4444' : v.score >= 40 ? '#f59e0b' : '#10b981'}">${v.score}%</span>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                    `;
                })()}

                <div class="tt-cues-box">
                    <div class="tt-cues-title">🔍 AI Synthesis & Suspicious Cues:</div>
                    <p style="margin: 4px 0 8px; color: #cbd5e1; font-size: 11px; line-height: 1.4;">${summary}</p>
                    ${cues.map(c => `<div class="tt-cue-item">• ${c}</div>`).join('')}
                </div>

                <div class="tt-hud-actions">
                    <a href="http://localhost:5173" target="_blank" class="tt-btn-dashboard">
                        Open SOC Platform Dashboard ↗
                    </a>
                </div>
            </div>
        `;

        document.body.appendChild(overlay);

        document.getElementById('tt-hud-close-btn').onclick = () => {
            overlay.remove();
        };
    }
})();
