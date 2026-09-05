const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = path.join(__dirname, '..', 'data');
const CASES_FILE = path.join(DATA_DIR, 'cases.json');

/**
 * Ensures data directory and JSON case file exist
 */
function initializeStorage() {
    if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    if (!fs.existsSync(CASES_FILE)) {
        // Initialize with default template cases if empty
        const initialCases = [
            {
                caseId: 'CASE-2026-0089',
                createdAt: new Date(Date.now() - 3600000 * 2).toISOString(),
                subject: 'URGENT: Outstanding Vendor Invoice #88492 Payment Divert',
                from: 'Accounts Payable <billing@corporate-finance-vendor.com>',
                senderDomain: 'corporate-finance-vendor.com',
                to: 'cfo@target-enterprise.com',
                threatScore: 92,
                threatCategory: 'Executive Impersonation (BEC)',
                urgencyLevel: 'Critical',
                isPhishing: true,
                originatingIP: '194.26.29.102',
                anonymizedIpHash: crypto.createHash('sha256').update('194.26.29.102').digest('hex'),
                maskedIp: '194.26.xxx.xxx',
                geo: { city: 'Frankfurt', country: 'Germany', isp: 'Bulletproof Host Network', lat: 50.1109, lon: 8.6821 },
                txHash: '0x9b78a9c2f689e472013854ba6cfbc23e0129a8d438912ef098a123fbcde54321',
                evidenceHash: '0x8f142bc394a12389defa982341908756cba9872134567890abcdef1234567890',
                authSummary: { spf: 'FAIL', dkim: 'FAIL', dmarc: 'FAIL' },
                summary: 'Sophisticated BEC payment redirection attempt spoofing trusted vendor domain. High urgency social engineering cues detected.'
            }
        ];
        fs.writeFileSync(CASES_FILE, JSON.stringify(initialCases, null, 2), 'utf-8');
    }
}

/**
 * Read all cases from JSON storage
 */
function readCases() {
    initializeStorage();
    try {
        const raw = fs.readFileSync(CASES_FILE, 'utf-8');
        return JSON.parse(raw);
    } catch (err) {
        console.error("Error reading cases.json:", err);
        return [];
    }
}

/**
 * Write cases array to JSON storage
 */
function writeCases(cases) {
    initializeStorage();
    fs.writeFileSync(CASES_FILE, JSON.stringify(cases, null, 2), 'utf-8');
}

/**
 * Privacy Safeguard (Block 12): Anonymize IP address via SHA-256 and octet masking
 */
function anonymizeIp(ip) {
    if (!ip) return { anonymizedIpHash: 'NONE', maskedIp: 'Unknown' };
    const anonymizedIpHash = crypto.createHash('sha256').update(ip).digest('hex');
    const parts = ip.split('.');
    const maskedIp = parts.length === 4 ? `${parts[0]}.${parts[1]}.xxx.xxx` : 'Masked IP';
    return { anonymizedIpHash, maskedIp };
}

/**
 * Save a new forensic analysis case into persistent storage
 */
function saveCase(analysisData) {
    const cases = readCases();
    const caseId = analysisData.caseId || `CASE-${new Date().getFullYear()}-${String(Date.now()).slice(-5)}`;
    
    const { anonymizedIpHash, maskedIp } = anonymizeIp(analysisData.routing?.originatingIP);

    const newCase = {
        caseId,
        createdAt: new Date().toISOString(),
        subject: analysisData.emailDetails?.subject || 'No Subject',
        from: analysisData.emailDetails?.from || 'Unknown Sender',
        senderDomain: analysisData.domainIntelligence?.domain || 'Unknown',
        to: analysisData.emailDetails?.to || 'Unknown Recipient',
        threatScore: analysisData.aiThreatAnalysis?.threatScore || 0,
        threatCategory: analysisData.aiThreatAnalysis?.threatCategory || 'General Analysis',
        urgencyLevel: analysisData.aiThreatAnalysis?.urgencyLevel || 'Low',
        isPhishing: analysisData.aiThreatAnalysis?.isPhishing || false,
        originatingIP: analysisData.routing?.originatingIP || null,
        anonymizedIpHash,
        maskedIp,
        geo: analysisData.routing?.location || { city: 'Unknown', country: 'Unknown', isp: 'Unknown', lat: 0, lon: 0 },
        txHash: analysisData.blockchain?.txHash || null,
        evidenceHash: analysisData.blockchain?.evidenceHash || null,
        authSummary: {
            spf: analysisData.authentication?.spf || 'UNVERIFIED',
            dkim: analysisData.authentication?.dkim || 'UNVERIFIED',
            dmarc: analysisData.authentication?.dmarc || 'UNVERIFIED'
        },
        summary: analysisData.aiThreatAnalysis?.summary || '',
        fullAnalysis: analysisData
    };

    // Prepend new case to top
    cases.unshift(newCase);
    writeCases(cases);
    return newCase;
}

/**
 * List cases with search, category filtering, and pagination
 */
function listCases({ search = '', category = '', limit = 50 } = {}) {
    let cases = readCases();

    if (search) {
        const q = search.toLowerCase().trim();
        cases = cases.filter(c => 
            (c.caseId && c.caseId.toLowerCase().includes(q)) ||
            (c.subject && c.subject.toLowerCase().includes(q)) ||
            (c.from && c.from.toLowerCase().includes(q)) ||
            (c.senderDomain && c.senderDomain.toLowerCase().includes(q)) ||
            (c.threatCategory && c.threatCategory.toLowerCase().includes(q))
        );
    }

    if (category && category !== 'ALL') {
        cases = cases.filter(c => c.threatCategory === category);
    }

    return cases.slice(0, limit);
}

/**
 * Retrieve a specific case by its Case ID
 */
function getCaseById(caseId) {
    const cases = readCases();
    return cases.find(c => c.caseId === caseId) || null;
}

/**
 * Delete a case by its Case ID
 */
function deleteCase(caseId) {
    let cases = readCases();
    const initialLen = cases.length;
    cases = cases.filter(c => c.caseId !== caseId);
    if (cases.length !== initialLen) {
        writeCases(cases);
        return true;
    }
    return false;
}

/**
 * Get aggregate statistics across all recorded cases
 */
function getCaseStats() {
    const cases = readCases();
    const total = cases.length;
    const highThreat = cases.filter(c => c.threatScore > 70).length;
    const phishingCount = cases.filter(c => c.isPhishing).length;
    const avgScore = total > 0 ? Math.round(cases.reduce((sum, c) => sum + (c.threatScore || 0), 0) / total) : 0;

    return { total, highThreat, phishingCount, avgScore };
}

module.exports = {
    saveCase,
    listCases,
    getCaseById,
    deleteCase,
    getCaseStats,
    anonymizeIp
};
