/**
 * ThreatTrace AI - URL Forensics & Phishing Link Reputation Engine
 * Extracts, analyzes, and scores hyperlinks from email content for deceptive routing,
 * homograph spoofing, direct IP destinations, and credential harvesting paths.
 */

const axios = require('axios');
const { extractDomain, getApexDomain } = require('./headerParser');

// High-Risk Top-Level Domains frequently utilized in disposable phishing kits
const HIGH_RISK_TLDS = new Set([
    'xyz', 'top', 'cc', 'ru', 'click', 'gq', 'cf', 'work', 'fit', 'rest',
    'tk', 'ml', 'ga', 'buzz', 'cam', 'live', 'loan', 'stream', 'win', 'bid',
    'country', 'zip', 'mov', 'surf', 'quest', 'monster', 'beauty', 'icu'
]);

// Known URL shorteners and redirect services
const URL_SHORTENERS = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly', 'ow.ly',
    'rebrand.ly', 'buff.ly', 'shorte.st', 't.ly', 'clck.ru', 'v.gd'
]);

// High-risk path keywords indicating authentication or financial credential harvesting
const CREDENTIAL_PATH_REGEX = /\/(login|signin|sign-in|verify|verification|secure|auth|authenticate|password|passcode|banking|update-account|webmail|portal|session|validate|wallet|recovery|invoice-payment)/i;

/**
 * Extract all unique URLs from HTML and plaintext email bodies
 */
function extractUrls(bodyText = '', bodyHtml = '') {
    const rawUrls = new Map(); // url -> { href, anchorText }

    // 1. Extract from HTML anchor tags: <a href="..." >Anchor Text</a>
    if (typeof bodyHtml === 'string' && bodyHtml.length > 0) {
        const anchorRegex = /<a\s+(?:[^>]*?\s+)?href=(["'])(.*?)\1[^>]*>(.*?)<\/a>/gi;
        let match;
        while ((match = anchorRegex.exec(bodyHtml)) !== null) {
            const href = match[2]?.trim();
            const anchorText = match[3]?.replace(/<[^>]*>/g, '').trim();
            if (href && (href.startsWith('http://') || href.startsWith('https://'))) {
                rawUrls.set(href, { href, anchorText: anchorText || '' });
            }
        }
    }

    // 2. Extract plain text URLs using strict URL regex
    const textUrlRegex = /https?:\/\/[^\s<>"'{}|\\^`[\]]+/gi;
    const combined = `${bodyText} ${bodyHtml}`;
    const textMatches = combined.match(textUrlRegex) || [];

    for (const raw of textMatches) {
        // Clean trailing punctuation attached to URLs in prose
        const cleaned = raw.replace(/[.,;:!?)]+$/, '');
        if (!rawUrls.has(cleaned)) {
            rawUrls.set(cleaned, { href: cleaned, anchorText: '' });
        }
    }

    return Array.from(rawUrls.values());
}

/**
 * Inspect individual URL for phishing, deception, and reputation flags
 */
function inspectUrl({ href, anchorText = '' }) {
    let parsedUrl;
    try {
        parsedUrl = new URL(href);
    } catch {
        return null; // Invalid URL structure
    }

    const flags = [];
    let riskScore = 0;

    const hostname = parsedUrl.hostname.toLowerCase();
    const pathname = parsedUrl.pathname.toLowerCase();
    const search = parsedUrl.search.toLowerCase();
    const protocol = parsedUrl.protocol.toLowerCase();
    const port = parsedUrl.port;

    // 1. Direct IP Address in URL Hostname (e.g. http://194.26.29.102/login)
    const isIpHost = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.startsWith('[');
    if (isIpHost) {
        flags.push("Direct IP address used as URL host (bypasses domain reputation)");
        riskScore += 40;
    }

    // 2. IDN / Punycode Homograph Spoofing (e.g. xn--pypal-4ve.com)
    const isPunycode = hostname.includes('xn--');
    if (isPunycode) {
        flags.push("Internationalized Domain Name (Punycode / Homograph character spoofing detected)");
        riskScore += 45;
    }

    // 3. High-Risk TLD Detection
    const domainParts = hostname.split('.');
    const tld = domainParts[domainParts.length - 1];
    const isHighRiskTld = HIGH_RISK_TLDS.has(tld);
    if (isHighRiskTld) {
        flags.push(`High-risk top-level domain (.${tld}) associated with disposable phishing kits`);
        riskScore += 25;
    }

    // 4. URL Shortener / Obfuscation
    const apex = getApexDomain(hostname) || hostname;
    const isShortener = URL_SHORTENERS.has(apex) || URL_SHORTENERS.has(hostname);
    if (isShortener) {
        flags.push("URL Shortener used to obscure true destination endpoint");
        riskScore += 20;
    }

    // 5. Deceptive Display Text Mismatch (e.g. <a href="http://phish.cc">https://login.microsoft.com</a>)
    let displayMismatch = false;
    if (anchorText) {
        const anchorDomainMatch = anchorText.match(/(?:https?:\/\/)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i);
        if (anchorDomainMatch) {
            const anchorDomain = anchorDomainMatch[1].toLowerCase();
            const anchorApex = getApexDomain(anchorDomain);
            if (anchorApex && apex && anchorApex !== apex) {
                displayMismatch = true;
                flags.push(`Deceptive anchor text mismatch (Displays: "${anchorDomain}", Redirects to: "${hostname}")`);
                riskScore += 45;
            }
        }
    }

    // 6. Credential Harvesting Keywords in Path / Query
    const hasCredentialKeywords = CREDENTIAL_PATH_REGEX.test(pathname) || CREDENTIAL_PATH_REGEX.test(search);
    if (hasCredentialKeywords) {
        flags.push("Authentication / Credential harvesting keyword pattern detected in URL path");
        riskScore += 25;
    }

    // 7. Excessive Subdomain Stacking (e.g. paypal.com.account-verify.attacker.com)
    if (domainParts.length > 3 && !isIpHost) {
        flags.push(`Excessive subdomain depth (${domainParts.length} levels) mimicking brand names`);
        riskScore += 15;
    }

    // 8. Non-Standard Ports
    if (port && port !== '80' && port !== '443') {
        flags.push(`Non-standard HTTP port (:${port}) used for connection`);
        riskScore += 20;
    }

    // 9. Insecure Protocol for Authentication
    if (protocol === 'http:' && (hasCredentialKeywords || isIpHost)) {
        flags.push("Insecure HTTP protocol used on sensitive authentication/login target");
        riskScore += 15;
    }

    // Normalize risk score and level
    riskScore = Math.min(100, riskScore);
    let riskLevel = 'CLEAN';
    if (riskScore >= 70) riskLevel = 'CRITICAL';
    else if (riskScore >= 50) riskLevel = 'HIGH';
    else if (riskScore >= 25) riskLevel = 'MEDIUM';
    else if (riskScore > 0) riskLevel = 'LOW';

    return {
        url: href,
        domain: hostname,
        apexDomain: apex,
        isIpUrl: isIpHost,
        isPunycode,
        highRiskTld: isHighRiskTld,
        isShortener,
        displayMismatch,
        credentialKeywords: hasCredentialKeywords,
        riskScore,
        riskLevel,
        flags
    };
}

/**
 * Optional Google Safe Browsing API lookup (if API key is configured)
 */
async function checkGoogleSafeBrowsing(urls) {
    const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
    if (!apiKey || !Array.isArray(urls) || urls.length === 0) {
        return {};
    }

    try {
        const payload = {
            client: {
                clientId: "threattrace-ai",
                clientVersion: "1.0.0"
            },
            threatInfo: {
                threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                platformTypes: ["ANY_PLATFORM"],
                threatEntryTypes: ["URL"],
                threatEntries: urls.slice(0, 20).map(u => ({ url: u }))
            }
        };

        const res = await axios.post(
            `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
            payload,
            { timeout: 4000 }
        );

        const matches = res.data?.matches || [];
        const resultMap = {};
        for (const m of matches) {
            resultMap[m.threat?.url] = {
                threatType: m.threatType,
                platformType: m.platformType
            };
        }
        return resultMap;
    } catch (err) {
        console.warn("Safe Browsing API check skipped:", err.message);
        return {};
    }
}

/**
 * Master URL Intelligence Pipeline
 * Extracts, enriches, and evaluates all links present in the email payload
 */
async function analyzeUrls({ bodyText = '', bodyHtml = '' } = {}) {
    const extractedList = extractUrls(bodyText, bodyHtml);

    if (extractedList.length === 0) {
        return {
            totalUrls: 0,
            suspiciousUrlsCount: 0,
            maliciousUrlsCount: 0,
            maxRiskScore: 0,
            riskLevel: 'CLEAN',
            flags: [],
            urls: []
        };
    }

    // Inspect each extracted URL
    const inspected = extractedList.map(inspectUrl).filter(Boolean);

    // Optional Google Safe Browsing enrichment
    const urlStrings = inspected.map(i => i.url);
    const safeBrowsingResults = await checkGoogleSafeBrowsing(urlStrings);

    for (const item of inspected) {
        const sbMatch = safeBrowsingResults[item.url];
        if (sbMatch) {
            item.riskScore = 100;
            item.riskLevel = 'CRITICAL';
            item.flags.unshift(`Google Safe Browsing: Flagged as ${sbMatch.threatType}`);
        }
    }

    const totalUrls = inspected.length;
    const suspiciousUrlsCount = inspected.filter(u => u.riskScore >= 40 && u.riskScore < 70).length;
    const maliciousUrlsCount = inspected.filter(u => u.riskScore >= 70).length;

    const maxRiskScore = totalUrls > 0 ? Math.max(...inspected.map(u => u.riskScore)) : 0;

    let overallRiskLevel = 'CLEAN';
    if (maxRiskScore >= 70) overallRiskLevel = 'CRITICAL';
    else if (maxRiskScore >= 50) overallRiskLevel = 'HIGH';
    else if (maxRiskScore >= 25) overallRiskLevel = 'MEDIUM';
    else if (maxRiskScore > 0) overallRiskLevel = 'LOW';

    // Aggregate unique threat flags
    const aggregateFlags = Array.from(new Set(inspected.flatMap(u => u.flags)));

    return {
        totalUrls,
        suspiciousUrlsCount,
        maliciousUrlsCount,
        maxRiskScore,
        riskLevel: overallRiskLevel,
        flags: aggregateFlags,
        urls: inspected
    };
}

module.exports = {
    extractUrls,
    inspectUrl,
    analyzeUrls
};
