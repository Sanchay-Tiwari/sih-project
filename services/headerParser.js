const { simpleParser } = require('mailparser');

/**
 * Extract apex / root domain from hostname or domain string
 * e.g., "mail.sub.google.com" -> "google.com", "bounces.sendgrid.net" -> "sendgrid.net"
 */
function getApexDomain(domain) {
    if (!domain) return null;
    const clean = domain.toLowerCase().trim().replace(/^@/, '');
    const parts = clean.split('.');
    if (parts.length <= 2) return clean;
    // Handle common two-part TLDs like .co.uk, .com.au, .co.in, .gov.in
    const twoPartTlds = ['co.uk', 'co.in', 'gov.in', 'com.au', 'co.nz', 'co.jp', 'org.uk', 'ac.in', 'edu.in'];
    const lastTwo = parts.slice(-2).join('.');
    if (twoPartTlds.includes(lastTwo) && parts.length >= 3) {
        return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
}

/**
 * Extract domain name from an email address or header string
 * e.g., "CEO <ceo@company.com>" -> "company.com"
 */
function extractDomain(emailOrHeader) {
    if (!emailOrHeader) return null;
    const match = String(emailOrHeader).match(/@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    return match ? match[1].toLowerCase().trim() : null;
}

/**
 * Extract clean email address from string
 * e.g. "John Doe <john@example.com>" -> "john@example.com"
 */
function extractEmail(headerStr) {
    if (!headerStr) return null;
    const match = String(headerStr).match(/<([^>]+)>/) || String(headerStr).match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    return match ? match[1].toLowerCase().trim() : String(headerStr).trim();
}

/**
 * Filter and extract only public IPv4 addresses (excluding timestamp/ID artifacts and private subnets)
 */
function extractPublicIPs(text) {
    if (!text) return [];
    // Strict IPv4 regex: ensures 4 octets (0-255) not embedded in larger dot-delimited sequences
    const ipv4Regex = /(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?![\d.])/g;
    const matches = text.match(ipv4Regex) || [];

    return matches.filter(ip => {
        // Discard octets with leading zeroes like '08.31.09.04' from date stamps
        const rawOctets = ip.split('.');
        if (rawOctets.some(o => o.length > 1 && o.startsWith('0'))) return false;

        const parts = rawOctets.map(Number);
        if (parts.some(p => isNaN(p) || p < 0 || p > 255)) return false;
        
        // Exclude private / loopback / link-local / multicast / reserved
        if (parts[0] === 0 || parts[0] === 127 || parts[0] === 10) return false;
        if (parts[0] === 192 && parts[1] === 168) return false;
        if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false;
        if (parts[0] === 169 && parts[1] === 254) return false;
        if (parts[0] >= 224) return false;
        return true;
    });
}


// Known authorized Enterprise Email Service Providers (ESPs) that legitimately handle Return-Path / relays
const AUTHORIZED_ESPS = [
    'amazonses.com', 'sendgrid.net', 'mailgun.org', 'mailgun.net', 'mailchimp.com', 'mcsv.net',
    'postmarkapp.com', 'sparkpostmail.com', 'zendesk.com', 'salesforce.com', 'hubspotemail.net',
    'google.com', 'googlemail.com', 'outlook.com', 'microsoft.com', 'protection.outlook.com',
    'constantcontact.com', 'exacttarget.com'
];

/**
 * Comprehensive Email Header Parser with Calibrated Anomaly Detection Engine
 */
async function parseEmailHeaders(rawEmailText) {
    if (!rawEmailText || typeof rawEmailText !== 'string') {
        throw new Error("Invalid or empty raw email content.");
    }

    try {
        const parsed = await simpleParser(rawEmailText);

        // 1. Core Header Extraction
        const fromHeader = parsed.headers.get('from')?.text || parsed.from?.text || '';
        const toHeader = parsed.headers.get('to')?.text || parsed.to?.text || '';
        const returnPathHeader = parsed.headers.get('return-path')?.text || parsed.headers.get('return-path') || '';
        const replyToHeader = parsed.headers.get('reply-to')?.text || parsed.headers.get('reply-to') || '';
        const messageIdHeader = parsed.headers.get('message-id') || parsed.messageId || '';
        const subject = parsed.subject || 'No Subject';
        const date = parsed.date || new Date();
        const bodyText = parsed.text || parsed.html || '';

        const fromEmail = extractEmail(fromHeader);
        const fromDomain = extractDomain(fromHeader);
        const returnPathDomain = extractDomain(returnPathHeader);
        const replyToDomain = extractDomain(replyToHeader);
        const messageIdDomain = extractDomain(messageIdHeader);

        const fromApex = getApexDomain(fromDomain);
        const returnPathApex = getApexDomain(returnPathDomain);
        const replyToApex = getApexDomain(replyToDomain);

        // 2. Authentication Protocol Parsing (SPF, DKIM, DMARC)
        const authResults = parsed.headers.get('authentication-results') || '';
        const authString = Array.isArray(authResults) ? authResults.join(' ') : String(authResults);
        const hasAuthHeader = Boolean(authString && authString.trim().length > 0);

        const dkimSignature = parsed.headers.get('dkim-signature') || '';

        let spfStatus = 'UNVERIFIED';
        let dkimStatus = 'UNVERIFIED';
        let dmarcStatus = 'UNVERIFIED';

        if (hasAuthHeader) {
            if (/spf=pass/i.test(authString)) spfStatus = 'PASS';
            else if (/spf=fail/i.test(authString)) spfStatus = 'FAIL';
            else if (/spf=softfail/i.test(authString)) spfStatus = 'SOFTFAIL';
            else if (/spf=neutral/i.test(authString)) spfStatus = 'NEUTRAL';

            if (/dkim=pass/i.test(authString) || Boolean(dkimSignature)) dkimStatus = 'PASS';
            else if (/dkim=fail/i.test(authString)) dkimStatus = 'FAIL';

            if (/dmarc=pass/i.test(authString)) dmarcStatus = 'PASS';
            else if (/dmarc=fail/i.test(authString)) dmarcStatus = 'FAIL';
        } else if (dkimSignature) {
            dkimStatus = 'PASS';
        }

        // 3. Hop Chain / Relay Analysis
        const receivedHeaders = parsed.headers.get('received') || [];
        const rawHops = Array.isArray(receivedHeaders) ? receivedHeaders : [receivedHeaders];

        const extractedIPs = [];
        const hopDetails = [];

        rawHops.forEach((hop, idx) => {
            const hopStr = typeof hop === 'object' ? JSON.stringify(hop) : String(hop);
            const ips = extractPublicIPs(hopStr);
            ips.forEach(ip => extractedIPs.push(ip));
            hopDetails.push({
                hopNumber: idx + 1,
                raw: hopStr.substring(0, 180),
                extractedIPs: ips
            });
        });

        const uniqueIPChain = [...new Set(extractedIPs)];
        const originatingIP = uniqueIPChain[uniqueIPChain.length - 1] || null;

        // 4. Calibrated Anomaly Detection Engine (Minimizing False Positives)
        const anomalies = [];

        // Anomaly A: From vs Return-Path Mismatch
        if (fromApex && returnPathApex && fromApex !== returnPathApex) {
            const isAuthorizedEsp = AUTHORIZED_ESPS.some(esp => returnPathDomain?.endsWith(esp));
            if (!isAuthorizedEsp) {
                anomalies.push({
                    type: 'RETURN_PATH_MISMATCH',
                    severity: 'HIGH',
                    title: 'From & Return-Path Domain Mismatch',
                    description: `Sender displays domain '@${fromDomain}', but envelope return path directs to unrelated domain '@${returnPathDomain}'. Common indicator of address spoofing.`,
                    senderDomain: fromDomain,
                    returnPathDomain: returnPathDomain
                });
            }
        }

        // Anomaly B: From vs Reply-To Mismatch
        if (fromApex && replyToApex && fromApex !== replyToApex) {
            const isAuthorizedEsp = AUTHORIZED_ESPS.some(esp => replyToDomain?.endsWith(esp));
            if (!isAuthorizedEsp) {
                anomalies.push({
                    type: 'REPLY_TO_MISMATCH',
                    severity: 'HIGH',
                    title: 'Reply-To Diversion Detected',
                    description: `Replies are redirected to an external domain '@${replyToDomain}' instead of sender domain '@${fromDomain}'. Common in spear phishing and invoice fraud.`,
                    senderDomain: fromDomain,
                    replyToDomain: replyToDomain
                });
            }
        }

        // Anomaly C: Explicit Authentication Failures (Only flag when explicitly FAIL/SOFTFAIL)
        if (spfStatus === 'FAIL' || dmarcStatus === 'FAIL') {
            anomalies.push({
                type: 'AUTH_EXPLICIT_FAIL',
                severity: 'HIGH',
                title: 'Cryptographic Protocol Authentication Failed',
                description: `Email explicitly failed sender policy authentication (SPF: ${spfStatus}, DMARC: ${dmarcStatus}). Sender IP is unauthorized by domain DNS.`
            });
        }

        // Anomaly D: Relay depth anomaly (only when excessive > 7 hops)
        if (uniqueIPChain.length > 7) {
            anomalies.push({
                type: 'EXCESSIVE_HOPS',
                severity: 'LOW',
                title: 'High Relay Hop Count',
                description: `Email traversed ${uniqueIPChain.length} distinct public IP hops.`
            });
        }

        return {
            subject,
            from: fromHeader,
            fromEmail,
            senderDomain: fromDomain,
            to: toHeader,
            date,
            bodyText: typeof bodyText === 'string' ? bodyText.slice(0, 15000) : '',
            messageId: messageIdHeader,
            returnPath: returnPathHeader,
            returnPathDomain,
            replyTo: replyToHeader,
            replyToDomain,
            authentication: {
                spf: spfStatus,
                dkim: dkimStatus,
                dmarc: dmarcStatus,
                rawAuthResults: authString || 'None provided'
            },
            hopIPChain: uniqueIPChain,
            hopDetails,
            originatingIP,
            anomalies
        };
    } catch (error) {
        console.error("Header Parsing Error:", error);
        throw new Error(`Failed to parse raw email content: ${error.message}`);
    }
}

module.exports = { parseEmailHeaders, extractDomain, extractEmail, extractPublicIPs, getApexDomain };