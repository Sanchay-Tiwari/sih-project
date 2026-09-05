const { GoogleGenerativeAI } = require('@google/generative-ai');

/**
 * Calibrated Heuristic Engine for balanced threat assessment
 */
function computeHeuristicAnalysis({ subject = '', bodyText = '', anomalies = [], authentication = {}, domainIntel = {}, threatIntel = {} }) {
    let score = 8;
    const cues = [];
    let category = "Legitimate Communication";
    let isPhishing = false;

    // Check high-confidence anomalies
    if (anomalies.some(a => a.type === 'RETURN_PATH_MISMATCH')) {
        score += 35;
        cues.push("From & Return-Path domain mismatch indicates envelope sender spoofing.");
        category = "Domain Spoofing / Impersonation";
        isPhishing = true;
    }

    if (anomalies.some(a => a.type === 'REPLY_TO_MISMATCH')) {
        score += 30;
        cues.push("Reply-To header redirects correspondence away from sender domain.");
        category = "Executive Impersonation (BEC)";
        isPhishing = true;
    }

    if (anomalies.some(a => a.type === 'AUTH_EXPLICIT_FAIL')) {
        score += 20;
        cues.push("Email explicitly failed cryptographic SPF/DMARC authentication.");
    }

    if (domainIntel.domainAgeDays !== null && domainIntel.domainAgeDays < 15) {
        score += 25;
        cues.push(`Sender domain is newly registered (${domainIntel.domainAgeDays} days old), a common indicator for disposable attack infrastructure.`);
        isPhishing = true;
    }

    if (threatIntel.abuseConfidenceScore > 50) {
        score += 30;
        cues.push(`Originating IP is flagged in threat intelligence feeds with an abuse confidence score of ${threatIntel.abuseConfidenceScore}%.`);
        isPhishing = true;
    }

    // High-confidence fraudulent keywords check (only when combined with urgency or payment divert)
    const lowerBody = (subject + ' ' + bodyText).toLowerCase();
    const isWireDivert = /wire transfer|escrow settlement|updated bank account|offshore account|routing number/i.test(lowerBody);
    const isCredentialTheft = /password expires in \d+|verify your login|account suspension in \d+|retain your password/i.test(lowerBody);

    if (isWireDivert && (anomalies.length > 0 || isPhishing)) {
        score += 30;
        cues.push("Financial wire transfer diversion instructions detected in email content.");
        category = "Executive Impersonation (BEC)";
        isPhishing = true;
    } else if (isCredentialTheft) {
        score += 25;
        cues.push("Urgent credential expiration and account suspension coercion detected.");
        category = "Credential Harvesting";
        isPhishing = true;
    }

    // Reward verified cryptographic protocol alignment
    if (authentication.spf === 'PASS' && authentication.dkim === 'PASS') {
        score = Math.max(5, score - 20);
    }

    score = Math.min(100, Math.max(5, score));
    const urgency = score >= 75 ? "Critical" : score >= 50 ? "High" : score >= 25 ? "Medium" : "Low";

    return {
        isPhishing,
        threatScore: score,
        threatCategory: isPhishing ? category : "Legitimate Communication",
        urgencyLevel: urgency,
        attributionAssessment: isPhishing ? "Untrusted Relay / Spoofed Infrastructure" : "Legitimate Authorized Mailer",
        suspiciousCues: cues.length > 0 ? cues : ["Standard routing and authentic sender parameters. No malicious indicators found."],
        summary: isPhishing 
            ? `Forensic analysis detected high-risk threat indicators (Score: ${score}/100) including protocol/header anomalies and deceptive content intent.`
            : `Email appears legitimate with normal business communications and authentic delivery parameters.`,
        mitigationSteps: isPhishing 
            ? ["Quarantine email from recipient mailboxes", "Block sender domain and originating IP on gateway", "Notify security operations of targeted attempt"]
            : ["No containment action required", "Normal delivery approved"]
    };
}

/**
 * AI-Powered Threat Detection Engine with Strict False Positive Calibration
 */
async function analyzeEmailWithAI({
    subject = '',
    bodyText = '',
    headers = {},
    anomalies = [],
    authentication = {},
    domainIntel = {},
    threatIntel = {}
}) {
    const apiKey = process.env.GEMINI_API_KEY;

    if (!apiKey) {
        return computeHeuristicAnalysis({ subject, bodyText, anomalies, authentication, domainIntel, threatIntel });
    }

    try {
        const genAI = new GoogleGenerativeAI(apiKey);
        const model = genAI.getGenerativeModel({
            model: "gemini-1.5-flash",
            generationConfig: {
                responseMimeType: "application/json",
                temperature: 0.0
            }
        });

        const prompt = `
You are an expert Lead Cyber Forensic & Email Threat Analyst. 
Evaluate this email forensic telemetry package accurately and objectively, minimizing false positives.

=== CRITICAL CALIBRATION GUIDELINES ===
- Do NOT flag normal business emails, newsletters, casual requests, or vendor invoices as phishing unless there is clear technical or behavioral evidence of fraud/deceit.
- Subdomains (e.g. mail.google.com and google.com) and legitimate Enterprise Email Providers (SendGrid, Mailchimp, Amazon SES) are standard legitimate practice, NOT spoofing.
- Use this strict scoring standard:
  * 0 - 20 (CLEAN/LEGITIMATE): Standard personal/business emails, authentic invoices, meeting invites, notifications with no deceptive cues.
  * 21 - 45 (LOW RISK): Marketing emails, cold outreach, newsletters, or unauthenticated text with no malicious links/requests.
  * 46 - 70 (SUSPICIOUS): Ambiguous payment change requests, unverified external senders asking for sensitive files, or unusual routing.
  * 71 - 100 (CRITICAL MALICIOUS): Confirmed BEC wire transfer scams, password/credential harvesting pages, executive impersonation from spoofed domains, or malware delivery.

=== EMAIL METADATA ===
Subject: ${subject}
From: ${headers.from || 'Unknown'}
To: ${headers.to || 'Unknown'}
Date: ${headers.date || 'Unknown'}
Return-Path: ${headers.returnPath || 'None'}
Reply-To: ${headers.replyTo || 'None'}

=== PROTOCOL AUTHENTICATION ===
SPF: ${authentication.spf || 'UNVERIFIED'}
DKIM: ${authentication.dkim || 'UNVERIFIED'}
DMARC: ${authentication.dmarc || 'UNVERIFIED'}

=== TECHNICAL ANOMALIES DETECTED ===
${JSON.stringify(anomalies, null, 2)}

=== DOMAIN INTELLIGENCE ===
Domain: ${domainIntel.domain || 'Unknown'}
Has MX Records: ${domainIntel.hasMx}
Domain Age: ${domainIntel.domainAgeDays ? domainIntel.domainAgeDays + ' days' : 'Historical/Verified'}
Registrar: ${domainIntel.registrar || 'Unknown'}
Risk Flags: ${JSON.stringify(domainIntel.riskFlags || [])}

=== THREAT INTEL & IP REPUTATION ===
Origin IP: ${threatIntel.ip || 'Unknown'}
Abuse Score: ${threatIntel.abuseConfidenceScore || 0}%
Threat Level: ${threatIntel.threatLevel || 'CLEAN'}
Reputation Note: ${threatIntel.reputationSummary || 'None'}

=== EMAIL BODY CONTENT (TRUNCATED) ===
${bodyText.slice(0, 3000)}

=== INSTRUCTIONS ===
Provide your objective forensic assessment strictly in the following JSON schema:
{
  "isPhishing": true/false,
  "threatScore": <integer between 0 and 100 based on the calibration scale above>,
  "threatCategory": "<Executive Impersonation (BEC) | Credential Harvesting | Invoice Fraud | Brand Impersonation | Malware Delivery | Legitimate Communication>",
  "urgencyLevel": "<Critical | High | Medium | Low>",
  "attributionAssessment": "<e.g. Likely Spoofed Domain / Compromised Server / Bulletproof Host / Legitimate Authorized Mailer>",
  "suspiciousCues": ["<concise specific indicator 1>", ...],
  "summary": "<2-sentence accurate cyber-forensic summary of the email>",
  "mitigationSteps": ["<SOC action step 1>", "<SOC action step 2>", "<SOC action step 3>"]
}
`;

        const result = await model.generateContent(prompt);
        const parsed = JSON.parse(result.response.text());
        return parsed;
    } catch (error) {
        console.warn("Gemini API Error (using calibrated heuristics):", error.message);
        return computeHeuristicAnalysis({ subject, bodyText, anomalies, authentication, domainIntel, threatIntel });
    }
}

module.exports = { analyzeEmailWithAI };