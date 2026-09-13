/**
 * Unified Multi-Vector Threat Score Matrix
 * Computes calibrated risk across all 6 forensic vectors:
 * 1. Protocol Authentication & Header Anomalies (15%)
 * 2. Domain Intelligence & Age (15%)
 * 3. IP Threat Feeds & AbuseIPDB (15%)
 * 4. URL Forensics & Link Reputation (20%)
 * 5. Attachment & PDF Exploit Engine (20%)
 * 6. Gemini Vision & Quishing Analysis (15%)
 */
function computeThreatVectorMatrix({
    anomalies = [],
    authentication = {},
    domainIntel = {},
    threatIntel = {},
    urlIntelligence = {},
    attachmentIntelligence = {},
    visionIntelligence = {}
}) {
    // Vector 1: Protocol Authentication & Header Anomalies (Weight: 15%)
    let headerScore = 0;
    const headerFindings = [];
    if (authentication.spf === 'FAIL' || authentication.dmarc === 'FAIL') {
        headerScore += 45;
        headerFindings.push('SPF/DMARC authentication failed');
    } else if (authentication.spf === 'SOFTFAIL' || authentication.spf === 'NONE') {
        headerScore += 20;
        headerFindings.push('Incomplete or missing SPF policy');
    }
    if (anomalies.some(a => a.type === 'RETURN_PATH_MISMATCH')) {
        headerScore += 40;
        headerFindings.push('Return-Path envelope spoofing detected');
    }
    if (anomalies.some(a => a.type === 'REPLY_TO_MISMATCH')) {
        headerScore += 35;
        headerFindings.push('Reply-To header diversion detected');
    }
    if (anomalies.some(a => a.type === 'AUTH_EXPLICIT_FAIL')) {
        headerScore += 25;
        headerFindings.push('Authentication-Results explicitly failed');
    }
    headerScore = Math.min(100, Math.max(0, headerScore));
    if (authentication.spf === 'PASS' && authentication.dkim === 'PASS' && anomalies.length === 0) {
        headerScore = 0;
        headerFindings.push('SPF and DKIM cryptographically verified');
    }
    const headerStatus = headerScore >= 70 ? 'CRITICAL' : headerScore >= 40 ? 'SUSPICIOUS' : headerScore > 0 ? 'LOW' : 'CLEAN';

    // Vector 2: Domain Intelligence & Age (Weight: 15%)
    let domainScore = 0;
    const domainFindings = [];
    if (domainIntel.hasMx === false) {
        domainScore += 80;
        domainFindings.push('Sender domain lacks valid MX records');
    }
    if (domainIntel.domainAgeDays !== null && domainIntel.domainAgeDays !== undefined) {
        if (domainIntel.domainAgeDays < 15) {
            domainScore += 75;
            domainFindings.push(`Newly registered domain (${domainIntel.domainAgeDays} days old)`);
        } else if (domainIntel.domainAgeDays < 60) {
            domainScore += 40;
            domainFindings.push(`Recently registered domain (${domainIntel.domainAgeDays} days old)`);
        } else {
            domainFindings.push(`Established domain (${domainIntel.domainAgeDays} days old)`);
        }
    }
    if (domainIntel.riskRating === 'HIGH') {
        domainScore = Math.max(domainScore, 75);
        domainFindings.push('High-risk domain classification');
    }
    domainScore = Math.min(100, Math.max(0, domainScore));
    const domainStatus = domainScore >= 70 ? 'CRITICAL' : domainScore >= 40 ? 'SUSPICIOUS' : domainScore > 0 ? 'LOW' : 'CLEAN';

    // Vector 3: IP Reputation & AbuseIPDB (Weight: 15%)
    let ipScore = 0;
    const ipFindings = [];
    if (threatIntel.abuseConfidenceScore > 0) {
        ipScore = threatIntel.abuseConfidenceScore;
        ipFindings.push(`AbuseIPDB confidence: ${threatIntel.abuseConfidenceScore}% (${threatIntel.totalReports || 0} reports)`);
    } else if (threatIntel.isWhitelisted) {
        ipScore = 0;
        ipFindings.push('Origin IP verified benign / whitelisted');
    } else {
        ipFindings.push('No malicious reports in threat feeds');
    }
    ipScore = Math.min(100, Math.max(0, ipScore));
    const ipStatus = ipScore >= 70 ? 'CRITICAL' : ipScore >= 40 ? 'SUSPICIOUS' : ipScore > 0 ? 'LOW' : 'CLEAN';

    // Vector 4: URL Forensics & Phishing Link Intelligence (Weight: 20%)
    let urlScore = 0;
    const urlFindings = [];
    if (urlIntelligence && urlIntelligence.totalUrls > 0) {
        urlScore = urlIntelligence.maxRiskScore || 0;
        if (urlIntelligence.maliciousUrlsCount > 0) {
            urlFindings.push(`${urlIntelligence.maliciousUrlsCount} malicious URL(s) detected`);
        }
        if (urlIntelligence.suspiciousUrlsCount > 0) {
            urlFindings.push(`${urlIntelligence.suspiciousUrlsCount} suspicious link(s) detected`);
        }
        if (Array.isArray(urlIntelligence.flags) && urlIntelligence.flags.length > 0) {
            urlFindings.push(...urlIntelligence.flags.slice(0, 2));
        }
    } else {
        urlFindings.push('No hyperlinks in email body');
    }
    urlScore = Math.min(100, Math.max(0, urlScore));
    const urlStatus = urlScore >= 70 ? 'CRITICAL' : urlScore >= 40 ? 'SUSPICIOUS' : urlScore > 0 ? 'LOW' : 'CLEAN';

    // Vector 5: Attachment Forensics & PDF Exploits (Weight: 20%)
    let attScore = 0;
    const attFindings = [];
    if (attachmentIntelligence && attachmentIntelligence.totalAttachments > 0) {
        attScore = attachmentIntelligence.maxRiskScore || 0;
        if (attachmentIntelligence.hasPdfExploits) {
            attFindings.push('Exploit objects (/JavaScript, /Launch, /OpenAction) in PDF');
        }
        if (attachmentIntelligence.hasDangerousExtensions) {
            attFindings.push('Blocked executable or deceptive double extension');
        }
        if (attachmentIntelligence.maliciousCount > 0) {
            attFindings.push(`${attachmentIntelligence.maliciousCount} weaponized attachment(s)`);
        }
        if (Array.isArray(attachmentIntelligence.flags) && attachmentIntelligence.flags.length > 0) {
            attFindings.push(...attachmentIntelligence.flags.slice(0, 2));
        }
    } else {
        attFindings.push('No file attachments found');
    }
    attScore = Math.min(100, Math.max(0, attScore));
    const attStatus = attScore >= 70 ? 'CRITICAL' : attScore >= 40 ? 'SUSPICIOUS' : attScore > 0 ? 'LOW' : 'CLEAN';

    // Vector 6: Gemini Multimodal Vision & Quishing (Weight: 15%)
    let visScore = 0;
    const visFindings = [];
    if (visionIntelligence && (visionIntelligence.totalImages > 0 || visionIntelligence.totalImagesScanned > 0)) {
        visScore = visionIntelligence.maxRiskScore || 0;
        if (visionIntelligence.hasQuishing || visionIntelligence.quishingDetected) {
            visFindings.push('QR code phishing (Quishing) detected');
        }
        if (visionIntelligence.hasFakeLogin || visionIntelligence.fakeLoginDetected) {
            visFindings.push('Simulated fake login portal detected');
        }
        if (visionIntelligence.impersonatedBrands && visionIntelligence.impersonatedBrands.length > 0) {
            visFindings.push(`Brand spoofing: ${visionIntelligence.impersonatedBrands.join(', ')}`);
        }
        if (Array.isArray(visionIntelligence.flags) && visionIntelligence.flags.length > 0) {
            visFindings.push(...visionIntelligence.flags.slice(0, 2));
        }
    } else {
        visFindings.push('No visual image attachments or QR codes');
    }
    visScore = Math.min(100, Math.max(0, visScore));
    const visStatus = visScore >= 70 ? 'CRITICAL' : visScore >= 40 ? 'SUSPICIOUS' : visScore > 0 ? 'LOW' : 'CLEAN';

    // Composite Calculation (Weighted Sum)
    const weights = {
        headerAuth: 0.15,
        domainIntel: 0.15,
        ipReputation: 0.15,
        urlForensics: 0.20,
        attachmentForensics: 0.20,
        visionIntelligence: 0.15
    };

    const weightedScores = {
        headerAuth: +(headerScore * weights.headerAuth).toFixed(1),
        domainIntel: +(domainScore * weights.domainIntel).toFixed(1),
        ipReputation: +(ipScore * weights.ipReputation).toFixed(1),
        urlForensics: +(urlScore * weights.urlForensics).toFixed(1),
        attachmentForensics: +(attScore * weights.attachmentForensics).toFixed(1),
        visionIntelligence: +(visScore * weights.visionIntelligence).toFixed(1)
    };

    let compositeScore = Math.round(
        weightedScores.headerAuth +
        weightedScores.domainIntel +
        weightedScores.ipReputation +
        weightedScores.urlForensics +
        weightedScores.attachmentForensics +
        weightedScores.visionIntelligence
    );

    // Hard floor protection for high-confidence single-vector critical attacks
    const maxSingleVector = Math.max(headerScore, domainScore, ipScore, urlScore, attScore, visScore);
    if (maxSingleVector >= 90) {
        compositeScore = Math.max(compositeScore, 78);
    } else if (maxSingleVector >= 70) {
        compositeScore = Math.max(compositeScore, 55);
    }

    compositeScore = Math.min(100, Math.max(0, compositeScore));

    let overallRiskLevel = 'CLEAN';
    if (compositeScore >= 70) overallRiskLevel = 'CRITICAL';
    else if (compositeScore >= 45) overallRiskLevel = 'HIGH';
    else if (compositeScore >= 25) overallRiskLevel = 'MEDIUM';
    else if (compositeScore > 0) overallRiskLevel = 'LOW';

    return {
        compositeScore,
        overallRiskLevel,
        vectors: {
            headerAuth: {
                name: "Header & Authentication",
                score: headerScore,
                weight: weights.headerAuth,
                weightedScore: weightedScores.headerAuth,
                status: headerStatus,
                finding: headerFindings[0] || "Header parameters normal"
            },
            domainIntel: {
                name: "Domain Intelligence & Age",
                score: domainScore,
                weight: weights.domainIntel,
                weightedScore: weightedScores.domainIntel,
                status: domainStatus,
                finding: domainFindings[0] || "Domain characteristics verified"
            },
            ipReputation: {
                name: "IP Threat Feeds & AbuseIPDB",
                score: ipScore,
                weight: weights.ipReputation,
                weightedScore: weightedScores.ipReputation,
                status: ipStatus,
                finding: ipFindings[0] || "Clean IP reputation"
            },
            urlForensics: {
                name: "URL Forensics & Link Reputation",
                score: urlScore,
                weight: weights.urlForensics,
                weightedScore: weightedScores.urlForensics,
                status: urlStatus,
                finding: urlFindings[0] || "No malicious links identified"
            },
            attachmentForensics: {
                name: "Attachment & PDF Exploit Engine",
                score: attScore,
                weight: weights.attachmentForensics,
                weightedScore: weightedScores.attachmentForensics,
                status: attStatus,
                finding: attFindings[0] || "No weaponized attachments"
            },
            visionIntelligence: {
                name: "Gemini Vision & Quishing Analysis",
                score: visScore,
                weight: weights.visionIntelligence,
                weightedScore: weightedScores.visionIntelligence,
                status: visStatus,
                finding: visFindings[0] || "No visual spoofing detected"
            }
        }
    };
}

/**
 * Calibrated Heuristic Engine for balanced threat assessment
 */
function computeHeuristicAnalysis({
    subject = '',
    bodyText = '',
    anomalies = [],
    authentication = {},
    domainIntel = {},
    threatIntel = {},
    urlIntelligence = {},
    attachmentIntelligence = {},
    visionIntelligence = {}
}) {
    const matrix = computeThreatVectorMatrix({
        anomalies,
        authentication,
        domainIntel,
        threatIntel,
        urlIntelligence,
        attachmentIntelligence,
        visionIntelligence
    });

    let score = matrix.compositeScore;
    const cues = [];
    let category = "Legitimate Communication";
    let isPhishing = score >= 40;

    // Determine category based on dominant threat vector
    if (anomalies.some(a => a.type === 'RETURN_PATH_MISMATCH')) {
        cues.push("From & Return-Path domain mismatch indicates envelope sender spoofing.");
        category = "Domain Spoofing / Impersonation";
        isPhishing = true;
    }

    if (anomalies.some(a => a.type === 'REPLY_TO_MISMATCH')) {
        cues.push("Reply-To header redirects correspondence away from sender domain.");
        category = "Executive Impersonation (BEC)";
        isPhishing = true;
    }

    if (anomalies.some(a => a.type === 'AUTH_EXPLICIT_FAIL')) {
        cues.push("Email explicitly failed cryptographic SPF/DMARC authentication.");
    }

    if (domainIntel.domainAgeDays !== null && domainIntel.domainAgeDays < 15) {
        cues.push(`Sender domain is newly registered (${domainIntel.domainAgeDays} days old), a common indicator for disposable attack infrastructure.`);
        isPhishing = true;
    }

    if (threatIntel.abuseConfidenceScore > 50) {
        cues.push(`Originating IP is flagged in threat intelligence feeds with an abuse confidence score of ${threatIntel.abuseConfidenceScore}%.`);
        isPhishing = true;
    }

    // URL Forensics & Phishing Link Evaluation
    if (urlIntelligence && urlIntelligence.totalUrls > 0) {
        if (urlIntelligence.maliciousUrlsCount > 0 || urlIntelligence.maxRiskScore >= 70) {
            isPhishing = true;
            category = "Credential Harvesting / Phishing Link";
            cues.push(`High-risk phishing / malicious hyperlink detected (${urlIntelligence.maliciousUrlsCount} critical link targets).`);
        } else if (urlIntelligence.suspiciousUrlsCount > 0 || urlIntelligence.maxRiskScore >= 40) {
            isPhishing = true;
            cues.push(`Suspicious URL characteristics detected (IP host, homograph, or credential keywords in path).`);
        }

        if (Array.isArray(urlIntelligence.flags) && urlIntelligence.flags.length > 0) {
            urlIntelligence.flags.slice(0, 3).forEach(flag => cues.push(`URL Flag: ${flag}`));
        }
    }

    // Attachment Forensics & PDF Exploit Evaluation
    if (attachmentIntelligence && attachmentIntelligence.totalAttachments > 0) {
        if (attachmentIntelligence.maliciousCount > 0 || attachmentIntelligence.hasPdfExploits || attachmentIntelligence.hasDangerousExtensions) {
            isPhishing = true;
            category = "Malicious Attachment / Weaponized PDF";
            cues.push(`Weaponized email attachment detected (${attachmentIntelligence.maliciousCount} critical file threats identified).`);
        } else if (attachmentIntelligence.suspiciousCount > 0 || attachmentIntelligence.maxRiskScore >= 30) {
            isPhishing = true;
            cues.push(`Suspicious attachment attributes detected (macro capability or urgent payment demand in PDF).`);
        }

        if (Array.isArray(attachmentIntelligence.flags) && attachmentIntelligence.flags.length > 0) {
            attachmentIntelligence.flags.slice(0, 3).forEach(flag => cues.push(`Attachment Flag: ${flag}`));
        }
    }

    // Multimodal Vision Intelligence & Quishing Evaluation
    if (visionIntelligence && (visionIntelligence.totalImages > 0 || visionIntelligence.totalImagesScanned > 0)) {
        if (visionIntelligence.hasQuishing || visionIntelligence.quishingDetected) {
            isPhishing = true;
            category = "QR Code Phishing (Quishing)";
            cues.push("Embedded QR Code detected designed for mobile phishing redirection (Quishing).");
        } else if (visionIntelligence.hasFakeLogin || visionIntelligence.fakeLoginDetected || visionIntelligence.maliciousCount > 0) {
            isPhishing = true;
            category = "Visual Brand Impersonation / Fake Login";
            cues.push(`Visual analysis detected simulated brand portal (${visionIntelligence.impersonatedBrands?.join(', ') || 'Corporate Login'}).`);
        } else if (visionIntelligence.maxRiskScore >= 30) {
            isPhishing = true;
            cues.push("Suspicious visual artifact or unauthorized corporate logo styling detected.");
        }

        if (Array.isArray(visionIntelligence.flags) && visionIntelligence.flags.length > 0) {
            visionIntelligence.flags.slice(0, 3).forEach(flag => cues.push(`Vision Cue: ${flag}`));
        }
    }

    // High-confidence fraudulent keywords check
    const lowerBody = (subject + ' ' + bodyText).toLowerCase();
    const isWireDivert = /wire transfer|escrow settlement|updated bank account|offshore account|routing number/i.test(lowerBody);
    const isCredentialTheft = /password expires in \d+|verify your login|account suspension in \d+|retain your password/i.test(lowerBody);

    if (isWireDivert && (anomalies.length > 0 || isPhishing)) {
        cues.push("Financial wire transfer diversion instructions detected in email content.");
        if (category === "Legitimate Communication") category = "Executive Impersonation (BEC)";
        isPhishing = true;
    } else if (isCredentialTheft) {
        cues.push("Urgent credential expiration and account suspension coercion detected.");
        if (category === "Legitimate Communication") category = "Credential Harvesting";
        isPhishing = true;
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
            ? `Forensic analysis detected high-risk multi-vector threat indicators (Composite Score: ${score}/100) across protocols, URLs, attachments, and visual artifacts.`
            : `Email appears legitimate with normal business communications and authentic delivery parameters.`,
        mitigationSteps: isPhishing 
            ? ["Quarantine email from recipient mailboxes", "Block sender domain and originating IP on gateway", "Block and sinkhole detected phishing URLs", "Isolate and sandbox suspicious attachments", "Block detected Quishing QR destinations", "Notify security operations of targeted attempt"]
            : ["No containment action required", "Normal delivery approved"],
        threatVectorMatrix: matrix
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
    threatIntel = {},
    urlIntelligence = {},
    attachmentIntelligence = {},
    visionIntelligence = {}
}) {
    const matrix = computeThreatVectorMatrix({
        anomalies,
        authentication,
        domainIntel,
        threatIntel,
        urlIntelligence,
        attachmentIntelligence,
        visionIntelligence
    });

    const apiKey = process.env.GEMINI_API_KEY;

    if (!apiKey) {
        return computeHeuristicAnalysis({ subject, bodyText, anomalies, authentication, domainIntel, threatIntel, urlIntelligence, attachmentIntelligence, visionIntelligence });
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
  * 71 - 100 (CRITICAL MALICIOUS): Confirmed BEC wire transfer scams, password/credential harvesting pages, executive impersonation from spoofed domains, weaponized attachments, or QR code phishing.

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

=== URL FORENSICS & LINK INTELLIGENCE ===
Total URLs Found: ${urlIntelligence.totalUrls || 0}
Malicious URLs: ${urlIntelligence.maliciousUrlsCount || 0}
Suspicious URLs: ${urlIntelligence.suspiciousUrlsCount || 0}
Max URL Risk Score: ${urlIntelligence.maxRiskScore || 0}/100
URL Risk Level: ${urlIntelligence.riskLevel || 'CLEAN'}
URL Threat Flags: ${JSON.stringify(urlIntelligence.flags || [])}

=== ATTACHMENT FORENSICS & PDF EXPLOIT INTEL ===
Total Attachments: ${attachmentIntelligence.totalAttachments || 0}
Malicious Attachments: ${attachmentIntelligence.maliciousCount || 0}
Suspicious Attachments: ${attachmentIntelligence.suspiciousCount || 0}
PDF Exploit Objects Found: ${attachmentIntelligence.hasPdfExploits ? 'YES' : 'NO'}
Dangerous Extensions: ${attachmentIntelligence.hasDangerousExtensions ? 'YES' : 'NO'}
Max Attachment Risk Score: ${attachmentIntelligence.maxRiskScore || 0}/100
Attachment Risk Level: ${attachmentIntelligence.riskLevel || 'CLEAN'}
Attachment Threat Flags: ${JSON.stringify(attachmentIntelligence.flags || [])}

=== GEMINI MULTIMODAL VISION & QUISHING INTEL ===
Total Image Attachments: ${visionIntelligence.totalImages || 0}
Quishing / QR Phishing Detected: ${visionIntelligence.hasQuishing ? 'YES' : 'NO'}
Fake Login Screens: ${visionIntelligence.hasFakeLogin ? 'YES' : 'NO'}
Impersonated Brands: ${JSON.stringify(visionIntelligence.impersonatedBrands || [])}
Vision Threat Level: ${visionIntelligence.riskLevel || 'CLEAN'}
Vision Threat Flags: ${JSON.stringify(visionIntelligence.flags || [])}

=== EMAIL BODY CONTENT (TRUNCATED) ===
${bodyText.slice(0, 3000)}

=== INSTRUCTIONS ===
Provide your objective forensic assessment strictly in the following JSON schema:
{
  "isPhishing": true/false,
  "threatScore": <integer between 0 and 100 based on the calibration scale above>,
  "threatCategory": "<Executive Impersonation (BEC) | Credential Harvesting | Invoice Fraud | Brand Impersonation | Malicious Attachment / Weaponized PDF | QR Code Phishing (Quishing) | Malware Delivery | Legitimate Communication>",
  "urgencyLevel": "<Critical | High | Medium | Low>",
  "attributionAssessment": "<e.g. Likely Spoofed Domain / Compromised Server / Bulletproof Host / Weaponized Drop Loader / Quishing Campaign / Legitimate Authorized Mailer>",
  "suspiciousCues": ["<concise specific indicator 1>", ...],
  "summary": "<2-sentence accurate cyber-forensic summary of the email>",
  "mitigationSteps": ["<SOC action step 1>", "<SOC action step 2>", "<SOC action step 3>", "<SOC action step 4>"]
}
`;

        const result = await model.generateContent(prompt);
        const parsed = JSON.parse(result.response.text());
        parsed.threatVectorMatrix = matrix;
        return parsed;
    } catch (error) {
        console.warn("Gemini API Error (using calibrated heuristics):", error.message);
        return computeHeuristicAnalysis({ subject, bodyText, anomalies, authentication, domainIntel, threatIntel, urlIntelligence, attachmentIntelligence, visionIntelligence });
    }
}

module.exports = {
    analyzeEmailWithAI,
    computeThreatVectorMatrix,
    computeHeuristicAnalysis
};