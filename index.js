const express = require('express');
const cors = require('cors');
require('dotenv').config();
const mongoose = require('mongoose');

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ MongoDB Atlas connected successfully"))
    .catch((err) => {
        console.error("❌ MongoDB connection FAILED:", err.message);
        process.exit(1);
    });

const { parseEmailHeaders } = require('./services/headerParser');
const { getGeoLocation } = require('./services/geoService');
const { getDomainIntelligence } = require('./services/domainService');
const { checkThreatIntel } = require('./services/threatIntelService');
const { analyzeUrls } = require('./services/urlService');
const { analyzeAttachments } = require('./services/attachmentService');
const { analyzeVisionAttachments } = require('./services/visionService');
const { recordBlockchainEvidence } = require('./services/blockchainService');
const { saveCase, listCases, getCaseById, deleteCase, getCaseStats } = require('./services/caseStorage');
const { analyzeEmailWithAI } = require('./services/aiEngine');

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('./Database/models/User');
const { requireAuth, requireRole } = require('./Middleware/auth');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json({ limit: '15mb' }));

// POST /auth/register
app.post('/auth/register', async (req, res) => {
    try {
        const { email, password, role } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: "Email and password required" });
        }

        const existing = await User.findOne({ email: email.toLowerCase() });
        if (existing) {
            return res.status(409).json({ error: "User already exists" });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        const user = await User.create({ email, passwordHash, role: role || 'analyst' });

        res.status(201).json({ message: "User registered", userId: user._id, role: user.role });
    } catch (err) {
        console.error("Register error:", err);
        res.status(500).json({ error: "Registration failed" });
    }
});

// POST /auth/login
app.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email: email?.toLowerCase() });
        if (!user) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const match = await bcrypt.compare(password, user.passwordHash);
        if (!match) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const token = jwt.sign(
            { userId: user._id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '8h' }
        );

        res.json({ token, role: user.role, email: user.email, userId: user._id });
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ error: "Login failed" });
    }
});

// GET /auth/me - Validate current token and fetch session user profile
app.get('/auth/me', requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-passwordHash');
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }
        res.json({ user });
    } catch (err) {
        console.error("Auth me error:", err);
        res.status(500).json({ error: "Failed to verify user session" });
    }
});

// Health Check & Service Readiness
app.get('/api/health', (req, res) => {
    res.json({
        status: "ok",
        platform: "AI-Powered Email Forensics & Threat Intelligence Platform",
        version: "2.0.0",
        services: {
            geminiAI: Boolean(process.env.GEMINI_API_KEY),
            geminiVision: Boolean(process.env.GEMINI_API_KEY),
            abuseIPDB: Boolean(process.env.ABUSEIPDB_API_KEY),
            googleSafeBrowsing: Boolean(process.env.GOOGLE_SAFE_BROWSING_API_KEY),
            urlIntelligence: "Active (Regex DOM, Homograph, Shorteners, IP-Detection)",
            attachmentForensics: "Active (PDF Structural Analysis, Exploit Scanning, Text Heuristics)",
            visionForensics: "Active (Multimodal Gemini Vision, Brand Impersonation, Quishing)",
            blockchainEVM: Boolean(process.env.PRIVATE_KEY),
            caseStorage: "Active (MongoDB Atlas)",
            privacySafeguards: "SHA-256 IP Anonymization (Block 12 Compliant)"
        }
    });
});

// Main Forensic Analysis Pipeline (Analyst & Admin only)
app.post('/api/analyze', requireAuth, requireRole('analyst', 'admin'), async (req, res) => {
    try {
        const { rawEmail } = req.body;
        if (!rawEmail || typeof rawEmail !== 'string') {
            return res.status(400).json({ error: "No rawEmail payload provided." });
        }

        // Step 1: Deep Header Parsing & Protocol Anomaly Detection
        const parsedHeader = await parseEmailHeaders(rawEmail);

        // Step 2: Parallel Telemetry Enrichment (Geo, Domain Intel, Threat Intel, URL Forensics, Attachment & Vision Forensics)
        const [geoData, domainIntel, threatIntel, urlIntel, attachmentIntel, visionIntel] = await Promise.all([
            getGeoLocation(parsedHeader.originatingIP),
            getDomainIntelligence(parsedHeader.senderDomain),
            checkThreatIntel(parsedHeader.originatingIP),
            analyzeUrls({ bodyText: parsedHeader.bodyText, bodyHtml: parsedHeader.bodyHtml }),
            analyzeAttachments(parsedHeader.rawAttachments),
            analyzeVisionAttachments(parsedHeader.rawAttachments)
        ]);

        // Step 3: Multi-Signal AI Threat Classification (Gemini Flash + Telemetry + URL + Attachments + Vision)
        const aiAnalysis = await analyzeEmailWithAI({
            subject: parsedHeader.subject,
            bodyText: parsedHeader.bodyText,
            headers: {
                from: parsedHeader.from,
                to: parsedHeader.to,
                date: parsedHeader.date,
                returnPath: parsedHeader.returnPath,
                replyTo: parsedHeader.replyTo
            },
            anomalies: parsedHeader.anomalies,
            authentication: parsedHeader.authentication,
            domainIntel,
            threatIntel,
            urlIntelligence: urlIntel,
            attachmentIntelligence: attachmentIntel,
            visionIntelligence: visionIntel
        });

        // Step 4: Blockchain Evidence Preservation & Chain-of-Custody (Web3 EVM)
        const caseId = `CASE-${new Date().getFullYear()}-${String(Date.now()).slice(-5)}`;
        const blockchainReceipt = await recordBlockchainEvidence({
            caseId,
            subject: parsedHeader.subject,
            from: parsedHeader.from,
            date: parsedHeader.date,
            originatingIP: parsedHeader.originatingIP,
            threatScore: aiAnalysis.threatScore
        });

        // Step 5: Construct Unified Forensic Report
        const report = {
            success: true,
            caseId,
            timestamp: new Date().toISOString(),
            emailDetails: {
                subject: parsedHeader.subject,
                from: parsedHeader.from,
                fromEmail: parsedHeader.fromEmail,
                senderDomain: parsedHeader.senderDomain,
                to: parsedHeader.to,
                date: parsedHeader.date,
                returnPath: parsedHeader.returnPath,
                replyTo: parsedHeader.replyTo,
                messageId: parsedHeader.messageId
            },
            authentication: parsedHeader.authentication,
            anomalies: parsedHeader.anomalies,
            urlIntelligence: urlIntel,
            attachmentIntelligence: attachmentIntel,
            visionIntelligence: visionIntel,
            routing: {
                hopChain: parsedHeader.hopIPChain,
                hopDetails: parsedHeader.hopDetails,
                originatingIP: parsedHeader.originatingIP,
                location: geoData
            },
            domainIntelligence: domainIntel,
            threatIntelligence: threatIntel,
            threatVectorMatrix: aiAnalysis.threatVectorMatrix,
            aiThreatAnalysis: aiAnalysis,
            blockchain: blockchainReceipt,
            privacyCompliance: {
                standard: "GDPR / DPDP Article 12 Evidentiary Standard",
                anonymizationMethod: "SHA-256 Hash + Octet Masking",
                rawIpRetained: false
            }
        };

        // Step 6: Persist in MongoDB with IP Anonymization (Block 9 & 12) & User Association
        await saveCase(report, req.user?.userId);

        res.json(report);
    } catch (error) {
        console.error("Forensic Pipeline Error:", error);
        res.status(500).json({ error: error.message || "Internal Forensic Pipeline Error" });
    }
});

// Case Management Endpoints (Analyst, Admin & Auditor for read; Admin only for delete)
app.get('/api/cases', requireAuth, requireRole('analyst', 'admin', 'auditor'), async (req, res) => {
    try {
        const { search, category, limit } = req.query;
        const cases = await listCases({ search, category, limit: Number(limit) || 50 });
        const stats = await getCaseStats();
        res.json({ cases, stats });
    } catch (err) {
        console.error("Error retrieving cases:", err);
        res.status(500).json({ error: "Failed to retrieve case records" });
    }
});

app.get('/api/cases/:id', requireAuth, requireRole('analyst', 'admin', 'auditor'), async (req, res) => {
    try {
        const caseRecord = await getCaseById(req.params.id);
        if (!caseRecord) return res.status(404).json({ error: "Case record not found" });
        res.json(caseRecord);
    } catch (err) {
        console.error("Error retrieving case:", err);
        res.status(500).json({ error: "Failed to retrieve case details" });
    }
});

app.delete('/api/cases/:id', requireAuth, requireRole('admin'), async (req, res) => {
    try {
        const deleted = await deleteCase(req.params.id);
        if (!deleted) return res.status(404).json({ error: "Case not found" });
        res.json({ success: true, message: `Case ${req.params.id} deleted` });
    } catch (err) {
        console.error("Error deleting case:", err);
        res.status(500).json({ error: "Failed to delete case" });
    }
});

// Preset Demo Samples for Instant Testing
app.get('/api/samples', (req, res) => {
    const samples = [
        {
            name: "CEO Urgent Wire Transfer (BEC Attack)",
            type: "BEC_PHISHING",
            rawEmail: `Received: from mail-out.attacker-relay.net (194.26.29.102) by mx.target-corp.com with SMTP; 05 Sep 2026 10:14:22 +0000
Received: from internal.spoofer (10.0.0.5) by mail-out.attacker-relay.net; 05 Sep 2026 10:14:20 +0000
Authentication-Results: mx.target-corp.com; spf=fail (sender IP is 194.26.29.102) smtp.mailfrom=spoof-exec@ceo-private-corp.com; dkim=fail; dmarc=fail
From: "Jonathan Reed (CEO)" <ceo@target-corp.com>
Return-Path: <bounce@spoof-exec-redirect.com>
Reply-To: <executive-desk@external-offshore-settlement.com>
To: "Emily Chen (CFO)" <cfo@target-corp.com>
Subject: URGENT & CONFIDENTIAL: Acquisition Escrow Wire Transfer #99481
Date: Fri, 05 Sep 2026 10:14:15 +0000
Message-ID: <unverified-random-msg-9921@attacker-relay.net>

Emily,

I am currently in an all-day board meeting with confidential acquisition counsel. 
We need to finalize the escrow settlement payment of $248,500 immediately before market close today.

Please process the wire transfer to our settlement partner's updated bank coordinates:
Beneficiary: Offshore Corporate Escrow Ltd
Routing: 021000021
Account: 9948210492

Do not call my phone as I cannot interrupt the board presentation. Confirm via reply as soon as the wire transaction is submitted.

Best regards,
Jonathan Reed
Chief Executive Officer
Target Corp International`
        },
        {
            name: "Microsoft 365 Password Expiration (Credential Theft)",
            type: "CREDENTIAL_HARVESTING",
            rawEmail: `Received: from relay-host.cloud-vps.org (45.154.255.88) by mail.company.com with ESMTP; 04 Sep 2026 14:20:11 +0000
Authentication-Results: mail.company.com; spf=softfail (IP 45.154.255.88); dkim=none; dmarc=fail action=none
From: "Microsoft 365 Security Team" <admin@microsoft-security-alert-center.com>
Return-Path: <no-reply@microsoft-security-alert-center.com>
Reply-To: <no-reply@microsoft-security-alert-center.com>
To: "User Account" <employee@company.com>
Subject: Action Required: Your Office 365 Password Expires in 2 Hours
Date: Thu, 04 Sep 2026 14:20:00 +0000
Message-ID: <ms-sec-88492041@microsoft-security-alert-center.com>

Dear User,

Your Microsoft Office 365 enterprise account password will expire today in 2 hours. 
To avoid loss of email access, cloud documents, and SharePoint directories, you must retain your existing password now.

>> Keep My Same Password: http://microsoft-auth-portal-verify.phish-site.cc/login?user=employee

Failure to update will result in administrative account lockout within 120 minutes.

Security Operations Center
Microsoft Cloud Infrastructure Services`
        },
        {
            name: "Deceptive Phishing Links & Homograph Spoofing",
            type: "URL_PHISHING",
            rawEmail: `Received: from relay.bulletproof-host.xyz (185.220.101.42) by mail.target-company.com with ESMTP; 06 Sep 2026 16:30:00 +0000
Authentication-Results: mail.target-company.com; spf=fail; dkim=none; dmarc=fail
From: "DocuSign Electronic Signature Service" <service@docus1gn-sign-portal.top>
Return-Path: <bounce@attacker-dropzone.ru>
Reply-To: <phish-collector@mail-box.xyz>
To: "Finance Team" <accounts@target-company.com>
Subject: IMPORTANT: Review & Sign Audit Confirmation Document #DocuSign-9821
Date: Sun, 06 Sep 2026 16:30:00 +0000
Message-ID: <docusign-fraud-8819@docus1gn-sign-portal.top>
Content-Type: text/html; charset="UTF-8"

<p>Hello Accounts Team,</p>
<p>You have received a new confidential financial statement requiring your electronic signature.</p>
<p>Please review and sign the attached statement immediately via the secure DocuSign authentication gateway:</p>
<p>
  <a href="http://194.26.29.102:8080/auth/signin?session=99281">https://account.docusign.com/esign/portal</a>
</p>
<p>Alternatively, click the secondary mirror link: <a href="http://xn--dcusgn-xta1a.xyz/login">http://docusign.com/audit-review</a> or short link <a href="https://bit.ly/secure-doc-auth">https://bit.ly/secure-doc-auth</a></p>
<p>Thank you,<br/>DocuSign Trust Center</p>`
        },
        {
            name: "Authentic Google Cloud Invoice (Legitimate)",
            type: "LEGITIMATE",
            rawEmail: `Received: from mail-sor-f65.google.com (209.85.220.65) by mx.company.com with SMTP; 01 Sep 2026 08:00:00 +0000
Authentication-Results: mx.company.com; spf=pass (google.com: domain of 3j21-z@doc-cloud.bounces.google.com designates 209.85.220.65 as permitted sender) smtp.mailfrom=3j21-z@doc-cloud.bounces.google.com; dkim=pass header.i=@google.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
From: "Google Cloud Billing" <cloud-billing-noreply@google.com>
Return-Path: <3j21-z@doc-cloud.bounces.google.com>
Reply-To: <cloud-billing-noreply@google.com>
To: "Billing Admin" <admin@company.com>
Subject: Your Google Cloud Monthly Invoice is Ready
Date: Tue, 01 Sep 2026 08:00:00 +0000
Message-ID: <google-cloud-billing-2026-09@google.com>

Hello Google Cloud Customer,

Your monthly invoice for Google Cloud services (Account ID: 018492-49102-1940) for August 2026 is now available in your Google Cloud Console.

Total Amount: $42.15 USD
Due Date: Automatic payment scheduled

You can view your detailed usage breakdown and billing report directly in the Google Cloud Console: https://console.cloud.google.com/billing

Thank you for building with Google Cloud.`
        }
    ];

    res.json(samples);
});

app.listen(PORT, () => {
    console.log(`=======================================================`);
    console.log(`🚀 Email Forensics & Threat Platform running on :${PORT}`);
    console.log(`📍 Web3 Blockchain & SOC Case Management Active`);
    console.log(`🔒 Block 12 Privacy Safeguards Enabled (IP Hashing)`);
    console.log(`=======================================================`);
});