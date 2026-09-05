const express = require('express');
const cors = require('cors');
require('dotenv').config();

const { parseEmailHeaders } = require('./services/headerParser');
const { getGeoLocation } = require('./services/geoService');
const { getDomainIntelligence } = require('./services/domainService');
const { checkThreatIntel } = require('./services/threatIntelService');
const { recordBlockchainEvidence } = require('./services/blockchainService');
const { saveCase, listCases, getCaseById, deleteCase, getCaseStats } = require('./services/caseStorage');
const { analyzeEmailWithAI } = require('./services/aiEngine');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json({ limit: '15mb' }));

// Health Check & Service Readiness
app.get('/api/health', (req, res) => {
    res.json({
        status: "ok",
        platform: "AI-Powered Email Forensics & Threat Intelligence Platform",
        version: "2.0.0",
        services: {
            geminiAI: Boolean(process.env.GEMINI_API_KEY),
            abuseIPDB: Boolean(process.env.ABUSEIPDB_API_KEY),
            blockchainEVM: Boolean(process.env.PRIVATE_KEY),
            caseStorage: "Active (data/cases.json)",
            privacySafeguards: "SHA-256 IP Anonymization (Block 12 Compliant)"
        }
    });
});

// Main Forensic Analysis Pipeline
app.post('/api/analyze', async (req, res) => {
    try {
        const { rawEmail } = req.body;
        if (!rawEmail || typeof rawEmail !== 'string') {
            return res.status(400).json({ error: "No rawEmail payload provided." });
        }

        // Step 1: Deep Header Parsing & Protocol Anomaly Detection
        const parsedHeader = await parseEmailHeaders(rawEmail);

        // Step 2: Parallel Telemetry Enrichment (Geo, Domain Intel, Threat Intel)
        const [geoData, domainIntel, threatIntel] = await Promise.all([
            getGeoLocation(parsedHeader.originatingIP),
            getDomainIntelligence(parsedHeader.senderDomain),
            checkThreatIntel(parsedHeader.originatingIP)
        ]);

        // Step 3: Multi-Signal AI Threat Classification (Gemini Flash + Telemetry)
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
            threatIntel
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
            routing: {
                hopChain: parsedHeader.hopIPChain,
                hopDetails: parsedHeader.hopDetails,
                originatingIP: parsedHeader.originatingIP,
                location: geoData
            },
            domainIntelligence: domainIntel,
            threatIntelligence: threatIntel,
            aiThreatAnalysis: aiAnalysis,
            blockchain: blockchainReceipt,
            privacyCompliance: {
                standard: "GDPR / DPDP Article 12 Evidentiary Standard",
                anonymizationMethod: "SHA-256 Hash + Octet Masking",
                rawIpRetained: false
            }
        };

        // Step 6: Persist in Case Storage with IP Anonymization (Block 9 & 12)
        saveCase(report);

        res.json(report);
    } catch (error) {
        console.error("Forensic Pipeline Error:", error);
        res.status(500).json({ error: error.message || "Internal Forensic Pipeline Error" });
    }
});

// Case Management Endpoints
app.get('/api/cases', (req, res) => {
    try {
        const { search, category, limit } = req.query;
        const cases = listCases({ search, category, limit: Number(limit) || 50 });
        const stats = getCaseStats();
        res.json({ cases, stats });
    } catch (err) {
        res.status(500).json({ error: "Failed to retrieve case records" });
    }
});

app.get('/api/cases/:id', (req, res) => {
    try {
        const caseRecord = getCaseById(req.params.id);
        if (!caseRecord) return res.status(404).json({ error: "Case record not found" });
        res.json(caseRecord);
    } catch (err) {
        res.status(500).json({ error: "Failed to retrieve case details" });
    }
});

app.delete('/api/cases/:id', (req, res) => {
    try {
        const deleted = deleteCase(req.params.id);
        if (!deleted) return res.status(404).json({ error: "Case not found" });
        res.json({ success: true, message: `Case ${req.params.id} deleted` });
    } catch (err) {
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

You can view your detailed usage breakdown and billing report directly in the Google Cloud Console.

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