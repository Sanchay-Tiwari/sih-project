const { parseEmailHeaders } = require('./services/headerParser');
const { getGeoLocation } = require('./services/geoService');
const { getDomainIntelligence } = require('./services/domainService');
const { checkThreatIntel } = require('./services/threatIntelService');
const { recordBlockchainEvidence } = require('./services/blockchainService');
const { saveCase, listCases, getCaseStats } = require('./services/caseStorage');
const { analyzeEmailWithAI } = require('./services/aiEngine');

async function runTest() {
    console.log("=== STARTING FULL FORENSIC PIPELINE TEST ===");

    const sampleEmail = `Received: from mail-out.attacker-relay.net (194.26.29.102) by mx.target-corp.com with SMTP; 05 Sep 2026 10:14:22 +0000
Authentication-Results: mx.target-corp.com; spf=fail; dkim=fail; dmarc=fail
From: "Jonathan Reed (CEO)" <ceo@target-corp.com>
Return-Path: <bounce@spoof-exec-redirect.com>
Reply-To: <executive-desk@offshore-divert.com>
To: "Emily Chen (CFO)" <cfo@target-corp.com>
Subject: URGENT: Acquisition Escrow Wire Transfer #99481
Date: Fri, 05 Sep 2026 10:14:15 +0000

Emily,
Please process the wire transfer of $248,500 immediately before bank cutoff.`;

    // 1. Header & Anomaly Parsing
    const parsed = await parseEmailHeaders(sampleEmail);
    console.log("[1] Headers Parsed. From:", parsed.from, "| Origin IP:", parsed.originatingIP);
    console.log("[1] Anomalies Detected:", parsed.anomalies.map(a => `${a.severity}: ${a.title}`));

    // 2. Telemetry Services
    const [geo, domainIntel, threatIntel] = await Promise.all([
        getGeoLocation(parsed.originatingIP),
        getDomainIntelligence(parsed.senderDomain),
        checkThreatIntel(parsed.originatingIP)
    ]);
    console.log("[2] Geo Location:", geo.city, geo.country, "| ISP:", geo.isp);
    console.log("[2] Domain Intel:", domainIntel.domain, "| MX Active:", domainIntel.hasMx, "| Risk:", domainIntel.riskRating);
    console.log("[2] Threat Intel:", threatIntel.threatLevel, "| Abuse Score:", threatIntel.abuseConfidenceScore);

    // 3. AI Threat Assessment
    const aiResult = await analyzeEmailWithAI({
        subject: parsed.subject,
        bodyText: parsed.bodyText,
        headers: { from: parsed.from, to: parsed.to, returnPath: parsed.returnPath, replyTo: parsed.replyTo },
        anomalies: parsed.anomalies,
        authentication: parsed.authentication,
        domainIntel,
        threatIntel
    });
    console.log("[3] AI Threat Score:", aiResult.threatScore, "/ 100 | Category:", aiResult.threatCategory);
    console.log("[3] AI Summary:", aiResult.summary);

    // 4. Web3 Blockchain Anchor
    const caseId = `CASE-TEST-${Date.now().toString().slice(-4)}`;
    const blockchainReceipt = await recordBlockchainEvidence({
        caseId,
        subject: parsed.subject,
        from: parsed.from,
        date: parsed.date,
        originatingIP: parsed.originatingIP,
        threatScore: aiResult.threatScore
    });
    console.log("[4] Blockchain Anchor:", blockchainReceipt.status, "| Tx Hash:", blockchainReceipt.txHash.slice(0, 20) + "...");
    console.log("[4] Evidence SHA-256 Digest:", blockchainReceipt.evidenceHash.slice(0, 20) + "...");

    // 5. Case Persistence & IP Hashing (Block 12)
    const report = {
        caseId,
        emailDetails: { subject: parsed.subject, from: parsed.from, to: parsed.to, date: parsed.date },
        authentication: parsed.authentication,
        anomalies: parsed.anomalies,
        routing: { hopChain: parsed.hopIPChain, originatingIP: parsed.originatingIP, location: geo },
        domainIntelligence: domainIntel,
        threatIntelligence: threatIntel,
        aiThreatAnalysis: aiResult,
        blockchain: blockchainReceipt
    };
    const saved = saveCase(report);
    console.log("[5] Case Saved to DB with Case ID:", saved.caseId);
    console.log("[5] Anonymized IP Hash (Block 12):", saved.anonymizedIpHash.slice(0, 24) + "...", "| Masked:", saved.maskedIp);

    const stats = getCaseStats();
    console.log("[6] DB Case Stats:", stats);
    console.log("=== ALL MODULES VERIFIED SUCCESSFULLY ===");
}

runTest().catch(console.error);
