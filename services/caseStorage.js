const Case = require('../Database/models/Case');

/**
 * Privacy Safeguard (Block 12): Anonymize IP address via SHA-256 and octet masking
 */
const crypto = require('crypto');
function anonymizeIp(ip) {
    if (!ip) return { anonymizedIpHash: 'NONE', maskedIp: 'Unknown' };
    const anonymizedIpHash = crypto.createHash('sha256').update(ip).digest('hex');
    const parts = ip.split('.');
    const maskedIp = parts.length === 4 ? `${parts[0]}.${parts[1]}.xxx.xxx` : 'Masked IP';
    return { anonymizedIpHash, maskedIp };
}

/**
 * Save a new forensic analysis case into MongoDB
 */
async function saveCase(analysisData, userId = null) {
    const caseId = analysisData.caseId || `CASE-${new Date().getFullYear()}-${String(Date.now()).slice(-5)}`;
    const { anonymizedIpHash, maskedIp } = anonymizeIp(analysisData.routing?.originatingIP);

    const newCase = new Case({
        caseId,
        createdAt: new Date(),
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
        analyzedBy: userId || analysisData.analyzedBy || null,
        summary: analysisData.aiThreatAnalysis?.summary || '',
        fullAnalysis: analysisData
    });

    await newCase.save();
    return newCase.toObject();
}

/**
 * List cases with search, category filtering, and pagination
 */
async function listCases({ search = '', category = '', limit = 50 } = {}) {
    const query = {};

    if (search) {
        const regex = new RegExp(search.trim(), 'i'); // case-insensitive search
        query.$or = [
            { caseId: regex },
            { subject: regex },
            { from: regex },
            { senderDomain: regex },
            { threatCategory: regex }
        ];
    }

    if (category && category !== 'ALL') {
        query.threatCategory = category;
    }

    return await Case.find(query)
        .populate('analyzedBy', 'email role')
        .sort({ createdAt: -1 })   // newest first, same as old unshift() behavior
        .limit(Number(limit))
        .lean();                   // returns plain JS objects, faster than full Mongoose docs
}

/**
 * Retrieve a specific case by its Case ID
 */
async function getCaseById(caseId) {
    return await Case.findOne({ caseId })
        .populate('analyzedBy', 'email role')
        .lean();
}

/**
 * Delete a case by its Case ID
 */
async function deleteCase(caseId) {
    const result = await Case.deleteOne({ caseId });
    return result.deletedCount > 0;
}

/**
 * Get aggregate statistics across all recorded cases
 */
async function getCaseStats() {
    const total = await Case.countDocuments();
    const highThreat = await Case.countDocuments({ threatScore: { $gt: 70 } });
    const phishingCount = await Case.countDocuments({ isPhishing: true });

    const avgResult = await Case.aggregate([
        { $group: { _id: null, avg: { $avg: '$threatScore' } } }
    ]);
    const avgScore = avgResult.length > 0 ? Math.round(avgResult[0].avg) : 0;

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