const mongoose = require('mongoose');
const { Schema } = mongoose;

// ─────────────────────────────────────────────────────────────
// Case Schema
// Matches the real shape of your existing cases.json records.
// Top-level fields are strictly typed (used for search/filter/sort
// on the dashboard). fullAnalysis is kept flexible (Mixed) since
// it's a deep nested forensic report we don't want to risk
// silently truncating with an overly strict sub-schema.
// ─────────────────────────────────────────────────────────────

const caseSchema = new Schema({
    caseId: {
        type: String,
        required: true,
        unique: true,       // prevents two cases from ever sharing an ID
        index: true         // speeds up lookups by caseId (Case.findOne({ caseId }))
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    subject: String,
    from: String,
    senderDomain: String,
    to: String,

    threatScore: {
        type: Number,
        min: 0,
        max: 100
    },
    threatCategory: String,
    urgencyLevel: String,
    isPhishing: Boolean,

    originatingIP: {
        type: String,
        default: null        // some of your real records have null IPs (internal relays)
    },
    anonymizedIpHash: String,
    maskedIp: String,

    txHash: String,
    evidenceHash: String,

    authSummary: {
        spf: String,
        dkim: String,
        dmarc: String
    },

    summary: String,

    geo: {
    type: Schema.Types.Mixed,
    default: {}
},

    // The full nested forensic report (emailDetails, authentication,
    // anomalies, routing, domainIntelligence, threatIntelligence,
    // aiThreatAnalysis, blockchain, privacyCompliance, etc.)
    // Stored as-is, no strict shape enforced.
    fullAnalysis: {
        type: Schema.Types.Mixed,
        default: {}
    }
}, {
    timestamps: false   // we already track createdAt ourselves above
});

module.exports = mongoose.model('Case', caseSchema);