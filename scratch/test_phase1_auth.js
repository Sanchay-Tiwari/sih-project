require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const User = require('../Database/models/User');
const Case = require('../Database/models/Case');
const { saveCase, listCases, getCaseById } = require('../services/caseStorage');

async function verifyPhase1() {
    console.log("=== VERIFYING PHASE 1 IMPLEMENTATION ===");

    await mongoose.connect(process.env.MONGO_URI);
    console.log("✅ Connected to MongoDB");

    // 1. Create or Find Test Users
    const testAdminEmail = `admin_test_${Date.now()}@soc.local`;
    const testAnalystEmail = `analyst_test_${Date.now()}@soc.local`;
    const testAuditorEmail = `auditor_test_${Date.now()}@soc.local`;

    const adminHash = await bcrypt.hash("admin123", 10);
    const analystHash = await bcrypt.hash("analyst123", 10);
    const auditorHash = await bcrypt.hash("auditor123", 10);

    const adminUser = await User.create({ email: testAdminEmail, passwordHash: adminHash, role: 'admin' });
    const analystUser = await User.create({ email: testAnalystEmail, passwordHash: analystHash, role: 'analyst' });
    const auditorUser = await User.create({ email: testAuditorEmail, passwordHash: auditorHash, role: 'auditor' });

    console.log(`✅ Created test users: Admin (${adminUser._id}), Analyst (${analystUser._id}), Auditor (${auditorUser._id})`);

    // 2. Generate Tokens
    const adminToken = jwt.sign({ userId: adminUser._id, role: adminUser.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    const analystToken = jwt.sign({ userId: analystUser._id, role: analystUser.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    const auditorToken = jwt.sign({ userId: auditorUser._id, role: auditorUser.role }, process.env.JWT_SECRET, { expiresIn: '1h' });

    console.log("✅ JWT generation verified for all 3 roles");

    // 3. Test Save Case with analyzedBy User ID
    const testCaseId = `CASE-PH1-TEST-${Date.now().toString().slice(-5)}`;
    const mockReport = {
        caseId: testCaseId,
        emailDetails: { subject: "Phase 1 Verification Email", from: "phish@test.com", to: "victim@corp.com" },
        routing: { originatingIP: "1.2.3.4", location: { city: "TestCity", country: "TestCountry" } },
        aiThreatAnalysis: { threatScore: 85, threatCategory: "Credential Theft", isPhishing: true, summary: "Phase 1 test" },
        blockchain: { txHash: "0xmocktx", evidenceHash: "0xmockhash" }
    };

    const saved = await saveCase(mockReport, analystUser._id);
    console.log(`✅ Case saved with ID: ${saved.caseId}`);

    // 4. Test Case Retrieval & Population
    const fetchedCase = await getCaseById(testCaseId);
    console.log(`✅ Case retrieved. AnalyzedBy populated:`, fetchedCase.analyzedBy ? `${fetchedCase.analyzedBy.email} (${fetchedCase.analyzedBy.role})` : "None");

    if (fetchedCase.analyzedBy && fetchedCase.analyzedBy.email === testAnalystEmail) {
        console.log("🎯 SUCCESS: analyzedBy user association and population verified!");
    } else {
        console.error("❌ FAILURE: analyzedBy not populated as expected");
    }

    // Cleanup test artifacts
    await Case.deleteOne({ caseId: testCaseId });
    await User.deleteMany({ _id: { $in: [adminUser._id, analystUser._id, auditorUser._id] } });
    console.log("🧹 Cleaned up test artifacts");

    await mongoose.disconnect();
    console.log("=== PHASE 1 VERIFICATION COMPLETED SUCCESSFULLY ===");
}

verifyPhase1().catch((err) => {
    console.error("Verification failed with error:", err);
    process.exit(1);
});
