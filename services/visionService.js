/**
 * ThreatTrace AI - Multimodal Vision Analysis Engine (Gemini API)
 * Analyzes embedded screenshots, image attachments, brand stationery, fake login portals,
 * and QR code phishing (Quishing) vectors using Gemini Vision multimodal capabilities.
 */

const { GoogleGenerativeAI } = require('@google/generative-ai');
const crypto = require('crypto');

// Supported image MIME types for Gemini multimodal vision
const SUPPORTED_IMAGE_TYPES = new Set([
    'image/png', 'image/jpeg', 'image/jpg', 'image/webp', 'image/heic', 'image/heif'
]);

/**
 * Filter and extract image attachments from email MIME payload
 */
function extractImageAttachments(rawAttachments = []) {
    if (!Array.isArray(rawAttachments)) return [];

    return rawAttachments.filter(att => {
        const contentType = (att.contentType || '').toLowerCase().trim();
        const filename = (att.filename || '').toLowerCase().trim();
        const isSupportedMime = SUPPORTED_IMAGE_TYPES.has(contentType);
        const hasImageExt = /\.(png|jpe?g|webp|heic|heif)$/i.test(filename);
        return (isSupportedMime || hasImageExt) && att.content && att.content.length > 0;
    });
}

/**
 * Heuristic fallback when Gemini Vision API key is not configured or fails
 */
function computeHeuristicVisionAnalysis(att) {
    const filename = att.filename || 'image.png';
    const isQrNamed = /qr|code|scan|quick\s*response/i.test(filename);
    const isLoginNamed = /login|signin|office|portal|docusign|invoice|statement/i.test(filename);

    const flags = [];
    let riskScore = 0;

    if (isQrNamed) {
        flags.push("Image filename suggests QR Code mobile redirection mechanism");
        riskScore += 25;
    }

    if (isLoginNamed) {
        flags.push("Image filename matches corporate authentication / financial document themes");
        riskScore += 15;
    }

    let riskLevel = 'CLEAN';
    if (riskScore >= 70) riskLevel = 'CRITICAL';
    else if (riskScore >= 40) riskLevel = 'HIGH';
    else if (riskScore >= 20) riskLevel = 'MEDIUM';

    return {
        filename,
        contentType: att.contentType || 'image/png',
        sizeBytes: att.size || (att.content ? att.content.length : 0),
        sha256: crypto.createHash('sha256').update(att.content || '').digest('hex'),
        isVisualPhishing: riskScore >= 40,
        visualThreatScore: riskScore,
        impersonatedBrand: null,
        isQuishing: isQrNamed,
        isFakeLogin: false,
        visualCues: flags.length > 0 ? flags : ["Visual inspection: Standard graphical asset. No overt visual deception markers."],
        verdict: riskScore >= 40 ? "Suspicious image attachment" : "Neutral graphical asset",
        previewDataUrl: `data:${att.contentType || 'image/png'};base64,${(att.content || Buffer.from('')).toString('base64')}`
    };
}

/**
 * Inspect individual image using Gemini Vision Multimodal Model
 */
async function inspectImageWithGeminiVision(att, apiKey) {
    const buffer = att.content || Buffer.from('');
    const mimeType = att.contentType && SUPPORTED_IMAGE_TYPES.has(att.contentType.toLowerCase())
        ? att.contentType.toLowerCase()
        : 'image/png';
    const base64Data = buffer.toString('base64');
    const previewDataUrl = `data:${mimeType};base64,${base64Data}`;
    const filename = att.filename || 'unnamed_image.png';
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');

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
You are a Lead Cyber Forensic Computer Vision Specialist.
Inspect this email image attachment for visual phishing, brand impersonation, and QR code redirection (Quishing).

Check specifically for:
1. Fake Login Screens: Microsoft 365, Google Workspace, DocuSign, PayPal, Bank portals, Apple ID, Okta, etc.
2. QR Code Phishing (Quishing): Embedded QR codes intended for mobile credential harvesting or MFA bypass.
3. Brand Misuse & Spoofed Corporate Stationery: Illegitimate corporate logos, forged invoice headers, fraudulent security badges.
4. Urgency/Threat Banners: Fake antivirus alerts, account termination notices, or blurred document teasers prompting login.

Respond strictly in this JSON schema:
{
  "isVisualPhishing": true/false,
  "visualThreatScore": <integer 0 to 100>,
  "impersonatedBrand": "<e.g. Microsoft 365 | DocuSign | Google | PayPal | None>",
  "isQuishing": true/false,
  "isFakeLogin": true/false,
  "visualCues": ["<specific visual indicator 1>", ...],
  "verdict": "<concise 1-sentence forensic visual finding>"
}
`;

        const imagePart = {
            inlineData: {
                data: base64Data,
                mimeType
            }
        };

        const result = await model.generateContent([prompt, imagePart]);
        const responseJson = JSON.parse(result.response.text());

        let riskLevel = 'CLEAN';
        const score = Number(responseJson.visualThreatScore) || 0;
        if (score >= 70) riskLevel = 'CRITICAL';
        else if (score >= 50) riskLevel = 'HIGH';
        else if (score >= 25) riskLevel = 'MEDIUM';
        else if (score > 0) riskLevel = 'LOW';

        return {
            filename,
            contentType: mimeType,
            sizeBytes: buffer.length,
            sha256,
            isVisualPhishing: Boolean(responseJson.isVisualPhishing),
            visualThreatScore: score,
            riskLevel,
            impersonatedBrand: responseJson.impersonatedBrand === 'None' ? null : responseJson.impersonatedBrand,
            isQuishing: Boolean(responseJson.isQuishing),
            isFakeLogin: Boolean(responseJson.isFakeLogin),
            visualCues: Array.isArray(responseJson.visualCues) ? responseJson.visualCues : [],
            verdict: responseJson.verdict || "Visual inspection completed.",
            previewDataUrl
        };
    } catch (err) {
        console.warn(`Gemini Vision analysis skipped for ${filename}:`, err.message);
        return computeHeuristicVisionAnalysis(att);
    }
}

/**
 * Master Vision Analysis Pipeline
 * Processes all image attachments in parallel and aggregates visual threat metrics
 */
async function analyzeVisionAttachments(rawAttachments = []) {
    const images = extractImageAttachments(rawAttachments);

    if (images.length === 0) {
        return {
            totalImages: 0,
            maliciousCount: 0,
            hasQuishing: false,
            hasFakeLogin: false,
            impersonatedBrands: [],
            maxRiskScore: 0,
            riskLevel: 'CLEAN',
            flags: [],
            imageAnalyses: []
        };
    }

    const apiKey = process.env.GEMINI_API_KEY;
    const inspectPromises = images.slice(0, 4).map(img => {
        if (apiKey) {
            return inspectImageWithGeminiVision(img, apiKey);
        }
        return Promise.resolve(computeHeuristicVisionAnalysis(img));
    });

    const inspectedList = await Promise.all(inspectPromises);

    const totalImages = inspectedList.length;
    const maliciousCount = inspectedList.filter(img => img.visualThreatScore >= 70 || img.isVisualPhishing).length;
    const hasQuishing = inspectedList.some(img => img.isQuishing);
    const hasFakeLogin = inspectedList.some(img => img.isFakeLogin);
    
    const brandsSet = new Set();
    inspectedList.forEach(img => {
        if (img.impersonatedBrand && img.impersonatedBrand !== 'None') {
            brandsSet.add(img.impersonatedBrand);
        }
    });
    const impersonatedBrands = Array.from(brandsSet);

    const maxRiskScore = totalImages > 0 ? Math.max(...inspectedList.map(img => img.visualThreatScore)) : 0;

    let overallRiskLevel = 'CLEAN';
    if (maxRiskScore >= 70) overallRiskLevel = 'CRITICAL';
    else if (maxRiskScore >= 50) overallRiskLevel = 'HIGH';
    else if (maxRiskScore >= 25) overallRiskLevel = 'MEDIUM';
    else if (maxRiskScore > 0) overallRiskLevel = 'LOW';

    const aggregateFlags = Array.from(new Set(inspectedList.flatMap(img => img.visualCues)));

    return {
        totalImages,
        totalImagesScanned: totalImages,
        maliciousCount,
        hasQuishing,
        quishingDetected: hasQuishing,
        hasFakeLogin,
        fakeLoginDetected: hasFakeLogin,
        impersonatedBrands,
        maxRiskScore,
        riskLevel: overallRiskLevel,
        flags: aggregateFlags,
        imageAnalyses: inspectedList
    };
}

module.exports = {
    analyzeVisionAttachments,
    extractImageAttachments,
    inspectImageWithGeminiVision,
    computeHeuristicVisionAnalysis
};
