/**
 * ThreatTrace AI - Attachment Handling & PDF Exploit Forensics Engine
 * Performs deep static structural analysis, dangerous object detection (/JavaScript, /Launch, /EmbeddedFiles),
 * text extraction with heuristic phishing analysis, and file type / double extension spoofing checks.
 */

const crypto = require('crypto');
const pdfParse = require('pdf-parse');

// Dangerous file extensions associated with drop loaders, scripts, and executable binaries
const DANGEROUS_EXTENSIONS = new Set([
    'exe', 'scr', 'bat', 'cmd', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh',
    'hta', 'pif', 'cpl', 'jar', 'iso', 'img', 'ps1', 'psm1', 'msi', 'dll',
    'com', 'gadget', 'inf', 'reg', 'sct', 'shb', 'vb', 'ws'
]);

// Office macro extensions capable of executing VBA payloads
const MACRO_EXTENSIONS = new Set([
    'xlsm', 'docm', 'pptm', 'dotm', 'xltm', 'xlam', 'ppam', 'ppsm', 'sldm', 'iqy'
]);

// Archive extensions that frequently package weaponized files
const ARCHIVE_EXTENSIONS = new Set([
    'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'cab', 'ace', 'arj'
]);

// Dangerous PDF object markers in byte stream
const PDF_EXPLOIT_MARKERS = [
    { key: 'JAVASCRIPT', regex: /\/JavaScript|\/JS\b/i, severity: 'CRITICAL', score: 45, desc: "Embedded JavaScript execution (/JavaScript or /JS object)" },
    { key: 'LAUNCH', regex: /\/Launch\b/i, severity: 'CRITICAL', score: 50, desc: "Arbitrary external process launch trigger (/Launch object)" },
    { key: 'EMBEDDED_FILES', regex: /\/EmbeddedFiles\b/i, severity: 'HIGH', score: 35, desc: "Secondary payload embedded inside PDF container (/EmbeddedFiles)" },
    { key: 'OPEN_ACTION', regex: /\/OpenAction\b|\/AA\b/i, severity: 'HIGH', score: 30, desc: "Automatic action trigger on document opening (/OpenAction or /AA)" },
    { key: 'SUBMIT_FORM', regex: /\/SubmitForm\b/i, severity: 'HIGH', score: 35, desc: "Direct data exfiltration form submission (/SubmitForm)" },
    { key: 'REMOTE_URI', regex: /\/URI\s*\([^)]+\)/i, severity: 'MEDIUM', score: 20, desc: "Embedded remote URI link redirection (/URI)" },
    { key: 'ACRO_FORM', regex: /\/AcroForm\b/i, severity: 'MEDIUM', score: 15, desc: "Interactive form fields (/AcroForm) commonly used for fake credential inputs" }
];

// Heuristics for PDF text content
const INVOICE_URGENCY_REGEX = /\b(overdue|past\s*due|final\s*notice|immediate\s*payment|urgent\s*settlement|invoice\s*#?\d+|amount\s*due|remittance\s*advice|payment\s*required)\b/i;
const BANKING_WIRE_REGEX = /\b(wire\s*transfer|beneficiary\s*name|routing\s*number|swift\s*code|account\s*number|iban|bank\s*coordinates|offshore\s*escrow)\b/i;
const CALLBACK_PHISH_REGEX = /\b(call\s*our\s*(?:support|desk|team|billing)|toll\s*free|dispute\s*this\s*charge|cancel\s*your\s*(?:order|subscription)|call\s*(?:us\s*at|\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}))\b/i;
const CREDENTIAL_COERCION_REGEX = /\b(password\s*expir|account\s*(?:suspend|lockout|freeze|terminate)|retain\s*your\s*access|verify\s*your\s*(?:identity|account|login))\b/i;

/**
 * Compute SHA-256 hash of buffer
 */
function computeSha256(buffer) {
    if (!Buffer.isBuffer(buffer)) {
        buffer = Buffer.from(buffer || '');
    }
    return crypto.createHash('sha256').update(buffer).digest('hex');
}

/**
 * Extract file extension from filename
 */
function getFileExtension(filename = '') {
    const clean = String(filename).trim().toLowerCase();
    const parts = clean.split('.');
    return parts.length > 1 ? parts[parts.length - 1] : '';
}

/**
 * Check for double extensions like 'invoice.pdf.exe'
 */
function detectDoubleExtension(filename = '') {
    const clean = String(filename).trim().toLowerCase();
    const parts = clean.split('.');
    if (parts.length >= 3) {
        const lastExt = parts[parts.length - 1];
        const secondLastExt = parts[parts.length - 2];
        const decoyExtensions = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'png', 'txt'];
        if (decoyExtensions.includes(secondLastExt) && DANGEROUS_EXTENSIONS.has(lastExt)) {
            return {
                isDoubleExt: true,
                decoy: secondLastExt,
                actual: lastExt
            };
        }
    }
    return { isDoubleExt: false };
}

/**
 * Inspect individual PDF attachment for structural exploits and textual phishing cues
 */
async function inspectPdfAttachment(attachment) {
    const buffer = attachment.content || Buffer.from('');
    const rawString = buffer.toString('binary');
    const flags = [];
    const structuralExploits = [];
    let riskScore = 0;

    // 1. Static Structural Analysis (Raw PDF stream scan)
    for (const marker of PDF_EXPLOIT_MARKERS) {
        if (marker.regex.test(rawString)) {
            structuralExploits.push({
                key: marker.key,
                severity: marker.severity,
                score: marker.score,
                description: marker.desc
            });
            flags.push(marker.desc);
            riskScore += marker.score;
        }
    }

    // 2. Text Extraction & Phishing Language Analysis
    let extractedText = '';
    let pageCount = 1;
    let textAnalysis = {
        hasInvoiceUrgency: false,
        hasBankingCoordinates: false,
        hasCallbackPhishing: false,
        hasCredentialCoercion: false
    };

    try {
        let pdfTextResult = '';
        let totalPages = 1;

        const pdfLib = require('pdf-parse');
        if (pdfLib && pdfLib.PDFParse) {
            const parser = new pdfLib.PDFParse({ data: buffer });
            const parsed = await parser.getText();
            pdfTextResult = parsed?.text || '';
            totalPages = parsed?.total || 1;
        } else if (typeof pdfLib === 'function') {
            const parsed = await pdfLib(buffer);
            pdfTextResult = parsed?.text || '';
            totalPages = parsed?.numpages || 1;
        }

        extractedText = pdfTextResult;
        pageCount = totalPages;

        if (INVOICE_URGENCY_REGEX.test(extractedText)) {
            textAnalysis.hasInvoiceUrgency = true;
            flags.push("PDF content contains urgent financial invoice/payment coercion language");
            riskScore += 25;
        }

        if (BANKING_WIRE_REGEX.test(extractedText)) {
            textAnalysis.hasBankingCoordinates = true;
            flags.push("PDF content contains direct wire transfer/banking coordinates");
            riskScore += 25;
        }

        if (CALLBACK_PHISH_REGEX.test(extractedText)) {
            textAnalysis.hasCallbackPhishing = true;
            flags.push("PDF contains Callback Phishing / Telephone support impersonation instructions");
            riskScore += 30;
        }

        if (CREDENTIAL_COERCION_REGEX.test(extractedText)) {
            textAnalysis.hasCredentialCoercion = true;
            flags.push("PDF content contains account lockout or credential reset coercion");
            riskScore += 30;
        }
    } catch (err) {
        // Obfuscated, encrypted, or stream anomalies
        flags.push(`PDF parsing anomaly: ${err.message}`);
        riskScore += 10;
    }

    // Cap individual risk score
    riskScore = Math.min(100, riskScore);
    let riskLevel = 'CLEAN';
    if (riskScore >= 70) riskLevel = 'CRITICAL';
    else if (riskScore >= 50) riskLevel = 'HIGH';
    else if (riskScore >= 25) riskLevel = 'MEDIUM';
    else if (riskScore > 0) riskLevel = 'LOW';

    return {
        filename: attachment.filename || 'unnamed.pdf',
        contentType: attachment.contentType || 'application/pdf',
        sizeBytes: attachment.size || buffer.length,
        sha256: computeSha256(buffer),
        isPdf: true,
        pageCount,
        hasStructuralExploits: structuralExploits.length > 0,
        structuralExploits,
        textAnalysis,
        extractedTextSnippet: extractedText.trim().slice(0, 500),
        riskScore,
        riskLevel,
        flags
    };
}

/**
 * Inspect non-PDF attachment (executables, macros, archives, images, documents)
 */
function inspectGenericAttachment(attachment) {
    const buffer = attachment.content || Buffer.from('');
    const filename = attachment.filename || 'unnamed.bin';
    const ext = getFileExtension(filename);
    const contentType = attachment.contentType || 'application/octet-stream';
    const flags = [];
    let riskScore = 0;

    // 1. Double extension check (e.g. invoice.pdf.exe)
    const doubleExt = detectDoubleExtension(filename);
    if (doubleExt.isDoubleExt) {
        flags.push(`Deceptive double extension detected: disguised as '.${doubleExt.decoy}' but executes as '.${doubleExt.actual}'`);
        riskScore += 60;
    }

    // 2. Dangerous executable/script extensions
    if (DANGEROUS_EXTENSIONS.has(ext)) {
        flags.push(`Dangerous executable / script file extension ('.${ext}') blocked by security policy`);
        riskScore += 50;
    }

    // 3. Macro-enabled Office files
    if (MACRO_EXTENSIONS.has(ext)) {
        flags.push(`Macro-enabled document format ('.${ext}') capable of executing malicious VBA code`);
        riskScore += 35;
    }

    // 4. Archive packages
    if (ARCHIVE_EXTENSIONS.has(ext)) {
        flags.push(`Compressed archive container ('.${ext}') commonly used to bypass email gateway filters`);
        riskScore += 15;
    }

    // 5. Content-Type vs Extension Mismatch
    if (ext === 'pdf' && !contentType.includes('pdf')) {
        flags.push(`MIME type mismatch: extension claims .pdf but content type is '${contentType}'`);
        riskScore += 30;
    }

    riskScore = Math.min(100, riskScore);
    let riskLevel = 'CLEAN';
    if (riskScore >= 70) riskLevel = 'CRITICAL';
    else if (riskScore >= 50) riskLevel = 'HIGH';
    else if (riskScore >= 25) riskLevel = 'MEDIUM';
    else if (riskScore > 0) riskLevel = 'LOW';

    return {
        filename,
        contentType,
        sizeBytes: attachment.size || buffer.length,
        sha256: computeSha256(buffer),
        isPdf: false,
        extension: ext,
        isDoubleExtension: doubleExt.isDoubleExt,
        isDangerousExecutable: DANGEROUS_EXTENSIONS.has(ext),
        isMacroEnabled: MACRO_EXTENSIONS.has(ext),
        riskScore,
        riskLevel,
        flags
    };
}

/**
 * Master Attachment Forensics Pipeline
 * Processes all MIME attachments, runs PDF deep analysis, checks binaries, and computes threat scores.
 */
async function analyzeAttachments(rawAttachments = []) {
    if (!Array.isArray(rawAttachments) || rawAttachments.length === 0) {
        return {
            totalAttachments: 0,
            suspiciousCount: 0,
            maliciousCount: 0,
            hasPdfExploits: false,
            hasDangerousExtensions: false,
            maxRiskScore: 0,
            riskLevel: 'CLEAN',
            flags: [],
            attachments: []
        };
    }

    const inspectedList = [];

    for (const att of rawAttachments) {
        const filename = att.filename || '';
        const ext = getFileExtension(filename);
        const isPdf = ext === 'pdf' || (att.contentType && att.contentType.toLowerCase().includes('pdf'));

        if (isPdf) {
            const inspectedPdf = await inspectPdfAttachment(att);
            inspectedList.push(inspectedPdf);
        } else {
            const inspectedGeneric = inspectGenericAttachment(att);
            inspectedList.push(inspectedGeneric);
        }
    }

    const totalAttachments = inspectedList.length;
    const suspiciousCount = inspectedList.filter(a => a.riskScore >= 30 && a.riskScore < 70).length;
    const maliciousCount = inspectedList.filter(a => a.riskScore >= 70).length;
    const hasPdfExploits = inspectedList.some(a => a.hasStructuralExploits);
    const hasDangerousExtensions = inspectedList.some(a => a.isDangerousExecutable || a.isDoubleExtension);

    const maxRiskScore = totalAttachments > 0 ? Math.max(...inspectedList.map(a => a.riskScore)) : 0;

    let overallRiskLevel = 'CLEAN';
    if (maxRiskScore >= 70) overallRiskLevel = 'CRITICAL';
    else if (maxRiskScore >= 50) overallRiskLevel = 'HIGH';
    else if (maxRiskScore >= 25) overallRiskLevel = 'MEDIUM';
    else if (maxRiskScore > 0) overallRiskLevel = 'LOW';

    const aggregateFlags = Array.from(new Set(inspectedList.flatMap(a => a.flags)));

    return {
        totalAttachments,
        suspiciousCount,
        maliciousCount,
        hasPdfExploits,
        hasDangerousExtensions,
        maxRiskScore,
        riskLevel: overallRiskLevel,
        flags: aggregateFlags,
        attachments: inspectedList
    };
}

module.exports = {
    analyzeAttachments,
    inspectPdfAttachment,
    inspectGenericAttachment,
    computeSha256,
    getFileExtension,
    detectDoubleExtension
};
