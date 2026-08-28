const { simpleParser } = require('mailparser');

function extractPublicIPs(text) {
    if (!text) return [];
    const ipv4Regex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
    const matches = text.match(ipv4Regex) || [];

    return matches.filter(ip => {
        return !ip.startsWith('127.') && !ip.startsWith('10.') && 
               !ip.startsWith('192.168.') && !ip.startsWith('172.16.') && !ip.startsWith('0.');
    });
}

async function parseEmailHeaders(rawEmailText) {
    try {
        const parsed = await simpleParser(rawEmailText);
        const authResults = parsed.headers.get('authentication-results') || '';
        const authString = Array.isArray(authResults) ? authResults.join(' ') : String(authResults);

        const spfPass = /spf=pass/i.test(authString);
        const dkimPass = /dkim=pass/i.test(authString);
        const dmarcPass = /dmarc=pass/i.test(authString);

        const receivedHeaders = parsed.headers.get('received') || [];
        const rawHops = Array.isArray(receivedHeaders) ? receivedHeaders : [receivedHeaders];

        const extractedIPs = [];
        rawHops.forEach(hop => extractedIPs.push(...extractPublicIPs(String(hop))));

        const uniqueIPChain = [...new Set(extractedIPs)];
        const originatingIP = uniqueIPChain[uniqueIPChain.length - 1] || null;

        return {
            subject: parsed.subject || 'No Subject',
            from: parsed.from?.text || 'Unknown Sender',
            to: parsed.to?.text || 'Unknown Recipient',
            date: parsed.date || new Date(),
            bodyText: parsed.text || '',
            authentication: {
                spf: spfPass ? 'PASS' : 'FAIL / UNVERIFIED',
                dkim: dkimPass ? 'PASS' : 'FAIL / UNVERIFIED',
                dmarc: dmarcPass ? 'PASS' : 'FAIL / UNVERIFIED',
            },
            hopIPChain: uniqueIPChain,
            originatingIP: originatingIP
        };
    } catch (error) {
        throw new Error("Failed to parse raw email content.");
    }
}

module.exports = { parseEmailHeaders };