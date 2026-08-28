const express = require('express');
const cors = require('cors');
require('dotenv').config();

const { parseEmailHeaders } = require('./services/headerParser');
const { getGeoLocation } = require('./services/geoService');
const { analyzeEmailWithAI } = require('./services/aiEngine');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json({ limit: '10mb' }));

app.get('/api/health', (req, res) => {
    res.json({ status: "ok", message: "Email Forensics API running" });
});

app.post('/api/analyze', async (req, res) => {
    try {
        const { rawEmail } = req.body;
        if (!rawEmail) return res.status(400).json({ error: "No rawEmail payload provided" });

        const parsedHeader = await parseEmailHeaders(rawEmail);
        const geoData = await getGeoLocation(parsedHeader.originatingIP);
        const aiAnalysis = await analyzeEmailWithAI(parsedHeader.subject, parsedHeader.bodyText);

        res.json({
            success: true,
            emailDetails: {
                subject: parsedHeader.subject,
                from: parsedHeader.from,
                to: parsedHeader.to,
                date: parsedHeader.date,
            },
            authentication: parsedHeader.authentication,
            routing: {
                hopChain: parsedHeader.hopIPChain,
                originatingIP: parsedHeader.originatingIP,
                location: geoData
            },
            aiThreatAnalysis: aiAnalysis
        });
    } catch (error) {
        console.error("Pipeline Error:", error);
        res.status(500).json({ error: error.message });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});