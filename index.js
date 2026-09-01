import express from 'express';
import cors from 'cors';
import 'dotenv/config';
import { ethers } from 'ethers'; //

import { parseEmailHeaders } from './services/headerParser.js';
import { getGeoLocation } from './services/geoService.js';
import { analyzeEmailWithAI } from './services/aiEngine.js';

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// --- WEB3 SETUP ---
// 1. Connect to the local Hardhat blockchain using JsonRpcProvider
const provider = new ethers.JsonRpcProvider("http://127.0.0.1:8545");

// 2. Use Hardhat's default Account #0 Private Key to act as the signer
const PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const signer = new ethers.Wallet(PRIVATE_KEY, provider);

// 3. Paste your deployed contract address here
const CONTRACT_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3"; 

// 4. Define the Human-Readable ABI fragment for the function Ethers needs to call
const ABI = [
  "function logThreat(string _ipAddress, uint256 _threatScore) public"
];

// 5. Create the Contract instance containing the code and allocated storage
const threatLoggerContract = new ethers.Contract(CONTRACT_ADDRESS, ABI, signer);
// ------------------

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

        // --- BLOCKCHAIN LOGGING ---
        let txHash = null;
        if (parsedHeader.originatingIP) {
            try {
                // Execute the state-changing operation against the Contract
                const tx = await threatLoggerContract.logThreat(
                    parsedHeader.originatingIP, 
                    aiAnalysis.threatScore
                );
                
                // Wait until the transaction is mined to ensure it is included in the blockchain
                await tx.wait(); 
                txHash = tx.hash;
                console.log(`Threat logged to blockchain! TX Hash: ${txHash}`);
            } catch (web3Error) {
                console.error("Blockchain logging failed:", web3Error);
            }
        }
        // --------------------------

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
            aiThreatAnalysis: aiAnalysis,
            blockchainReceipt: txHash // Send the hash back to the frontend
        });
    } catch (error) {
        console.error("Pipeline Error:", error);
        res.status(500).json({ error: error.message });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});