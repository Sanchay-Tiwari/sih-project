import { GoogleGenerativeAI } from '@google/generative-ai';

async function analyzeEmailWithAI(subject, bodyText) {
    const apiKey = process.env.GEMINI_API_KEY;
    const fallbackResponse = { isPhishing: false, threatScore: 0, threatCategory: "Analysis Error", urgencyLevel: "Low", suspiciousCues: [], summary: "AI Analysis unavailable." };
    
    if (!apiKey) {
        console.log(" Missing API Key in .env file");
        return { ...fallbackResponse, summary: "Set GEMINI_API_KEY in .env" };
    }

    try {
        const genAI = new GoogleGenerativeAI(apiKey);
        const model = genAI.getGenerativeModel({ 
            model: "gemini-3.6-flash", 
            generationConfig: { responseMimeType: "application/json" } 
        });
        
        const prompt = `
          Analyze this email for phishing, social engineering, and fraud intent.
          Subject: ${subject}
          Body: ${bodyText}

          Respond ONLY with a JSON object matching this exact schema:
          {
            "isPhishing": true/false,
            "threatScore": 85,
            "threatCategory": "Executive Impersonation",
            "urgencyLevel": "High",
            "suspiciousCues": ["list", "of", "cues"],
            "summary": "Short 2-sentence forensic summary."
          }
        `;

        const result = await model.generateContent(prompt);
        return JSON.parse(result.response.text());
    } catch (error) {
        console.error("\n===  GEMINI API ERROR  ===");
        console.error(error);
        console.error("==============================\n");
        return fallbackResponse;
    }
}

export { analyzeEmailWithAI };