# Project Roadmap — Technical Plan (7 Features)

---

## 1. MongoDB Integration

### Tech Stack
- **Database:** MongoDB (Atlas free tier for dev, self-hosted later if needed)
- **ODM:** Mongoose (schema validation + easy queries from Node/Express)
- **Migration tool:** simple one-off script to import existing `cases.json` into Mongo

### Schema Design (Pseudocode)

```javascript
// models/Case.js
const caseSchema = new Schema({
  caseId: { type: String, required: true, unique: true },
  createdAt: Date,
  subject: String,
  from: String,
  senderDomain: String,
  to: String,
  threatScore: Number,
  threatCategory: String,
  urgencyLevel: String,
  isPhishing: Boolean,
  originatingIP: String,
  anonymizedIpHash: String,
  maskedIp: String,
  geo: {
    ip: String, city: String, region: String,
    country: String, countryCode: String,
    lat: Number, lon: Number
  },
  blockchain: {
    status: String,        // ON_CHAIN_CONFIRMED / IMMUTABLE_EVIDENCE_ANCHORED
    txHash: String,
    contractAddress: String,
    blockNumber: Number,
    evidenceHash: String
  },
  analyzedBy: { type: ObjectId, ref: 'User' }  // ties to Phase 2 auth
});
```

### Migration & Integration Steps
```
1. npm install mongoose --save
2. Set MONGO_URI in .env (Atlas connection string)
3. Connect on backend startup:
     mongoose.connect(process.env.MONGO_URI)
4. Replace all fs.readFile/writeFile calls on cases.json with:
     Case.create(newCaseData)      // instead of appending to JSON
     Case.find().sort({createdAt:-1})   // instead of reading whole file
     Case.findOne({caseId})        // instead of array.find()
5. One-time migration script:
     const oldCases = JSON.parse(fs.readFileSync('data/cases.json'))
     await Case.insertMany(oldCases)
6. Keep cases.json as a local backup/export option, not the source of truth anymore
```

---

## 2. JWT + RBAC Authentication

### Tech Stack
- **Password hashing:** bcrypt
- **Token signing:** jsonwebtoken
- **Middleware:** custom Express middleware for role checks
- **Roles:** `analyst`, `admin`, `auditor`

### Schema (Pseudocode)

```javascript
// models/User.js
const userSchema = new Schema({
  email: { type: String, unique: true },
  passwordHash: String,
  role: { type: String, enum: ['analyst', 'admin', 'auditor'], default: 'analyst' },
  createdAt: Date
});
```

### Auth Flow (Pseudocode)

```javascript
// POST /auth/register
function register(email, password, role) {
  passwordHash = bcrypt.hash(password, 10)
  user = User.create({ email, passwordHash, role })
  return { message: "registered" }
}

// POST /auth/login
function login(email, password) {
  user = User.findOne({ email })
  if (!user || !bcrypt.compare(password, user.passwordHash)) 
      throw "Invalid credentials"

  token = jwt.sign(
    { userId: user._id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '8h' }
  )
  return { token }
}

// middleware/auth.js
function requireAuth(req, res, next) {
  token = req.headers.authorization?.split(' ')[1]
  if (!token) return res.status(401).send("No token")
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET)
    req.user = decoded
    next()
  } catch { return res.status(401).send("Invalid token") }
}

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role))
      return res.status(403).send("Forbidden")
    next()
  }
}

// Usage on routes:
app.post('/api/analyze', requireAuth, analyzeEmailHandler)
app.post('/api/anchor', requireAuth, requireRole('admin'), anchorEvidenceHandler)
app.get('/api/cases', requireAuth, requireRole('analyst','admin','auditor'), listCasesHandler)
```

### Frontend Integration
```
1. Login form -> POST /auth/login -> store JWT in memory (NOT localStorage for security-sensitive apps; consider httpOnly cookie)
2. Attach token to every API call: headers: { Authorization: `Bearer ${token}` }
3. Hide/show UI elements (e.g. "Anchor to Blockchain" button) based on decoded role
4. Auto-redirect to login if a 401 response comes back
```

---

## 3. Browser Extension (Gmail → Outlook → Yahoo)

### Tech Stack
- **Extension framework:** Chrome Manifest V3 (works for Chrome/Edge; Firefox needs minor manifest tweaks)
- **Gmail integration:** Gmail API (OAuth2) — read-only scope `gmail.readonly`
- **Content injection:** Content script to inject a "Scan This Email" button into the Gmail UI
- **Communication:** Extension → your deployed backend API (Phase 2's auth applies here too)

### Manifest (Pseudocode)

```json
// manifest.json
{
  "manifest_version": 3,
  "name": "Email Threat Scanner",
  "permissions": ["identity", "storage"],
  "host_permissions": ["https://mail.google.com/*", "https://your-backend.vercel.app/*"],
  "content_scripts": [{
    "matches": ["https://mail.google.com/*"],
    "js": ["content.js"]
  }],
  "background": { "service_worker": "background.js" }
}
```

### Flow (Pseudocode)

```javascript
// content.js — injected into Gmail's page
function injectScanButton() {
  observeGmailDOM(() => {
    if (emailOpened() && !buttonExists()) {
      addButton("🛡️ Scan This Email", onScanClick)
    }
  })
}

function onScanClick() {
  emailContent = extractCurrentEmailHTML()  // grab subject, body, headers from DOM
  chrome.runtime.sendMessage({ type: "SCAN_EMAIL", data: emailContent })
}

// background.js
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "SCAN_EMAIL") {
    token = getStoredAuthToken()
    fetch("https://your-backend.vercel.app/api/analyze", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: JSON.stringify(msg.data)
    })
    .then(res => res.json())
    .then(result => showResultPopup(result))
  }
})
```

### Rollout Order
```
1. Build + test fully on Gmail (best documented API, largest user base)
2. Abstract the "extract email from DOM" logic behind an interface
   -> makes it easier to swap in Outlook Web / Yahoo Mail's different DOM structure later
3. Add Outlook Web support (uses Microsoft Graph API instead of Gmail API)
4. Yahoo Mail last — least mature API, may require more DOM-scraping vs. official API access
```

---

## 4. Vercel Deployment

### Tech Stack
- **Frontend:** Vercel (native React/Vite hosting)
- **Backend:** Vercel Serverless Functions, OR Render/Railway if you need long-running processes (blockchain node connections can be awkward in serverless — see note below)
- **Environment variables:** Vercel dashboard → Project Settings → Environment Variables (never commit `.env`)

### Important Architecture Note
```
Serverless functions (Vercel) are short-lived and stateless by design.
Your blockchain connection (Ethers.js + provider) reconnects on every request,
which is fine for occasional writes but adds latency.

Recommendation:
- Deploy frontend + simple REST API endpoints (auth, case CRUD) on Vercel
- Deploy the blockchain-interfacing service separately on a small persistent
  server (Render/Railway/a VPS) if you move to a real permissioned network,
  since those need a stable, long-running connection to your consortium nodes
```

### Deployment Steps (Pseudocode)
```
1. vercel.json config:
   { "builds": [{"src": "api/**/*.js", "use": "@vercel/node"}] }
2. Move Express routes into /api folder as individual serverless functions,
   OR use a Vercel-compatible Express wrapper (e.g. serverless-http)
3. Set all secrets (MONGO_URI, JWT_SECRET, GEMINI_API_KEY, ABUSEIPDB_API_KEY,
   PRIVATE_KEY, CONTRACT_ADDRESS) in Vercel's environment variable dashboard
4. vercel --prod to deploy
5. Update your extension's background.js to point at the new production URL
```

---

## 5. Multi-Modal Analysis (Images, URLs, PDFs, Documents)

### Tech Stack
- **URL analysis:** Google Safe Browsing API or VirusTotal API (URL reputation)
- **PDF parsing:** `pdf-parse` (extract text) + check for embedded JS/launch actions (malicious PDF indicator)
- **Image analysis:** Gemini's multimodal vision capability (it can accept images directly) OR Google Cloud Vision API for OCR + logo/brand detection (useful for detecting fake login page screenshots)
- **Attachment handling:** `mailparser` already extracts attachments — extend to route each by MIME type

### Flow (Pseudocode)

```javascript
async function analyzeAttachments(parsedEmail) {
  results = []

  for (attachment of parsedEmail.attachments) {
    if (attachment.contentType === 'application/pdf') {
      text = await pdfParse(attachment.content)
      results.push(await scanTextForPhishingIndicators(text))
      results.push(checkPdfForEmbeddedJS(attachment.content))
    }

    if (attachment.contentType.startsWith('image/')) {
      // Option A: send directly to Gemini vision
      geminiResult = await gemini.generateContent([
        "Does this image contain a fake login page, brand impersonation, or phishing content?",
        { inlineData: { data: attachment.content.toString('base64'), mimeType: attachment.contentType } }
      ])
      results.push(geminiResult)
    }
  }

  for (url of extractUrlsFromBody(parsedEmail.body)) {
    safeBrowsingResult = await checkGoogleSafeBrowsing(url)
    results.push(safeBrowsingResult)
  }

  return results
}

// Fold into composite score
function computeThreatScore(headerSignals, aiVerdict, attachmentResults) {
  score = baseScore(headerSignals, aiVerdict)
  for (r of attachmentResults) {
    if (r.malicious) score += r.weight
  }
  return clamp(score, 0, 100)
}
```

### Rollout Order
```
1. URL reputation checking first (highest signal-to-effort ratio, simple API call)
2. PDF text extraction + phishing language scan (reuses your existing Gemini text pipeline)
3. Image analysis via Gemini vision (newest capability, most experimental — test accuracy before trusting it in scoring)
```

---

## 6. Real Permissioned Blockchain (3–4 Devices)

### Tech Stack
- **Framework:** Hyperledger Besu (easier than Fabric to get running quickly, and stays EVM/Solidity-compatible — so your existing `ThreatLogger.sol` mostly carries over) OR Quorum
- **Consensus:** IBFT 2.0 (Istanbul BFT) — Besu's built-in permissioned consensus, no mining/gas needed
- **Networking:** All 3–4 devices on the same LAN (or VPN like Tailscale/ZeroTier if devices are physically apart) so nodes can reach each other

### Setup Flow (Pseudocode)

```
1. On each of the 3-4 devices, install Besu
2. Generate a node key + validator identity for each device:
     besu operator generate-blockchain-config \
       --config-file=ibftConfigFile.json \
       --output-dir=networkFiles

3. Share the generated genesis.json across ALL devices — this defines the
   network's shared starting state and the list of validator nodes

4. Each device starts its node, pointing at the others as bootnodes:
     besu --data-path=data --genesis-file=genesis.json \
          --bootnodes=enode://<peer1>,enode://<peer2>,enode://<peer3> \
          --rpc-http-enabled --rpc-http-api=ETH,NET,IBFT

5. Deploy your EXISTING ThreatLogger.sol contract to this network
   (same Hardhat deploy script, just point --network at one of the Besu nodes'
   RPC endpoint instead of localhost:8545)

6. Update backend .env:
     RPC_URL=http://<besu-node-ip>:8545
     (no PRIVATE_KEY changes needed if using a similar account model,
      but Besu accounts differ slightly from Hardhat's auto-funded ones —
      you'll need to pre-fund/allowlist an account in the genesis config)

7. Backend calls logThreat() exactly as before via Ethers.js —
   the CODE DOESN'T CHANGE, only the network it points to changes
```

### Why This Is a Great Demo Upgrade
```
- Turns your "we'd use a permissioned blockchain" answer from a claim into
  a literal, physical demonstration — 3-4 laptops on a table, each a validator
- You can kill one device mid-demo and show the network still works
  (that's the actual point of Byzantine fault tolerance — worth showing off)
```

---

## 7. IP-Hop / True Origin Tracing via Mail Routing

### Tech Stack
- **Header parsing:** extend your existing `mailparser` usage to extract ALL `Received:` headers, not just one
- **Chain reconstruction:** custom parser using regex/string parsing on each `Received:` line
- **Anomaly detection:** combine with your existing geolocation calls, run per-hop

### Flow (Pseudocode)

```javascript
function extractReceivedChain(rawHeaders) {
  receivedLines = rawHeaders.getAll('received')  // array, top to bottom
  hops = []

  for (line of receivedLines.reverse()) {  // reverse: read oldest (closest to origin) first
    ipMatch = line.match(/\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?/)
    timestampMatch = line.match(/;\s*(.+)$/)
    hostnameMatch = line.match(/from\s+(\S+)/)

    hops.push({
      hopIndex: hops.length,
      ip: ipMatch?.[1],
      hostname: hostnameMatch?.[1],
      timestamp: parseDate(timestampMatch?.[1])
    })
  }

  return hops
}

async function analyzeHopChain(hops) {
  enrichedHops = []
  for (hop of hops) {
    if (hop.ip) {
      geo = await getGeolocation(hop.ip)
      abuseScore = await checkAbuseIPDB(hop.ip)
      isVpnOrDatacenter = geo.isp?.match(/VPN|hosting|datacenter/i)
      enrichedHops.push({ ...hop, geo, abuseScore, isVpnOrDatacenter })
    }
  }

  anomalies = []
  for (i = 1; i < enrichedHops.length; i++) {
    prev = enrichedHops[i-1]
    curr = enrichedHops[i]
    timeDiff = curr.timestamp - prev.timestamp
    distance = haversineDistance(prev.geo, curr.geo)

    // impossible travel check: e.g. India -> Brazil in 4 seconds
    if (distance > 5000 && timeDiff < 60) {
      anomalies.push({ hopIndex: i, reason: "Impossible geographic jump between hops" })
    }
  }

  earliestReliableHop = enrichedHops[0]  // closest to true origin, per PS requirement
  return { enrichedHops, anomalies, probableOrigin: earliestReliableHop }
}
```

### Honest Scope Boundary (keep this in mind while building)
```
- This traces the RELAY chain accurately — this part is fully achievable
- This does NOT defeat VPN/TOR anonymization — the "earliest reliable hop"
  will just be the VPN exit node's IP if one was used, not the attacker's
  real device. Flag isVpnOrDatacenter=true in that case rather than
  claiming to have found the "true" IP.
```

---

## Suggested Build Sequence Recap

```
Week 1-2:  MongoDB + JWT/RBAC (Phase 1 — foundation)
Week 3-4:  Gmail extension MVP + Vercel deployment (Phase 2 — reach)
Week 5-6:  Multi-modal analysis (URLs first, then PDFs, then images)
Week 7-8:  Real permissioned blockchain across physical devices
Week 9+:   Full Received-chain parsing + anomaly detection,
           then Outlook/Yahoo extension support
```

Adjust pacing based on how much time you actually have between now and whatever your next milestone is (next hackathon round, personal deadline, etc.) — this order prioritizes foundation-before-features so nothing has to be rebuilt later.
