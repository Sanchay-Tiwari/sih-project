# ThreatTrace AI — Chrome / Edge / Brave Browser Extension (Manifest V3)

Real-time AI email threat detection, deep RFC-822 header forensics, and Web3 blockchain evidentiary anchoring directly inside **Gmail**, **Outlook Web**, and **Yahoo Mail**.

---

## 🚀 How to Install and Load the Extension

### 1. Open Browser Extension Manager
- **Google Chrome / Brave:** Navigate to `chrome://extensions`
- **Microsoft Edge:** Navigate to `edge://extensions`

### 2. Enable Developer Mode
- Toggle the **"Developer mode"** switch in the top-right corner of the Extensions page.

### 3. Load Unpacked Extension
1. Click the **"Load unpacked"** button in the top-left corner.
2. Select the `extension/` directory from this repository:
   ```
   c:\Users\Asus\.antigravity-ide\sih-project\extension
   ```
3. The **ThreatTrace AI** extension card will appear in your extensions list.

---

## 🛡️ How to Test & Use

### Option A: In-Page Scanning (Gmail / Outlook / Yahoo)
1. Open [Gmail](https://mail.google.com), [Outlook](https://outlook.live.com), or [Yahoo Mail](https://mail.yahoo.com).
2. Open any email message.
3. You will see the injected **`🛡️ ThreatTrace AI Scan`** button on the action toolbar.
4. Click the button — the AI Multi-Signal pipeline will analyze the message headers, DNS MX records, and IP reputation, and anchor evidence to Web3 blockchain.
5. A floating **Forensic Verdict HUD** will display the Threat Score, Category, Phishing Cues, and Blockchain Tx Hash.
6. Click **"Open SOC Platform Dashboard"** to view the full enterprise investigation report.

### Option B: Extension Popup Control
1. Click the **ThreatTrace icon** in your browser toolbar.
2. Check real-time connection status to the local/deployed backend.
3. Switch user roles with **1-Click Demo Profiles** (`Admin`, `Analyst`, `Auditor`).
4. Click **"Scan Current Active Email"** to trigger a scan on your current open webmail tab.
5. Review recent scan history.

---

## ⚙️ Configuration
- Default API URL: `http://localhost:5000`
- You can change the backend URL directly from the Extension popup settings drawer when deploying to production (e.g., Vercel / Render).
