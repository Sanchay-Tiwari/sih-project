import { useState } from 'react';
import axios from 'axios';
import { ShieldAlert, ShieldCheck, MapPin, AlertTriangle, FileText, Activity, Send } from 'lucide-react';
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';
import html2pdf from 'html2pdf.js';
import 'leaflet/dist/leaflet.css';

interface AnalysisResult {
  emailDetails: {
    subject: string;
    from: string;
    to: string;
    date: string;
  };
  authentication: {
    spf: string;
    dkim: string;
    dmarc: string;
  };
  routing: {
    hopChain: string[];
    originatingIP: string | null;
    location: {
      ip: string;
      city: string;
      country: string;
      lat: number;
      lon: number;
      isp: string;
    };
  };
  aiThreatAnalysis: {
    isPhishing: boolean;
    threatScore: number;
    threatCategory: string;
    urgencyLevel: string;
    suspiciousCues: string[];
    summary: string;
  };
}

export default function App() {
  const [rawEmail, setRawEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState('');

  const handleAnalyze = async () => {
    if (!rawEmail.trim()) {
      setError('Please paste raw email headers or email text first.');
      return;
    }
    setError('');
    setLoading(true);

    try {
      const response = await axios.post('http://localhost:5000/api/analyze', { rawEmail });
      setResult(response.data);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to connect to backend server.');
    } finally {
      setLoading(false);
    }
  };

  const handleExportPDF = () => {
    const element = document.getElementById('forensic-report');
    if (!element) return;
    const opt = {
      margin: 0.5,
      filename: `Forensic_Report_${Date.now()}.pdf`,
      image: { type: 'jpeg' as const, quality: 0.98 },
      html2canvas: { scale: 2 },
      jsPDF: { unit: 'in', format: 'letter', orientation: 'portrait' as const }
    };
    html2pdf().set(opt).from(element).save();
  };

  const mapPosition: [number, number] = result 
    ? [result.routing.location.lat, result.routing.location.lon] 
    : [0, 0];

  return (
    <div style={{ minHeight: '100vh', backgroundColor: '#0f172a', color: '#f8fafc', fontFamily: 'sans-serif', padding: '24px' }}>
      {/* Header */}
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingBottom: '20px', borderBottom: '1px solid #334155', marginBottom: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <ShieldAlert size={36} color="#38bdf8" />
          <div>
            <h1 style={{ margin: 0, fontSize: '24px', fontWeight: 'bold', color: '#f8fafc' }}>Email Forensics & Threat Scanner</h1>
            <p style={{ margin: 0, fontSize: '14px', color: '#94a3b8' }}>AI-Powered Header Analysis & Origin Geolocation</p>
          </div>
        </div>
        {result && (
          <button 
            onClick={handleExportPDF} 
            style={{ display: 'flex', alignItems: 'center', gap: '8px', backgroundColor: '#0284c7', color: '#fff', border: 'none', padding: '10px 16px', borderRadius: '6px', cursor: 'pointer', fontWeight: 'bold' }}
          >
            <FileText size={18} /> Export PDF Report
          </button>
        )}
      </header>

      {/* Input Section */}
      <div style={{ backgroundColor: '#1e293b', padding: '20px', borderRadius: '8px', marginBottom: '24px', border: '1px solid #334155' }}>
        <label style={{ display: 'block', marginBottom: '8px', fontWeight: 'bold', color: '#cbd5e1' }}>Paste Raw Email Headers / EML Body:</label>
        <textarea
          rows={6}
          value={rawEmail}
          onChange={(e) => setRawEmail(e.target.value)}
          placeholder="Paste headers or raw email text here (e.g. Received: from mail.example.com...)"
          style={{ width: '100%', backgroundColor: '#0f172a', color: '#f8fafc', border: '1px solid #475569', borderRadius: '6px', padding: '12px', fontFamily: 'monospace', fontSize: '13px', boxSizing: 'border-box' }}
        />
        {error && <p style={{ color: '#ef4444', marginTop: '8px' }}>{error}</p>}
        <button
          onClick={handleAnalyze}
          disabled={loading}
          style={{ marginTop: '12px', display: 'flex', alignItems: 'center', gap: '8px', backgroundColor: loading ? '#475569' : '#10b981', color: '#fff', border: 'none', padding: '12px 24px', borderRadius: '6px', cursor: loading ? 'not-allowed' : 'pointer', fontWeight: 'bold', fontSize: '15px' }}
        >
          {loading ? <Activity className="animate-spin" size={20} /> : <Send size={20} />}
          {loading ? 'Running Forensic Pipeline...' : 'Analyze Email'}
        </button>
      </div>

      {/* Results Dashboard */}
      {result && (
        <div id="forensic-report" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          
          {/* Top Row: AI Threat Overview & Auth Badges */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
            
            {/* AI Threat Card */}
            <div style={{ backgroundColor: '#1e293b', padding: '20px', borderRadius: '8px', border: `2px solid ${result.aiThreatAnalysis.threatScore > 50 ? '#ef4444' : '#10b981'}` }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <h2 style={{ margin: 0, fontSize: '18px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <AlertTriangle color={result.aiThreatAnalysis.threatScore > 50 ? '#ef4444' : '#10b981'} />
                  AI Threat Assessment
                </h2>
                <span style={{ backgroundColor: result.aiThreatAnalysis.threatScore > 50 ? '#7f1d1d' : '#064e3b', color: result.aiThreatAnalysis.threatScore > 50 ? '#fca5a5' : '#6ee7b7', padding: '6px 12px', borderRadius: '20px', fontWeight: 'bold', fontSize: '14px' }}>
                  Score: {result.aiThreatAnalysis.threatScore}/100
                </span>
              </div>
              <p><strong>Category:</strong> {result.aiThreatAnalysis.threatCategory}</p>
              <p><strong>Urgency:</strong> {result.aiThreatAnalysis.urgencyLevel}</p>
              <p><strong>Forensic Summary:</strong> {result.aiThreatAnalysis.summary}</p>
              {result.aiThreatAnalysis.suspiciousCues.length > 0 && (
                <div>
                  <strong>Suspicious Indicators:</strong>
                  <ul style={{ color: '#fca5a5', paddingLeft: '20px' }}>
                    {result.aiThreatAnalysis.suspiciousCues.map((cue, idx) => (
                      <li key={idx}>{cue}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            {/* Authentication Verification Card */}
            <div style={{ backgroundColor: '#1e293b', padding: '20px', borderRadius: '8px', border: '1px solid #334155' }}>
              <h2 style={{ margin: '0 0 16px 0', fontSize: '18px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <ShieldCheck color="#38bdf8" /> Protocol Authentication
              </h2>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {['spf', 'dkim', 'dmarc'].map((proto) => {
                  const val = result.authentication[proto as keyof typeof result.authentication];
                  const passed = val.includes('PASS');
                  return (
                    <div key={proto} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', backgroundColor: '#0f172a', padding: '12px', borderRadius: '6px' }}>
                      <span style={{ fontWeight: 'bold', textTransform: 'uppercase' }}>{proto}</span>
                      <span style={{ backgroundColor: passed ? '#064e3b' : '#7f1d1d', color: passed ? '#6ee7b7' : '#fca5a5', padding: '4px 10px', borderRadius: '4px', fontSize: '12px', fontWeight: 'bold' }}>
                        {val}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Bottom Row: IP Routing & Interactive Map */}
          <div style={{ backgroundColor: '#1e293b', padding: '20px', borderRadius: '8px', border: '1px solid #334155' }}>
            <h2 style={{ margin: '0 0 16px 0', fontSize: '18px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <MapPin color="#f59e0b" /> Originating IP Geolocation
            </h2>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '20px' }}>
              <div>
                <p><strong>Origin IP:</strong> {result.routing.originatingIP || 'Not Extracted'}</p>
                <p><strong>City:</strong> {result.routing.location.city}</p>
                <p><strong>Country:</strong> {result.routing.location.country}</p>
                <p><strong>ISP:</strong> {result.routing.location.isp}</p>
                <hr style={{ borderColor: '#334155', margin: '16px 0' }} />
                <strong>Hop Chain:</strong>
                <ol style={{ paddingLeft: '20px', fontSize: '13px', color: '#94a3b8' }}>
                  {result.routing.hopChain.map((ip, i) => (
                    <li key={i}>{ip}</li>
                  ))}
                </ol>
              </div>

              {/* Map Container */}
              <div style={{ height: '300px', borderRadius: '8px', overflow: 'hidden' }}>
                {result.routing.location.lat !== 0 ? (
                  <MapContainer 
                    {...({ center: mapPosition, zoom: 5, style: { height: '100%', width: '100%' } } as any)}
                  >
                    <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
                    <Marker position={mapPosition}>
                      <Popup>
                        <strong>Origin Server</strong><br />
                        {result.routing.location.city}, {result.routing.location.country}<br />
                        IP: {result.routing.location.ip}
                      </Popup>
                    </Marker>
                  </MapContainer>
                ) : (
                  <div style={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', backgroundColor: '#0f172a', color: '#64748b' }}>
                    No Map Co-ordinates Available
                  </div>
                )}
              </div>
            </div>
          </div>

        </div>
      )}
    </div>
  );
}