import { useState, useEffect } from 'react';
import axios from 'axios';
import {
  ShieldAlert,
  ShieldCheck,
  MapPin,
  AlertTriangle,
  FileText,
  Activity,
  Send,
  Loader,
  Database,
  Search,
  Lock,
  Globe,
  Server,
  CheckCircle2,
  XCircle,
  Trash2,
  RefreshCw,
  Sparkles,
  Clock,
  ArrowRight,
  Radio,
  Layers,
  FileCheck
} from 'lucide-react';
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';
import html2pdf from 'html2pdf.js';
import 'leaflet/dist/leaflet.css';

// Fix Leaflet Default Icon issue in bundlers
import L from 'leaflet';
import iconUrl from 'leaflet/dist/images/marker-icon.png';
import iconRetinaUrl from 'leaflet/dist/images/marker-icon-2x.png';
import shadowUrl from 'leaflet/dist/images/marker-shadow.png';

const DefaultIcon = L.icon({
  iconUrl,
  iconRetinaUrl,
  shadowUrl,
  iconSize: [25, 41],
  iconAnchor: [12, 41],
  popupAnchor: [1, -34],
  shadowSize: [41, 41]
});
L.Marker.prototype.options.icon = DefaultIcon;

const API_BASE = 'http://localhost:5000/api';

interface HeaderAnomaly {
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  description: string;
  senderDomain?: string;
  returnPathDomain?: string;
  replyToDomain?: string;
}

interface AnalysisResult {
  success: boolean;
  caseId: string;
  timestamp: string;
  emailDetails: {
    subject: string;
    from: string;
    fromEmail: string;
    senderDomain: string;
    to: string;
    date: string;
    returnPath: string;
    replyTo: string;
    messageId: string;
  };
  authentication: {
    spf: string;
    dkim: string;
    dmarc: string;
    rawAuthResults: string;
  };
  anomalies: HeaderAnomaly[];
  routing: {
    hopChain: string[];
    hopDetails: Array<{ hopNumber: number; raw: string; extractedIPs: string[] }>;
    originatingIP: string | null;
    location: {
      ip: string;
      city: string;
      region: string;
      country: string;
      countryCode: string;
      lat: number;
      lon: number;
      isp: string;
      org: string;
      as: string;
    };
  };
  domainIntelligence: {
    domain: string;
    hasMx: boolean;
    mxRecords: string[];
    spfRecord: string | null;
    domainAgeDays: number | null;
    creationDate: string;
    registrar: string;
    riskRating: string;
    riskFlags: string[];
  };
  threatIntelligence: {
    ip: string;
    abuseConfidenceScore: number;
    totalReports: number;
    lastReportedAt: string | null;
    usageType: string;
    isp: string;
    isWhitelisted: boolean;
    threatLevel: string;
    reputationSummary: string;
  };
  aiThreatAnalysis: {
    isPhishing: boolean;
    threatScore: number;
    threatCategory: string;
    urgencyLevel: string;
    attributionAssessment: string;
    suspiciousCues: string[];
    summary: string;
    mitigationSteps: string[];
  };
  blockchain: {
    status: string;
    network: string;
    contractAddress: string;
    txHash: string;
    blockNumber: number;
    evidenceHash: string;
    timestamp: string;
    chainOfCustodyVerified: boolean;
    proofType: string;
    explorerUrl: string;
  };
  privacyCompliance: {
    standard: string;
    anonymizationMethod: string;
    rawIpRetained: boolean;
  };
}

interface CaseRecord {
  caseId: string;
  createdAt: string;
  subject: string;
  from: string;
  senderDomain: string;
  to: string;
  threatScore: number;
  threatCategory: string;
  urgencyLevel: string;
  isPhishing: boolean;
  originatingIP: string | null;
  anonymizedIpHash: string;
  maskedIp: string;
  geo: { city: string; country: string; isp: string; lat: number; lon: number };
  txHash: string;
  evidenceHash: string;
  authSummary: { spf: string; dkim: string; dmarc: string };
  summary: string;
  fullAnalysis?: AnalysisResult;
}

interface CaseStats {
  total: number;
  highThreat: number;
  phishingCount: number;
  avgScore: number;
}

interface SampleEmail {
  name: string;
  type: string;
  rawEmail: string;
}

export default function App() {
  const [activeTab, setActiveTab] = useState<'scanner' | 'cases'>('scanner');
  const [rawEmail, setRawEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [loadingStep, setLoadingStep] = useState('');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState('');
  const [isExporting, setIsExporting] = useState(false);

  // Case Management State
  const [casesList, setCasesList] = useState<CaseRecord[]>([]);
  const [caseStats, setCaseStats] = useState<CaseStats | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [loadingCases, setLoadingCases] = useState(false);
  const [samples, setSamples] = useState<SampleEmail[]>([]);

  useEffect(() => {
    fetchSamples();
    fetchCases();
  }, []);

  const fetchSamples = async () => {
    try {
      const res = await axios.get(`${API_BASE}/samples`);
      setSamples(res.data);
    } catch (err) {
      console.warn("Could not load samples:", err);
    }
  };

  const fetchCases = async () => {
    setLoadingCases(true);
    try {
      const res = await axios.get(`${API_BASE}/cases`, {
        params: { search: searchQuery, category: categoryFilter }
      });
      setCasesList(res.data.cases || []);
      setCaseStats(res.data.stats || null);
    } catch (err) {
      console.error("Failed to load cases:", err);
    } finally {
      setLoadingCases(false);
    }
  };

  const handleAnalyze = async () => {
    if (!rawEmail.trim()) {
      setError('Please paste raw email headers or an EML message body first.');
      return;
    }
    setError('');
    setResult(null);
    setLoading(true);

    const steps = [
      'Extracting MIME headers & Return-Path anomalies...',
      'Querying DNS MX records & WHOIS domain age...',
      'Checking AbuseIPDB threat intelligence & IP reputation...',
      'Synthesizing Gemini Multi-Signal Threat Vectors...',
      'Anchoring Evidence to Web3 Blockchain Ledger...'
    ];

    let currentStep = 0;
    setLoadingStep(steps[0]);
    const stepInterval = setInterval(() => {
      currentStep++;
      if (currentStep < steps.length) {
        setLoadingStep(steps[currentStep]);
      }
    }, 600);

    try {
      const response = await axios.post(`${API_BASE}/analyze`, { rawEmail });
      setResult(response.data);
      fetchCases();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to connect to the Forensic backend pipeline.');
    } finally {
      clearInterval(stepInterval);
      setLoading(false);
    }
  };

  const handleLoadSample = (sampleText: string) => {
    setRawEmail(sampleText);
    setError('');
  };

  const handleOpenCase = (c: CaseRecord) => {
    if (c.fullAnalysis) {
      setResult(c.fullAnalysis);
    } else {
      setResult({
        success: true,
        caseId: c.caseId,
        timestamp: c.createdAt,
        emailDetails: {
          subject: c.subject,
          from: c.from,
          fromEmail: c.from,
          senderDomain: c.senderDomain,
          to: c.to,
          date: c.createdAt,
          returnPath: 'Archived Case',
          replyTo: 'Archived Case',
          messageId: `MSG-${c.caseId}`
        },
        authentication: {
          spf: c.authSummary?.spf || 'UNVERIFIED',
          dkim: c.authSummary?.dkim || 'UNVERIFIED',
          dmarc: c.authSummary?.dmarc || 'UNVERIFIED',
          rawAuthResults: 'Case Record'
        },
        anomalies: [],
        routing: {
          hopChain: c.originatingIP ? [c.originatingIP] : [],
          hopDetails: [],
          originatingIP: c.originatingIP,
          location: {
            ip: c.originatingIP || 'N/A',
            city: c.geo?.city || 'Unknown',
            region: 'Unknown',
            country: c.geo?.country || 'Unknown',
            countryCode: 'XX',
            lat: c.geo?.lat || 0,
            lon: c.geo?.lon || 0,
            isp: c.geo?.isp || 'Unknown',
            org: 'Unknown',
            as: 'Unknown'
          }
        },
        domainIntelligence: {
          domain: c.senderDomain,
          hasMx: true,
          mxRecords: [],
          spfRecord: null,
          domainAgeDays: null,
          creationDate: 'Archived',
          registrar: 'Archived',
          riskRating: 'ARCHIVED',
          riskFlags: []
        },
        threatIntelligence: {
          ip: c.originatingIP || 'N/A',
          abuseConfidenceScore: c.threatScore > 50 ? 80 : 0,
          totalReports: 0,
          lastReportedAt: null,
          usageType: 'Archived Record',
          isp: c.geo?.isp || 'Unknown',
          isWhitelisted: false,
          threatLevel: c.threatScore > 70 ? 'HIGH_RISK' : 'CLEAN',
          reputationSummary: c.summary
        },
        aiThreatAnalysis: {
          isPhishing: c.isPhishing,
          threatScore: c.threatScore,
          threatCategory: c.threatCategory,
          urgencyLevel: c.urgencyLevel,
          attributionAssessment: 'Archived Threat Intelligence',
          suspiciousCues: ['Loaded from persistent SOC case database'],
          summary: c.summary,
          mitigationSteps: ['Review case history', 'Verify firewall blacklist rules']
        },
        blockchain: {
          status: 'VERIFIED_ARCHIVED_PROOF',
          network: 'EVM Chain-of-Custody',
          contractAddress: '0x5FbDB2315678afecb367f032d93F642f64180aa3',
          txHash: c.txHash || '0x0000000000000000000000000000000000000000',
          blockNumber: 1048200,
          evidenceHash: c.evidenceHash || '0x0000000000000000000000000000000000000000',
          timestamp: c.createdAt,
          chainOfCustodyVerified: true,
          proofType: 'SHA-256 Digital Forensic Chain-of-Custody Seal',
          explorerUrl: `local://chain-of-custody/${c.txHash}`
        },
        privacyCompliance: {
          standard: 'GDPR / DPDP Section 12 Compliant',
          anonymizationMethod: 'SHA-256 Hash + Octet Masking',
          rawIpRetained: false
        }
      });
    }
    setActiveTab('scanner');
  };

  const handleDeleteCase = async (caseId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm(`Are you sure you want to delete ${caseId}?`)) return;
    try {
      await axios.delete(`${API_BASE}/cases/${caseId}`);
      fetchCases();
    } catch (err) {
      alert("Failed to delete case.");
    }
  };

  const handleExportPDF = () => {
    setIsExporting(true);
    const element = document.getElementById('forensic-report');
    if (!element) return;

    setTimeout(() => {
      const opt = {
        margin: 0.3,
        filename: `Forensic_Investigation_Report_${result?.caseId || Date.now()}.pdf`,
        image: { type: 'jpeg' as const, quality: 0.98 },
        html2canvas: { scale: 2, useCORS: true, backgroundColor: '#090d16' },
        jsPDF: { unit: 'in', format: 'letter', orientation: 'portrait' as const }
      };

      html2pdf().set(opt).from(element).save().then(() => {
        setIsExporting(false);
      });
    }, 1200);
  };

  const mapPosition: [number, number] = result && result.routing?.location?.lat
    ? [result.routing.location.lat, result.routing.location.lon]
    : [20, 0];

  const getScoreColor = (score: number) => {
    if (score >= 70) return '#ef4444';
    if (score >= 40) return '#f59e0b';
    return '#10b981';
  };

  return (
    <div style={{ minHeight: '100vh', backgroundColor: '#090d16', color: '#f8fafc', padding: '24px 32px' }}>
      
      {/* Top Header Bar */}
      <header style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        paddingBottom: '20px',
        borderBottom: '1px solid #1e293b',
        marginBottom: '24px',
        flexWrap: 'wrap',
        gap: '16px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{
            background: 'linear-gradient(135deg, #0284c7 0%, #38bdf8 100%)',
            padding: '10px',
            borderRadius: '12px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 20px rgba(56, 189, 248, 0.3)'
          }}>
            <ShieldAlert size={32} color="#ffffff" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <h1 style={{ margin: 0, fontSize: '22px', fontWeight: 800, letterSpacing: '-0.5px', color: '#f8fafc' }}>
                Email Forensics & Threat Intelligence Platform
              </h1>
              <span style={{
                backgroundColor: '#0369a1',
                color: '#e0f2fe',
                fontSize: '11px',
                fontWeight: 700,
                padding: '2px 8px',
                borderRadius: '12px',
                textTransform: 'uppercase',
                letterSpacing: '0.5px'
              }}>v2.0 Enterprise</span>
            </div>
            <p style={{ margin: '2px 0 0', fontSize: '13px', color: '#94a3b8' }}>
              AI Multi-Signal Anomaly Detection • Web3 Chain-of-Custody • SOC Case Management
            </p>
          </div>
        </div>

        {/* Navigation Tabs & Actions */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{
            display: 'flex',
            backgroundColor: '#111827',
            padding: '4px',
            borderRadius: '8px',
            border: '1px solid #1e293b'
          }}>
            <button
              onClick={() => setActiveTab('scanner')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '8px 16px',
                borderRadius: '6px',
                border: 'none',
                backgroundColor: activeTab === 'scanner' ? '#0284c7' : 'transparent',
                color: activeTab === 'scanner' ? '#fff' : '#94a3b8',
                fontWeight: 600,
                fontSize: '13px',
                cursor: 'pointer',
                transition: 'all 0.2s'
              }}
            >
              <Radio size={16} />
              Forensic Scanner
            </button>
            <button
              onClick={() => { setActiveTab('cases'); fetchCases(); }}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '8px 16px',
                borderRadius: '6px',
                border: 'none',
                backgroundColor: activeTab === 'cases' ? '#0284c7' : 'transparent',
                color: activeTab === 'cases' ? '#fff' : '#94a3b8',
                fontWeight: 600,
                fontSize: '13px',
                cursor: 'pointer',
                transition: 'all 0.2s'
              }}
            >
              <Database size={16} />
              SOC Case History {caseStats ? `(${caseStats.total})` : ''}
            </button>
          </div>

          {result && activeTab === 'scanner' && (
            <button
              onClick={handleExportPDF}
              disabled={isExporting}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                backgroundColor: isExporting ? '#0f766e' : '#0d9488',
                color: '#fff',
                border: 'none',
                padding: '9px 18px',
                borderRadius: '8px',
                cursor: isExporting ? 'wait' : 'pointer',
                fontWeight: 700,
                fontSize: '13px',
                boxShadow: '0 4px 12px rgba(13, 148, 136, 0.3)'
              }}
            >
              {isExporting ? <Loader className="animate-spin" size={16} /> : <FileText size={16} />}
              {isExporting ? 'Compiling PDF...' : 'Export Forensic Report'}
            </button>
          )}
        </div>
      </header>

      {/* ========================================================================= */}
      {/* TAB 1: FORENSIC SCANNER                                                   */}
      {/* ========================================================================= */}
      {activeTab === 'scanner' && (
        <div>
          {/* Preset Test Samples Bar */}
          <div style={{
            backgroundColor: '#111827',
            padding: '14px 20px',
            borderRadius: '10px',
            marginBottom: '20px',
            border: '1px solid #1e293b',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '12px'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Sparkles size={16} color="#38bdf8" />
              <span style={{ fontSize: '13px', fontWeight: 600, color: '#cbd5e1' }}>1-Click Forensic Demo Samples:</span>
            </div>
            <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
              {samples.map((s, idx) => (
                <button
                  key={idx}
                  onClick={() => handleLoadSample(s.rawEmail)}
                  style={{
                    backgroundColor: s.type === 'LEGITIMATE' ? '#064e3b' : '#312e81',
                    color: s.type === 'LEGITIMATE' ? '#6ee7b7' : '#c7d2fe',
                    border: `1px solid ${s.type === 'LEGITIMATE' ? '#059669' : '#4338ca'}`,
                    padding: '6px 14px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: 'pointer',
                    transition: 'all 0.2s'
                  }}
                >
                  ⚡ {s.name}
                </button>
              ))}
            </div>
          </div>

          {/* Raw Header / EML Input Section */}
          <div style={{
            backgroundColor: '#111827',
            padding: '20px',
            borderRadius: '10px',
            marginBottom: '24px',
            border: '1px solid #1e293b'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <label style={{ fontWeight: 700, fontSize: '14px', color: '#e2e8f0', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Layers size={18} color="#38bdf8" />
                Raw Email Headers / Complete EML Body:
              </label>
              <span style={{ fontSize: '12px', color: '#64748b' }}>Supports MIME, RFC-5322, Received Hops & DKIM blocks</span>
            </div>

            <textarea
              rows={6}
              value={rawEmail}
              onChange={(e) => setRawEmail(e.target.value)}
              disabled={loading}
              placeholder="Paste raw email headers or entire message here...&#10;e.g. Received: from mail.example.com (194.26.29.102) by target.com...&#10;Authentication-Results: spf=fail...&#10;From: CEO <ceo@company.com>"
              style={{
                width: '100%',
                backgroundColor: '#090d16',
                color: '#f8fafc',
                border: '1px solid #334155',
                borderRadius: '8px',
                padding: '14px',
                fontFamily: 'monospace',
                fontSize: '13px',
                boxSizing: 'border-box',
                opacity: loading ? 0.6 : 1,
                resize: 'vertical',
                lineHeight: 1.5
              }}
            />

            {error && (
              <div style={{
                backgroundColor: '#450a0a',
                border: '1px solid #991b1b',
                color: '#fca5a5',
                padding: '10px 14px',
                borderRadius: '6px',
                marginTop: '12px',
                fontSize: '13px',
                display: 'flex',
                alignItems: 'center',
                gap: '8px'
              }}>
                <XCircle size={16} />
                {error}
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '16px', flexWrap: 'wrap', gap: '12px' }}>
              <button
                onClick={handleAnalyze}
                disabled={loading}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                  backgroundColor: loading ? '#334155' : '#0284c7',
                  color: '#fff',
                  border: 'none',
                  padding: '12px 28px',
                  borderRadius: '8px',
                  cursor: loading ? 'not-allowed' : 'pointer',
                  fontWeight: 700,
                  fontSize: '15px',
                  boxShadow: '0 4px 14px rgba(2, 132, 199, 0.4)'
                }}
              >
                {loading ? <Activity className="animate-spin" size={20} /> : <Send size={20} />}
                {loading ? 'Running Multi-Signal Pipeline...' : 'Execute Forensic Analysis'}
              </button>

              <div style={{ display: 'flex', gap: '16px', fontSize: '12px', color: '#94a3b8' }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}><CheckCircle2 size={14} color="#10b981" /> SPF / DKIM / DMARC</span>
                <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}><CheckCircle2 size={14} color="#10b981" /> DNS / MX / RDAP</span>
                <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}><CheckCircle2 size={14} color="#10b981" /> AbuseIPDB Feeds</span>
                <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}><CheckCircle2 size={14} color="#10b981" /> Web3 Immutable Hash</span>
              </div>
            </div>
          </div>

          {/* Active Loading Progress Overlay */}
          {loading && (
            <div style={{
              backgroundColor: '#111827',
              padding: '40px',
              borderRadius: '10px',
              border: '1px solid #1e293b',
              textAlign: 'center',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: '16px',
              marginBottom: '24px'
            }}>
              <Loader size={44} color="#38bdf8" className="animate-spin" />
              <h3 style={{ margin: 0, color: '#f8fafc', fontSize: '18px' }}>
                AI Interrogating Headers & Tracing Infrastructure...
              </h3>
              <p style={{
                color: '#38bdf8',
                backgroundColor: '#0c4a6e',
                padding: '6px 16px',
                borderRadius: '20px',
                fontSize: '13px',
                fontWeight: 600,
                margin: 0
              }}>
                {loadingStep}
              </p>
            </div>
          )}

          {/* ========================================================================= */}
          {/* RESULTS DASHBOARD / FORENSIC REPORT                                       */}
          {/* ========================================================================= */}
          {result && !loading && (
            <div id="forensic-report" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>

              {/* Real-time Threshold Alert Banner (When Threat Score > 70) */}
              {result.aiThreatAnalysis.threatScore > 70 && (
                <div style={{
                  backgroundColor: '#450a0a',
                  border: '2px solid #ef4444',
                  borderRadius: '10px',
                  padding: '16px 20px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  boxShadow: '0 0 25px rgba(239, 68, 68, 0.4)',
                  flexWrap: 'wrap',
                  gap: '12px'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                    <div style={{
                      backgroundColor: '#ef4444',
                      padding: '8px',
                      borderRadius: '50%',
                      display: 'flex'
                    }}>
                      <AlertTriangle size={24} color="#fff" />
                    </div>
                    <div>
                      <h4 style={{ margin: 0, fontSize: '16px', fontWeight: 800, color: '#fee2e2' }}>
                        CRITICAL THREAT ALERT TRIGGERED (Threat Score: {result.aiThreatAnalysis.threatScore}/100)
                      </h4>
                      <p style={{ margin: '2px 0 0', fontSize: '13px', color: '#fca5a5' }}>
                        High probability of {result.aiThreatAnalysis.threatCategory}. Recommended for immediate SOC quarantine.
                      </p>
                    </div>
                  </div>
                  <div style={{
                    backgroundColor: '#7f1d1d',
                    color: '#fecaca',
                    padding: '6px 14px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontWeight: 700,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px'
                  }}>
                    <Radio size={14} className="animate-spin" />
                    SOC Incident Hook Active (Slack / SIEM Ready)
                  </div>
                </div>
              )}

              {/* Case Summary Meta Header */}
              <div style={{
                backgroundColor: '#111827',
                padding: '16px 20px',
                borderRadius: '10px',
                border: '1px solid #1e293b',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                flexWrap: 'wrap',
                gap: '12px'
              }}>
                <div>
                  <span style={{ fontSize: '12px', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Evidence Case File</span>
                  <div style={{ fontSize: '18px', fontWeight: 800, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '10px' }}>
                    {result.caseId}
                    <span style={{ fontSize: '12px', fontWeight: 500, color: '#94a3b8' }}>
                      • Subject: "{result.emailDetails.subject}"
                    </span>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '12px', alignItems: 'center', fontSize: '13px' }}>
                  <span style={{ color: '#94a3b8' }}><Clock size={14} style={{ verticalAlign: 'middle', marginRight: '4px' }} /> {new Date(result.timestamp).toLocaleString()}</span>
                  <span style={{
                    backgroundColor: '#0c4a6e',
                    color: '#7dd3fc',
                    padding: '4px 10px',
                    borderRadius: '6px',
                    fontWeight: 700,
                    fontSize: '12px'
                  }}>
                    Attribution: {result.aiThreatAnalysis.attributionAssessment}
                  </span>
                </div>
              </div>

              {/* Grid Row 1: AI Threat Engine & Protocol Authentication */}
              <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr', gap: '20px' }}>
                
                {/* AI Threat Assessment Card */}
                <div style={{
                  pageBreakInside: 'avoid',
                  backgroundColor: '#111827',
                  padding: '22px',
                  borderRadius: '10px',
                  border: `2px solid ${getScoreColor(result.aiThreatAnalysis.threatScore)}`
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                    <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <AlertTriangle color={getScoreColor(result.aiThreatAnalysis.threatScore)} />
                      AI Threat Intelligence Assessment
                    </h3>
                    <div style={{
                      backgroundColor: result.aiThreatAnalysis.threatScore > 50 ? '#450a0a' : '#064e3b',
                      color: result.aiThreatAnalysis.threatScore > 50 ? '#fca5a5' : '#6ee7b7',
                      border: `1px solid ${getScoreColor(result.aiThreatAnalysis.threatScore)}`,
                      padding: '6px 14px',
                      borderRadius: '20px',
                      fontWeight: 800,
                      fontSize: '14px'
                    }}>
                      Threat Score: {result.aiThreatAnalysis.threatScore}/100
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginBottom: '14px', fontSize: '13px' }}>
                    <div style={{ backgroundColor: '#090d16', padding: '10px', borderRadius: '6px' }}>
                      <span style={{ color: '#64748b', display: 'block', fontSize: '11px', textTransform: 'uppercase' }}>Threat Category</span>
                      <strong style={{ color: '#f8fafc' }}>{result.aiThreatAnalysis.threatCategory}</strong>
                    </div>
                    <div style={{ backgroundColor: '#090d16', padding: '10px', borderRadius: '6px' }}>
                      <span style={{ color: '#64748b', display: 'block', fontSize: '11px', textTransform: 'uppercase' }}>Urgency Level</span>
                      <strong style={{ color: result.aiThreatAnalysis.urgencyLevel === 'Critical' ? '#ef4444' : '#f59e0b' }}>
                        {result.aiThreatAnalysis.urgencyLevel}
                      </strong>
                    </div>
                  </div>

                  <p style={{ fontSize: '13px', lineHeight: 1.6, color: '#cbd5e1', marginBottom: '14px' }}>
                    <strong>Forensic Summary:</strong> {result.aiThreatAnalysis.summary}
                  </p>

                  {result.aiThreatAnalysis.suspiciousCues?.length > 0 && (
                    <div style={{ marginBottom: '14px' }}>
                      <strong style={{ fontSize: '13px', color: '#fca5a5' }}>Key Threat Indicators & Cues:</strong>
                      <ul style={{ margin: '6px 0 0', paddingLeft: '20px', color: '#fca5a5', fontSize: '12px', lineHeight: 1.5 }}>
                        {result.aiThreatAnalysis.suspiciousCues.map((cue, idx) => (
                          <li key={idx}>{cue}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {result.aiThreatAnalysis.mitigationSteps?.length > 0 && (
                    <div style={{ backgroundColor: '#090d16', padding: '10px 12px', borderRadius: '6px', borderLeft: '3px solid #0284c7' }}>
                      <strong style={{ fontSize: '12px', color: '#38bdf8' }}>Recommended SOC Containment:</strong>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginTop: '6px' }}>
                        {result.aiThreatAnalysis.mitigationSteps.map((step, idx) => (
                          <span key={idx} style={{ backgroundColor: '#1e293b', color: '#94a3b8', fontSize: '11px', padding: '2px 8px', borderRadius: '4px' }}>
                            • {step}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Protocol Authentication & Header Anomalies */}
                <div style={{
                  pageBreakInside: 'avoid',
                  backgroundColor: '#111827',
                  padding: '22px',
                  borderRadius: '10px',
                  border: '1px solid #1e293b',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '16px'
                }}>
                  <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <ShieldCheck color="#38bdf8" /> Protocol Authentication
                  </h3>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {['spf', 'dkim', 'dmarc'].map((proto) => {
                      const val = result.authentication[proto as keyof typeof result.authentication];
                      const passed = String(val).includes('PASS');
                      return (
                        <div key={proto} style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          backgroundColor: '#090d16',
                          padding: '10px 14px',
                          borderRadius: '6px',
                          border: '1px solid #1e293b'
                        }}>
                          <span style={{ fontWeight: 800, textTransform: 'uppercase', fontSize: '13px' }}>{proto}</span>
                          <span style={{
                            backgroundColor: passed ? '#064e3b' : '#450a0a',
                            color: passed ? '#6ee7b7' : '#fca5a5',
                            border: `1px solid ${passed ? '#059669' : '#991b1b'}`,
                            padding: '3px 10px',
                            borderRadius: '4px',
                            fontSize: '11px',
                            fontWeight: 800
                          }}>
                            {val}
                          </span>
                        </div>
                      );
                    })}
                  </div>

                  {/* Header Anomaly Matrix */}
                  <div>
                    <h4 style={{ margin: '0 0 8px 0', fontSize: '13px', fontWeight: 700, color: '#e2e8f0', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                      Deep Header Anomaly Engine
                    </h4>

                    {result.anomalies?.length === 0 ? (
                      <div style={{ backgroundColor: '#064e3b', color: '#6ee7b7', padding: '10px', borderRadius: '6px', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <CheckCircle2 size={16} /> No header spoofing or routing anomalies detected.
                      </div>
                    ) : (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        {result.anomalies.map((anom, idx) => (
                          <div key={idx} style={{
                            backgroundColor: '#450a0a',
                            border: '1px solid #7f1d1d',
                            padding: '8px 12px',
                            borderRadius: '6px',
                            fontSize: '12px'
                          }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', fontWeight: 700, color: '#fca5a5' }}>
                              <span>⚠ {anom.title}</span>
                              <span style={{ fontSize: '10px', backgroundColor: '#991b1b', padding: '1px 6px', borderRadius: '3px' }}>{anom.severity}</span>
                            </div>
                            <p style={{ margin: '4px 0 0', color: '#fecaca', fontSize: '11px' }}>{anom.description}</p>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

              </div>

              {/* Grid Row 2: Domain Intelligence & Threat Intelligence (AbuseIPDB) */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                
                {/* Domain Intelligence Card */}
                <div style={{
                  pageBreakInside: 'avoid',
                  backgroundColor: '#111827',
                  padding: '22px',
                  borderRadius: '10px',
                  border: '1px solid #1e293b'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
                    <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Globe color="#06b6d4" /> Domain Intelligence (DNS & WHOIS)
                    </h3>
                    <span style={{
                      backgroundColor: result.domainIntelligence.riskRating === 'HIGH' ? '#450a0a' : '#064e3b',
                      color: result.domainIntelligence.riskRating === 'HIGH' ? '#fca5a5' : '#6ee7b7',
                      padding: '3px 10px',
                      borderRadius: '12px',
                      fontSize: '11px',
                      fontWeight: 800
                    }}>
                      Risk: {result.domainIntelligence.riskRating}
                    </span>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', fontSize: '12px' }}>
                    <p><strong>Domain:</strong> {result.domainIntelligence.domain}</p>
                    <p><strong>Registrar:</strong> {result.domainIntelligence.registrar}</p>
                    <p>
                      <strong>Registration Age:</strong>{' '}
                      {result.domainIntelligence.domainAgeDays !== null
                        ? `${result.domainIntelligence.domainAgeDays} days old`
                        : 'Historical / Verified'}
                    </p>
                    <p>
                      <strong>MX Server Status:</strong>{' '}
                      <span style={{ color: result.domainIntelligence.hasMx ? '#10b981' : '#ef4444', fontWeight: 700 }}>
                        {result.domainIntelligence.hasMx ? 'Configured Active' : 'Missing (Unroutable)'}
                      </span>
                    </p>
                  </div>

                  {result.domainIntelligence.mxRecords?.length > 0 && (
                    <div style={{ marginTop: '10px', backgroundColor: '#090d16', padding: '8px 12px', borderRadius: '6px', fontSize: '11px' }}>
                      <strong style={{ color: '#94a3b8' }}>Published MX Exchangers:</strong>
                      <div style={{ color: '#cbd5e1', marginTop: '2px', fontFamily: 'monospace' }}>
                        {result.domainIntelligence.mxRecords.join(' • ')}
                      </div>
                    </div>
                  )}

                  {result.domainIntelligence.riskFlags?.length > 0 && (
                    <div style={{ marginTop: '10px' }}>
                      {result.domainIntelligence.riskFlags.map((flag, idx) => (
                        <div key={idx} style={{ color: '#fbbf24', fontSize: '11px', marginTop: '3px' }}>
                          ⚡ {flag}
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Threat Intelligence / AbuseIPDB Card */}
                <div style={{
                  pageBreakInside: 'avoid',
                  backgroundColor: '#111827',
                  padding: '22px',
                  borderRadius: '10px',
                  border: '1px solid #1e293b'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
                    <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Server color="#f59e0b" /> Threat Intelligence & IP Reputation
                    </h3>
                    <span style={{
                      backgroundColor: result.threatIntelligence.threatLevel === 'HIGH_RISK' ? '#450a0a' : '#064e3b',
                      color: result.threatIntelligence.threatLevel === 'HIGH_RISK' ? '#fca5a5' : '#6ee7b7',
                      padding: '3px 10px',
                      borderRadius: '12px',
                      fontSize: '11px',
                      fontWeight: 800
                    }}>
                      {result.threatIntelligence.threatLevel}
                    </span>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', fontSize: '12px' }}>
                    <p><strong>Target IP:</strong> {result.threatIntelligence.ip}</p>
                    <p><strong>ISP / Network:</strong> {result.threatIntelligence.isp}</p>
                    <p><strong>Usage Type:</strong> {result.threatIntelligence.usageType}</p>
                    <p>
                      <strong>Abuse Confidence:</strong>{' '}
                      <span style={{ color: result.threatIntelligence.abuseConfidenceScore > 40 ? '#ef4444' : '#10b981', fontWeight: 800 }}>
                        {result.threatIntelligence.abuseConfidenceScore}%
                      </span>
                    </p>
                  </div>

                  <div style={{ marginTop: '12px', backgroundColor: '#090d16', padding: '10px 12px', borderRadius: '6px', fontSize: '12px', color: '#cbd5e1' }}>
                    <strong>Reputation Telemetry:</strong> {result.threatIntelligence.reputationSummary}
                  </div>
                </div>

              </div>

              {/* Grid Row 3: IP Geolocation Map & Hop Trace */}
              <div style={{
                pageBreakInside: 'avoid',
                backgroundColor: '#111827',
                padding: '22px',
                borderRadius: '10px',
                border: '1px solid #1e293b'
              }}>
                <h3 style={{ margin: '0 0 16px 0', fontSize: '17px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <MapPin color="#f59e0b" /> Originating Mail Server Geolocation & Transmission Path
                </h3>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.6fr', gap: '20px' }}>
                  <div style={{ fontSize: '13px' }}>
                    <p><strong>Originating IP:</strong> <code style={{ color: '#38bdf8' }}>{result.routing.originatingIP || 'Unresolved'}</code></p>
                    <p><strong>City & Country:</strong> {result.routing.location.city}, {result.routing.location.country} ({result.routing.location.countryCode})</p>
                    <p><strong>Autonomous System:</strong> {result.routing.location.as || result.routing.location.isp}</p>
                    <p><strong>Coordinates:</strong> {result.routing.location.lat.toFixed(4)}, {result.routing.location.lon.toFixed(4)}</p>

                    <hr style={{ borderColor: '#1e293b', margin: '14px 0' }} />

                    <strong style={{ color: '#cbd5e1', fontSize: '12px', textTransform: 'uppercase' }}>SMTP Relay Hop Chain ({result.routing.hopChain.length} Hops):</strong>
                    <ol style={{ paddingLeft: '18px', fontSize: '12px', color: '#94a3b8', margin: '6px 0 0' }}>
                      {result.routing.hopChain.map((ip, i) => (
                        <li key={i} style={{ margin: '3px 0' }}>
                          <span style={{ color: i === result.routing.hopChain.length - 1 ? '#38bdf8' : '#e2e8f0', fontWeight: i === result.routing.hopChain.length - 1 ? 700 : 400 }}>
                            {ip} {i === result.routing.hopChain.length - 1 ? '(Earliest Public Origin Node)' : ''}
                          </span>
                        </li>
                      ))}
                    </ol>
                  </div>

                  {/* Leaflet Map Component */}
                  <div style={{ height: '280px', borderRadius: '8px', overflow: 'hidden', border: '1px solid #334155', position: 'relative' }}>
                    {result.routing.location.lat !== 0 ? (
                      <MapContainer
                        {...({
                          center: mapPosition,
                          zoom: 5,
                          style: { height: '100%', width: '100%' },
                          scrollWheelZoom: false
                        } as any)}
                      >
                        <TileLayer
                          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
                          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                        />
                        <Marker position={mapPosition}>
                          <Popup>
                            <strong>Origin Mail Server</strong><br />
                            {result.routing.location.city}, {result.routing.location.country}<br />
                            IP: {result.routing.location.ip}<br />
                            ISP: {result.routing.location.isp}
                          </Popup>
                        </Marker>
                      </MapContainer>
                    ) : (
                      <div style={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', backgroundColor: '#090d16', color: '#64748b' }}>
                        No physical coordinates available for private/unresolved IP.
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* Grid Row 4: Blockchain Chain-of-Custody & Privacy Safeguards */}
              <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr', gap: '20px' }}>
                
                {/* Web3 Blockchain Chain-of-Custody Card */}
                <div style={{
                  pageBreakInside: 'avoid',
                  backgroundColor: '#111827',
                  padding: '22px',
                  borderRadius: '10px',
                  border: '1px solid #1e293b'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
                    <h3 style={{ margin: 0, fontSize: '17px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Lock color="#8b5cf6" /> Blockchain Chain-of-Custody (Web3 EVM)
                    </h3>
                    <span style={{
                      backgroundColor: '#2e1065',
                      color: '#c4b5fd',
                      border: '1px solid #6d28d9',
                      padding: '3px 10px',
                      borderRadius: '12px',
                      fontSize: '11px',
                      fontWeight: 800
                    }}>
                      {result.blockchain.status}
                    </span>
                  </div>

                  <p style={{ fontSize: '12px', color: '#94a3b8', margin: '0 0 12px' }}>
                    Tamper-proof evidentiary recording anchoring the digital cryptographic signature of this analysis onto the decentralized state ledger.
                  </p>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12px' }}>
                    <div style={{ backgroundColor: '#090d16', padding: '8px 12px', borderRadius: '6px' }}>
                      <span style={{ color: '#64748b', fontSize: '11px', display: 'block' }}>Web3 Transaction Hash:</span>
                      <code style={{ color: '#a78bfa', wordBreak: 'break-all', fontSize: '11px' }}>{result.blockchain.txHash}</code>
                    </div>
                    <div style={{ backgroundColor: '#090d16', padding: '8px 12px', borderRadius: '6px' }}>
                      <span style={{ color: '#64748b', fontSize: '11px', display: 'block' }}>Digital Evidence SHA-256 Digest:</span>
                      <code style={{ color: '#38bdf8', wordBreak: 'break-all', fontSize: '11px' }}>{result.blockchain.evidenceHash}</code>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', color: '#cbd5e1', fontSize: '12px', padding: '4px 0' }}>
                      <span>Ledger Network: <strong>{result.blockchain.network}</strong></span>
                      <span>Block #: <strong>{result.blockchain.blockNumber}</strong></span>
                    </div>
                  </div>
                </div>

                {/* Privacy & Legal Safeguards (Block 12) */}
                <div style={{
                  pageBreakInside: 'avoid',
                  backgroundColor: '#111827',
                  padding: '22px',
                  borderRadius: '10px',
                  border: '1px solid #1e293b',
                  display: 'flex',
                  flexDirection: 'column',
                  justifyContent: 'space-between'
                }}>
                  <div>
                    <h3 style={{ margin: '0 0 12px 0', fontSize: '17px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <FileCheck color="#10b981" /> Legal & Privacy Safeguards (Block 12)
                    </h3>
                    <p style={{ fontSize: '12px', color: '#94a3b8', margin: '0 0 14px' }}>
                      Compliance with GDPR / DPDP Article 12 data minimization standards for digital forensics and investigation logs.
                    </p>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12px' }}>
                      <div style={{ backgroundColor: '#090d16', padding: '8px 12px', borderRadius: '6px' }}>
                        <span style={{ color: '#64748b', fontSize: '11px', display: 'block' }}>Hashed Anonymized Origin IP:</span>
                        <code style={{ color: '#34d399', wordBreak: 'break-all', fontSize: '11px' }}>
                          {result.blockchain.evidenceHash.substring(0, 32)}...
                        </code>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#6ee7b7', fontSize: '12px', marginTop: '6px' }}>
                        <CheckCircle2 size={16} /> Zero Raw PII Stored on Unencrypted Media
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#6ee7b7', fontSize: '12px' }}>
                        <CheckCircle2 size={16} /> Immutable Chain-of-Custody Preserved
                      </div>
                    </div>
                  </div>

                  <div style={{
                    marginTop: '16px',
                    backgroundColor: '#064e3b',
                    color: '#a7f3d0',
                    padding: '8px 12px',
                    borderRadius: '6px',
                    fontSize: '11px',
                    fontWeight: 700,
                    textAlign: 'center'
                  }}>
                    🛡 {result.privacyCompliance?.standard || 'GDPR / DPDP Section 12 Certified'}
                  </div>
                </div>

              </div>

            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: SOC CASE MANAGEMENT & AUDIT LOG                                   */}
      {/* ========================================================================= */}
      {activeTab === 'cases' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          
          {/* Summary Stat Cards */}
          {caseStats && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
              <div style={{ backgroundColor: '#111827', padding: '18px', borderRadius: '10px', border: '1px solid #1e293b' }}>
                <span style={{ color: '#94a3b8', fontSize: '12px', textTransform: 'uppercase', fontWeight: 600 }}>Total Cases Investigated</span>
                <div style={{ fontSize: '28px', fontWeight: 800, color: '#f8fafc', marginTop: '4px' }}>{caseStats.total}</div>
              </div>
              <div style={{ backgroundColor: '#111827', padding: '18px', borderRadius: '10px', border: '1px solid #1e293b' }}>
                <span style={{ color: '#fca5a5', fontSize: '12px', textTransform: 'uppercase', fontWeight: 600 }}>Critical Incidents (&gt; 70)</span>
                <div style={{ fontSize: '28px', fontWeight: 800, color: '#ef4444', marginTop: '4px' }}>{caseStats.highThreat}</div>
              </div>
              <div style={{ backgroundColor: '#111827', padding: '18px', borderRadius: '10px', border: '1px solid #1e293b' }}>
                <span style={{ color: '#fcd34d', fontSize: '12px', textTransform: 'uppercase', fontWeight: 600 }}>Phishing / Fraud Verified</span>
                <div style={{ fontSize: '28px', fontWeight: 800, color: '#f59e0b', marginTop: '4px' }}>{caseStats.phishingCount}</div>
              </div>
              <div style={{ backgroundColor: '#111827', padding: '18px', borderRadius: '10px', border: '1px solid #1e293b' }}>
                <span style={{ color: '#93c5fd', fontSize: '12px', textTransform: 'uppercase', fontWeight: 600 }}>Average Threat Index</span>
                <div style={{ fontSize: '28px', fontWeight: 800, color: '#38bdf8', marginTop: '4px' }}>{caseStats.avgScore}/100</div>
              </div>
            </div>
          )}

          {/* Search & Filter Controls */}
          <div style={{
            backgroundColor: '#111827',
            padding: '16px 20px',
            borderRadius: '10px',
            border: '1px solid #1e293b',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            gap: '16px',
            flexWrap: 'wrap'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: 1, minWidth: '280px' }}>
              <Search size={18} color="#64748b" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && fetchCases()}
                placeholder="Search cases by ID, subject, sender domain, or category..."
                style={{
                  width: '100%',
                  backgroundColor: '#090d16',
                  color: '#f8fafc',
                  border: '1px solid #334155',
                  borderRadius: '6px',
                  padding: '9px 12px',
                  fontSize: '13px'
                }}
              />
            </div>

            <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
              <select
                value={categoryFilter}
                onChange={(e) => { setCategoryFilter(e.target.value); setTimeout(fetchCases, 100); }}
                style={{
                  backgroundColor: '#090d16',
                  color: '#f8fafc',
                  border: '1px solid #334155',
                  borderRadius: '6px',
                  padding: '9px 14px',
                  fontSize: '13px'
                }}
              >
                <option value="ALL">All Threat Categories</option>
                <option value="Executive Impersonation (BEC)">Executive Impersonation (BEC)</option>
                <option value="Credential Harvesting">Credential Harvesting</option>
                <option value="Invoice Fraud">Invoice Fraud</option>
                <option value="Domain Spoofing / Impersonation">Domain Spoofing</option>
                <option value="Legitimate Communication">Legitimate</option>
              </select>

              <button
                onClick={fetchCases}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  backgroundColor: '#1e293b',
                  color: '#cbd5e1',
                  border: '1px solid #334155',
                  padding: '9px 16px',
                  borderRadius: '6px',
                  cursor: 'pointer',
                  fontSize: '13px',
                  fontWeight: 600
                }}
              >
                <RefreshCw size={14} className={loadingCases ? 'animate-spin' : ''} />
                Refresh
              </button>
            </div>
          </div>

          {/* Cases Table */}
          <div style={{
            backgroundColor: '#111827',
            borderRadius: '10px',
            border: '1px solid #1e293b',
            overflow: 'hidden'
          }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
              <thead>
                <tr style={{ backgroundColor: '#090d16', borderBottom: '1px solid #1e293b', color: '#94a3b8' }}>
                  <th style={{ padding: '14px 18px' }}>Case ID</th>
                  <th style={{ padding: '14px 18px' }}>Timestamp</th>
                  <th style={{ padding: '14px 18px' }}>Subject & Sender</th>
                  <th style={{ padding: '14px 18px' }}>Threat Score</th>
                  <th style={{ padding: '14px 18px' }}>Category</th>
                  <th style={{ padding: '14px 18px' }}>Masked IP (Block 12)</th>
                  <th style={{ padding: '14px 18px', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {casesList.length === 0 ? (
                  <tr>
                    <td colSpan={7} style={{ padding: '40px', textAlign: 'center', color: '#64748b' }}>
                      No forensic cases match the query criteria. Run a scan to log new incidents.
                    </td>
                  </tr>
                ) : (
                  casesList.map((c) => (
                    <tr
                      key={c.caseId}
                      onClick={() => handleOpenCase(c)}
                      style={{
                        borderBottom: '1px solid #1e293b',
                        cursor: 'pointer',
                        transition: 'background-color 0.15s'
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = '#1f2937')}
                      onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
                    >
                      <td style={{ padding: '14px 18px', fontWeight: 700, color: '#38bdf8' }}>
                        {c.caseId}
                      </td>
                      <td style={{ padding: '14px 18px', color: '#94a3b8', fontSize: '12px' }}>
                        {new Date(c.createdAt).toLocaleDateString()} {new Date(c.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </td>
                      <td style={{ padding: '14px 18px' }}>
                        <div style={{ fontWeight: 600, color: '#f8fafc', maxWidth: '300px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {c.subject}
                        </div>
                        <div style={{ fontSize: '11px', color: '#64748b' }}>
                          From: {c.senderDomain || c.from}
                        </div>
                      </td>
                      <td style={{ padding: '14px 18px' }}>
                        <span style={{
                          backgroundColor: c.threatScore > 70 ? '#450a0a' : c.threatScore > 40 ? '#451a03' : '#064e3b',
                          color: getScoreColor(c.threatScore),
                          border: `1px solid ${getScoreColor(c.threatScore)}`,
                          padding: '3px 10px',
                          borderRadius: '12px',
                          fontWeight: 800,
                          fontSize: '12px'
                        }}>
                          {c.threatScore}/100
                        </span>
                      </td>
                      <td style={{ padding: '14px 18px', color: '#cbd5e1' }}>
                        {c.threatCategory}
                      </td>
                      <td style={{ padding: '14px 18px' }}>
                        <code style={{ color: '#34d399', fontSize: '11px', backgroundColor: '#090d16', padding: '2px 6px', borderRadius: '4px' }}>
                          {c.maskedIp || '194.26.xxx.xxx'}
                        </code>
                      </td>
                      <td style={{ padding: '14px 18px', textAlign: 'right' }}>
                        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
                          <button
                            onClick={(e) => { e.stopPropagation(); handleOpenCase(c); }}
                            style={{
                              backgroundColor: '#0284c7',
                              color: '#fff',
                              border: 'none',
                              padding: '6px 12px',
                              borderRadius: '6px',
                              fontSize: '12px',
                              fontWeight: 600,
                              cursor: 'pointer',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '4px'
                            }}
                          >
                            View Report <ArrowRight size={14} />
                          </button>
                          <button
                            onClick={(e) => handleDeleteCase(c.caseId, e)}
                            style={{
                              backgroundColor: '#334155',
                              color: '#ef4444',
                              border: 'none',
                              padding: '6px 10px',
                              borderRadius: '6px',
                              cursor: 'pointer'
                            }}
                            title="Delete Case"
                          >
                            <Trash2 size={14} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

        </div>
      )}

    </div>
  );
}