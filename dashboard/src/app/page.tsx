"use client";

import { useState, useEffect, useRef } from 'react';

type BotStatus = {
  id: string;
  port: number;
  status: 'online' | 'offline';
  url: string;
};

const SCAN_CATEGORIES = [
  'prompt_injection', 'jailbreak', 'data_extraction',
  'output_handling', 'rag_poisoning', 'availability',
];

const CAT_LABEL: Record<string, string> = {
  prompt_injection: 'Prompt Injection',
  jailbreak: 'Jailbreak',
  data_extraction: 'Data Extraction',
  output_handling: 'Output Handling',
  rag_poisoning: 'RAG Poisoning',
  availability: 'Availability',
};

const STATUS_COLOR: Record<string, string> = {
  pending: '#6b7280',
  running: '#f59e0b',
  complete: '#10b981',
  failed: '#ef4444',
};

function SparkLine({ scores }: { scores: number[] }) {
  if (scores.length < 2) return null;
  const w = 80, h = 28;
  const min = Math.min(...scores);
  const max = Math.max(...scores);
  const range = max - min || 10;
  const pts = scores
    .map((s, i) => {
      const x = (i / (scores.length - 1)) * w;
      const y = h - 4 - ((s - min) / range) * (h - 8);
      return `${x},${y}`;
    })
    .join(' ');
  return (
    <svg width={w} height={h} style={{ overflow: 'visible', display: 'block' }}>
      <polyline
        points={pts}
        fill="none"
        stroke="var(--accent)"
        strokeWidth="1.5"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
    </svg>
  );
}

// ── Pipeline flow stages ──────────────────────────────────────────
const PIPELINE_STAGES = [
  { id: 'target',       label: 'Target',       sub: 'health check',  ai: false },
  { id: 'scanners',     label: 'Scanners',     sub: '6 parallel',    ai: true  },
  { id: 'dedup',        label: 'Dedup',        sub: 'non-AI node',   ai: false },
  { id: 'knowledge',    label: 'RAG',          sub: 'ChromaDB',      ai: true  },
  { id: 'analysis',     label: 'Analysis',     sub: 'LLM classify',  ai: true  },
  { id: 'threat_intel', label: 'Threat Intel', sub: 'MITRE map',     ai: true  },
  { id: 'score',        label: 'Score',        sub: 'grade A–F',     ai: false },
] as const;

function getStageStatus(id: string, catStatus: Record<string, string>, scanComplete: boolean): string {
  switch (id) {
    case 'target':
      return catStatus['target'] || '';
    case 'scanners': {
      const sts = SCAN_CATEGORIES.map(c => catStatus[c]).filter(Boolean);
      if (sts.some(s => s === 'running' || s === 'retrying')) return 'running';
      if (sts.length === SCAN_CATEGORIES.length && sts.every(s => s === 'complete' || s === 'failed')) return 'complete';
      if (sts.length > 0) return 'running';
      return '';
    }
    case 'dedup': {
      const sts = SCAN_CATEGORIES.map(c => catStatus[c]).filter(Boolean);
      const allDone = sts.length === SCAN_CATEGORIES.length && sts.every(s => s === 'complete' || s === 'failed');
      if (catStatus['knowledge'] || catStatus['analysis']) return 'complete';
      if (allDone) return 'running';
      return '';
    }
    case 'knowledge': return catStatus['knowledge'] || '';
    case 'analysis':  return catStatus['analysis']  || '';
    case 'threat_intel': return catStatus['threat_intel'] || '';
    case 'score': return scanComplete ? 'complete' : (catStatus['analysis'] === 'complete' ? 'running' : '');
    default: return '';
  }
}

function stageColor(st: string): string {
  if (st === 'running' || st === 'retrying') return '#f59e0b';
  if (st === 'complete') return '#10b981';
  if (st === 'failed')   return '#ef4444';
  return '#374151';
}

const STAGE_DESCRIPTIONS: Record<string, string> = {
  target:       'HTTP health check — verifies the target chatbot is reachable before scanning starts.',
  scanners:     '6 scanner agents run in parallel (Semaphore 3). Each sends attack prompts via HTTP then calls the LLM once to classify the full batch.',
  dedup:        'Non-AI deduplication node — removes duplicate findings across categories using title + evidence[:100] as the dedup key.',
  knowledge:    'RAG agent queries ChromaDB with each finding\'s category and title. Returns OWASP remediation advice grounded in the local knowledge base.',
  analysis:     'Analysis agent reviews all deduplicated findings, removes false positives, assigns final severity, and writes the executive summary.',
  threat_intel: 'Threat Intel agent maps each finding to a MITRE ATT&CK technique, identifies likely threat actors, and lists related CVEs.',
  score:        'Non-AI scorer — applies severity deductions (Critical −20, High −10, Medium −5, Low −2) to produce a 0–100 score and A–F grade.',
};

function PipelineFlow({
  catStatus, scanComplete, selectedStage, onSelectStage, stageMessages, scanErrors,
}: {
  catStatus: Record<string, string>;
  scanComplete: boolean;
  selectedStage: string | null;
  onSelectStage: (id: string) => void;
  stageMessages: Record<string, string[]>;
  scanErrors: string[];
}) {
  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', overflowX: 'auto', gap: 0 }}>
      {PIPELINE_STAGES.map((stage, i) => {
        const st = getStageStatus(stage.id, catStatus, scanComplete);
        const color = stageColor(st);
        const isRunning = st === 'running' || st === 'retrying';
        const isComplete = st === 'complete';
        const isFailed = st === 'failed';
        const isActive = !!st;
        const isSelected = selectedStage === stage.id;

        return (
          <div key={stage.id} style={{ display: 'flex', alignItems: 'flex-start', flex: '0 0 auto' }}>
            {/* clickable stage column */}
            <button
              onClick={() => onSelectStage(stage.id)}
              style={{
                display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '4px',
                width: '68px', background: 'none', border: 'none', cursor: 'pointer',
                padding: '0 0 4px',
                outline: isSelected ? `2px solid ${color || 'var(--accent)'}` : 'none',
                outlineOffset: '4px', borderRadius: '8px',
              }}
              title={`Click to see ${stage.label} details`}
            >
              <div style={{
                width: '34px', height: '34px',
                borderRadius: stage.ai ? '8px' : '50%',
                border: `2px solid ${color}`,
                background: isSelected ? `${color}33` : isActive ? `${color}22` : 'rgba(0,0,0,0.3)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                flexShrink: 0,
                boxShadow: isRunning ? `0 0 8px ${color}55` : isSelected ? `0 0 6px ${color || 'var(--accent)'}44` : 'none',
                transition: 'all 0.3s',
              }}>
                {isComplete && (
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="20 6 9 17 4 12"/>
                  </svg>
                )}
                {isFailed && <span style={{ color: '#ef4444', fontSize: '0.8rem', fontWeight: 700, lineHeight: 1 }}>✗</span>}
                {isRunning && <span className="loader" style={{ width: '14px', height: '14px', borderWidth: '2px' }} />}
                {!isActive && <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#4b5563', display: 'block' }} />}
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '0.63rem', fontWeight: 600, color: isActive ? 'white' : '#6b7280', whiteSpace: 'nowrap' }}>{stage.label}</div>
                <div style={{ fontSize: '0.55rem', color: '#6b7280', whiteSpace: 'nowrap' }}>{stage.sub}</div>
                {stage.ai && <div style={{ fontSize: '0.5rem', color: 'var(--accent)', fontWeight: 700, marginTop: '1px' }}>AI</div>}
              </div>
            </button>
            {/* connector */}
            {i < PIPELINE_STAGES.length - 1 && (
              <div style={{ width: '20px', flexShrink: 0, paddingTop: '16px' }}>
                <div style={{ height: '2px', background: isComplete ? '#10b981' : 'rgba(255,255,255,0.1)', transition: 'background 0.5s' }} />
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function StageDetail({
  stageId, catStatus, scanComplete, stageMessages, scanErrors,
}: {
  stageId: string;
  catStatus: Record<string, string>;
  scanComplete: boolean;
  stageMessages: Record<string, string[]>;
  scanErrors: string[];
}) {
  const stage = PIPELINE_STAGES.find(s => s.id === stageId);
  if (!stage) return null;

  const st = getStageStatus(stageId, catStatus, scanComplete);
  const color = stageColor(st);

  // Collect messages: for "scanners" aggregate all 6 categories; for others use stage id
  const msgKeys = stageId === 'scanners' ? SCAN_CATEGORIES : [stageId];
  const messages = msgKeys.flatMap(k => stageMessages[k] || []);

  // Errors relevant to this stage
  const errors = scanErrors.filter(e => {
    const lower = e.toLowerCase();
    if (stageId === 'scanners') return SCAN_CATEGORIES.some(c => lower.includes(c));
    return lower.includes(stageId.replace('_', ' ')) || lower.includes(stageId) || lower.includes(stageId.replace('_', ''));
  });

  const statusLabel = st === 'running' ? 'Running' : st === 'complete' ? 'Complete' : st === 'failed' ? 'Failed' : 'Not started';
  const description = STAGE_DESCRIPTIONS[stageId] || '';

  return (
    <div style={{ marginTop: '0.75rem', background: 'rgba(0,0,0,0.3)', border: `1px solid ${color || 'var(--border)'}44`, borderRadius: '8px', padding: '0.75rem 1rem', fontSize: '0.8rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <strong style={{ color: 'white' }}>{stage.label}</strong>
          {stage.ai && <span style={{ fontSize: '0.6rem', color: 'var(--accent)', fontWeight: 700, background: 'rgba(99,102,241,0.15)', padding: '1px 5px', borderRadius: '4px' }}>AI agent</span>}
        </div>
        {st && <span style={{ fontSize: '0.7rem', color: color, fontWeight: 600 }}>{statusLabel}</span>}
      </div>

      <p style={{ color: 'var(--text-secondary)', marginBottom: messages.length || errors.length ? '0.5rem' : 0, lineHeight: '1.5' }}>{description}</p>

      {errors.length > 0 && (
        <div style={{ marginBottom: '0.5rem' }}>
          <div style={{ fontSize: '0.65rem', color: '#ef4444', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.3rem' }}>Error</div>
          {errors.map((e, i) => (
            <div key={i} style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: '#ef4444', background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)', borderRadius: '4px', padding: '0.4rem 0.6rem', marginBottom: '0.25rem', wordBreak: 'break-word' }}>
              {e}
            </div>
          ))}
        </div>
      )}

      {messages.length > 0 && (
        <div>
          <div style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.3rem' }}>Progress log</div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', background: 'rgba(0,0,0,0.25)', borderRadius: '4px', padding: '0.4rem 0.6rem', maxHeight: '120px', overflowY: 'auto' }}>
            {messages.map((m, i) => (
              <div key={i} style={{ color: i === messages.length - 1 ? 'white' : 'var(--text-secondary)', marginBottom: '0.15rem', lineHeight: '1.5' }}>{m}</div>
            ))}
          </div>
        </div>
      )}

      {!st && !messages.length && (
        <div style={{ color: '#6b7280', fontSize: '0.75rem', fontStyle: 'italic' }}>This stage has not started yet.</div>
      )}
    </div>
  );
}

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export default function Dashboard() {
  const [targetUrl, setTargetUrl] = useState('http://localhost:9001');
  const [isScanning, setIsScanning] = useState(false);
  const [activeTab, setActiveTab] = useState('findings');
  const [scanComplete, setScanComplete] = useState(false);
  const [bots, setBots] = useState<BotStatus[]>([]);
  const [loadingBot, setLoadingBot] = useState<string | null>(null);
  const [scanReport, setScanReport] = useState<any>(null);
  const [scanDepth, setScanDepth] = useState<'small' | 'medium' | 'full'>('medium');
  const [progressLines, setProgressLines] = useState<string[]>([]);
  const [depthInfoOpen, setDepthInfoOpen] = useState<string | null>(null);
  const [categoryStatus, setCategoryStatus] = useState<Record<string, string>>({});
  const [liveCategoryResults, setLiveCategoryResults] = useState<Record<string, any>>({});
  const [scanHistory, setScanHistory] = useState<any[]>([]);
  const [selectedStage, setSelectedStage] = useState<string | null>(null);
  const [stageMessages, setStageMessages] = useState<Record<string, string[]>>({});
  const abortRef = useRef<AbortController | null>(null);
  const progressEndRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    progressEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [progressLines]);

  const fetchBots = async () => {
    try {
      const res = await fetch('/api/bots');
      const data = await res.json();
      if (data.bots) setBots(data.bots);
    } catch (e) {
      console.error(e);
    }
  };

  const fetchHistory = async () => {
    try {
      const res = await fetch('/api/history');
      const data = await res.json();
      setScanHistory(data.history || []);
    } catch {}
  };

  const handleExport = () => {
    if (!scanReport) return;
    const blob = new Blob([JSON.stringify(scanReport, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const host = targetUrl.replace(/https?:\/\//, '').replace(/[/:]/g, '-');
    a.download = `saife-report-${host}-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleClearHistory = async () => {
    if (!window.confirm('Clear all scan history? This cannot be undone.')) return;
    await fetch('/api/history', { method: 'DELETE' });
    setScanHistory([]);
  };

  useEffect(() => {
    fetchBots();
    fetchHistory();
    const interval = setInterval(fetchBots, 3000);
    // Request notification permission once — user can dismiss, no harm
    if (typeof window !== 'undefined' && 'Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission();
    }
    return () => clearInterval(interval);
  }, []);

  const handleBotAction = async (id: string, action: 'start' | 'stop') => {
    setLoadingBot(id);
    try {
      await fetch('/api/bots', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, action }),
      });
      await fetchBots();
    } finally {
      setLoadingBot(null);
    }
  };

  const handleCancel = () => {
    abortRef.current?.abort();
    abortRef.current = null;
    setIsScanning(false);
    setProgressLines([]);
  };

  const handleScan = async () => {
    await fetch('/api/scan', { method: 'DELETE' }).catch(() => {});
    setIsScanning(true);
    setScanComplete(false);
    setScanReport(null);
    setProgressLines([]);
    setCategoryStatus({});
    setLiveCategoryResults({});
    setStageMessages({});
    setSelectedStage(null);
    setActiveTab('findings');

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetUrl, scanDepth }),
        signal: controller.signal,
      });

      const reader = res.body!.getReader();
      const decoder = new TextDecoder();

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const text = decoder.decode(value, { stream: true });
        for (const line of text.split('\n')) {
          if (!line.startsWith('data:')) continue;
          try {
            const event = JSON.parse(line.slice(5).trim());
            if (event.type === 'progress') {
              setProgressLines(prev => [...prev.slice(-30), event.data]);
              const match = event.data.match(/\[(\w+)\]\s+(\w+)/);
              if (match) {
                setCategoryStatus(prev => ({ ...prev, [match[1]]: match[2] }));
                setStageMessages(prev => ({
                  ...prev,
                  [match[1]]: [...(prev[match[1]] || []), event.data],
                }));
              }
            } else if (event.type === 'partial_result') {
              setLiveCategoryResults(prev => ({ ...prev, [event.data.category]: event.data.result }));
            } else if (event.type === 'result') {
              if (event.data?.error) {
                alert('Scan failed: ' + event.data.error);
              } else {
                setScanReport(event.data);
                setScanComplete(true);
                fetchHistory();
                if (typeof window !== 'undefined' && 'Notification' in window && Notification.permission === 'granted') {
                  const score = event.data.score?.score ?? '?';
                  const grade = event.data.score?.grade ?? '?';
                  const n = event.data.analysis?.findings?.length ?? 0;
                  new Notification('SAIFE Scan Complete', {
                    body: `${targetUrl} — Score: ${score}/100 (${grade}) · ${n} finding${n !== 1 ? 's' : ''}`,
                  });
                }
              }
            } else if (event.type === 'error') {
              alert('Scan error: ' + event.data);
            }
          } catch {}
        }
      }
    } catch (e: any) {
      if (e.name !== 'AbortError') alert('Network error: ' + e.message);
    } finally {
      abortRef.current = null;
      setIsScanning(false);
    }
  };

  // Sparkline: last 8 scores for the current target (oldest → newest)
  const sparkScores = scanHistory
    .filter(h => h.target_url === targetUrl)
    .slice(0, 8)
    .reverse()
    .map((h: any) => h.score);

  return (
    <div>
      {/* ── Test Targets ── */}
      <div className="card" style={{ marginBottom: '2rem', borderColor: 'rgba(16, 185, 129, 0.2)' }}>
        <div className="card-header">
          <h2 style={{ fontSize: '1.25rem', margin: 0, color: 'var(--success)' }}>Test Targets</h2>
          <span style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>Manage local test bots</span>
        </div>
        <div className="grid grid-3">
          {['vulnerable', 'partial', 'secure'].map((id) => {
            const bot = bots.find(b => b.id === id);
            const isOnline = bot?.status === 'online';
            const isLoading = loadingBot === id;
            const titles = { vulnerable: 'Vulnerable Bot', partial: 'Partial Bot', secure: 'Secure Bot' };
            return (
              <div key={id} style={{ background: 'rgba(0,0,0,0.2)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                  <strong style={{ textTransform: 'capitalize' }}>{titles[id as keyof typeof titles]}</strong>
                  <span className={`badge ${isOnline ? 'low' : 'critical'}`}>{isOnline ? 'Online' : 'Offline'}</span>
                </div>
                <div style={{ fontSize: '0.85rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
                  Port: {bot?.port || '---'}
                </div>
                <div style={{ display: 'flex', gap: '0.5rem', flexDirection: 'column' }}>
                  <button
                    className="btn btn-outline"
                    style={{ width: '100%', padding: '0.5rem' }}
                    onClick={() => handleBotAction(id, isOnline ? 'stop' : 'start')}
                    disabled={isLoading}
                  >
                    {isLoading ? '...' : (isOnline ? 'Stop Bot' : 'Boot Bot')}
                  </button>
                  {isOnline && (
                    <button
                      className="btn btn-primary"
                      style={{ width: '100%', padding: '0.5rem', fontSize: '0.875rem' }}
                      onClick={() => { if (bot) setTargetUrl(bot.url); window.scrollTo({ top: 300, behavior: 'smooth' }); }}
                    >
                      Target this Bot
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* ── New Scan Card ── */}
      <div className="card" style={{ marginBottom: '2rem' }}>
        <h2 style={{ marginBottom: '1.5rem', fontSize: '1.5rem' }}>New Security Scan</h2>

        <div className="input-group" style={{ marginBottom: '1rem' }}>
          <label className="input-label">Target Application URL</label>
          <input
            className="input"
            type="text"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="e.g. http://localhost:9001"
          />
        </div>

        <div style={{ marginBottom: '1.25rem' }}>
          <label className="input-label" style={{ marginBottom: '0.5rem', display: 'block' }}>Scan Depth</label>
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            {([
              {
                key: 'small', label: 'Quick', attacks: '~12 attacks', time: '~2-3 min',
                info: [
                  'prompt_injection: Direct override, Indirect injection',
                  'jailbreak: DAN attack, Role-play bypass',
                  'data_extraction: System prompt extraction, Training data',
                  'output_handling: XSS via output, SQL injection via output',
                  'rag_poisoning: RAG poisoning probe, Embedding collision',
                  'availability: Token exhaustion, Recursive loop',
                ],
              },
              {
                key: 'medium', label: 'Standard', attacks: '~24 attacks', time: '~3-5 min',
                info: [
                  'prompt_injection: 4 attacks (adds Multi-language, Base64)',
                  'jailbreak: 4 attacks (adds Hypothetical framing, Auth bypass)',
                  'data_extraction: 4 attacks (adds PII extraction, API key leakage)',
                  'output_handling: 4 attacks (adds Command injection, SSRF)',
                  'rag_poisoning: 3 attacks (all — adds Context manipulation)',
                  'availability: 4 attacks (all — adds Rate limit, Model DoS)',
                ],
              },
              {
                key: 'full', label: 'Full', attacks: '32 attacks', time: '~5-8 min',
                info: [
                  'prompt_injection: All 7 attacks (+ Delimiter injection, Authority escalation, Context overflow)',
                  'jailbreak: All 6 attacks (+ Encoding jailbreak, Token smuggling)',
                  'data_extraction: All 6 attacks (+ Architecture disclosure, History leakage)',
                  'output_handling: All 6 attacks (+ Excessive agency, Tool abuse)',
                  'rag_poisoning: All 3 attacks',
                  'availability: All 4 attacks',
                ],
              },
            ] as const).map(({ key, label, attacks, time, info }) => (
              <div key={key} style={{ position: 'relative' }}>
                <div style={{ display: 'flex', alignItems: 'stretch', borderRadius: '6px', border: `1px solid ${scanDepth === key ? 'var(--accent)' : 'var(--border)'}`, overflow: 'hidden' }}>
                  <button
                    onClick={() => setScanDepth(key)}
                    disabled={isScanning}
                    style={{
                      padding: '0.5rem 1rem',
                      background: scanDepth === key ? 'rgba(99,102,241,0.15)' : 'rgba(0,0,0,0.2)',
                      color: scanDepth === key ? 'var(--accent)' : 'var(--text-secondary)',
                      cursor: isScanning ? 'not-allowed' : 'pointer',
                      textAlign: 'left', border: 'none',
                    }}
                  >
                    <div style={{ fontWeight: 600, fontSize: '0.875rem' }}>{label}</div>
                    <div style={{ fontSize: '0.75rem', opacity: 0.8 }}>{attacks} · {time}</div>
                  </button>
                  <button
                    onClick={() => setDepthInfoOpen(depthInfoOpen === key ? null : key)}
                    style={{ padding: '0 0.5rem', background: 'rgba(255,255,255,0.05)', color: 'var(--text-secondary)', border: 'none', borderLeft: '1px solid var(--border)', cursor: 'pointer', fontSize: '0.75rem' }}
                    title="Show attacks"
                  >ℹ</button>
                </div>
                {depthInfoOpen === key && (
                  <div style={{ position: 'absolute', top: '100%', left: 0, zIndex: 10, marginTop: '4px', background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '8px', padding: '0.75rem 1rem', minWidth: '320px', boxShadow: '0 8px 24px rgba(0,0,0,0.4)', fontSize: '0.8rem' }}>
                    <div style={{ fontWeight: 600, color: 'white', marginBottom: '0.5rem' }}>{label} — Attack Categories</div>
                    {info.map((line, i) => (
                      <div key={i} style={{ padding: '0.25rem 0', borderBottom: i < info.length - 1 ? '1px solid rgba(255,255,255,0.05)' : 'none', color: 'var(--text-secondary)' }}>
                        <span style={{ color: 'var(--accent)', fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>{line.split(':')[0]}:</span>
                        {line.slice(line.indexOf(':') + 1)}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <button className="btn btn-primary" onClick={handleScan} disabled={isScanning} style={{ height: '3.125rem' }}>
            {isScanning ? (
              <><span className="loader"></span>Scanning…</>
            ) : (
              <>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <polygon points="5 3 19 12 5 21 5 3"></polygon>
                </svg>
                Run Assessment
              </>
            )}
          </button>
          {isScanning && (
            <button className="btn btn-outline" onClick={handleCancel} style={{ height: '3.125rem', borderColor: 'var(--critical)', color: 'var(--critical)' }}>
              ✕ Cancel
            </button>
          )}
        </div>

        {/* Pipeline flow — visual step indicator */}
        {(isScanning || scanComplete) && (
          <div style={{ marginTop: '1rem', background: 'rgba(0,0,0,0.2)', border: '1px solid var(--border)', borderRadius: '8px', padding: '0.6rem 0.8rem' }}>
            <div style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Agent Pipeline — click any step for details</div>
            <PipelineFlow
              catStatus={categoryStatus}
              scanComplete={scanComplete}
              selectedStage={selectedStage}
              onSelectStage={(id) => setSelectedStage(prev => prev === id ? null : id)}
              stageMessages={stageMessages}
              scanErrors={scanReport?.errors || []}
            />
            {selectedStage && (
              <StageDetail
                stageId={selectedStage}
                catStatus={categoryStatus}
                scanComplete={scanComplete}
                stageMessages={stageMessages}
                scanErrors={scanReport?.errors || []}
              />
            )}
          </div>
        )}

        {/* Live progress log */}
        {isScanning && progressLines.length > 0 && (
          <div style={{ marginTop: '0.75rem', fontFamily: 'var(--font-mono)', fontSize: '0.78rem', background: 'rgba(0,0,0,0.35)', border: '1px solid var(--border)', borderRadius: '6px', padding: '0.6rem 0.8rem', maxHeight: '130px', overflowY: 'auto' }}>
            {progressLines.map((line, i) => (
              <div key={i} style={{ color: i === progressLines.length - 1 ? 'var(--accent)' : 'var(--text-secondary)', marginBottom: '0.18rem', lineHeight: '1.5' }}>
                {line}
              </div>
            ))}
            <div ref={progressEndRef} />
          </div>
        )}

        {/* Category status grid */}
        {isScanning && (
          <div style={{ marginTop: '0.75rem', display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.4rem' }}>
            {SCAN_CATEGORIES.map(cat => {
              const status = categoryStatus[cat] || 'pending';
              const liveResult = liveCategoryResults[cat];
              return (
                <div key={cat} style={{ background: 'rgba(0,0,0,0.2)', border: `1px solid ${STATUS_COLOR[status]}33`, borderRadius: '6px', padding: '0.4rem 0.6rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <span style={{ color: STATUS_COLOR[status], fontSize: '0.6rem' }}>●</span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: '0.72rem', color: 'white', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{CAT_LABEL[cat]}</div>
                    <div style={{ fontSize: '0.65rem', color: STATUS_COLOR[status] }}>
                      {status === 'running' ? 'scanning…' : status === 'complete' ? `${liveResult?.findings?.length ?? 0} findings` : status === 'failed' ? 'failed' : 'pending'}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {isScanning && (
          <div style={{ marginTop: '0.5rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            Running {scanDepth === 'small' ? '~12' : scanDepth === 'medium' ? '~24' : '32'} attack checks — please wait, this takes a few minutes with a local LLM.
          </div>
        )}
      </div>

      {/* ── Stats Grid ── */}
      {(isScanning || scanComplete) && (
        <div className="grid grid-3" style={{ marginBottom: '2rem' }}>
          <div className="card">
            <div className="card-header">
              <span className="card-title">Security Score</span>
              <span className={`badge ${scanReport?.score?.grade === 'F' ? 'critical' : 'low'}`}>
                {scanReport ? `${scanReport.score.grade} Grade` : '...'}
              </span>
            </div>
            <div className={`stat-value ${isScanning ? 'animate-pulse' : ''}`} style={{ color: scanComplete ? (scanReport?.score?.score > 50 ? 'var(--success)' : 'var(--critical)') : 'var(--text-secondary)' }}>
              {isScanning ? '---' : (scanReport?.score?.score || '0')}
              <span style={{ fontSize: '1rem', color: 'var(--text-secondary)' }}>/100</span>
            </div>
            {sparkScores.length >= 2 && scanComplete && (
              <div style={{ marginTop: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <SparkLine scores={sparkScores} />
                <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>last {sparkScores.length} scans</span>
              </div>
            )}
          </div>

          <div className="card">
            <div className="card-header"><span className="card-title">Vulnerabilities</span></div>
            <div className={`stat-value ${isScanning ? 'animate-pulse' : ''}`}>
              {isScanning ? '-' : (scanReport?.analysis?.findings?.length || 0)}
            </div>
            <div style={{ marginTop: '0.5rem', display: 'flex', gap: '0.5rem' }}>
              <span className="badge critical">{scanReport ? scanReport.analysis?.findings?.filter((f: any) => f.severity === 'critical').length : 0} Critical</span>
              <span className="badge high">{scanReport ? scanReport.analysis?.findings?.filter((f: any) => f.severity === 'high').length : 0} High</span>
            </div>
          </div>

          <div className="card">
            <div className="card-header"><span className="card-title">Scan Duration</span></div>
            <div className={`stat-value ${isScanning ? 'animate-pulse' : ''}`}>
              {isScanning ? '...' : `${(scanReport?.scan_duration_seconds || 0).toFixed(1)}s`}
            </div>
            <div style={{ marginTop: '0.5rem', fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
              Depth: {scanReport?.scan_depth || scanDepth} · 6 categories
            </div>
          </div>
        </div>
      )}

      {/* ── Live findings card (during scan, once categories start finishing) ── */}
      {isScanning && Object.keys(liveCategoryResults).length > 0 && (
        <div className="card" style={{ marginBottom: '2rem' }}>
          <h3 style={{ color: 'white', marginBottom: '1rem', fontSize: '1rem' }}>Live Results — Categories Finished</h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.75rem' }}>
            {SCAN_CATEGORIES.map(cat => {
              const result = liveCategoryResults[cat];
              if (!result) return null;
              const findingCount = result.findings?.length ?? 0;
              return (
                <div key={cat} style={{ background: 'rgba(0,0,0,0.2)', border: '1px solid var(--border)', borderRadius: '8px', padding: '0.75rem' }}>
                  <div style={{ color: 'white', fontSize: '0.8rem', fontWeight: 600, marginBottom: '0.4rem' }}>{CAT_LABEL[cat]}</div>
                  <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                    <span className={`badge ${findingCount > 0 ? 'critical' : 'low'}`} style={{ fontSize: '0.7rem' }}>{findingCount} finding{findingCount !== 1 ? 's' : ''}</span>
                    <span className="badge low" style={{ fontSize: '0.7rem' }}>{result.attacks_blocked ?? 0} blocked</span>
                    <span className="badge high" style={{ fontSize: '0.7rem' }}>{result.attacks_successful ?? 0} vuln</span>
                  </div>
                  {findingCount > 0 && (
                    <div style={{ marginTop: '0.4rem' }}>
                      {result.findings.slice(0, 2).map((f: any, i: number) => (
                        <div key={i} style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: '0.3rem', marginTop: '0.3rem' }}>
                          <span className={`badge ${f.severity}`} style={{ fontSize: '0.6rem', marginRight: '0.3rem' }}>{f.severity}</span>
                          {f.title}
                        </div>
                      ))}
                      {findingCount > 2 && <div style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>+{findingCount - 2} more</div>}
                    </div>
                  )}
                </div>
              );
            }).filter(Boolean)}
          </div>
        </div>
      )}

      {/* ── Results Tabs ── */}
      {scanComplete && scanReport && (
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
            <div className="tabs" style={{ marginBottom: 0, flex: 1 }}>
              <button className={`tab ${activeTab === 'findings' ? 'active' : ''}`} onClick={() => setActiveTab('findings')}>Security Findings</button>
              <button className={`tab ${activeTab === 'metrics' ? 'active' : ''}`} onClick={() => setActiveTab('metrics')}>Analysis Report</button>
              <button className={`tab ${activeTab === 'threat' ? 'active' : ''}`} onClick={() => setActiveTab('threat')}>Threat Intel</button>
              <button className={`tab ${activeTab === 'pipeline' ? 'active' : ''}`} onClick={() => setActiveTab('pipeline')}>Pipeline Debug</button>
            </div>
            <div style={{ display: 'flex', gap: '0.5rem', marginLeft: '1rem', flexShrink: 0 }}>
              <button className="btn btn-outline" style={{ padding: '0.4rem 0.75rem', fontSize: '0.8rem' }} onClick={handleExport} title="Download report as JSON">
                ↓ Export
              </button>
              <button className="btn btn-primary" style={{ padding: '0.4rem 0.75rem', fontSize: '0.8rem' }} onClick={handleScan} title="Re-run scan with same settings">
                ↺ Re-run
              </button>
            </div>
          </div>

          {activeTab === 'findings' && (
            <div className="finding-list">
              {scanReport.analysis?.findings?.length > 0 ? scanReport.analysis.findings.map((finding: any, i: number) => (
                <div key={i} className={`finding-item ${finding.severity}`}>
                  <div className="finding-header">
                    <h3 style={{ fontSize: '1.125rem', marginBottom: 0 }}>{finding.title}</h3>
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                      <span className={`badge ${finding.severity}`}>{finding.severity}</span>
                      <span className="badge" style={{ background: 'rgba(255,255,255,0.1)' }}>{finding.owasp_id || 'Unknown'}</span>
                    </div>
                  </div>
                  <p style={{ marginTop: '0.5rem', color: 'var(--text-primary)' }}>{finding.recommendation}</p>
                  <div className="finding-evidence">{finding.evidence || 'No evidence provided.'}</div>
                </div>
              )) : (
                <div style={{ color: 'var(--success)', padding: '2rem', textAlign: 'center' }}>No vulnerabilities detected! Great job.</div>
              )}
            </div>
          )}

          {activeTab === 'metrics' && (
            <div style={{ color: 'var(--text-secondary)' }}>
              <h3 style={{ color: 'white', marginBottom: '1rem' }}>Executive Summary</h3>
              <p style={{ whiteSpace: 'pre-wrap', lineHeight: '1.8' }}>{scanReport.analysis?.executive_summary || 'No analysis available.'}</p>
            </div>
          )}

          {activeTab === 'pipeline' && (
            <div style={{ color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '2rem' }}>
              <section>
                <h3 style={{ color: 'white', marginBottom: '1rem' }}>Agent Pipeline Status</h3>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border)', textAlign: 'left' }}>
                      <th style={{ padding: '0.5rem 0.75rem', color: 'var(--text-secondary)' }}>Agent / Node</th>
                      <th style={{ padding: '0.5rem 0.75rem', color: 'var(--text-secondary)' }}>Type</th>
                      <th style={{ padding: '0.5rem 0.75rem', color: 'var(--text-secondary)' }}>Status</th>
                      <th style={{ padding: '0.5rem 0.75rem', color: 'var(--text-secondary)' }}>Findings</th>
                      <th style={{ padding: '0.5rem 0.75rem', color: 'var(--text-secondary)' }}>Duration</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(scanReport.state?.agents || {}).map(([cat, agent]: [string, any]) => (
                      <tr key={cat} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                        <td style={{ padding: '0.5rem 0.75rem', color: 'white', fontFamily: 'var(--font-mono)' }}>{cat}</td>
                        <td style={{ padding: '0.5rem 0.75rem' }}><span className="badge" style={{ background: 'rgba(99,102,241,0.2)', color: 'var(--accent)', fontSize: '0.7rem' }}>AI · Scanner</span></td>
                        <td style={{ padding: '0.5rem 0.75rem' }}><span className={`badge ${agent.status === 'complete' ? 'low' : agent.status === 'failed' ? 'critical' : 'medium'}`} style={{ fontSize: '0.7rem' }}>{agent.status}</span></td>
                        <td style={{ padding: '0.5rem 0.75rem' }}>{agent.findings_count ?? '—'}</td>
                        <td style={{ padding: '0.5rem 0.75rem', fontFamily: 'var(--font-mono)' }}>{agent.duration_seconds ? `${agent.duration_seconds.toFixed(1)}s` : '—'}</td>
                      </tr>
                    ))}
                    <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                      <td style={{ padding: '0.5rem 0.75rem', color: 'white', fontFamily: 'var(--font-mono)' }}>knowledge_agent</td>
                      <td style={{ padding: '0.5rem 0.75rem' }}><span className="badge" style={{ background: 'rgba(99,102,241,0.2)', color: 'var(--accent)', fontSize: '0.7rem' }}>AI · RAG</span></td>
                      <td style={{ padding: '0.5rem 0.75rem' }}><span className={`badge ${scanReport.owasp_context?.length > 0 ? 'low' : 'medium'}`} style={{ fontSize: '0.7rem' }}>{scanReport.owasp_context?.length > 0 ? 'complete' : 'skipped'}</span></td>
                      <td style={{ padding: '0.5rem 0.75rem' }}>{scanReport.owasp_context?.length ?? 0} contexts</td>
                      <td style={{ padding: '0.5rem 0.75rem' }}>—</td>
                    </tr>
                    <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                      <td style={{ padding: '0.5rem 0.75rem', color: 'white', fontFamily: 'var(--font-mono)' }}>analysis_agent</td>
                      <td style={{ padding: '0.5rem 0.75rem' }}><span className="badge" style={{ background: 'rgba(99,102,241,0.2)', color: 'var(--accent)', fontSize: '0.7rem' }}>AI · LLM</span></td>
                      <td style={{ padding: '0.5rem 0.75rem' }}><span className={`badge ${scanReport.analysis ? 'low' : 'critical'}`} style={{ fontSize: '0.7rem' }}>{scanReport.analysis ? 'complete' : 'failed'}</span></td>
                      <td style={{ padding: '0.5rem 0.75rem' }}>{scanReport.analysis?.total_vulnerabilities ?? 0} vulns</td>
                      <td style={{ padding: '0.5rem 0.75rem' }}>—</td>
                    </tr>
                    <tr>
                      <td style={{ padding: '0.5rem 0.75rem', color: 'white', fontFamily: 'var(--font-mono)' }}>threat_intel_agent</td>
                      <td style={{ padding: '0.5rem 0.75rem' }}><span className="badge" style={{ background: 'rgba(99,102,241,0.2)', color: 'var(--accent)', fontSize: '0.7rem' }}>AI · LLM</span></td>
                      <td style={{ padding: '0.5rem 0.75rem' }}><span className={`badge ${scanReport.threat_intel ? 'low' : 'medium'}`} style={{ fontSize: '0.7rem' }}>{scanReport.threat_intel ? 'complete' : 'skipped/failed'}</span></td>
                      <td style={{ padding: '0.5rem 0.75rem' }}>{scanReport.threat_intel?.correlated_techniques?.length ?? 0} techniques</td>
                      <td style={{ padding: '0.5rem 0.75rem' }}>—</td>
                    </tr>
                  </tbody>
                </table>
              </section>

              <section>
                <h3 style={{ color: 'white', marginBottom: '1rem' }}>Raw Scanner Results (per Category)</h3>
                {Object.entries(scanReport.category_results || {}).length === 0 && <p>No category results available.</p>}
                {Object.entries(scanReport.category_results || {}).map(([cat, result]: [string, any]) => (
                  <div key={cat} style={{ marginBottom: '1.5rem', background: 'rgba(0,0,0,0.2)', borderRadius: '8px', border: '1px solid var(--border)', overflow: 'hidden' }}>
                    <div style={{ padding: '0.75rem 1rem', background: 'rgba(99,102,241,0.1)', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <strong style={{ color: 'white', fontFamily: 'var(--font-mono)' }}>{cat}</strong>
                      <div style={{ display: 'flex', gap: '0.5rem', fontSize: '0.75rem' }}>
                        <span className="badge" style={{ background: 'rgba(255,255,255,0.1)' }}>Sent: {result.total_attacks_sent}</span>
                        <span className="badge low">Blocked: {result.attacks_blocked}</span>
                        <span className="badge high">Vulnerable: {result.attacks_successful}</span>
                        <span className="badge critical">Findings: {result.findings?.length ?? 0}</span>
                      </div>
                    </div>
                    {result.findings?.length > 0 ? result.findings.map((f: any, i: number) => (
                      <div key={i} style={{ padding: '0.75rem 1rem', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                          <strong style={{ color: 'white', fontSize: '0.875rem' }}>{f.title}</strong>
                          <span className={`badge ${f.severity}`} style={{ fontSize: '0.7rem' }}>{f.severity}</span>
                        </div>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', fontSize: '0.8rem' }}>
                          <div>
                            <div style={{ color: 'var(--accent)', marginBottom: '0.25rem', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Attack Used</div>
                            <div className="finding-evidence" style={{ fontSize: '0.75rem', maxHeight: '60px', overflow: 'hidden' }}>{f.attack_used || '—'}</div>
                          </div>
                          <div>
                            <div style={{ color: 'var(--accent)', marginBottom: '0.25rem', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Target Response</div>
                            <div className="finding-evidence" style={{ fontSize: '0.75rem', maxHeight: '60px', overflow: 'hidden' }}>{f.target_response || '—'}</div>
                          </div>
                        </div>
                        <div style={{ marginTop: '0.5rem', fontSize: '0.8rem' }}>
                          <span style={{ color: 'var(--accent)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Evidence: </span>
                          {f.evidence || '—'}
                        </div>
                      </div>
                    )) : (
                      <div style={{ padding: '0.75rem 1rem', color: 'var(--success)', fontSize: '0.875rem' }}>No findings — target defended all attacks in this category.</div>
                    )}
                    {result.summary && (
                      <div style={{ padding: '0.5rem 1rem', fontSize: '0.8rem', borderTop: '1px solid rgba(255,255,255,0.04)', fontStyle: 'italic' }}>
                        Scanner summary: {result.summary}
                      </div>
                    )}
                  </div>
                ))}
              </section>

              <section>
                <h3 style={{ color: 'white', marginBottom: '1rem' }}>Knowledge Agent — RAG Output</h3>
                {(scanReport.owasp_context?.length ?? 0) === 0 ? (
                  <p>No RAG context retrieved (no findings or knowledge agent skipped).</p>
                ) : scanReport.owasp_context.map((ctx: any, i: number) => (
                  <div key={i} style={{ marginBottom: '1rem', background: 'rgba(0,0,0,0.2)', borderRadius: '8px', border: '1px solid var(--border)', padding: '1rem' }}>
                    <div style={{ color: 'var(--accent)', fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.5rem' }}>Context {i + 1} · ChromaDB retrieval</div>
                    <p style={{ color: 'white', marginBottom: '0.5rem', fontSize: '0.875rem' }}>{ctx.answer}</p>
                    {ctx.source_snippet && <div className="finding-evidence" style={{ fontSize: '0.75rem' }}>Source: {ctx.source_snippet}</div>}
                    {ctx.confidence_score !== undefined && <div style={{ marginTop: '0.5rem', fontSize: '0.75rem' }}>Confidence: {ctx.confidence_score}</div>}
                  </div>
                ))}
              </section>

              {(scanReport.errors?.length ?? 0) > 0 && (
                <section>
                  <h3 style={{ color: 'var(--critical)', marginBottom: '1rem' }}>Errors / Warnings</h3>
                  {scanReport.errors.map((err: string, i: number) => (
                    <div key={i} style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: '6px', padding: '0.75rem 1rem', marginBottom: '0.5rem', fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--critical)' }}>{err}</div>
                  ))}
                </section>
              )}

              <section>
                <h3 style={{ color: 'white', marginBottom: '1rem' }}>Non-AI Nodes Summary</h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem' }}>
                  {[
                    { label: 'HTTP Caller', detail: 'Sent attacks to target /chat', status: 'ok' },
                    { label: 'Response Parser', detail: 'Regex/keyword signal detection', status: 'ok' },
                    { label: 'Deduplicator', detail: `${scanReport.total_findings} unique findings after dedup`, status: 'ok' },
                    { label: 'Scorer', detail: `Score: ${scanReport.score?.score ?? '—'} / Grade: ${scanReport.score?.grade ?? '—'}`, status: 'ok' },
                    { label: 'Memory Store', detail: 'Scan history saved to SQLite', status: scanReport.errors?.some((e: string) => e.includes('Memory')) ? 'warn' : 'ok' },
                    { label: 'PII Guardrail', detail: 'PII stripped before storage', status: 'ok' },
                  ].map(node => (
                    <div key={node.label} style={{ background: 'rgba(0,0,0,0.2)', border: '1px solid var(--border)', borderRadius: '8px', padding: '0.75rem' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                        <strong style={{ color: 'white', fontSize: '0.875rem' }}>{node.label}</strong>
                        <span className={`badge ${node.status === 'ok' ? 'low' : 'medium'}`} style={{ fontSize: '0.65rem' }}>{node.status === 'ok' ? 'OK' : 'WARN'}</span>
                      </div>
                      <div style={{ fontSize: '0.75rem' }}>{node.detail}</div>
                    </div>
                  ))}
                </div>
              </section>
            </div>
          )}

          {activeTab === 'threat' && (
            <div style={{ color: 'var(--text-secondary)' }}>
              <h3 style={{ color: 'white', marginBottom: '1rem' }}>Cyber Threat Intelligence</h3>
              {scanReport.threat_intel ? (
                <div className="grid grid-2">
                  <div>
                    <h4 style={{ color: 'var(--accent)' }}>Global Threat Summary</h4>
                    <p>{scanReport.threat_intel.global_threat_summary}</p>
                    <h4 style={{ color: 'var(--accent)', marginTop: '1.5rem' }}>Likely Threat Actors</h4>
                    <ul style={{ paddingLeft: '1.5rem', marginTop: '0.5rem' }}>
                      {scanReport.threat_intel.likely_threat_actors.map((actor: string, i: number) => <li key={i}>{actor}</li>)}
                    </ul>
                  </div>
                  <div>
                    <h4 style={{ color: 'var(--accent)' }}>Correlated Techniques</h4>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginTop: '1rem' }}>
                      {scanReport.threat_intel.correlated_techniques.map((tech: any, i: number) => (
                        <div key={i} style={{ background: 'rgba(0,0,0,0.3)', padding: '1rem', borderRadius: '8px' }}>
                          <strong style={{ color: 'white' }}>{tech.mitre_technique_id} - {tech.mitre_technique_name}</strong>
                          <p style={{ fontSize: '0.85rem', marginTop: '0.25rem' }}>{tech.description}</p>
                          {tech.cve_examples?.length > 0 && (
                            <div style={{ marginTop: '0.5rem', display: 'flex', gap: '0.5rem' }}>
                              {tech.cve_examples.map((cve: string) => <span key={cve} className="badge high" style={{ fontSize: '0.7rem' }}>{cve}</span>)}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <p>No threat intel available for this scan (possibly because no critical/high vulnerabilities were found).</p>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── Scan History ── */}
      <div className="card" style={{ marginTop: '2rem' }}>
        <div className="card-header">
          <h2 style={{ fontSize: '1.25rem', margin: 0 }}>Scan History</h2>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button className="btn btn-outline" style={{ padding: '0.4rem 0.75rem', fontSize: '0.8rem' }} onClick={fetchHistory}>
              ↺ Refresh
            </button>
            {scanHistory.length > 0 && (
              <button
                className="btn btn-outline"
                style={{ padding: '0.4rem 0.75rem', fontSize: '0.8rem', borderColor: 'var(--critical)', color: 'var(--critical)' }}
                onClick={handleClearHistory}
              >
                ✕ Clear
              </button>
            )}
          </div>
        </div>
        {scanHistory.length === 0 ? (
          <div style={{ color: 'var(--text-secondary)', padding: '1.5rem', textAlign: 'center', fontSize: '0.875rem' }}>
            No scans recorded yet. Run your first assessment above.
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)', textAlign: 'left' }}>
                  <th style={{ padding: '0.5rem 0.75rem', color: 'var(--text-secondary)', fontWeight: 500 }}>Target</th>
                  <th style={{ padding: '0.5rem 0.75rem', color: 'var(--text-secondary)', fontWeight: 500 }}>Score</th>
                  <th style={{ padding: '0.5rem 0.75rem', color: 'var(--text-secondary)', fontWeight: 500 }}>Grade</th>
                  <th style={{ padding: '0.5rem 0.75rem', color: 'var(--text-secondary)', fontWeight: 500 }}>Findings</th>
                  <th style={{ padding: '0.5rem 0.75rem', color: 'var(--text-secondary)', fontWeight: 500 }}>Categories</th>
                  <th style={{ padding: '0.5rem 0.75rem', color: 'var(--text-secondary)', fontWeight: 500 }}>When</th>
                </tr>
              </thead>
              <tbody>
                {scanHistory.map((h: any) => (
                  <tr
                    key={h.id}
                    style={{ borderBottom: '1px solid rgba(255,255,255,0.04)', cursor: 'pointer' }}
                    onClick={() => setTargetUrl(h.target_url)}
                    title="Click to set as target"
                  >
                    <td style={{ padding: '0.5rem 0.75rem', fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--accent)' }}>{h.target_url}</td>
                    <td style={{ padding: '0.5rem 0.75rem' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        <span style={{ fontWeight: 600, color: h.score >= 70 ? 'var(--success)' : h.score >= 40 ? '#f59e0b' : 'var(--critical)' }}>{h.score}</span>
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>/100</span>
                      </div>
                    </td>
                    <td style={{ padding: '0.5rem 0.75rem' }}>
                      <span className={`badge ${h.grade === 'A' ? 'low' : h.grade === 'B' ? 'low' : h.grade === 'C' ? 'medium' : h.grade === 'D' ? 'high' : 'critical'}`} style={{ fontSize: '0.75rem' }}>{h.grade}</span>
                    </td>
                    <td style={{ padding: '0.5rem 0.75rem' }}>{h.findings_count}</td>
                    <td style={{ padding: '0.5rem 0.75rem', fontSize: '0.75rem', color: 'var(--text-secondary)', maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{h.categories}</td>
                    <td style={{ padding: '0.5rem 0.75rem', fontSize: '0.8rem', color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>{timeAgo(h.timestamp)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
