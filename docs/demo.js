import { h, render } from 'https://esm.sh/preact@10';
import { useState, useEffect, useRef } from 'https://esm.sh/preact@10/hooks';
import { html } from 'https://esm.sh/htm@3/preact';

// ── Sample Data ───────────────────────────────────────────────────────────────

const CONTEXT_MAP = {
  'payment-api':       { criticality: 'high',   public_facing: true,  owner: 'payments-team' },
  'auth-service':      { criticality: 'high',   public_facing: true,  owner: 'identity-team' },
  'order-service':     { criticality: 'medium', public_facing: true,  owner: 'commerce-team' },
  'data-pipeline':     { criticality: 'high',   public_facing: false, owner: 'data-eng' },
  'recommendation-api':{ criticality: 'medium', public_facing: true,  owner: 'ml-platform' },
  'internal-admin':    { criticality: 'low',    public_facing: false, owner: 'platform-eng' },
};

const RAW_FINDINGS = [
  { id:'snyk-001', scanner:'snyk',     service:'payment-api',       severity:'critical', type:'SQL Injection',          environment:'production', internet_exposed:true,  sensitive_data:true,  cve:null,           description:'SQL injection in /checkout allows full authentication bypass and data exfiltration.' },
  { id:'trivy-001',scanner:'trivy',    service:'auth-service',      severity:'high',     type:'Container Vulnerability',environment:'production', internet_exposed:true,  sensitive_data:false, cve:'CVE-2024-1234',description:'OpenSSL heap buffer overflow in base image — remote code execution possible.' },
  { id:'snyk-002', scanner:'snyk',     service:'payment-api',       severity:'high',     type:'XSS',                    environment:'production', internet_exposed:true,  sensitive_data:false, cve:null,           description:'Stored XSS in payment confirmation page. Attacker can exfiltrate session tokens.' },
  { id:'trivy-002',scanner:'trivy',    service:'auth-service',      severity:'medium',   type:'Container Vulnerability',environment:'production', internet_exposed:true,  sensitive_data:false, cve:'CVE-2024-9999',description:'libcurl SSRF vulnerability allows internal network scanning.' },
  { id:'semgrep-001',scanner:'semgrep',service:'data-pipeline',     severity:'medium',   type:'Hardcoded Secret',       environment:'production', internet_exposed:false, sensitive_data:true,  cve:null,           description:'AWS access key hardcoded in pipeline config. Provides read access to S3 buckets.' },
  { id:'grype-001',scanner:'grype',    service:'order-service',     severity:'critical', type:'Dependency Vulnerability',environment:'staging',   internet_exposed:false, sensitive_data:false, cve:'CVE-2024-5678',description:'Critical RCE in log4j dependency. Not yet in production.' },
  { id:'snyk-003', scanner:'snyk',     service:'recommendation-api',severity:'low',      type:'Deprecated Dependency',  environment:'staging',    internet_exposed:false, sensitive_data:false, cve:null,           description:'Using deprecated version of requests library with known MITM vulnerability.' },
  { id:'chk-001',  scanner:'checkov',  service:'internal-admin',    severity:'low',      type:'Misconfigured S3',       environment:'development',internet_exposed:false, sensitive_data:false, cve:null,           description:'S3 bucket ACL allows unintended public read. Internal tooling only.' },
];

const SEVERITY_PTS  = { critical:30, high:20, medium:10, low:2 };
const CRIT_PTS      = { high:20, medium:10, low:0 };
const SCANNER_COLOR = { snyk:'#A855F7', trivy:'#3B82F6', semgrep:'#F97316', grype:'#EF4444', checkov:'#EAB308' };

function scoreFinding(f) {
  const ctx = CONTEXT_MAP[f.service] || {};
  let s = SEVERITY_PTS[f.severity] || 0;
  if (f.environment === 'production') s += 40;
  if (f.internet_exposed) s += 30;
  if (f.sensitive_data)   s += 20;
  s += CRIT_PTS[ctx.criticality] || 0;
  if (ctx.public_facing && !f.internet_exposed) s += 15;
  return s;
}

function correlate(findings) {
  const notes = {};
  findings.forEach(f => { notes[f.id] = []; });

  // Same-service clusters
  const byService = {};
  findings.forEach(f => { (byService[f.service] = byService[f.service]||[]).push(f); });
  Object.values(byService).forEach(group => {
    if (group.length > 1)
      group.forEach(f => notes[f.id].push(`${group.length} findings in ${f.service} — assess combined blast radius`));
  });

  // CVE reuse
  const byCVE = {};
  findings.filter(f=>f.cve).forEach(f => { (byCVE[f.cve]=byCVE[f.cve]||[]).push(f); });
  Object.entries(byCVE).forEach(([cve, group]) => {
    if (group.length > 1)
      group.forEach(f => notes[f.id].push(`${cve} appears in ${group.map(x=>x.service).join(' & ')} — single remediation closes both`));
  });

  // Exposed + sensitive
  findings.filter(f => f.internet_exposed && f.sensitive_data)
    .forEach(f => notes[f.id].push('Internet-exposed service handles sensitive data — elevated breach risk'));

  // High-score cluster
  const highScore = findings.filter(f => (f._score||0) >= 80);
  if (highScore.length >= 3)
    highScore.forEach(f => notes[f.id].push(`High-score cluster detected in production — ${highScore.length} findings above score 80`));

  return notes;
}

const ENRICHMENT = {
  'snyk-001':  { exploitability:'Directly exploitable from the internet. No authentication required. CVSS 9.8. PoC exploit code is publicly available.', fix:'Parameterize all SQL queries in /checkout using prepared statements. Patch within the hour — treat as incident.', urgency:'now',       adjusted_priority:'high',   reason:null, combined_risk:'Combined with snyk-002 XSS, attacker has full account takeover + data exfil chain on payment-api.' },
  'trivy-001': { exploitability:'Remote code execution via malformed TLS handshake. Exploitable pre-authentication on all HTTPS endpoints.', fix:'Rebuild auth-service Docker image with OpenSSL ≥ 3.0.9. Update base image to python:3.12-slim and redeploy.', urgency:'now',       adjusted_priority:'high',   reason:null, combined_risk:'auth-service has 2 CVEs (CVE-2024-1234 + CVE-2024-9999). Patch both in same deployment.' },
  'snyk-002':  { exploitability:'Stored XSS reachable by any authenticated user. Session token theft enables account takeover.', fix:'Sanitize all user-supplied input in payment confirmation template using DOMPurify. Add Content-Security-Policy header.', urgency:'today',      adjusted_priority:'high',   reason:'Severity adjusted up — payment-api handles financial data, XSS = session theft = fraud.', combined_risk:null },
  'trivy-002': { exploitability:'SSRF allows unauthenticated scanning of internal services via crafted URLs. Not directly exploitable for RCE.', fix:'Upgrade libcurl to 8.6.0+. Add egress firewall rules to block auth-service from reaching internal metadata endpoints.', urgency:'today',      adjusted_priority:'medium', reason:'Score high due to production + internet exposure, but SSRF requires attacker to have request control.', combined_risk:null },
  'semgrep-001':{ exploitability:'Hardcoded AWS key provides S3 read access. Key may be in git history if committed. Blast radius depends on bucket contents.', fix:'Rotate the exposed AWS key immediately. Replace with IAM role + IRSA. Scan git history with trufflehog.', urgency:'today',      adjusted_priority:'high',   reason:'Adjusted up — data-pipeline accesses sensitive S3 buckets. Key rotation is a 10-minute fix.', combined_risk:null },
};

// ── Sub-components ────────────────────────────────────────────────────────────

const SEV_STYLE = {
  critical:{ color:'#EF4444', bg:'rgba(239,68,68,0.12)', border:'rgba(239,68,68,0.3)' },
  high:    { color:'#F97316', bg:'rgba(249,115,22,0.12)', border:'rgba(249,115,22,0.3)' },
  medium:  { color:'#EAB308', bg:'rgba(234,179,8,0.12)',  border:'rgba(234,179,8,0.3)' },
  low:     { color:'#64748B', bg:'rgba(100,116,139,0.1)', border:'rgba(100,116,139,0.2)' },
};
const URG_STYLE = {
  now:      { color:'#EF4444', bg:'rgba(239,68,68,0.15)', label:'🔴 NOW' },
  today:    { color:'#F97316', bg:'rgba(249,115,22,0.15)', label:'🟠 TODAY' },
  'this-week':{ color:'#EAB308', bg:'rgba(234,179,8,0.15)',  label:'🟡 THIS WEEK' },
};

function Badge({ text, color, bg, border }) {
  return html`
    <span style=${{ display:'inline-block', padding:'2px 9px', borderRadius:'999px', fontSize:'0.72rem', fontWeight:600, fontFamily:"'Fira Code',monospace", color, background:bg, border:`1px solid ${border||color+'44'}`, letterSpacing:'0.03em' }}>
      ${text}
    </span>`;
}

function ScoreBar({ score }) {
  const pct = Math.min(score / 140, 1);
  const color = pct > 0.78 ? '#EF4444' : pct > 0.57 ? '#F97316' : pct > 0.36 ? '#EAB308' : '#22C55E';
  return html`
    <div style=${{ display:'flex', alignItems:'center', gap:10 }}>
      <div style=${{ flex:1, height:6, background:'#1E293B', borderRadius:3, overflow:'hidden' }}>
        <div style=${{ width:`${pct*100}%`, height:'100%', background:color, borderRadius:3, transition:'width 0.8s ease' }}></div>
      </div>
      <span style=${{ fontFamily:"'Fira Code',monospace", fontSize:'0.85rem', fontWeight:600, color, minWidth:32, textAlign:'right' }}>${score}</span>
    </div>`;
}

function FindingCard({ rank, finding, enrichment, corrNotes, visible }) {
  const [open, setOpen] = useState(false);
  const sev = SEV_STYLE[finding.severity] || SEV_STYLE.low;
  const urg = enrichment ? URG_STYLE[enrichment.urgency] : null;
  const ctx = CONTEXT_MAP[finding.service] || {};

  return html`
    <div style=${{
      background:'#0F172A', border:`1px solid ${open ? '#22C55E44' : '#334155'}`,
      borderRadius:12, overflow:'hidden', marginBottom:12,
      opacity: visible ? 1 : 0, transform: visible ? 'translateY(0)' : 'translateY(16px)',
      transition:`opacity 0.4s ease ${rank*0.08}s, transform 0.4s ease ${rank*0.08}s, border-color 0.2s`
    }}>
      <!-- Header (always visible) -->
      <div onClick=${()=>setOpen(!open)} style=${{ padding:'16px 20px', cursor:'pointer', display:'flex', alignItems:'center', gap:12, flexWrap:'wrap' }}>
        <span style=${{ fontFamily:"'Fira Code',monospace", fontSize:'1rem', fontWeight:700, color:'#22C55E', minWidth:28 }}>#${rank}</span>
        <div style=${{ flex:1 }}>
          <div style=${{ display:'flex', alignItems:'center', gap:8, flexWrap:'wrap', marginBottom:4 }}>
            <span style=${{ fontWeight:600, fontSize:'0.95rem', color:'#E2E8F0' }}>${finding.service}</span>
            <${Badge} text=${finding.type} color="#94A3B8" bg="rgba(148,163,184,0.08)" />
            <${Badge} text=${finding.severity} color=${sev.color} bg=${sev.bg} border=${sev.border} />
            <${Badge} text=${finding.environment} color=${finding.environment==='production'?'#EF4444':'#64748B'} bg=${finding.environment==='production'?'rgba(239,68,68,0.1)':'rgba(100,116,139,0.08)'} />
            ${finding.internet_exposed && html`<${Badge} text="internet-exposed" color="#F97316" bg="rgba(249,115,22,0.1)" />`}
            ${finding.sensitive_data   && html`<${Badge} text="sensitive-data" color="#A855F7" bg="rgba(168,85,247,0.1)" />`}
            ${urg && html`<${Badge} text=${urg.label} color=${urg.color} bg=${urg.bg} />`}
          </div>
          <${ScoreBar} score=${finding._score} />
        </div>
        <span style=${{ color:'#475569', fontSize:'1rem', transition:'transform 0.2s', transform: open?'rotate(180deg)':'rotate(0deg)' }}>▾</span>
      </div>

      <!-- Expanded -->
      ${open && html`
        <div style=${{ borderTop:'1px solid #1E293B', padding:'16px 20px', display:'grid', gap:16 }}>
          <!-- Description -->
          <div>
            <div style=${{ fontSize:'0.72rem', fontWeight:600, color:'#475569', textTransform:'uppercase', letterSpacing:'0.08em', marginBottom:6 }}>Description</div>
            <div style=${{ fontSize:'0.875rem', color:'#94A3B8', lineHeight:1.6 }}>${finding.description}</div>
          </div>

          <!-- Meta row -->
          <div style=${{ display:'flex', gap:20, flexWrap:'wrap' }}>
            ${finding.cve && html`
              <div>
                <div style=${{ fontSize:'0.72rem', color:'#475569', fontWeight:600, textTransform:'uppercase', letterSpacing:'0.08em', marginBottom:4 }}>CVE</div>
                <span style=${{ fontFamily:"'Fira Code',monospace", fontSize:'0.8rem', color:'#EF4444', background:'rgba(239,68,68,0.1)', padding:'2px 8px', borderRadius:4 }}>${finding.cve}</span>
              </div>`}
            ${ctx.owner && html`
              <div>
                <div style=${{ fontSize:'0.72rem', color:'#475569', fontWeight:600, textTransform:'uppercase', letterSpacing:'0.08em', marginBottom:4 }}>Owner</div>
                <span style=${{ fontSize:'0.85rem', color:'#E2E8F0' }}>${ctx.owner}</span>
              </div>`}
            ${ctx.criticality && html`
              <div>
                <div style=${{ fontSize:'0.72rem', color:'#475569', fontWeight:600, textTransform:'uppercase', letterSpacing:'0.08em', marginBottom:4 }}>Business Criticality</div>
                <${Badge} text=${ctx.criticality} color=${ctx.criticality==='high'?'#EF4444':ctx.criticality==='medium'?'#EAB308':'#64748B'} bg="rgba(0,0,0,0.2)" />
              </div>`}
            <div>
              <div style=${{ fontSize:'0.72rem', color:'#475569', fontWeight:600, textTransform:'uppercase', letterSpacing:'0.08em', marginBottom:4 }}>Scanner</div>
              <span style=${{ fontFamily:"'Fira Code',monospace", fontSize:'0.8rem', color: SCANNER_COLOR[finding.scanner]||'#94A3B8' }}>${finding.scanner}</span>
            </div>
          </div>

          <!-- Correlation -->
          ${corrNotes && corrNotes.length > 0 && html`
            <div style=${{ background:'rgba(234,179,8,0.06)', border:'1px solid rgba(234,179,8,0.2)', borderRadius:8, padding:'12px 14px' }}>
              <div style=${{ fontSize:'0.72rem', fontWeight:600, color:'#EAB308', textTransform:'uppercase', letterSpacing:'0.08em', marginBottom:6 }}>⚡ Correlation Detected</div>
              ${corrNotes.map(n => html`<div style=${{ fontSize:'0.8rem', color:'#94A3B8', lineHeight:1.6, marginBottom:3 }}>• ${n}</div>`)}
            </div>`}

          <!-- LLM Enrichment -->
          ${enrichment && html`
            <div style=${{ background:'rgba(34,197,94,0.04)', border:'1px solid rgba(34,197,94,0.2)', borderRadius:8, padding:'14px 16px', display:'grid', gap:12 }}>
              <div style=${{ fontSize:'0.72rem', fontWeight:600, color:'#22C55E', textTransform:'uppercase', letterSpacing:'0.08em' }}>🤖 LLM Analysis</div>
              <div>
                <div style=${{ fontSize:'0.72rem', color:'#475569', fontWeight:600, textTransform:'uppercase', letterSpacing:'0.08em', marginBottom:4 }}>Exploitability</div>
                <div style=${{ fontSize:'0.84rem', color:'#CBD5E1', lineHeight:1.6 }}>${enrichment.exploitability}</div>
              </div>
              <div>
                <div style=${{ fontSize:'0.72rem', color:'#475569', fontWeight:600, textTransform:'uppercase', letterSpacing:'0.08em', marginBottom:4 }}>Recommended Fix</div>
                <div style=${{ fontSize:'0.84rem', color:'#CBD5E1', lineHeight:1.6 }}>${enrichment.fix}</div>
              </div>
              ${enrichment.reason && html`
                <div>
                  <div style=${{ fontSize:'0.72rem', color:'#475569', fontWeight:600, textTransform:'uppercase', letterSpacing:'0.08em', marginBottom:4 }}>Priority Adjustment</div>
                  <div style=${{ fontSize:'0.84rem', color:'#94A3B8', lineHeight:1.6 }}>${enrichment.reason}</div>
                </div>`}
              ${enrichment.combined_risk && html`
                <div style=${{ background:'rgba(239,68,68,0.08)', borderRadius:6, padding:'10px 12px' }}>
                  <div style=${{ fontSize:'0.72rem', color:'#EF4444', fontWeight:600, textTransform:'uppercase', letterSpacing:'0.08em', marginBottom:4 }}>Combined Risk</div>
                  <div style=${{ fontSize:'0.84rem', color:'#94A3B8', lineHeight:1.6 }}>${enrichment.combined_risk}</div>
                </div>`}
            </div>`}
        </div>`}
    </div>`;
}

// ── Pipeline Step indicator ───────────────────────────────────────────────────

const STAGES = [
  { id:'ingest',    label:'Ingest',    icon:'⬇', desc:'Reading scanner findings' },
  { id:'normalize', label:'Normalize', icon:'🔄', desc:'Mapping severity / env aliases' },
  { id:'score',     label:'Score',     icon:'⚡', desc:'Running deterministic rule engine' },
  { id:'correlate', label:'Correlate', icon:'🔗', desc:'Detecting cross-finding clusters' },
  { id:'enrich',    label:'LLM Enrich',icon:'🤖', desc:'Analyzing top findings with AI' },
  { id:'done',      label:'Done',      icon:'✓',  desc:'Ranked action list ready' },
];

function Pipeline({ stage }) {
  const activeIdx = STAGES.findIndex(s => s.id === stage);
  return html`
    <div style=${{ display:'flex', alignItems:'center', gap:0, marginBottom:28, overflowX:'auto', paddingBottom:4 }}>
      ${STAGES.map((s, i) => {
        const done    = i < activeIdx;
        const active  = i === activeIdx;
        const pending = i > activeIdx;
        const color   = done ? '#22C55E' : active ? '#F97316' : '#334155';
        const textCol = done ? '#22C55E' : active ? '#F97316' : '#475569';
        return html`
          <div key=${s.id} style=${{ display:'flex', alignItems:'center' }}>
            <div style=${{ display:'flex', flexDirection:'column', alignItems:'center', minWidth:80 }}>
              <div style=${{
                width:36, height:36, borderRadius:'50%', border:`2px solid ${color}`,
                background: done ? '#22C55E22' : active ? '#F9731622' : 'transparent',
                display:'flex', alignItems:'center', justifyContent:'center',
                fontSize:'1rem', transition:'all 0.3s',
                boxShadow: active ? `0 0 12px ${color}66` : 'none'
              }}>
                ${done ? '✓' : s.icon}
              </div>
              <div style=${{ fontSize:'0.68rem', fontWeight:600, color:textCol, marginTop:4, textAlign:'center', lineHeight:1.2 }}>${s.label}</div>
              ${active && html`<div style=${{ fontSize:'0.6rem', color:'#64748B', textAlign:'center', maxWidth:72 }}>${s.desc}</div>`}
            </div>
            ${i < STAGES.length-1 && html`<div style=${{ width:24, height:2, background: i < activeIdx ? '#22C55E44' : '#1E293B', flexShrink:0, marginBottom:16 }}></div>`}
          </div>`;
      })}
    </div>`;
}

// ── Main Demo App ─────────────────────────────────────────────────────────────

function Demo() {
  const [phase, setPhase]         = useState('idle');   // idle | running | done
  const [stage, setStage]         = useState('');
  const [scored, setScored]       = useState([]);
  const [corrMap, setCorrMap]     = useState({});
  const [enrichMap, setEnrichMap] = useState({});
  const [log, setLog]             = useState([]);
  const [cardsVisible, setCardsVisible] = useState(false);
  const logRef = useRef(null);

  function addLog(line) {
    setLog(prev => [...prev, { id: Date.now() + Math.random(), text: line }]);
  }

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [log]);

  async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

  async function runTriage() {
    setPhase('running');
    setLog([]);
    setScored([]);
    setCorrMap({});
    setEnrichMap({});
    setCardsVisible(false);

    // Stage 1: Ingest
    setStage('ingest');
    addLog('→ Receiving findings batch from 5 scanners…');
    await sleep(600);
    for (const f of RAW_FINDINGS) {
      addLog(`  [${f.scanner.padEnd(8)}] ${f.id.padEnd(12)} severity=${f.severity.padEnd(8)} service=${f.service}`);
      await sleep(90);
    }
    addLog(`✓ ${RAW_FINDINGS.length} findings ingested`);
    await sleep(400);

    // Stage 2: Normalize
    setStage('normalize');
    addLog('\n→ Normalizing fields…');
    await sleep(400);
    addLog("  'CRITICAL' → 'critical'  |  'prod' → 'production'");
    await sleep(250);
    addLog("  String booleans → bool  |  Missing IDs → auto-generated");
    await sleep(300);
    addLog('✓ Normalization complete');
    await sleep(400);

    // Stage 3: Score
    setStage('score');
    addLog('\n→ Running deterministic rule engine…');
    await sleep(400);
    const scoredFindings = RAW_FINDINGS.map(f => ({ ...f, _score: scoreFindings(f) }));

    for (const f of scoredFindings) {
      const breakdown = buildBreakdown(f);
      addLog(`  ${f.id.padEnd(14)} score=${String(f._score).padStart(3)}  [${breakdown}]`);
      await sleep(110);
    }
    addLog('✓ Scoring complete');
    await sleep(400);

    // Stage 4: Correlate
    setStage('correlate');
    addLog('\n→ Running correlation rules…');
    await sleep(500);
    const cm = correlate(scoredFindings);
    const correlated = Object.values(cm).filter(v => v.length > 0).length;
    addLog(`  Same-service clustering    ✓`);
    await sleep(200);
    addLog(`  CVE reuse detection        ✓`);
    await sleep(200);
    addLog(`  Exposure + sensitive data  ✓`);
    await sleep(200);
    addLog(`  High-score cluster check   ✓`);
    await sleep(200);
    addLog(`✓ ${correlated} findings have correlation notes`);
    setCorrMap(cm);
    await sleep(400);

    // Stage 5: Enrich
    setStage('enrich');
    const sorted = [...scoredFindings].sort((a,b) => b._score - a._score);
    const top5 = sorted.slice(0,5);
    addLog('\n→ Sending top 5 to LLM provider (OpenRouter)…');
    await sleep(600);
    addLog('  Checking Redis cache… MISS — calling API');
    await sleep(500);

    const em = {};
    for (const f of top5) {
      addLog(`  Analyzing ${f.id}…`);
      await sleep(350);
      if (ENRICHMENT[f.id]) {
        em[f.id] = ENRICHMENT[f.id];
        addLog(`  ✓ ${f.id}  urgency=${ENRICHMENT[f.id].urgency}`);
      }
      await sleep(120);
    }
    addLog('  Caching results to Redis (TTL 24h)');
    await sleep(300);
    addLog('✓ LLM enrichment complete');
    setEnrichMap(em);
    await sleep(400);

    // Done
    setStage('done');
    addLog('\n✅ Triage complete — top 5 risks ranked below');
    setScored(sorted);
    await sleep(300);
    setPhase('done');
    await sleep(150);
    setCardsVisible(true);
  }

  function scoreFindings(f) {
    const ctx = CONTEXT_MAP[f.service] || {};
    let s = SEVERITY_PTS[f.severity] || 0;
    if (f.environment === 'production') s += 40;
    if (f.internet_exposed) s += 30;
    if (f.sensitive_data)   s += 20;
    s += CRIT_PTS[ctx.criticality] || 0;
    if (ctx.public_facing && !f.internet_exposed) s += 15;
    return s;
  }

  function buildBreakdown(f) {
    const ctx = CONTEXT_MAP[f.service] || {};
    const parts = [];
    if (SEVERITY_PTS[f.severity]) parts.push(`${f.severity}+${SEVERITY_PTS[f.severity]}`);
    if (f.environment==='production') parts.push('prod+40');
    if (f.internet_exposed) parts.push('exposed+30');
    if (f.sensitive_data)   parts.push('sensitive+20');
    if (ctx.criticality==='high') parts.push('crit+20');
    else if (ctx.criticality==='medium') parts.push('crit+10');
    if (ctx.public_facing && !f.internet_exposed) parts.push('public+15');
    return parts.join(' ');
  }

  const top5 = scored.slice(0,5);

  return html`
    <div style=${{ fontFamily:"'Inter',system-ui,sans-serif", color:'#E2E8F0' }}>

      <!-- Findings Input Panel -->
      ${phase === 'idle' && html`
        <div style=${{ marginBottom:28 }}>
          <div style=${{ fontSize:'0.78rem', fontWeight:600, color:'#475569', textTransform:'uppercase', letterSpacing:'0.08em', marginBottom:12 }}>
            Sample Findings — 8 findings from 5 scanners
          </div>
          <div style=${{ background:'#0F172A', border:'1px solid #1E293B', borderRadius:10, overflow:'hidden' }}>
            <table style=${{ width:'100%', borderCollapse:'collapse', fontSize:'0.8rem' }}>
              <thead>
                <tr style=${{ background:'#1E293B' }}>
                  ${['Scanner','ID','Service','Severity','Environment','Flags'].map(h => html`
                    <th key=${h} style=${{ padding:'8px 14px', textAlign:'left', color:'#475569', fontWeight:600, fontSize:'0.72rem', textTransform:'uppercase', letterSpacing:'0.06em', whiteSpace:'nowrap' }}>${h}</th>`)}
                </tr>
              </thead>
              <tbody>
                ${RAW_FINDINGS.map((f,i) => html`
                  <tr key=${f.id} style=${{ borderTop:'1px solid #1E293B22', background: i%2===0?'transparent':'rgba(30,41,59,0.3)' }}>
                    <td style=${{ padding:'7px 14px', fontFamily:"'Fira Code',monospace", color: SCANNER_COLOR[f.scanner]||'#94A3B8', fontSize:'0.75rem' }}>${f.scanner}</td>
                    <td style=${{ padding:'7px 14px', fontFamily:"'Fira Code',monospace", color:'#64748B', fontSize:'0.75rem' }}>${f.id}</td>
                    <td style=${{ padding:'7px 14px', fontWeight:500, color:'#CBD5E1' }}>${f.service}</td>
                    <td style=${{ padding:'7px 14px' }}>
                      <span style=${{ color: SEV_STYLE[f.severity]?.color, fontFamily:"'Fira Code',monospace", fontSize:'0.75rem', fontWeight:600 }}>${f.severity}</span>
                    </td>
                    <td style=${{ padding:'7px 14px', color:'#64748B', fontSize:'0.8rem' }}>${f.environment}</td>
                    <td style=${{ padding:'7px 14px', display:'flex', gap:4, flexWrap:'wrap' }}>
                      ${f.internet_exposed && html`<span style=${{ fontSize:'0.65rem', color:'#F97316', background:'rgba(249,115,22,0.1)', padding:'1px 6px', borderRadius:999 }}>exposed</span>`}
                      ${f.sensitive_data   && html`<span style=${{ fontSize:'0.65rem', color:'#A855F7', background:'rgba(168,85,247,0.1)', padding:'1px 6px', borderRadius:999 }}>sensitive</span>`}
                      ${f.cve             && html`<span style=${{ fontSize:'0.65rem', color:'#EF4444', background:'rgba(239,68,68,0.1)',  padding:'1px 6px', borderRadius:999 }}>CVE</span>`}
                    </td>
                  </tr>`)}
              </tbody>
            </table>
          </div>
        </div>`}

      <!-- Run button -->
      ${phase === 'idle' && html`
        <div style=${{ textAlign:'center', marginBottom:8 }}>
          <button onClick=${runTriage} style=${{
            background:'#22C55E', color:'#020617', fontWeight:700, fontSize:'1rem',
            padding:'14px 40px', borderRadius:8, border:'none', cursor:'pointer',
            fontFamily:"'Inter',sans-serif", letterSpacing:'0.02em',
            boxShadow:'0 0 24px rgba(34,197,94,0.3)', transition:'opacity 0.15s'
          }}
          onMouseOver=${e=>e.target.style.opacity='0.88'}
          onMouseOut=${e=>e.target.style.opacity='1'}>
            ▶  Run TRTE Triage
          </button>
          <div style=${{ fontSize:'0.78rem', color:'#475569', marginTop:8 }}>Simulates the full pipeline: ingest → score → correlate → LLM enrich</div>
        </div>`}

      <!-- Pipeline + log -->
      ${phase !== 'idle' && html`
        <div style=${{ marginBottom:24 }}>
          <${Pipeline} stage=${stage} />
          <div ref=${logRef} style=${{
            background:'#020617', border:'1px solid #1E293B', borderRadius:8,
            padding:'14px 16px', height:200, overflowY:'auto',
            fontFamily:"'Fira Code',monospace", fontSize:'0.76rem', lineHeight:1.8, color:'#64748B'
          }}>
            ${log.map(l => html`<div key=${l.id} style=${{ color: l.text.startsWith('✓')||l.text.startsWith('✅') ? '#22C55E' : l.text.startsWith('→') ? '#94A3B8' : '#64748B' }}>${l.text}</div>`)}
            ${phase==='running' && html`<span style=${{ color:'#22C55E' }}>▋</span>`}
          </div>
        </div>`}

      <!-- Results -->
      ${phase === 'done' && html`
        <div>
          <div style=${{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:16 }}>
            <div style=${{ fontSize:'0.78rem', fontWeight:600, color:'#475569', textTransform:'uppercase', letterSpacing:'0.08em' }}>
              Top 5 Risks — click any card to expand
            </div>
            <button onClick=${()=>{ setPhase('idle'); setStage(''); setScored([]); setLog([]); }} style=${{
              background:'transparent', border:'1px solid #334155', color:'#94A3B8',
              padding:'5px 14px', borderRadius:6, cursor:'pointer', fontSize:'0.8rem', fontFamily:"'Inter',sans-serif"
            }}>Reset</button>
          </div>
          ${top5.map((f, i) => html`
            <${FindingCard}
              key=${f.id}
              rank=${i+1}
              finding=${f}
              enrichment=${enrichMap[f.id] || null}
              corrNotes=${corrMap[f.id] || []}
              visible=${cardsVisible}
            />`)}
        </div>`}
    </div>`;
}

// ── Mount ─────────────────────────────────────────────────────────────────────
render(html`<${Demo} />`, document.getElementById('demo-root'));
