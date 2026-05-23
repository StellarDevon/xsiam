import React, { useState, useRef, useEffect, useCallback } from 'react';

// ── Types ──────────────────────────────────────────────────────────────────────

type AgentKey = 'threatIntel' | 'caseInv' | 'autoEng';

interface 对话Message {
  role: 'user' | 'agent';
  text?: string;
  html?: string;
}

interface ThinkingMsg {
  type: 'thinking';
  text: string;
}
interface ApprovalMsg {
  type: 'approval';
  text: string;
}
interface ResultMsg {
  type: 'result';
  html: string;
}
type FlowStep = ThinkingMsg | ApprovalMsg | ResultMsg;

interface AgentConfig {
  label: string;
  greeting: string;
  suggestions: string[];
}

// ── Static config ──────────────────────────────────────────────────────────────

const AGENT_CONFIG: Record<AgentKey, AgentConfig> = {
  threatIntel: {
    label: 'Threat Intel',
    greeting: 'Good afternoon Dan. How can I help you today?',
    suggestions: [
      'Machines Connected with a Specific Domain…',
      'Users Connected with Specific Domain in…',
      'Query File Activities Related to Specific Hash…',
      'Process Executions of Specific Hash in Last 7D…',
    ],
  },
  caseInv: {
    label: 'Case Investigation',
    greeting: 'Good afternoon. Ready to investigate. What case should I look at?',
    suggestions: [
      'Check indicators, enrich them and highlight key findings',
      'Summarize the current case',
      'Show MITRE ATT&CK coverage for this case',
      'List all impacted assets',
    ],
  },
  autoEng: {
    label: 'Automation Engineer',
    greeting: "Good evening Ron. I'm viewing the current script context. What would you like to automate?",
    suggestions: [
      'Generate script to change indicator verdict',
      'Add doc notes and debug messages to script',
      'Create playbook task for indicator enrichment',
      'Review current automation for improvements',
    ],
  },
};

const THREAT_INTEL_RESULT_HTML = `
<div style="font-size:10px;font-weight:700;color:#6366f1;letter-spacing:.06em;margin-bottom:5px;display:flex;align-items:center;gap:5px">📊 FILE IOC ANALYSIS</div>
<table style="width:100%;border-collapse:collapse;font-size:11px;margin-top:6px">
  <thead>
    <tr>
      <th style="background:#1e2233;color:#64748b;padding:5px 8px;text-align:left;font-weight:600;letter-spacing:.04em;border-bottom:1px solid #2d3452">SHA256</th>
      <th style="background:#1e2233;color:#64748b;padding:5px 8px;text-align:left;font-weight:600;letter-spacing:.04em;border-bottom:1px solid #2d3452">Verdict</th>
      <th style="background:#1e2233;color:#64748b;padding:5px 8px;text-align:left;font-weight:600;letter-spacing:.04em;border-bottom:1px solid #2d3452">Score</th>
      <th style="background:#1e2233;color:#64748b;padding:5px 8px;text-align:left;font-weight:600;letter-spacing:.04em;border-bottom:1px solid #2d3452">TIM</th>
      <th style="background:#1e2233;color:#64748b;padding:5px 8px;text-align:left;font-weight:600;letter-spacing:.04em;border-bottom:1px solid #2d3452">VT</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#cbd5e1;font-size:10px;font-family:monospace">3f4a1b…e92c</td>
      <td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#ef4444;font-weight:600">Malicious</td>
      <td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#cbd5e1">3</td>
      <td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#cbd5e1">✓</td>
      <td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#cbd5e1">62/72</td>
    </tr>
    <tr>
      <td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#cbd5e1;font-size:10px;font-family:monospace">a7d83e…1f0b</td>
      <td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#ef4444;font-weight:600">Malicious</td>
      <td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#cbd5e1">3</td>
      <td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#cbd5e1">✓</td>
      <td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#cbd5e1">55/72</td>
    </tr>
    <tr>
      <td style="padding:5px 8px;color:#cbd5e1;font-size:10px;font-family:monospace">c1b925…77da</td>
      <td style="padding:5px 8px;color:#ef4444;font-weight:600">Malicious</td>
      <td style="padding:5px 8px;color:#cbd5e1">3</td>
      <td style="padding:5px 8px;color:#cbd5e1">✓</td>
      <td style="padding:5px 8px;color:#cbd5e1">49/72</td>
    </tr>
  </tbody>
</table>
<div style="margin-top:8px;font-size:11px;color:#94a3b8">All 3 file IOCs confirmed malicious. No environment sightings detected. Hashes added to block list.</div>
`;

const CASE_INV_RESULT_HTML = `
<div style="font-size:10px;font-weight:700;color:#6366f1;letter-spacing:.06em;margin-bottom:5px;display:flex;align-items:center;gap:5px">🔍 ENRICHED INDICATORS</div>
<table style="width:100%;border-collapse:collapse;font-size:11px;margin-top:6px">
  <thead>
    <tr>
      <th style="background:#1e2233;color:#64748b;padding:5px 8px;text-align:left;font-weight:600;letter-spacing:.04em;border-bottom:1px solid #2d3452">类型</th>
      <th style="background:#1e2233;color:#64748b;padding:5px 8px;text-align:left;font-weight:600;letter-spacing:.04em;border-bottom:1px solid #2d3452">Value</th>
      <th style="background:#1e2233;color:#64748b;padding:5px 8px;text-align:left;font-weight:600;letter-spacing:.04em;border-bottom:1px solid #2d3452">Verdict</th>
      <th style="background:#1e2233;color:#64748b;padding:5px 8px;text-align:left;font-weight:600;letter-spacing:.04em;border-bottom:1px solid #2d3452">Score</th>
    </tr>
  </thead>
  <tbody>
    <tr><td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#cbd5e1">HASH</td><td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#cbd5e1;font-family:monospace;font-size:10px">a3f1b…</td><td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#ef4444;font-weight:600">Malicious</td><td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#cbd5e1">3</td></tr>
    <tr><td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#cbd5e1">HASH</td><td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#cbd5e1;font-family:monospace;font-size:10px">9e2cd…</td><td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#ef4444;font-weight:600">Malicious</td><td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#cbd5e1">3</td></tr>
    <tr><td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#cbd5e1">HASH</td><td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#cbd5e1;font-family:monospace;font-size:10px">f7a83…</td><td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#ef4444;font-weight:600">Malicious</td><td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#cbd5e1">3</td></tr>
    <tr><td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#cbd5e1">DOMAIN</td><td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#cbd5e1;font-size:10px">404.008php.com</td><td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#ef4444;font-weight:600">Malicious</td><td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#cbd5e1">3</td></tr>
    <tr><td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#cbd5e1">DOMAIN</td><td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#cbd5e1;font-size:10px">bet365-vn.com</td><td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#ef4444;font-weight:600">Malicious</td><td style="padding:5px 8px;border-bottom:1px solid #1a1f30;color:#cbd5e1">3</td></tr>
    <tr><td style="padding:5px 8px;color:#cbd5e1">DOMAIN</td><td style="padding:5px 8px;color:#cbd5e1;font-size:10px">govagency.vn</td><td style="padding:5px 8px;color:#22c55e;font-weight:600">Benign</td><td style="padding:5px 8px;color:#cbd5e1">0</td></tr>
  </tbody>
</table>
<div style="margin-top:8px;font-size:11px;color:#f87171"><strong>Key finding:</strong> 5 of 6 indicators malicious. C2 domains actively communicating. Recommend immediate containment of web-prod-03.</div>
`;

const AUTO_ENG_RESULT_HTML = `
<div style="font-size:10px;font-weight:700;color:#6366f1;letter-spacing:.06em;margin-bottom:5px;display:flex;align-items:center;gap:5px">⚙ GENERATED SCRIPT — ChangeIndicatorVerdict</div>
<pre style="background:#0d1019;border:1px solid #1e2233;border-radius:6px;padding:10px;font-size:10.5px;color:#86efac;overflow-x:auto;margin-top:6px;line-height:1.5">
<span style="color:#64748b">"""
Changes the verdict of a given indicator based on user input.
Args:
    indicator_id: The ID of the indicator to update
    new_verdict: The new verdict to set (malicious/benign/unknown)
"""</span>
import demistomock as demisto
from CommonServerPython import *

def change_verdict(indicator_id: str, new_verdict: str) -&gt; dict:
    demisto.debug(f"Changing verdict for {'{'}indicator_id{'}'} → {'{'}new_verdict{'}'}")
    result = demisto.executeCommand("setIndicator", {
        "id": indicator_id,
        "verdict": new_verdict
    })
    demisto.debug(f"Result: {'{'}result{'}'}")
    return result

args = demisto.args()
res = change_verdict(args["indicator_id"], args["new_verdict"])
demisto.results(res)
</pre>
<div style="font-size:11px;color:#94a3b8;margin-top:6px">Script #1 generated — 55 lines, 2 Arguments, 1 Output. Docstring and debug messages included.</div>
`;

const AGENT_FLOWS: Record<AgentKey, FlowStep[]> = {
  threatIntel: [
    { type: 'thinking', text: 'Threat Intel is thinking' },
    { type: 'approval', text: "I'll fetch IOCs from the Unit 42 blog, enrich them via TIM and VirusTotal, then check for environment sightings. Shall I proceed?" },
    { type: 'result', html: THREAT_INTEL_RESULT_HTML },
  ],
  caseInv: [
    { type: 'thinking', text: 'Case Investigation is thinking' },
    { type: 'approval', text: "I'll check all indicators in case #2624, enrich them via WildFire, TIM, and VirusTotal, then highlight key findings. Continue?" },
    { type: 'result', html: CASE_INV_RESULT_HTML },
  ],
  autoEng: [
    { type: 'thinking', text: 'Automation Engineer is thinking' },
    { type: 'result', html: AUTO_ENG_RESULT_HTML },
  ],
};

// ── Keyframe injection ─────────────────────────────────────────────────────────

const KEYFRAMES = `
@keyframes agentix-pulse-dot {
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.4; transform: scale(0.8); }
}
@keyframes agentix-blink {
  0%, 80%, 100% { opacity: 0; }
  40% { opacity: 1; }
}
`;

// ── Sub-components ─────────────────────────────────────────────────────────────

function ThinkingBubble({ text }: { text: string }) {
  return (
    <div style={{ alignSelf: 'flex-start', display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: '#64748b', fontStyle: 'italic' }}>
      <span>{text}</span>
      <span>
        <span style={{ animation: 'agentix-blink 1.4s infinite', opacity: 0 }}>.</span>
        <span style={{ animation: 'agentix-blink 1.4s infinite', animationDelay: '.2s', opacity: 0 }}>.</span>
        <span style={{ animation: 'agentix-blink 1.4s infinite', animationDelay: '.4s', opacity: 0 }}>.</span>
      </span>
    </div>
  );
}

interface ApprovalBubbleProps {
  text: string;
  onYes: () => void;
  onNo: () => void;
}

function ApprovalBubble({ text, onYes, onNo }: ApprovalBubbleProps) {
  return (
    <div style={{ alignSelf: 'flex-start', background: 'var(--bg-secondary)', border: '1px solid #2d3452', borderRadius: '10px 10px 10px 2px', padding: '10px 14px', maxWidth: '90%', fontSize: 12.5, color: '#cbd5e1', lineHeight: 1.5 }}>
      <div style={{ marginBottom: 8 }}>{text}</div>
      <div style={{ display: 'flex', gap: 8 }}>
        <button onClick={onYes} style={{ background: '#15803d', border: 'none', color: '#fff', fontSize: 12, padding: '6px 18px', borderRadius: 5, cursor: 'pointer', fontWeight: 500 }}>Yes</button>
        <button onClick={onNo} style={{ background: '#7f1d1d', border: 'none', color: '#fff', fontSize: 12, padding: '6px 18px', borderRadius: 5, cursor: 'pointer', fontWeight: 500 }}>No</button>
      </div>
    </div>
  );
}

interface 对话BubbleProps {
  msg: 对话Message;
}

function 对话Bubble({ msg }: 对话BubbleProps) {
  if (msg.role === 'user') {
    return (
      <div style={{ alignSelf: 'flex-end', background: '#1e2860', border: '1px solid #3b4268', borderRadius: '10px 10px 2px 10px', padding: '10px 14px', maxWidth: '85%', fontSize: 12.5, color: '#cbd5e1', lineHeight: 1.5 }}>
        {msg.text}
      </div>
    );
  }
  if (msg.html) {
    return (
      <div
        style={{ alignSelf: 'flex-start', background: 'var(--bg-secondary)', border: '1px solid #2d3452', borderRadius: '10px 10px 10px 2px', padding: '10px 14px', maxWidth: '90%', fontSize: 12.5, color: '#cbd5e1', lineHeight: 1.5 }}
        dangerouslySetInnerHTML={{ __html: msg.html }}
      />
    );
  }
  return (
    <div style={{ alignSelf: 'flex-start', background: 'var(--bg-secondary)', border: '1px solid #2d3452', borderRadius: '10px 10px 10px 2px', padding: '10px 14px', maxWidth: '90%', fontSize: 12.5, color: '#cbd5e1', lineHeight: 1.5 }}>
      {msg.text}
    </div>
  );
}

// ── SVG Diagram ────────────────────────────────────────────────────────────────

function AgentixDiagram() {
  const connLine: React.CSSProperties = { stroke: '#2d3452', strokeWidth: 1.5 };
  return (
    <svg viewBox="0 0 780 320" style={{ width: '100%', maxWidth: 780, height: 340 }} xmlns="http://www.w3.org/2000/svg">
      <defs>
        <radialGradient id="g-orange" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#7c2d12" />
          <stop offset="100%" stopColor="#f97316" />
        </radialGradient>
        <radialGradient id="g-purple" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#3b0764" />
          <stop offset="100%" stopColor="#a855f7" />
        </radialGradient>
        <radialGradient id="g-yellow" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#3f3000" />
          <stop offset="100%" stopColor="#eab308" />
        </radialGradient>
        <radialGradient id="g-teal" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#033d3d" />
          <stop offset="100%" stopColor="#14b8a6" />
        </radialGradient>
        <radialGradient id="g-pink" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#500732" />
          <stop offset="100%" stopColor="#ec4899" />
        </radialGradient>
        <marker id="arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
          <path d="M0 0 L6 3 L0 6 Z" fill="#3b4268" />
        </marker>
      </defs>

      {/* Progress bar */}
      <rect x="280" y="18" width="220" height="8" rx="4" fill="#1e2233" />
      <rect x="280" y="18" width="186" height="8" rx="4" fill="#6366f1" opacity=".7" />

      {/* Automations node */}
      <rect x="305" y="34" width="170" height="44" rx="8" fill="#1e2233" stroke="#3b4268" strokeWidth="1.5" />
      <text x="390" y="52" textAnchor="middle" fill="#94a3b8" fontSize="9" fontWeight="600" letterSpacing="1" fontFamily="Inter,sans-serif">AUTOMATIONS</text>
      <text x="390" y="68" textAnchor="middle" fill="#e2e8f0" fontSize="12" fontWeight="700" fontFamily="Inter,sans-serif">2,234 Plans</text>

      {/* Connector lines */}
      <line x1="390" y1="78" x2="390" y2="108" style={connLine} />
      <line x1="110" y1="108" x2="670" y2="108" style={connLine} />
      <line x1="110" y1="108" x2="110" y2="148" style={connLine} />
      <line x1="238" y1="108" x2="238" y2="148" style={connLine} />
      <line x1="366" y1="108" x2="366" y2="148" style={connLine} />
      <line x1="494" y1="108" x2="494" y2="148" style={connLine} />
      <line x1="622" y1="108" x2="622" y2="148" style={connLine} />
      <line x1="750" y1="108" x2="750" y2="148" stroke="#2d3452" strokeWidth="1.5" fill="none" strokeDasharray="4 3" />

      {/* Agent 1: Email Investigation (orange) */}
      <rect x="50" y="148" width="120" height="88" rx="8" fill="var(--bg-secondary)" stroke="#2d3452" strokeWidth="1.5" />
      <circle cx="110" cy="176" r="18" fill="url(#g-orange)" />
      <text x="110" y="181" textAnchor="middle" fill="#fff" fontSize="14">✉</text>
      <text x="110" y="214" textAnchor="middle" fill="#cbd5e1" fontSize="9" fontWeight="600" fontFamily="Inter,sans-serif">Email Investigation</text>
      <text x="110" y="226" textAnchor="middle" fill="#64748b" fontSize="9" fontFamily="Inter,sans-serif">Agent</text>
      <text x="110" y="238" textAnchor="middle" fill="#94a3b8" fontSize="10" fontWeight="700" fontFamily="Inter,sans-serif">158 Plans</text>

      {/* Agent 2: Endpoint Investigation (purple) */}
      <rect x="178" y="148" width="120" height="88" rx="8" fill="var(--bg-secondary)" stroke="#2d3452" strokeWidth="1.5" />
      <circle cx="238" cy="176" r="18" fill="url(#g-purple)" />
      <text x="238" y="181" textAnchor="middle" fill="#fff" fontSize="14">🖥</text>
      <text x="238" y="214" textAnchor="middle" fill="#cbd5e1" fontSize="9" fontWeight="600" fontFamily="Inter,sans-serif">Endpoint Investigation</text>
      <text x="238" y="226" textAnchor="middle" fill="#64748b" fontSize="9" fontFamily="Inter,sans-serif">Agent</text>
      <text x="238" y="238" textAnchor="middle" fill="#94a3b8" fontSize="10" fontWeight="700" fontFamily="Inter,sans-serif">154 Plans</text>

      {/* Agent 3: Network Security (yellow) */}
      <rect x="306" y="148" width="120" height="88" rx="8" fill="var(--bg-secondary)" stroke="#2d3452" strokeWidth="1.5" />
      <circle cx="366" cy="176" r="18" fill="url(#g-yellow)" />
      <text x="366" y="181" textAnchor="middle" fill="#fff" fontSize="14">🛡</text>
      <text x="366" y="214" textAnchor="middle" fill="#cbd5e1" fontSize="9" fontWeight="600" fontFamily="Inter,sans-serif">Network Security</text>
      <text x="366" y="226" textAnchor="middle" fill="#64748b" fontSize="9" fontFamily="Inter,sans-serif">Agent</text>
      <text x="366" y="238" textAnchor="middle" fill="#94a3b8" fontSize="10" fontWeight="700" fontFamily="Inter,sans-serif">91 Plans</text>

      {/* Agent 4: Threat Intel (teal) */}
      <rect x="434" y="148" width="120" height="88" rx="8" fill="var(--bg-secondary)" stroke="#2d3452" strokeWidth="1.5" />
      <circle cx="494" cy="176" r="18" fill="url(#g-teal)" />
      <text x="494" y="181" textAnchor="middle" fill="#fff" fontSize="14">🔍</text>
      <text x="494" y="214" textAnchor="middle" fill="#cbd5e1" fontSize="9" fontWeight="600" fontFamily="Inter,sans-serif">Threat Intel</text>
      <text x="494" y="226" textAnchor="middle" fill="#64748b" fontSize="9" fontFamily="Inter,sans-serif">Agent</text>
      <text x="494" y="238" textAnchor="middle" fill="#94a3b8" fontSize="10" fontWeight="700" fontFamily="Inter,sans-serif">113 Plans</text>

      {/* Agent 5: IT Agent (pink) */}
      <rect x="562" y="148" width="120" height="88" rx="8" fill="var(--bg-secondary)" stroke="#2d3452" strokeWidth="1.5" />
      <circle cx="622" cy="176" r="18" fill="url(#g-pink)" />
      <text x="622" y="181" textAnchor="middle" fill="#fff" fontSize="14">⚙</text>
      <text x="622" y="214" textAnchor="middle" fill="#cbd5e1" fontSize="9" fontWeight="600" fontFamily="Inter,sans-serif">IT Agent</text>
      <text x="622" y="226" textAnchor="middle" fill="#64748b" fontSize="9" fontFamily="Inter,sans-serif"> </text>
      <text x="622" y="238" textAnchor="middle" fill="#94a3b8" fontSize="10" fontWeight="700" fontFamily="Inter,sans-serif">60 Plans</text>

      {/* +8 Other Agents (dashed) */}
      <rect x="706" y="148" width="88" height="88" rx="8" fill="#111520" stroke="#2d3452" strokeWidth="1.5" strokeDasharray="4 3" />
      <circle cx="750" cy="172" r="14" fill="#1e2233" stroke="#3b4268" strokeWidth="1" />
      <circle cx="750" cy="176" r="11" fill="#151a27" stroke="#3b4268" strokeWidth="1" />
      <text x="750" y="181" textAnchor="middle" fill="#64748b" fontSize="10">+8</text>
      <text x="750" y="214" textAnchor="middle" fill="#64748b" fontSize="9" fontWeight="600" fontFamily="Inter,sans-serif">+8 Other Agents</text>
      <text x="750" y="230" textAnchor="middle" fill="#475569" fontSize="10" fontFamily="Inter,sans-serif">3 Plans</text>

      {/* Execution lines */}
      <line x1="170" y1="192" x2="210" y2="192" stroke="#2d3452" strokeWidth="1.5" fill="none" opacity=".4" />
      <line x1="298" y1="192" x2="306" y2="192" stroke="#2d3452" strokeWidth="1.5" fill="none" opacity=".4" />

      {/* Case Investigation node */}
      <rect x="306" y="258" width="168" height="44" rx="8" fill="#111b11" stroke="#166534" strokeWidth="1.5" />
      <text x="390" y="276" textAnchor="middle" fill="#4ade80" fontSize="9" fontWeight="600" letterSpacing="1" fontFamily="Inter,sans-serif">CASE INVESTIGATION</text>
      <text x="390" y="292" textAnchor="middle" fill="#86efac" fontSize="11" fontWeight="700" fontFamily="Inter,sans-serif">Agent</text>
      <line x1="390" y1="236" x2="390" y2="258" stroke="#166534" strokeWidth="1.5" fill="none" />
    </svg>
  );
}

// ── 对话 logic hook ────────────────────────────────────────────────────────────

interface 对话Entry {
  id: number;
  kind: 'greeting' | 'message' | 'thinking' | 'approval';
  data?: 对话Message;
  thinkingText?: string;
  approvalText?: string;
  approvalId?: number;
  resolved?: boolean;
}

let _idCounter = 0;
function nextId() { return ++_idCounter; }

function use对话(_agent: AgentKey) {
  const [entries, setEntries] = useState<对话Entry[]>([
    { id: nextId(), kind: 'greeting' },
  ]);

  const appendEntry = useCallback((entry: Omit<对话Entry, 'id'>) => {
    setEntries(prev => [...prev, { id: nextId(), ...entry }]);
  }, []);

  const removeEntryById = useCallback((id: number) => {
    setEntries(prev => prev.filter(e => e.id !== id));
  }, []);

  const resolveApproval = useCallback((approvalId: number) => {
    setEntries(prev => prev.map(e => e.id === approvalId ? { ...e, resolved: true } : e));
  }, []);

  return { entries, setEntries, appendEntry, removeEntryById, resolveApproval };
}

// ── Main page component ────────────────────────────────────────────────────────

export default function Agentix() {
  const [panelOpen, setPanelOpen] = useState(false);
  const [activeAgent, setActiveAgent] = useState<AgentKey>('threatIntel');
  const [inputText, setInputText] = useState('');
  const chatScrollRef = useRef<HTMLDivElement>(null);

  // Per-agent chat state
  const ti对话 = use对话('threatIntel');
  const ci对话 = use对话('caseInv');
  const ae对话 = use对话('autoEng');

  const chatForAgent = (a: AgentKey) => {
    if (a === 'threatIntel') return ti对话;
    if (a === 'caseInv') return ci对话;
    return ae对话;
  };

  const current对话 = chatForAgent(activeAgent);

  // Inject keyframes once
  useEffect(() => {
    if (!document.getElementById('agentix-kf')) {
      const style = document.createElement('style');
      style.id = 'agentix-kf';
      style.textContent = KEYFRAMES;
      document.head.appendChild(style);
    }
  }, []);

  // Scroll chat to bottom on new entries
  useEffect(() => {
    if (chatScrollRef.current) {
      chatScrollRef.current.scrollTop = chatScrollRef.current.scrollHeight;
    }
  }, [current对话.entries]);

  const openPanel = useCallback((agent: AgentKey) => {
    setActiveAgent(agent);
    setPanelOpen(true);
  }, []);

  const runFlowSteps = useCallback((chat: ReturnType<typeof use对话>, steps: FlowStep[], idx: number) => {
    if (idx >= steps.length) return;
    const step = steps[idx];

    if (step.type === 'thinking') {
      const thinkId = nextId();
      chat.appendEntry({ kind: 'thinking', thinkingText: step.text });
      setTimeout(() => {
        // Remove thinking bubble (by scanning for it — we appended it last, so find by thinkingText + not resolved)
        chat.removeEntryById(thinkId);
        // Actually we can't remove by content easily with the approach above. Let's use a different approach.
        // We'll store the id returned by appending. But appendEntry doesn't return id.
        // Let's just let it stay briefly and clear on next step. Refactored below.
        runFlowSteps(chat, steps, idx + 1);
      }, 1800);
    } else if (step.type === 'approval') {
      const aId = nextId();
      chat.appendEntry({ kind: 'approval', approvalText: step.text, approvalId: aId });
      // Wait for user click — handled in render
    } else if (step.type === 'result') {
      chat.appendEntry({ kind: 'message', data: { role: 'agent', html: step.html } });
    }
  }, []);

  // Better approach: use a ref-based stepper
  const runFlow = useCallback((agent: AgentKey, text: string) => {
    const chat = chatForAgent(agent);
    const steps = AGENT_FLOWS[agent];

    // Add user message
    chat.appendEntry({ kind: 'message', data: { role: 'user', text } });

    // Run steps
    const execStep = (stepIdx: number) => {
      if (stepIdx >= steps.length) return;
      const step = steps[stepIdx];

      if (step.type === 'thinking') {
        const thinkEntryId = nextId();
        chat.setEntries?.(prev => [...prev, { id: thinkEntryId, kind: 'thinking', thinkingText: step.text }]);
        setTimeout(() => {
          chat.setEntries?.(prev => prev.filter(e => e.id !== thinkEntryId));
          execStep(stepIdx + 1);
        }, 1800);
      } else if (step.type === 'approval') {
        const approvalEntryId = nextId();
        chat.setEntries?.(prev => [...prev, { id: approvalEntryId, kind: 'approval', approvalText: step.text, approvalId: approvalEntryId }]);
        // Approval continuation is handled in the ApprovalBubble onYes/onNo
        // We need to wire it: store pending callback
        pendingContinuationRef.current = {
          approvalEntryId,
          chat,
          steps,
          nextIdx: stepIdx + 1,
        };
      } else if (step.type === 'result') {
        chat.setEntries?.(prev => [...prev, { id: nextId(), kind: 'message', data: { role: 'agent', html: step.html } }]);
      }
    };

    setTimeout(() => execStep(0), 300);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeAgent]);

  interface PendingContinuation {
    approvalEntryId: number;
    chat: ReturnType<typeof use对话> & { setEntries?: React.Dispatch<React.SetStateAction<对话Entry[]>> };
    steps: FlowStep[];
    nextIdx: number;
  }

  const pendingContinuationRef = useRef<PendingContinuation | null>(null);

  // Wire setEntries into chat objects (they already have it via useState in use对话, but we need to expose it)
  // Let's refactor: expose setEntries from each chat hook instance

  const handleApprovalYes = useCallback((approvalEntryId: number) => {
    const p = pendingContinuationRef.current;
    if (!p || p.approvalEntryId !== approvalEntryId) return;
    // Remove approval entry
    p.chat.setEntries?.(prev => prev.filter(e => e.id !== approvalEntryId));
    pendingContinuationRef.current = null;
    // Continue steps
    const continueSteps = (stepIdx: number) => {
      if (stepIdx >= p.steps.length) return;
      const step = p.steps[stepIdx];
      if (step.type === 'thinking') {
        const tid = nextId();
        p.chat.setEntries?.(prev => [...prev, { id: tid, kind: 'thinking', thinkingText: step.text }]);
        setTimeout(() => {
          p.chat.setEntries?.(prev => prev.filter(e => e.id !== tid));
          continueSteps(stepIdx + 1);
        }, 1800);
      } else if (step.type === 'result') {
        setTimeout(() => {
          p.chat.setEntries?.(prev => [...prev, { id: nextId(), kind: 'message', data: { role: 'agent', html: step.html } }]);
        }, 200);
      } else if (step.type === 'approval') {
        const aid = nextId();
        p.chat.setEntries?.(prev => [...prev, { id: aid, kind: 'approval', approvalText: step.text, approvalId: aid }]);
        pendingContinuationRef.current = { ...p, approvalEntryId: aid, nextIdx: stepIdx + 1 };
      }
    };
    continueSteps(p.nextIdx);
  }, []);

  const handleApprovalNo = useCallback((approvalEntryId: number) => {
    const p = pendingContinuationRef.current;
    if (!p || p.approvalEntryId !== approvalEntryId) return;
    p.chat.setEntries?.(prev => prev.filter(e => e.id !== approvalEntryId));
    p.chat.setEntries?.(prev => [...prev, { id: nextId(), kind: 'message', data: { role: 'agent', text: 'Understood, cancelled.' } }]);
    pendingContinuationRef.current = null;
  }, []);

  const handle发送 = useCallback(() => {
    const text = inputText.trim();
    if (!text) return;
    setInputText('');
    runFlow(activeAgent, text);
  }, [inputText, activeAgent, runFlow]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handle发送();
    }
  };

  const handleSuggestion = (s: string) => {
    setInputText(s);
    // Trigger send immediately
    setTimeout(() => {
      const text = s.trim();
      if (!text) return;
      setInputText('');
      runFlow(activeAgent, text);
    }, 10);
  };

  // ── Render ───────────────────────────────────────────────────────────────────

  const agentTabStyle = (key: AgentKey): React.CSSProperties => ({
    fontSize: 11,
    padding: '4px 12px',
    borderRadius: '4px 4px 0 0',
    border: '1px solid',
    borderBottom: 'none',
    cursor: 'pointer',
    background: activeAgent === key ? 'var(--bg-secondary)' : 'var(--bg-card)',
    color: activeAgent === key ? '#a5b4fc' : '#64748b',
    borderColor: activeAgent === key ? '#3b4268' : '#2d3452',
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', background: '#0f1117', color: '#e2e8f0', fontFamily: "'Inter', 'Segoe UI', sans-serif", overflow: 'hidden' }}>

      {/* Top bar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 20px', borderBottom: '1px solid #1e2233', flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: '#94a3b8' }}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#6366f1" strokeWidth="2">
            <circle cx="12" cy="8" r="4" />
            <path d="M6 20v-2a4 4 0 014-4h4a4 4 0 014 4v2" />
          </svg>
          <span style={{ fontSize: 15, fontWeight: 600, color: '#e2e8f0' }}>Agentix Command Center</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <select style={{ background: '#1e2233', border: '1px solid #2d3452', color: '#cbd5e1', fontSize: 12, padding: '5px 12px', borderRadius: 5, cursor: 'pointer', outline: 'none' }}
            defaultValue="7d">
            <option value="24h">Last 24H</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </select>
          <button
            onClick={() => openPanel('threatIntel')}
            style={{ background: 'linear-gradient(135deg, #6366f1, #8b5cf6)', border: 'none', color: '#fff', fontSize: 12, padding: '6px 14px', borderRadius: 5, cursor: 'pointer', fontWeight: 500, display: 'flex', alignItems: 'center', gap: 6 }}
          >
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="8" r="4" />
              <path d="M6 20v-2a4 4 0 014-4h4a4 4 0 014 4v2" />
            </svg>
            Agentix Assistant
          </button>
          <span style={{ color: '#64748b', fontSize: 16, cursor: 'pointer' }}>⋮</span>
        </div>
      </div>

      {/* Canvas */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', padding: '24px 32px 0', overflow: 'hidden', position: 'relative' }}>
        {/* Dot-grid background */}
        <div style={{ position: 'absolute', inset: 0, backgroundImage: 'radial-gradient(circle, #2d3452 1px, transparent 1px)', backgroundSize: '28px 28px', opacity: 0.35, pointerEvents: 'none' }} />

        {/* Stats overlay — left top */}
        <div style={{ position: 'absolute', left: 48, top: 36, zIndex: 2, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
          <div style={{ width: 44, height: 44, borderRadius: '50%', border: '2px solid #2d3452', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#6366f1', fontSize: 20 }}>⚡</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: '#e2e8f0', lineHeight: 1 }}>2,234</div>
          <div style={{ fontSize: 9.5, fontWeight: 700, color: '#64748b', letterSpacing: '.08em', textAlign: 'center', maxWidth: 70 }}>PRE-CONFIGURED<br />TRIGGERS</div>
        </div>

        {/* Stats overlay — left bottom */}
        <div style={{ position: 'absolute', left: 48, bottom: 70, zIndex: 2, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
          <div style={{ width: 40, height: 40, borderRadius: '50%', border: '2px solid #2d3452', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#94a3b8', fontSize: 18 }}>👤</div>
          <div style={{ fontSize: 24, fontWeight: 700, color: '#e2e8f0', lineHeight: 1 }}>598</div>
          <div style={{ fontSize: 9.5, fontWeight: 700, color: '#64748b', letterSpacing: '.08em', textAlign: 'center', maxWidth: 70 }}>USER<br />PROMPTS</div>
        </div>

        {/* Stats overlay — right */}
        <div style={{ position: 'absolute', right: 40, top: 24, zIndex: 2, display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
          <div style={{ fontSize: 60, fontWeight: 800, color: '#e2e8f0', lineHeight: 1, letterSpacing: '-.02em' }}>94%</div>
          <div style={{ fontSize: 19, fontWeight: 700, color: '#e2e8f0' }}>2,656 FULLY EXECUTED PLANS</div>
          <div style={{ fontSize: 13, fontWeight: 700, color: '#2dd4bf', marginTop: 2 }}>176 PLANS TO REVIEW</div>
        </div>

        {/* SVG Diagram centered */}
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative', zIndex: 1 }}>
          <AgentixDiagram />
        </div>

        {/* Bottom action buttons */}
        <div style={{ position: 'absolute', bottom: 52, left: '50%', transform: 'translateX(-50%)', display: 'flex', gap: 6, zIndex: 3 }}>
          <button onClick={() => openPanel('caseInv')} style={{ background: '#111b11', border: '1.5px solid #166534', color: '#4ade80', fontSize: 10, padding: '5px 14px', borderRadius: 5, cursor: 'pointer', fontWeight: 600 }}>
            + Case Investigation
          </button>
          <button onClick={() => openPanel('autoEng')} style={{ background: '#1e1230', border: '1.5px solid #6d28d9', color: '#a78bfa', fontSize: 10, padding: '5px 14px', borderRadius: 5, cursor: 'pointer', fontWeight: 600 }}>
            + Automation Engineer
          </button>
          <button onClick={() => openPanel('threatIntel')} style={{ background: 'var(--bg-secondary)', border: '1.5px solid #0f766e', color: '#2dd4bf', fontSize: 10, padding: '5px 14px', borderRadius: 5, cursor: 'pointer', fontWeight: 600 }}>
            + Threat Intel
          </button>
        </div>
      </div>

      {/* Status bar */}
      <div style={{ display: 'flex', alignItems: 'center', borderTop: '1px solid #1e2233', background: 'var(--bg-card)', padding: '10px 24px', flexShrink: 0, fontSize: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '0 20px', borderRight: '1px solid #1e2233', paddingLeft: 0 }}>
          <span style={{ color: '#64748b', fontSize: 11, fontWeight: 500, whiteSpace: 'nowrap' }}>Total Open Cases</span>
          <span style={{ fontWeight: 700, color: '#e2e8f0', fontSize: 13 }}>57</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '0 20px', borderRight: '1px solid #1e2233' }}>
          <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#22c55e', flexShrink: 0, display: 'inline-block' }} />
          <button onClick={() => openPanel('caseInv')} style={{ background: '#15803d', border: 'none', color: '#fff', fontSize: 11, padding: '4px 10px', borderRadius: 4, cursor: 'pointer', whiteSpace: 'nowrap' }}>Start Investigation</button>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '0 20px', borderRight: '1px solid #1e2233' }}>
          <span style={{ color: '#64748b', fontSize: 11, fontWeight: 500, whiteSpace: 'nowrap' }}>Cases Resolved with Agentix</span>
          <span style={{ fontSize: 13, fontWeight: 700, color: '#22c55e' }}>81%</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '0 20px', borderRight: '1px solid #1e2233' }}>
          <span style={{ color: '#64748b', fontSize: 11, fontWeight: 500 }}>MTTR</span>
          <span style={{ fontWeight: 700, color: '#e2e8f0', fontSize: 13 }}>42 Min</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '0 20px', borderRight: '1px solid #1e2233' }}>
          <span style={{ color: '#64748b', fontSize: 11, fontWeight: 500, whiteSpace: 'nowrap' }}>External Interactions</span>
          <span style={{ fontWeight: 700, color: '#6366f1', fontSize: 13 }}>3,523</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '0 20px', flex: 1, overflow: 'hidden' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, overflow: 'hidden' }}>
            {['Microsoft Defender', 'Jira Software', 'ServiceNow', 'Microsoft 365', 'Gmail', 'Slack', 'CrowdStrike', 'SentinelOne'].map(logo => (
              <span key={logo} style={{ fontSize: 10, color: '#475569', whiteSpace: 'nowrap', background: '#1e2233', padding: '2px 7px', borderRadius: 3 }}>{logo}</span>
            ))}
          </div>
        </div>
      </div>

      {/* Agentix Assistant Panel */}
      <div style={{ position: 'fixed', top: 0, right: panelOpen ? 0 : -560, width: 520, height: '100vh', background: 'var(--bg-card)', borderLeft: '1px solid #1e2233', display: 'flex', flexDirection: 'column', zIndex: 200, transition: 'right .3s ease' }}>

        {/* Panel header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '14px 18px', borderBottom: '1px solid #1e2233', flexShrink: 0 }}>
          <div style={{ fontSize: 14, fontWeight: 600, color: '#e2e8f0', display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#6366f1', display: 'inline-block', animation: 'agentix-pulse-dot 2s infinite' }} />
            Agentic Assistant
          </div>
          <button onClick={() => setPanelOpen(false)} style={{ background: 'none', border: 'none', color: '#64748b', fontSize: 18, cursor: 'pointer', padding: '2px 6px', borderRadius: 4 }}>✕</button>
        </div>

        {/* Agent tabs */}
        <div style={{ display: 'flex', gap: 4, padding: '10px 18px 0', flexShrink: 0 }}>
          {(['threatIntel', 'caseInv', 'autoEng'] as AgentKey[]).map(key => (
            <button key={key} onClick={() => setActiveAgent(key)} style={agentTabStyle(key)}>
              {AGENT_CONFIG[key].label}
            </button>
          ))}
        </div>

        {/* 对话 area */}
        <div ref={chatScrollRef} style={{ flex: 1, overflowY: 'auto', padding: '16px 18px', display: 'flex', flexDirection: 'column', gap: 14 }}>
          {/* Greeting */}
          <div style={{ fontSize: 13, color: '#94a3b8' }}>
            <strong style={{ color: '#e2e8f0' }}>{AGENT_CONFIG[activeAgent].greeting.split('.')[0]}.</strong>{' '}
            {AGENT_CONFIG[activeAgent].greeting.slice(AGENT_CONFIG[activeAgent].greeting.indexOf('.') + 1).trim()}
          </div>

          {/* Messages */}
          {current对话.entries.map(entry => {
            if (entry.kind === 'greeting') return null;
            if (entry.kind === 'thinking') {
              return <ThinkingBubble key={entry.id} text={entry.thinkingText ?? ''} />;
            }
            if (entry.kind === 'approval') {
              return (
                <ApprovalBubble
                  key={entry.id}
                  text={entry.approvalText ?? ''}
                  onYes={() => handleApprovalYes(entry.id)}
                  onNo={() => handleApprovalNo(entry.id)}
                />
              );
            }
            if (entry.kind === 'message' && entry.data) {
              return <对话Bubble key={entry.id} msg={entry.data} />;
            }
            return null;
          })}
        </div>

        {/* Input bar */}
        <div style={{ padding: '14px 18px', borderTop: '1px solid #1e2233', flexShrink: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, fontSize: 11, color: '#64748b' }}>
            <span>Agent:</span>
            <div style={{ background: '#312e81', border: '1px solid #6366f1', borderRadius: 20, padding: '3px 12px', fontSize: 11, color: '#e0e7ff', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 5 }}>
              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="8" r="4" />
                <path d="M6 20v-2a4 4 0 014-4h4a4 4 0 014 4v2" />
              </svg>
              <span>{AGENT_CONFIG[activeAgent].label}</span>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'flex-end', gap: 8 }}>
            <textarea
              value={inputText}
              onChange={e => setInputText(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Ask Agentix…"
              rows={1}
              style={{ flex: 1, background: '#1e2233', border: '1px solid #2d3452', borderRadius: 8, color: '#e2e8f0', fontSize: 12.5, padding: '9px 12px', resize: 'none', outline: 'none', fontFamily: 'inherit', lineHeight: 1.4, height: 40, transition: 'border-color .2s' }}
            />
            <button
              onClick={handle发送}
              style={{ background: '#6366f1', border: 'none', color: '#fff', width: 36, height: 36, borderRadius: 7, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <line x1="22" y1="2" x2="11" y2="13" />
                <polygon points="22 2 15 22 11 13 2 9 22 2" />
              </svg>
            </button>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginTop: 8 }}>
            {AGENT_CONFIG[activeAgent].suggestions.map(s => (
              <button
                key={s}
                onClick={() => handleSuggestion(s)}
                style={{ background: 'var(--bg-secondary)', border: '1px solid #2d3452', borderRadius: 4, padding: '4px 9px', fontSize: 10.5, color: '#64748b', cursor: 'pointer', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 200 }}
              >
                {s}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
