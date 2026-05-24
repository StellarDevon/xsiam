import React, { useState, useRef, useEffect, useCallback } from 'react';
import api from '@/lib/api';

// ── Types ──────────────────────────────────────────────────────────────────────

type AgentKey = 'threatIntel' | 'caseInv' | 'autoEng';

// 'xql' is a special tab — not an agent, so kept separate from AgentKey
type PanelTab = AgentKey | 'xql';

type ContextMode = 'none' | 'alerts' | 'incidents' | 'vulns';

interface 对话Message {
  id: string;
  role: 'user' | 'agent';
  text?: string;
  html?: string;
  msgTime?: number; // Unix ms timestamp
  streaming?: boolean; // true while being typed
  hasContext?: boolean; // user message had context injected
  followUps?: string[]; // suggested follow-up questions
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

interface SavedAnalysis {
  id: string;
  timestamp: number;
  preview: string;
  fullText: string;
}

// ── Conversation history types ─────────────────────────────────────────────────

interface ConversationRecord {
  id: string;
  title: string;
  createdAt: number;
  messages: 对话Message[];
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

// ── Analysis templates ─────────────────────────────────────────────────────────

const ANALYSIS_TEMPLATES = [
  { label: '分析告警', text: '请分析以下告警的威胁等级和处置建议：' },
  { label: '溯源调查', text: '请帮我对以下事件进行攻击溯源分析：' },
  { label: '漏洞评估', text: '请评估以下漏洞的利用风险和修复优先级：' },
  { label: '生成报告', text: '请根据当前安全态势生成一份简要的安全周报：' },
];

// ── Copilot suggestion chips (shown in panel when input empty & no messages) ──

const COPILOT_CHIPS = [
  '分析最近告警趋势',
  '总结今日高危事件',
  '哪些资产风险最高？',
  '最近IOC匹配情况',
];

// ── Quick analysis prompt chips ───────────────────────────────────────────────

const QUICK_ANALYSIS_CHIPS = [
  '分析最近的告警趋势',
  '查找高危漏洞',
  '生成安全报告摘要',
  '识别异常行为模式',
];

// ── Follow-up question keyword rules ─────────────────────────────────────────

interface FollowUpRule {
  keywords: string[];
  questions: string[];
}

const FOLLOW_UP_RULES: FollowUpRule[] = [
  {
    keywords: ['incident', '事件', 'case', '案例'],
    questions: ['查看关联IOC', '运行取证脚本', '生成事件报告'],
  },
  {
    keywords: ['malware', 'threat', '恶意软件', '威胁'],
    questions: ['检查受影响主机', '提交WildFire分析', '隔离终端'],
  },
  {
    keywords: ['vulnerability', 'cve', '漏洞', 'cvss'],
    questions: ['查看修复建议', '生成漏洞报告', '分配给工程师'],
  },
  {
    keywords: ['hash', 'sha256', 'md5', 'file', '文件'],
    questions: ['查询VT沙箱报告', '检查环境内出现情况', '加入黑名单'],
  },
  {
    keywords: ['domain', 'ip', 'url', 'c2', 'network', '网络'],
    questions: ['查询域名注册信息', '检查通信主机', '生成封锁规则'],
  },
  {
    keywords: ['script', '脚本', 'playbook', '剧本', 'automation', '自动化'],
    questions: ['运行该脚本', '添加错误处理', '导出到剧本'],
  },
];

function getFollowUpQuestions(text: string): string[] {
  const lower = text.toLowerCase();
  for (const rule of FOLLOW_UP_RULES) {
    if (rule.keywords.some(kw => lower.includes(kw))) {
      return rule.questions.slice(0, 3);
    }
  }
  return ['继续分析', '生成报告', '关联事件'];
}

// ── localStorage helpers ───────────────────────────────────────────────────────

const LS_KEY = 'xsiam_copilot_history';
const LS_SAVED_KEY = 'xsiam_saved_analyses';
const LS_CONVERSATIONS_KEY = 'xsiam_agentix_conversations';

function loadHistory(): 对话Message[] {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed as 对话Message[];
  } catch {
    // ignore parse errors
  }
  return [];
}

function saveHistory(msgs: 对话Message[]) {
  try {
    localStorage.setItem(LS_KEY, JSON.stringify(msgs));
  } catch {
    // ignore quota errors
  }
}

function loadSaved(): SavedAnalysis[] {
  try {
    const raw = localStorage.getItem(LS_SAVED_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed as SavedAnalysis[];
  } catch {
    // ignore
  }
  return [];
}

function saveSavedList(list: SavedAnalysis[]) {
  try {
    localStorage.setItem(LS_SAVED_KEY, JSON.stringify(list));
  } catch {
    // ignore
  }
}

function loadConversations(): ConversationRecord[] {
  try {
    const raw = localStorage.getItem(LS_CONVERSATIONS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed as ConversationRecord[];
  } catch {
    // ignore
  }
  return [];
}

function saveConversations(list: ConversationRecord[]) {
  try {
    localStorage.setItem(LS_CONVERSATIONS_KEY, JSON.stringify(list));
  } catch {
    // ignore
  }
}

// ── Relative time helper ───────────────────────────────────────────────────────

function relativeTime(ts: number): string {
  const diff = Math.floor((Date.now() - ts) / 1000);
  if (diff < 60) return '刚刚';
  if (diff < 3600) return `${Math.floor(diff / 60)}分钟前`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}小时前`;
  return `${Math.floor(diff / 86400)}天前`;
}

function formatTimestamp(ts: number): string {
  const d = new Date(ts);
  return `${d.getMonth() + 1}/${d.getDate()} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

// ── Unique ID generator ────────────────────────────────────────────────────────

let _msgIdCounter = 0;
function newMsgId(): string {
  return `msg-${Date.now()}-${++_msgIdCounter}`;
}

function newConvId(): string {
  return `conv-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
}

// ── Markdown rendering (regex-based, no external lib) ─────────────────────────

function renderMarkdown(text: string): string {
  // Escape HTML to avoid XSS in plain text portions
  const escapeHtml = (s: string) =>
    s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  // Split on fenced code blocks first (``` ... ```)
  const parts = text.split(/(```[\s\S]*?```)/g);
  const rendered = parts.map((part, i) => {
    if (i % 2 === 1) {
      // Fenced code block
      const inner = part.replace(/^```[^\n]*\n?/, '').replace(/```$/, '');
      const escaped = escapeHtml(inner);
      const blockId = `cb-${Date.now()}-${i}`;
      return (
        `<div style="position:relative;margin:6px 0">` +
        `<button data-copy-target="${blockId}" onclick="(function(btn){` +
          `var pre=document.getElementById('${blockId}');` +
          `if(pre){navigator.clipboard.writeText(pre.innerText||pre.textContent||'').then(function(){` +
            `btn.textContent='✅ 已复制';setTimeout(function(){btn.textContent='复制'},1500)` +
          `})}` +
        `})(this)" style="position:absolute;top:6px;right:6px;background:#2d3452;border:none;color:#6a80a0;font-size:10px;padding:2px 8px;border-radius:3px;cursor:pointer;z-index:1">复制</button>` +
        `<pre id="${blockId}" style="background:#0d1019;border:1px solid #1e2233;border-radius:6px;padding:10px 12px;font-size:11px;color:#86efac;overflow-x:auto;line-height:1.5;margin:0;font-family:monospace">${escaped}</pre>` +
        `</div>`
      );
    }
    // Inline content
    let s = escapeHtml(part);

    // Inline code: `code`
    s = s.replace(/`([^`]+)`/g, '<code style="background:#1a1f30;border:1px solid #2d3452;border-radius:3px;padding:1px 5px;font-family:monospace;font-size:11px;color:#93c5fd">$1</code>');

    // Bold: **text**
    s = s.replace(/\*\*([^*]+)\*\*/g, '<strong style="color:#e2e8f0;font-weight:600">$1</strong>');

    // Bullet lists: lines starting with "- "
    s = s.replace(/^- (.+)$/gm, '<li style="margin:2px 0;color:#dce4f0">$1</li>');
    // Wrap consecutive <li> elements in <ul>
    s = s.replace(/(<li[^>]*>[\s\S]*?<\/li>\s*)+/g, (match) =>
      `<ul style="margin:6px 0;padding-left:18px;list-style:disc">${match}</ul>`
    );

    // Line breaks
    s = s.replace(/\n/g, '<br>');

    return s;
  });

  return rendered.join('');
}

const THREAT_INTEL_RESULT_HTML = `
<div style="font-size:10px;font-weight:700;color:#3fa0e0;letter-spacing:.06em;margin-bottom:5px;display:flex;align-items:center;gap:5px">📊 FILE IOC ANALYSIS</div>
<table style="width:100%;border-collapse:collapse;font-size:11px;margin-top:6px">
  <thead>
    <tr>
      <th style="background:#151c2a;color:#38506e;padding:5px 8px;text-align:left;font-weight:600;letter-spacing:.04em;border-bottom:1px solid #1e2b3f">SHA256</th>
      <th style="background:#151c2a;color:#38506e;padding:5px 8px;text-align:left;font-weight:600;letter-spacing:.04em;border-bottom:1px solid #1e2b3f">Verdict</th>
      <th style="background:#151c2a;color:#38506e;padding:5px 8px;text-align:left;font-weight:600;letter-spacing:.04em;border-bottom:1px solid #1e2b3f">Score</th>
      <th style="background:#151c2a;color:#38506e;padding:5px 8px;text-align:left;font-weight:600;letter-spacing:.04em;border-bottom:1px solid #1e2b3f">TIM</th>
      <th style="background:#151c2a;color:#38506e;padding:5px 8px;text-align:left;font-weight:600;letter-spacing:.04em;border-bottom:1px solid #1e2b3f">VT</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#dce4f0;font-size:10px;font-family:monospace">3f4a1b…e92c</td>
      <td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#e05050;font-weight:600">Malicious</td>
      <td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#dce4f0">3</td>
      <td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#dce4f0">✓</td>
      <td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#dce4f0">62/72</td>
    </tr>
    <tr>
      <td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#dce4f0;font-size:10px;font-family:monospace">a7d83e…1f0b</td>
      <td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#e05050;font-weight:600">Malicious</td>
      <td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#dce4f0">3</td>
      <td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#dce4f0">✓</td>
      <td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#dce4f0">55/72</td>
    </tr>
    <tr>
      <td style="padding:5px 8px;color:#dce4f0;font-size:10px;font-family:monospace">c1b925…77da</td>
      <td style="padding:5px 8px;color:#e05050;font-weight:600">Malicious</td>
      <td style="padding:5px 8px;color:#dce4f0">3</td>
      <td style="padding:5px 8px;color:#dce4f0">✓</td>
      <td style="padding:5px 8px;color:#dce4f0">49/72</td>
    </tr>
  </tbody>
</table>
<div style="margin-top:8px;font-size:11px;color:#6a80a0">All 3 file IOCs confirmed malicious. No environment sightings detected. Hashes added to block list.</div>
`;

const CASE_INV_RESULT_HTML = `
<div style="font-size:10px;font-weight:700;color:#3fa0e0;letter-spacing:.06em;margin-bottom:5px;display:flex;align-items:center;gap:5px">🔍 ENRICHED INDICATORS</div>
<table style="width:100%;border-collapse:collapse;font-size:11px;margin-top:6px">
  <thead>
    <tr>
      <th style="background:#151c2a;color:#38506e;padding:5px 8px;text-align:left;font-weight:600;letter-spacing:.04em;border-bottom:1px solid #1e2b3f">类型</th>
      <th style="background:#151c2a;color:#38506e;padding:5px 8px;text-align:left;font-weight:600;letter-spacing:.04em;border-bottom:1px solid #1e2b3f">Value</th>
      <th style="background:#151c2a;color:#38506e;padding:5px 8px;text-align:left;font-weight:600;letter-spacing:.04em;border-bottom:1px solid #1e2b3f">Verdict</th>
      <th style="background:#151c2a;color:#38506e;padding:5px 8px;text-align:left;font-weight:600;letter-spacing:.04em;border-bottom:1px solid #1e2b3f">Score</th>
    </tr>
  </thead>
  <tbody>
    <tr><td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#dce4f0">HASH</td><td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#dce4f0;font-family:monospace;font-size:10px">a3f1b…</td><td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#e05050;font-weight:600">Malicious</td><td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#dce4f0">3</td></tr>
    <tr><td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#dce4f0">HASH</td><td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#dce4f0;font-family:monospace;font-size:10px">9e2cd…</td><td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#e05050;font-weight:600">Malicious</td><td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#dce4f0">3</td></tr>
    <tr><td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#dce4f0">HASH</td><td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#dce4f0;font-family:monospace;font-size:10px">f7a83…</td><td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#e05050;font-weight:600">Malicious</td><td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#dce4f0">3</td></tr>
    <tr><td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#dce4f0">DOMAIN</td><td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#dce4f0;font-size:10px">404.008php.com</td><td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#e05050;font-weight:600">Malicious</td><td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#dce4f0">3</td></tr>
    <tr><td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#dce4f0">DOMAIN</td><td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#dce4f0;font-size:10px">bet365-vn.com</td><td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#e05050;font-weight:600">Malicious</td><td style="padding:5px 8px;border-bottom:1px solid #1e2b3f;color:#dce4f0">3</td></tr>
    <tr><td style="padding:5px 8px;color:#dce4f0">DOMAIN</td><td style="padding:5px 8px;color:#dce4f0;font-size:10px">govagency.vn</td><td style="padding:5px 8px;color:#22c55e;font-weight:600">Benign</td><td style="padding:5px 8px;color:#dce4f0">0</td></tr>
  </tbody>
</table>
<div style="margin-top:8px;font-size:11px;color:#f87171"><strong>Key finding:</strong> 5 of 6 indicators malicious. C2 domains actively communicating. Recommend immediate containment of web-prod-03.</div>
`;

const AUTO_ENG_RESULT_HTML = `
<div style="font-size:10px;font-weight:700;color:#3fa0e0;letter-spacing:.06em;margin-bottom:5px;display:flex;align-items:center;gap:5px">⚙ GENERATED SCRIPT — ChangeIndicatorVerdict</div>
<pre style="background:#0d1019;border:1px solid #1e2233;border-radius:6px;padding:10px;font-size:10.5px;color:#86efac;overflow-x:auto;margin-top:6px;line-height:1.5">
<span style="color:#38506e">"""
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
<div style="font-size:11px;color:#6a80a0;margin-top:6px">Script #1 generated — 55 lines, 2 Arguments, 1 Output. Docstring and debug messages included.</div>
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
@keyframes agentix-cursor-blink {
  0%, 100% { opacity: 1; }
  50% { opacity: 0; }
}
`;

// ── Sub-components ─────────────────────────────────────────────────────────────

function ThinkingBubble({ text }: { text: string }) {
  return (
    <div style={{ alignSelf: 'flex-start', display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--text-muted)', fontStyle: 'italic' }}>
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
    <div style={{ alignSelf: 'flex-start', background: 'var(--bg-secondary)', border: '1px solid var(--border-light)', borderRadius: '10px 10px 10px 2px', padding: '10px 14px', maxWidth: '90%', fontSize: 12.5, color: 'var(--text-primary)', lineHeight: 1.5 }}>
      <div style={{ marginBottom: 8 }}>{text}</div>
      <div style={{ display: 'flex', gap: 8 }}>
        <button onClick={onYes} className="btn-primary btn-sm">Yes</button>
        <button onClick={onNo} className="btn-danger btn-sm">No</button>
      </div>
    </div>
  );
}

// ── Follow-up question chips ───────────────────────────────────────────────────

interface FollowUpChipsProps {
  questions: string[];
  onSelect: (q: string) => void;
}

function FollowUpChips({ questions, onSelect }: FollowUpChipsProps) {
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginTop: 6, alignSelf: 'flex-start' }}>
      {questions.map(q => (
        <button
          key={q}
          onClick={() => onSelect(q)}
          style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-light)',
            borderRadius: 12,
            padding: '3px 10px',
            fontSize: 10.5,
            color: 'var(--accent-blue)',
            cursor: 'pointer',
            whiteSpace: 'nowrap',
            transition: 'background .15s, border-color .15s',
          }}
          onMouseEnter={e => {
            (e.currentTarget as HTMLButtonElement).style.background = 'var(--bg-card2)';
            (e.currentTarget as HTMLButtonElement).style.borderColor = 'var(--accent-blue)';
          }}
          onMouseLeave={e => {
            (e.currentTarget as HTMLButtonElement).style.background = 'var(--bg-card)';
            (e.currentTarget as HTMLButtonElement).style.borderColor = 'var(--border-light)';
          }}
        >
          {q}
        </button>
      ))}
    </div>
  );
}

// ── Message bubble with actions ────────────────────────────────────────────────

interface 对话BubbleProps {
  msg: 对话Message;
  onEdit?: (text: string) => void;
  onSave?: (text: string) => void;
  onFollowUp?: (q: string) => void;
}

function 对话Bubble({ msg, onEdit, onSave, onFollowUp }: 对话BubbleProps) {
  const [hovered, setHovered] = useState(false);
  const [copied, setCopied] = useState(false);
  const timeLabel = msg.msgTime ? relativeTime(msg.msgTime) : '';

  // Extract plain text from html for copy/save
  const plainText = msg.html
    ? (() => {
        const div = document.createElement('div');
        div.innerHTML = msg.html;
        return div.textContent ?? div.innerText ?? '';
      })()
    : (msg.text ?? '');

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(plainText).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }).catch(() => {/* ignore */});
  };

  const handleSave = (e: React.MouseEvent) => {
    e.stopPropagation();
    onSave?.(plainText);
  };

  const handleEdit = (e: React.MouseEvent) => {
    e.stopPropagation();
    onEdit?.(msg.text ?? '');
  };

  if (msg.role === 'user') {
    return (
      <div
        style={{ alignSelf: 'flex-end', display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 3, maxWidth: '85%' }}
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
      >
        {msg.hasContext && (
          <div style={{ fontSize: 10, background: 'rgba(63,160,224,.12)', border: '1px solid rgba(63,160,224,.25)', borderRadius: 10, padding: '2px 8px', color: 'var(--accent-blue)', marginBottom: 2, alignSelf: 'flex-end' }}>
            📌 上下文已附加
          </div>
        )}
        <div style={{ background: 'var(--bg-card2)', border: '1px solid var(--border-light)', borderRadius: '10px 10px 2px 10px', padding: '10px 14px', fontSize: 12.5, color: 'var(--text-primary)', lineHeight: 1.5 }}>
          {msg.text}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          {timeLabel && (
            <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{timeLabel}</span>
          )}
          <span style={{ opacity: hovered ? 1 : 0, transition: 'opacity .15s', display: 'flex', gap: 4 }}>
            <ActionBtn onClick={handleEdit} title="重发">✏️ 重发</ActionBtn>
          </span>
        </div>
      </div>
    );
  }

  if (msg.html) {
    return (
      <div
        style={{ alignSelf: 'flex-start', display: 'flex', flexDirection: 'column', gap: 3, maxWidth: '90%' }}
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
      >
        <div
          style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '10px 10px 10px 2px', padding: '10px 14px', fontSize: 12.5, color: 'var(--text-primary)', lineHeight: 1.5 }}
          dangerouslySetInnerHTML={{ __html: msg.html }}
        />
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {timeLabel && (
            <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{timeLabel}</span>
          )}
          <span style={{ opacity: hovered ? 1 : 0, transition: 'opacity .15s', display: 'flex', gap: 4 }}>
            <ActionBtn onClick={handleCopy} title="复制">{copied ? '✅' : '📋 复制'}</ActionBtn>
            <ActionBtn onClick={handleSave} title="收藏">⭐ 收藏</ActionBtn>
          </span>
        </div>
        {msg.followUps && msg.followUps.length > 0 && onFollowUp && (
          <FollowUpChips questions={msg.followUps} onSelect={onFollowUp} />
        )}
      </div>
    );
  }

  // Plain text agent message (may be streaming) — render markdown when not streaming
  const renderedHtml = !msg.streaming && msg.text ? renderMarkdown(msg.text) : null;

  return (
    <div
      style={{ alignSelf: 'flex-start', display: 'flex', flexDirection: 'column', gap: 3, maxWidth: '90%' }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <div
        style={{ background: 'var(--bg-secondary)', border: '1px solid #2d3452', borderRadius: '10px 10px 10px 2px', padding: '10px 14px', fontSize: 12.5, color: 'var(--text-primary)', lineHeight: 1.5 }}
      >
        {msg.streaming ? (
          <>
            {msg.text}
            <span style={{ display: 'inline-block', width: 2, height: 14, background: 'var(--accent-blue)', marginLeft: 2, verticalAlign: 'text-bottom', animation: 'agentix-cursor-blink 0.8s infinite' }} />
          </>
        ) : (
          <div dangerouslySetInnerHTML={{ __html: renderedHtml ?? '' }} />
        )}
      </div>
      {!msg.streaming && (
        <>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {timeLabel && (
              <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{timeLabel}</span>
            )}
            <span style={{ opacity: hovered ? 1 : 0, transition: 'opacity .15s', display: 'flex', gap: 4 }}>
              <ActionBtn onClick={handleCopy} title="复制">{copied ? '✅' : '📋 复制'}</ActionBtn>
              <ActionBtn onClick={handleSave} title="收藏">⭐ 收藏</ActionBtn>
            </span>
          </div>
          {msg.followUps && msg.followUps.length > 0 && onFollowUp && (
            <FollowUpChips questions={msg.followUps} onSelect={onFollowUp} />
          )}
        </>
      )}
    </div>
  );
}

function ActionBtn({ onClick, title, children }: { onClick: (e: React.MouseEvent) => void; title: string; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      title={title}
      style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border)',
        color: 'var(--text-secondary)',
        fontSize: 11,
        padding: '2px 6px',
        borderRadius: 4,
        cursor: 'pointer',
        lineHeight: 1.5,
        transition: 'background .15s',
      }}
      onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.background = 'var(--bg-card2)'; }}
      onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = 'var(--bg-card)'; }}
    >
      {children}
    </button>
  );
}

// ── Keyboard shortcuts tooltip ─────────────────────────────────────────────────

function ShortcutHelp() {
  const [open, setOpen] = useState(false);
  return (
    <div style={{ position: 'relative', display: 'inline-block' }}>
      <button
        onClick={() => setOpen(v => !v)}
        title="快捷键帮助"
        style={{ background: 'none', border: '1px solid var(--border)', color: 'var(--text-muted)', fontSize: 11, padding: '2px 7px', borderRadius: 4, cursor: 'pointer', lineHeight: 1.6 }}
      >
        ？
      </button>
      {open && (
        <div
          style={{
            position: 'absolute',
            bottom: 'calc(100% + 8px)',
            right: 0,
            background: 'var(--bg-drawer)',
            border: '1px solid var(--border-light)',
            borderRadius: 8,
            padding: '10px 14px',
            fontSize: 11,
            color: 'var(--text-secondary)',
            whiteSpace: 'nowrap',
            zIndex: 10,
            boxShadow: '0 4px 20px rgba(0,0,0,.5)',
            minWidth: 200,
          }}
        >
          <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: 8, fontSize: 12 }}>快捷键</div>
          {[
            ['Enter', '发送消息'],
            ['Shift+Enter', '换行'],
            ['Ctrl+K', '清空对话'],
            ['/', '聚焦输入框'],
          ].map(([key, desc]) => (
            <div key={key} style={{ display: 'flex', justifyContent: 'space-between', gap: 16, marginBottom: 5 }}>
              <kbd style={{ background: 'var(--bg-card2)', border: '1px solid var(--border-light)', borderRadius: 3, padding: '1px 5px', fontSize: 10, color: 'var(--accent-blue)', fontFamily: 'monospace' }}>{key}</kbd>
              <span>{desc}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── SVG Diagram ────────────────────────────────────────────────────────────────

function AgentixDiagram() {
  const connLine: React.CSSProperties = { stroke: 'var(--border-light)', strokeWidth: 1.5 };
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
          <path d="M0 0 L6 3 L0 6 Z" fill="var(--border-light)" />
        </marker>
      </defs>

      {/* Progress bar */}
      <rect x="280" y="18" width="220" height="8" rx="4" fill="var(--bg-card)" />
      <rect x="280" y="18" width="186" height="8" rx="4" fill="var(--accent-blue)" opacity=".7" />

      {/* Automations node */}
      <rect x="305" y="34" width="170" height="44" rx="8" fill="var(--bg-card)" stroke="var(--border-light)" strokeWidth="1.5" />
      <text x="390" y="52" textAnchor="middle" fill="var(--text-secondary)" fontSize="9" fontWeight="600" letterSpacing="1" fontFamily="Inter,sans-serif">AUTOMATIONS</text>
      <text x="390" y="68" textAnchor="middle" fill="var(--text-primary)" fontSize="12" fontWeight="700" fontFamily="Inter,sans-serif">2,234 Plans</text>

      {/* Connector lines */}
      <line x1="390" y1="78" x2="390" y2="108" style={connLine} />
      <line x1="110" y1="108" x2="670" y2="108" style={connLine} />
      <line x1="110" y1="108" x2="110" y2="148" style={connLine} />
      <line x1="238" y1="108" x2="238" y2="148" style={connLine} />
      <line x1="366" y1="108" x2="366" y2="148" style={connLine} />
      <line x1="494" y1="108" x2="494" y2="148" style={connLine} />
      <line x1="622" y1="108" x2="622" y2="148" style={connLine} />
      <line x1="750" y1="108" x2="750" y2="148" stroke="var(--border-light)" strokeWidth="1.5" fill="none" strokeDasharray="4 3" />

      {/* Agent 1: Email Investigation (orange) */}
      <rect x="50" y="148" width="120" height="88" rx="8" fill="var(--bg-secondary)" stroke="var(--border-light)" strokeWidth="1.5" />
      <circle cx="110" cy="176" r="18" fill="url(#g-orange)" />
      <text x="110" y="181" textAnchor="middle" fill="#fff" fontSize="14">✉</text>
      <text x="110" y="214" textAnchor="middle" fill="var(--text-primary)" fontSize="9" fontWeight="600" fontFamily="Inter,sans-serif">Email Investigation</text>
      <text x="110" y="226" textAnchor="middle" fill="var(--text-muted)" fontSize="9" fontFamily="Inter,sans-serif">Agent</text>
      <text x="110" y="238" textAnchor="middle" fill="var(--text-secondary)" fontSize="10" fontWeight="700" fontFamily="Inter,sans-serif">158 Plans</text>

      {/* Agent 2: Endpoint Investigation (purple) */}
      <rect x="178" y="148" width="120" height="88" rx="8" fill="var(--bg-secondary)" stroke="var(--border-light)" strokeWidth="1.5" />
      <circle cx="238" cy="176" r="18" fill="url(#g-purple)" />
      <text x="238" y="181" textAnchor="middle" fill="#fff" fontSize="14">🖥</text>
      <text x="238" y="214" textAnchor="middle" fill="var(--text-primary)" fontSize="9" fontWeight="600" fontFamily="Inter,sans-serif">Endpoint Investigation</text>
      <text x="238" y="226" textAnchor="middle" fill="var(--text-muted)" fontSize="9" fontFamily="Inter,sans-serif">Agent</text>
      <text x="238" y="238" textAnchor="middle" fill="var(--text-secondary)" fontSize="10" fontWeight="700" fontFamily="Inter,sans-serif">154 Plans</text>

      {/* Agent 3: Network Security (yellow) */}
      <rect x="306" y="148" width="120" height="88" rx="8" fill="var(--bg-secondary)" stroke="var(--border-light)" strokeWidth="1.5" />
      <circle cx="366" cy="176" r="18" fill="url(#g-yellow)" />
      <text x="366" y="181" textAnchor="middle" fill="#fff" fontSize="14">🛡</text>
      <text x="366" y="214" textAnchor="middle" fill="var(--text-primary)" fontSize="9" fontWeight="600" fontFamily="Inter,sans-serif">Network Security</text>
      <text x="366" y="226" textAnchor="middle" fill="var(--text-muted)" fontSize="9" fontFamily="Inter,sans-serif">Agent</text>
      <text x="366" y="238" textAnchor="middle" fill="var(--text-secondary)" fontSize="10" fontWeight="700" fontFamily="Inter,sans-serif">91 Plans</text>

      {/* Agent 4: Threat Intel (teal) */}
      <rect x="434" y="148" width="120" height="88" rx="8" fill="var(--bg-secondary)" stroke="var(--border-light)" strokeWidth="1.5" />
      <circle cx="494" cy="176" r="18" fill="url(#g-teal)" />
      <text x="494" y="181" textAnchor="middle" fill="#fff" fontSize="14">🔍</text>
      <text x="494" y="214" textAnchor="middle" fill="var(--text-primary)" fontSize="9" fontWeight="600" fontFamily="Inter,sans-serif">Threat Intel</text>
      <text x="494" y="226" textAnchor="middle" fill="var(--text-muted)" fontSize="9" fontFamily="Inter,sans-serif">Agent</text>
      <text x="494" y="238" textAnchor="middle" fill="var(--text-secondary)" fontSize="10" fontWeight="700" fontFamily="Inter,sans-serif">113 Plans</text>

      {/* Agent 5: IT Agent (pink) */}
      <rect x="562" y="148" width="120" height="88" rx="8" fill="var(--bg-secondary)" stroke="var(--border-light)" strokeWidth="1.5" />
      <circle cx="622" cy="176" r="18" fill="url(#g-pink)" />
      <text x="622" y="181" textAnchor="middle" fill="#fff" fontSize="14">⚙</text>
      <text x="622" y="214" textAnchor="middle" fill="var(--text-primary)" fontSize="9" fontWeight="600" fontFamily="Inter,sans-serif">IT Agent</text>
      <text x="622" y="226" textAnchor="middle" fill="var(--text-muted)" fontSize="9" fontFamily="Inter,sans-serif"> </text>
      <text x="622" y="238" textAnchor="middle" fill="var(--text-secondary)" fontSize="10" fontWeight="700" fontFamily="Inter,sans-serif">60 Plans</text>

      {/* +8 Other Agents (dashed) */}
      <rect x="706" y="148" width="88" height="88" rx="8" fill="#111520" stroke="var(--border-light)" strokeWidth="1.5" strokeDasharray="4 3" />
      <circle cx="750" cy="172" r="14" fill="var(--bg-card)" stroke="var(--border-light)" strokeWidth="1" />
      <circle cx="750" cy="176" r="11" fill="#151a27" stroke="var(--border-light)" strokeWidth="1" />
      <text x="750" y="181" textAnchor="middle" fill="var(--text-muted)" fontSize="10">+8</text>
      <text x="750" y="214" textAnchor="middle" fill="var(--text-muted)" fontSize="9" fontWeight="600" fontFamily="Inter,sans-serif">+8 Other Agents</text>
      <text x="750" y="230" textAnchor="middle" fill="var(--text-muted)" fontSize="10" fontFamily="Inter,sans-serif">3 Plans</text>

      {/* Execution lines */}
      <line x1="170" y1="192" x2="210" y2="192" stroke="var(--border-light)" strokeWidth="1.5" fill="none" opacity=".4" />
      <line x1="298" y1="192" x2="306" y2="192" stroke="var(--border-light)" strokeWidth="1.5" fill="none" opacity=".4" />

      {/* Case Investigation node */}
      <rect x="306" y="258" width="168" height="44" rx="8" fill="#111b11" stroke="rgba(47,176,122,.30)" strokeWidth="1.5" />
      <text x="390" y="276" textAnchor="middle" fill="var(--accent-green)" fontSize="9" fontWeight="600" letterSpacing="1" fontFamily="Inter,sans-serif">CASE INVESTIGATION</text>
      <text x="390" y="292" textAnchor="middle" fill="#86efac" fontSize="11" fontWeight="700" fontFamily="Inter,sans-serif">Agent</text>
      <line x1="390" y1="236" x2="390" y2="258" stroke="rgba(47,176,122,.30)" strokeWidth="1.5" fill="none" />
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

// ── Saved Analyses Modal ───────────────────────────────────────────────────────

interface SavedModalProps {
  item: SavedAnalysis;
  onClose: () => void;
}

function SavedModal({ item, onClose }: SavedModalProps) {
  return (
    <div
      style={{ position: 'fixed', inset: 0, zIndex: 400, background: 'var(--bg-overlay)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}
      onClick={onClose}
    >
      <div
        style={{ background: 'var(--bg-drawer)', border: '1px solid var(--border-light)', borderRadius: 10, padding: '20px 24px', maxWidth: 560, width: '90%', maxHeight: '70vh', overflow: 'auto', position: 'relative' }}
        onClick={e => e.stopPropagation()}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
          <span style={{ fontSize: 11, color: 'var(--text-muted)', background: 'var(--bg-card)', borderRadius: 10, padding: '2px 10px' }}>{formatTimestamp(item.timestamp)}</span>
          <button onClick={onClose} className="btn-icon">✕</button>
        </div>
        <div style={{ fontSize: 12.5, color: 'var(--text-primary)', lineHeight: 1.7, whiteSpace: 'pre-wrap' }}>{item.fullText}</div>
      </div>
    </div>
  );
}

// ── Saved Analyses Sidebar ─────────────────────────────────────────────────────

interface SavedSidebarProps {
  savedList: SavedAnalysis[];
  onDelete: (id: string) => void;
  onClearAll: () => void;
  onClose: () => void;
}

function SavedSidebar({ savedList, onDelete, onClearAll, onClose }: SavedSidebarProps) {
  const [modalItem, setModalItem] = useState<SavedAnalysis | null>(null);

  return (
    <>
      <div style={{
        width: 260,
        height: '100%',
        background: 'var(--bg-drawer)',
        borderLeft: '1px solid var(--border-light)',
        display: 'flex',
        flexDirection: 'column',
        flexShrink: 0,
      }}>
        {/* Sidebar header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 14px', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
          <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)' }}>📚 已保存分析 ({savedList.length})</span>
          <button onClick={onClose} className="btn-icon">✕</button>
        </div>

        {/* Items list */}
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {savedList.length === 0 && (
            <div style={{ padding: '16px 14px', fontSize: 11, color: 'var(--text-muted)', fontStyle: 'italic', textAlign: 'center' }}>暂无保存的分析</div>
          )}
          {savedList.slice(0, 20).map(item => (
            <div
              key={item.id}
              style={{ padding: '8px 14px', borderBottom: '1px solid var(--border)', cursor: 'pointer' }}
              onClick={() => setModalItem(item)}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 3 }}>
                <span style={{ fontSize: 10, background: 'var(--bg-card)', borderRadius: 8, padding: '1px 7px', color: 'var(--text-muted)' }}>{formatTimestamp(item.timestamp)}</span>
                <button
                  onClick={e => { e.stopPropagation(); onDelete(item.id); }}
                  title="删除"
                  className="btn-icon"
                  style={{ fontSize: 13 }}
                >
                  🗑️
                </button>
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-secondary)', overflow: 'hidden', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical' as const }}>
                {item.fullText.slice(0, 100)}{item.fullText.length > 100 ? '…' : ''}
              </div>
            </div>
          ))}
        </div>

        {/* Clear all button */}
        {savedList.length > 0 && (
          <div style={{ padding: '10px 14px', borderTop: '1px solid var(--border)', flexShrink: 0 }}>
            <button onClick={onClearAll} className="btn-secondary" style={{ width: '100%' }}>
              清空全部
            </button>
          </div>
        )}
      </div>

      {/* Modal for selected item */}
      {modalItem && (
        <SavedModal item={modalItem} onClose={() => setModalItem(null)} />
      )}
    </>
  );
}

// ── Conversation History Sidebar ───────────────────────────────────────────────

interface ConvHistorySidebarProps {
  conversations: ConversationRecord[];
  activeConvId: string | null;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  onNewConversation: () => void;
  onSelectConversation: (id: string) => void;
  onDeleteConversation: (id: string) => void;
}

function ConvHistorySidebar({
  conversations,
  activeConvId,
  searchQuery,
  onSearchChange,
  onNewConversation,
  onSelectConversation,
  onDeleteConversation,
}: ConvHistorySidebarProps) {
  const [hoveredId, setHoveredId] = useState<string | null>(null);

  const filtered = searchQuery.trim()
    ? conversations.filter(c => c.title.toLowerCase().includes(searchQuery.toLowerCase()))
    : conversations;

  return (
    <div style={{
      width: 220,
      height: '100%',
      background: 'var(--bg-drawer)',
      borderRight: '1px solid var(--border)',
      display: 'flex',
      flexDirection: 'column',
      flexShrink: 0,
    }}>
      {/* Header */}
      <div style={{ padding: '12px 12px 8px', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
        <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', letterSpacing: '.06em', marginBottom: 8 }}>对话历史</div>
        <button
          onClick={onNewConversation}
          className="btn-primary"
          style={{ width: '100%', justifyContent: 'center', marginBottom: 8 }}
        >
          <span style={{ fontSize: 14, lineHeight: 1 }}>+</span> 新对话
        </button>
        {/* Search */}
        <div style={{ position: 'relative' }}>
          <span style={{ position: 'absolute', left: 7, top: '50%', transform: 'translateY(-50%)', fontSize: 11, color: 'var(--text-muted)', pointerEvents: 'none' }}>🔍</span>
          <input
            type="text"
            placeholder="搜索…"
            value={searchQuery}
            onChange={e => onSearchChange(e.target.value)}
            className="filter-input"
            style={{ width: '100%', paddingLeft: 24 }}
          />
        </div>
      </div>

      {/* Conversation list */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {filtered.length === 0 && (
          <div style={{ padding: '14px 12px', fontSize: 11, color: 'var(--text-muted)', fontStyle: 'italic', textAlign: 'center' }}>
            {searchQuery ? '无匹配结果' : '暂无历史对话'}
          </div>
        )}
        {filtered.map(conv => (
          <div
            key={conv.id}
            onMouseEnter={() => setHoveredId(conv.id)}
            onMouseLeave={() => setHoveredId(null)}
            onClick={() => onSelectConversation(conv.id)}
            style={{
              padding: '8px 10px',
              borderBottom: '1px solid var(--border)',
              cursor: 'pointer',
              background: activeConvId === conv.id ? 'var(--bg-card2)' : hoveredId === conv.id ? 'var(--bg-card)' : 'transparent',
              display: 'flex',
              alignItems: 'flex-start',
              gap: 6,
              transition: 'background .15s',
              position: 'relative',
            }}
          >
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{
                fontSize: 11,
                color: activeConvId === conv.id ? 'var(--accent-blue)' : 'var(--text-secondary)',
                fontWeight: activeConvId === conv.id ? 600 : 400,
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
                marginBottom: 2,
              }}>
                {conv.title}
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>{relativeTime(conv.createdAt)}</div>
            </div>
            {/* Delete button on hover */}
            {hoveredId === conv.id && (
              <button
                onClick={e => { e.stopPropagation(); onDeleteConversation(conv.id); }}
                title="删除"
                className="btn-icon"
                style={{ color: 'var(--critical)', fontSize: 13 }}
              >
                🗑
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Main page component ────────────────────────────────────────────────────────

export default function Agentix() {
  const [panelOpen, setPanelOpen] = useState(false);
  const [activeAgent, setActiveAgent] = useState<AgentKey>('threatIntel');
  const [activePanelTab, setActivePanelTab] = useState<PanelTab>('threatIntel');
  const [inputText, setInputText] = useState('');
  const [loading, setLoading] = useState(false);
  const [contextMode, setContextMode] = useState<ContextMode>('none');
  const [contextLoaded, setContextLoaded] = useState<{ mode: ContextMode; count: number } | null>(null);
  const [savedOpen, setSavedOpen] = useState(false);
  const [savedList, setSavedList] = useState<SavedAnalysis[]>(() => loadSaved());
  const [streamingMsgId, setStreamingMsgId] = useState<string | null>(null);
  const streamCancelRef = useRef<boolean>(false);
  const chatScrollRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // NL2XQL state
  const [xqlInput, setXqlInput] = useState('');
  const [xqlResult, setXqlResult] = useState<string | null>(null);
  const [xqlLoading, setXqlLoading] = useState(false);
  const [xqlError, setXqlError] = useState<string | null>(null);
  const [xqlCopied, setXqlCopied] = useState(false);
  const [xqlToast, setXqlToast] = useState(false);

  // Alert AI summary state — cache keyed by alert _key
  const [alertSummaryCache, setAlertSummaryCache] = useState<Record<string, string>>({});
  const [alertSummaryKey, setAlertSummaryKey] = useState<string | null>(null);
  const [alertSummaryLoading, setAlertSummaryLoading] = useState(false);
  const [alertSummaryError, setAlertSummaryError] = useState<string | null>(null);

  // Conversation history sidebar state
  const [conversations, setConversations] = useState<ConversationRecord[]>(() => loadConversations());
  const [activeConvId, setActiveConvId] = useState<string | null>(null);
  const [convSearchQuery, setConvSearchQuery] = useState('');

  // Per-agent chat state
  const ti对话 = use对话('threatIntel');
  const ci对话 = use对话('caseInv');
  const ae对话 = use对话('autoEng');

  // Copilot (panel) conversation — separate from agent flows, persisted in localStorage
  const [copilotMessages, setCopilotMessages] = useState<对话Message[]>(() => loadHistory());

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
  }, [current对话.entries, copilotMessages]);

  // Persist copilot messages whenever they change
  useEffect(() => {
    saveHistory(copilotMessages);
    // Also update active conversation record if one is active
    if (activeConvId) {
      setConversations(prev => {
        const next = prev.map(c =>
          c.id === activeConvId ? { ...c, messages: copilotMessages } : c
        );
        saveConversations(next);
        return next;
      });
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [copilotMessages]);

  // Ctrl+K → clear history; / → focus input
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.key === 'k') {
        e.preventDefault();
        handleClearHistory();
      }
      if (e.key === '/' && document.activeElement !== textareaRef.current) {
        e.preventDefault();
        textareaRef.current?.focus();
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const openPanel = useCallback((agent: AgentKey) => {
    setActiveAgent(agent);
    setActivePanelTab(agent);
    setPanelOpen(true);
  }, []);

  // ── Conversation history management ───────────────────────────────────────

  const handleNewConversation = useCallback(() => {
    // Save current messages into current conv if there are messages
    if (copilotMessages.length > 0 && !activeConvId) {
      const title = (copilotMessages.find(m => m.role === 'user')?.text ?? '新对话').slice(0, 40);
      const newConv: ConversationRecord = {
        id: newConvId(),
        title,
        createdAt: Date.now(),
        messages: copilotMessages,
      };
      setConversations(prev => {
        const next = [newConv, ...prev].slice(0, 50);
        saveConversations(next);
        return next;
      });
    }
    // Start fresh
    streamCancelRef.current = true;
    setStreamingMsgId(null);
    setCopilotMessages([]);
    setActiveConvId(null);
    setContextLoaded(null);
    localStorage.removeItem(LS_KEY);
  }, [copilotMessages, activeConvId]);

  const handleSelectConversation = useCallback((id: string) => {
    // Save current conversation if it has messages and no active conv
    if (copilotMessages.length > 0 && !activeConvId) {
      const title = (copilotMessages.find(m => m.role === 'user')?.text ?? '新对话').slice(0, 40);
      const newConv: ConversationRecord = {
        id: newConvId(),
        title,
        createdAt: Date.now(),
        messages: copilotMessages,
      };
      setConversations(prev => {
        const next = [newConv, ...prev].slice(0, 50);
        saveConversations(next);
        return next;
      });
    }
    const conv = conversations.find(c => c.id === id);
    if (conv) {
      streamCancelRef.current = true;
      setStreamingMsgId(null);
      setCopilotMessages(conv.messages);
      setActiveConvId(id);
      setContextLoaded(null);
    }
  }, [conversations, copilotMessages, activeConvId]);

  const handleDeleteConversation = useCallback((id: string) => {
    setConversations(prev => {
      const next = prev.filter(c => c.id !== id);
      saveConversations(next);
      return next;
    });
    if (activeConvId === id) {
      setCopilotMessages([]);
      setActiveConvId(null);
    }
  }, [activeConvId]);

  // ── Clear conversation ─────────────────────────────────────────────────────

  const handleClearHistory = useCallback(() => {
    streamCancelRef.current = true;
    setStreamingMsgId(null);
    setCopilotMessages([]);
    setActiveConvId(null);
    setContextLoaded(null);
    localStorage.removeItem(LS_KEY);
  }, []);

  // ── Saved analyses ─────────────────────────────────────────────────────────

  const handleSave = useCallback((text: string) => {
    const item: SavedAnalysis = {
      id: newMsgId(),
      timestamp: Date.now(),
      preview: text.slice(0, 100),
      fullText: text,
    };
    setSavedList(prev => {
      const next = [item, ...prev].slice(0, 20);
      saveSavedList(next);
      return next;
    });
  }, []);

  const handleDeleteSaved = useCallback((id: string) => {
    setSavedList(prev => {
      const next = prev.filter(s => s.id !== id);
      saveSavedList(next);
      return next;
    });
  }, []);

  const handleClearAllSaved = useCallback(() => {
    setSavedList([]);
    saveSavedList([]);
  }, []);

  // ── Streaming simulation (~25ms per char) ──────────────────────────────────

  const startStreaming = useCallback((fullText: string, msgId: string) => {
    streamCancelRef.current = false;
    setStreamingMsgId(msgId);
    let idx = 0;

    // Insert placeholder message with streaming=true
    const placeholderMsg: 对话Message = { id: msgId, role: 'agent', text: '', streaming: true, msgTime: Date.now() };
    setCopilotMessages(prev => [...prev, placeholderMsg]);

    const tick = setInterval(() => {
      if (streamCancelRef.current) {
        clearInterval(tick);
        // Finalize with full text + follow-ups
        const followUps = getFollowUpQuestions(fullText);
        setCopilotMessages(prev =>
          prev.map(m => m.id === msgId ? { ...m, text: fullText, streaming: false, followUps } : m)
        );
        setStreamingMsgId(null);
        return;
      }
      idx += 1;
      const current = fullText.slice(0, idx);
      setCopilotMessages(prev =>
        prev.map(m => m.id === msgId ? { ...m, text: current } : m)
      );
      if (idx >= fullText.length) {
        clearInterval(tick);
        const followUps = getFollowUpQuestions(fullText);
        setCopilotMessages(prev =>
          prev.map(m => m.id === msgId ? { ...m, streaming: false, followUps } : m)
        );
        setStreamingMsgId(null);
      }
    }, 25);
  }, []);

  // ── Context fetching ───────────────────────────────────────────────────────

  const fetchContextBlock = useCallback(async (mode: ContextMode): Promise<string> => {
    if (mode === 'none') return '';
    try {
      if (mode === 'alerts') {
        const r = await api.get('/alerts', { params: { page_size: 3, sort_by: 'triggered_at', sort_desc: true } });
        const items: Array<Record<string, unknown>> = r.data?.data?.items ?? r.data?.items ?? [];
        if (!items.length) {
          setContextLoaded({ mode, count: 0 });
          return 'Recent alerts:\n暂无告警数据\n\n';
        }
        const summaries = items.map((a, i) =>
          `${i + 1}. ${String(a.name ?? a.title ?? a._key ?? '告警')} [${String(a.severity ?? '未知')}] 状态:${String(a.status ?? '')}`
        ).join('\n');
        setContextLoaded({ mode, count: items.length });
        return `Recent alerts:\n${summaries}\n\n`;
      }
      if (mode === 'incidents') {
        const r = await api.get('/incidents', { params: { page_size: 3 } });
        const items: Array<Record<string, unknown>> = r.data?.data?.items ?? r.data?.items ?? [];
        if (!items.length) {
          setContextLoaded({ mode, count: 0 });
          return 'Active incidents:\n暂无开放事件\n\n';
        }
        const summaries = items.map((a, i) =>
          `${i + 1}. ${String(a.title ?? a.name ?? a._key ?? '事件')} [score:${String(a.smart_score ?? a.score ?? '?')}] 状态:${String(a.status ?? '')}`
        ).join('\n');
        setContextLoaded({ mode, count: items.length });
        return `Active incidents:\n${summaries}\n\n`;
      }
      if (mode === 'vulns') {
        const r = await api.get('/vulnerabilities', { params: { page_size: 3 } });
        const items: Array<Record<string, unknown>> = r.data?.data?.items ?? r.data?.items ?? [];
        if (!items.length) {
          setContextLoaded({ mode, count: 0 });
          return 'Top vulnerabilities:\n暂无漏洞数据\n\n';
        }
        const summaries = items.map((a, i) =>
          `${i + 1}. ${String(a.cve_id ?? a.title ?? a._key ?? '漏洞')} [${String(a.severity ?? '未知')}] CVSS:${String(a.cvss_score ?? a.score ?? '?')}`
        ).join('\n');
        setContextLoaded({ mode, count: items.length });
        return `Top vulnerabilities:\n${summaries}\n\n`;
      }
    } catch {
      // silently fall through
    }
    return '';
  }, []);

  // ── Pending flow continuation ref ─────────────────────────────────────────

  interface PendingContinuation {
    approvalEntryId: number;
    chat: ReturnType<typeof use对话> & { setEntries?: React.Dispatch<React.SetStateAction<对话Entry[]>> };
    steps: FlowStep[];
    nextIdx: number;
  }

  const pendingContinuationRef = useRef<PendingContinuation | null>(null);

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
          p.chat.setEntries?.(prev => [...prev, { id: nextId(), kind: 'message', data: { id: newMsgId(), role: 'agent', html: step.html, msgTime: Date.now() } }]);
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
    p.chat.setEntries?.(prev => [...prev, { id: nextId(), kind: 'message', data: { id: newMsgId(), role: 'agent', text: 'Understood, cancelled.', msgTime: Date.now() } }]);
    pendingContinuationRef.current = null;
  }, []);

  // ── runFlow (agent flows) — reserved for future agent flow execution ────────
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  // @ts-ignore: reserved for future use
  const _runFlow = useCallback((agent: AgentKey, text: string) => {
    const chat = chatForAgent(agent);
    const steps = AGENT_FLOWS[agent];

    // Add user message
    chat.setEntries?.(prev => [...prev, { id: nextId(), kind: 'message', data: { id: newMsgId(), role: 'user', text, msgTime: Date.now() } }]);

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
        pendingContinuationRef.current = {
          approvalEntryId,
          chat,
          steps,
          nextIdx: stepIdx + 1,
        };
      } else if (step.type === 'result') {
        chat.setEntries?.(prev => [...prev, { id: nextId(), kind: 'message', data: { id: newMsgId(), role: 'agent', html: step.html, msgTime: Date.now() } }]);
      }
    };

    setTimeout(() => execStep(0), 300);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeAgent]);

  // ── sendMessage (copilot API, persisted) ──────────────────────────────────

  const sendMessage = useCallback(async (text: string) => {
    // Cancel any active streaming
    if (streamingMsgId) {
      streamCancelRef.current = true;
    }

    const hasContext = contextMode !== 'none';

    // Build final message with context prefix
    const contextBlock = await fetchContextBlock(contextMode);
    const finalText = contextBlock ? `${contextBlock}${text}` : text;

    const userMsg: 对话Message = { id: newMsgId(), role: 'user', text, msgTime: Date.now(), hasContext };

    // If no active conversation, auto-create one when first message is sent
    let convId = activeConvId;
    if (!convId) {
      const title = text.slice(0, 40);
      convId = newConvId();
      const newConv: ConversationRecord = {
        id: convId,
        title,
        createdAt: Date.now(),
        messages: [],
      };
      setConversations(prev => {
        const next = [newConv, ...prev].slice(0, 50);
        saveConversations(next);
        return next;
      });
      setActiveConvId(convId);
    }

    setCopilotMessages(prev => [...prev, userMsg]);
    setLoading(true);
    try {
      const r = await api.post('/copilot/chat', { message: finalText });
      const reply: string = r.data?.data?.reply ?? r.data?.reply ?? 'No response';
      const replyMsgId = newMsgId();
      setLoading(false);
      startStreaming(reply, replyMsgId);
    } catch {
      const replyMsgId = newMsgId();
      const errText = 'Error connecting to AI. Please try again.';
      setLoading(false);
      startStreaming(errText, replyMsgId);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [contextMode, streamingMsgId, fetchContextBlock, startStreaming, activeConvId]);

  const handle発送 = useCallback(() => {
    const text = inputText.trim();
    if (!text || loading) return;
    setInputText('');
    sendMessage(text);
  }, [inputText, loading, sendMessage]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handle発送();
    }
  };

  const handleSuggestion = (s: string) => {
    const text = s.trim();
    if (!text || loading) return;
    setInputText('');
    sendMessage(text);
  };

  const handleChipClick = (chip: string) => {
    if (loading) return;
    setInputText(chip);
  };

  const handleEditMessage = useCallback((text: string) => {
    setInputText(text);
    textareaRef.current?.focus();
  }, []);

  const handleFollowUp = useCallback((q: string) => {
    if (loading) return;
    sendMessage(q);
  }, [loading, sendMessage]);

  // Handle context mode change — reset loaded badge when selecting 'none'
  const handleContextModeChange = useCallback((mode: ContextMode) => {
    setContextMode(mode);
    if (mode === 'none') {
      setContextLoaded(null);
    }
  }, []);

  // ── NL2XQL ────────────────────────────────────────────────────────────────
  const handleNl2Xql = useCallback(async () => {
    const text = xqlInput.trim();
    if (!text || xqlLoading) return;
    setXqlLoading(true);
    setXqlError(null);
    setXqlResult(null);
    try {
      const r = await api.post('/copilot/nl2xql', { query: text });
      const xql: string = r.data?.data?.xql ?? r.data?.xql ?? r.data?.result ?? '';
      setXqlResult(xql || '(No XQL returned)');
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { message?: string } } })?.response?.data?.message ?? 'Failed to convert. Please try again.';
      setXqlError(msg);
    } finally {
      setXqlLoading(false);
    }
  }, [xqlInput, xqlLoading]);

  const handleXqlCopyToClipboard = useCallback(() => {
    if (!xqlResult) return;
    navigator.clipboard.writeText(xqlResult).then(() => {
      setXqlCopied(true);
      setXqlToast(true);
      setTimeout(() => { setXqlCopied(false); setXqlToast(false); }, 2000);
    }).catch(() => {/* ignore */});
  }, [xqlResult]);

  // ── Alert AI Summary ──────────────────────────────────────────────────────
  const fetchAlertSummary = useCallback(async (key: string) => {
    if (!key) return;
    if (alertSummaryCache[key]) {
      setAlertSummaryKey(key);
      return;
    }
    setAlertSummaryKey(key);
    setAlertSummaryLoading(true);
    setAlertSummaryError(null);
    try {
      const r = await api.get(`/alerts/${key}/summary`);
      const summary: string = r.data?.data?.summary ?? r.data?.summary ?? '(No summary available)';
      setAlertSummaryCache(prev => ({ ...prev, [key]: summary }));
    } catch {
      setAlertSummaryError('Unable to load AI summary for this alert.');
    } finally {
      setAlertSummaryLoading(false);
    }
  }, [alertSummaryCache]);

  // ── File attach ────────────────────────────────────────────────────────────

  const handleFileAttach = () => {
    fileInputRef.current?.click();
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    // Reset input so same file can be selected again
    e.target.value = '';
    const reader = new FileReader();
    reader.onload = (ev) => {
      const content = ev.target?.result as string;
      setInputText(prev => prev ? `${prev}\n\n\`\`\`\n[附件: ${file.name}]\n${content}\n\`\`\`` : `\`\`\`\n[附件: ${file.name}]\n${content}\n\`\`\``);
    };
    reader.readAsText(file);
  };

  // Determine whether to show suggestion chips
  // Show when textarea is empty AND no copilot messages
  const showChips = inputText === '' && copilotMessages.length === 0;

  const charCount = inputText.length;
  const charCountColor = charCount > 1800 ? 'var(--critical)' : charCount > 1500 ? 'var(--medium)' : 'var(--text-muted)';

  // Context label for badge
  // Panel total width: history sidebar (220) + chat column (520 or 780 w/ saved)
  const chatColumnWidth = savedOpen ? 520 : 520;
  const panelTotalWidth = 220 + chatColumnWidth + (savedOpen ? 260 : 0);

  // ── Render ───────────────────────────────────────────────────────────────────

  const panelTabStyle = (key: PanelTab): React.CSSProperties => ({
    fontSize: 11,
    padding: '4px 12px',
    borderRadius: '4px 4px 0 0',
    border: '1px solid',
    borderBottom: 'none',
    cursor: 'pointer',
    background: activePanelTab === key ? 'var(--bg-secondary)' : 'var(--bg-card)',
    color: activePanelTab === key ? 'var(--accent-blue)' : 'var(--text-muted)',
    borderColor: activePanelTab === key ? 'var(--border-light)' : 'var(--border)',
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', background: 'var(--bg-primary)', color: 'var(--text-primary)', fontFamily: "'Inter', 'Segoe UI', sans-serif", overflow: 'hidden' }}>

      {/* Top bar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 20px', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--text-secondary)' }}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="8" r="4" />
            <path d="M6 20v-2a4 4 0 014-4h4a4 4 0 014 4v2" />
          </svg>
          <span style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-primary)' }}>Agentix Command Center</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <select className="filter-select" defaultValue="7d">
            <option value="24h">Last 24H</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </select>
          <button onClick={() => openPanel('threatIntel')} className="btn-primary">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="8" r="4" />
              <path d="M6 20v-2a4 4 0 014-4h4a4 4 0 014 4v2" />
            </svg>
            Agentix Assistant
          </button>
          <span style={{ color: 'var(--text-muted)', fontSize: 16, cursor: 'pointer' }}>⋮</span>
        </div>
      </div>

      {/* Canvas */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', padding: '24px 32px 0', overflow: 'hidden', position: 'relative' }}>
        {/* Dot-grid background */}
        <div style={{ position: 'absolute', inset: 0, backgroundImage: 'radial-gradient(circle, var(--border) 1px, transparent 1px)', backgroundSize: '28px 28px', opacity: 0.5, pointerEvents: 'none' }} />

        {/* Stats overlay — left top */}
        <div style={{ position: 'absolute', left: 48, top: 36, zIndex: 2, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
          <div style={{ width: 44, height: 44, borderRadius: '50%', border: '2px solid var(--border-light)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent-blue)', fontSize: 20 }}>⚡</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>2,234</div>
          <div style={{ fontSize: 9.5, fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '.08em', textAlign: 'center', maxWidth: 70 }}>PRE-CONFIGURED<br />TRIGGERS</div>
        </div>

        {/* Stats overlay — left bottom */}
        <div style={{ position: 'absolute', left: 48, bottom: 70, zIndex: 2, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
          <div style={{ width: 40, height: 40, borderRadius: '50%', border: '2px solid var(--border-light)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-secondary)', fontSize: 18 }}>👤</div>
          <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>598</div>
          <div style={{ fontSize: 9.5, fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '.08em', textAlign: 'center', maxWidth: 70 }}>USER<br />PROMPTS</div>
        </div>

        {/* Stats overlay — right */}
        <div style={{ position: 'absolute', right: 40, top: 24, zIndex: 2, display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
          <div style={{ fontSize: 60, fontWeight: 800, color: 'var(--text-primary)', lineHeight: 1, letterSpacing: '-.02em' }}>94%</div>
          <div style={{ fontSize: 19, fontWeight: 700, color: 'var(--text-primary)' }}>2,656 FULLY EXECUTED PLANS</div>
          <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--accent-green)', marginTop: 2 }}>176 PLANS TO REVIEW</div>
        </div>

        {/* SVG Diagram centered */}
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative', zIndex: 1 }}>
          <AgentixDiagram />
        </div>

        {/* Bottom action buttons */}
        <div style={{ position: 'absolute', bottom: 52, left: '50%', transform: 'translateX(-50%)', display: 'flex', gap: 6, zIndex: 3 }}>
          <button onClick={() => openPanel('caseInv')} className="btn-ghost btn-sm">
            + Case Investigation
          </button>
          <button onClick={() => openPanel('autoEng')} className="btn-secondary btn-sm">
            + Automation Engineer
          </button>
          <button onClick={() => openPanel('threatIntel')} className="btn-ghost btn-sm">
            + Threat Intel
          </button>
        </div>
      </div>

      {/* Status bar */}
      <div style={{ display: 'flex', alignItems: 'center', borderTop: '1px solid var(--border)', background: 'var(--bg-card)', padding: '10px 24px', flexShrink: 0, fontSize: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '0 20px', borderRight: '1px solid var(--border)', paddingLeft: 0 }}>
          <span style={{ color: 'var(--text-muted)', fontSize: 11, fontWeight: 500, whiteSpace: 'nowrap' }}>Total Open Cases</span>
          <span style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: 13 }}>57</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '0 20px', borderRight: '1px solid var(--border)' }}>
          <span className="status-dot active" />
          <button onClick={() => openPanel('caseInv')} className="btn-primary btn-sm">Start Investigation</button>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '0 20px', borderRight: '1px solid var(--border)' }}>
          <span style={{ color: 'var(--text-muted)', fontSize: 11, fontWeight: 500, whiteSpace: 'nowrap' }}>Cases Resolved with Agentix</span>
          <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--accent-green)' }}>81%</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '0 20px', borderRight: '1px solid var(--border)' }}>
          <span style={{ color: 'var(--text-muted)', fontSize: 11, fontWeight: 500 }}>MTTR</span>
          <span style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: 13 }}>42 Min</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '0 20px', borderRight: '1px solid var(--border)' }}>
          <span style={{ color: 'var(--text-muted)', fontSize: 11, fontWeight: 500, whiteSpace: 'nowrap' }}>External Interactions</span>
          <span style={{ fontWeight: 700, color: 'var(--accent-blue)', fontSize: 13 }}>3,523</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '0 20px', flex: 1, overflow: 'hidden' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, overflow: 'hidden' }}>
            {['Microsoft Defender', 'Jira Software', 'ServiceNow', 'Microsoft 365', 'Gmail', 'Slack', 'CrowdStrike', 'SentinelOne'].map(logo => (
              <span key={logo} style={{ fontSize: 10, color: 'var(--text-muted)', whiteSpace: 'nowrap', background: 'var(--bg-card)', padding: '2px 7px', borderRadius: 3 }}>{logo}</span>
            ))}
          </div>
        </div>
      </div>

      {/* Agentix Assistant Panel */}
      <div style={{
        position: 'fixed',
        top: 0,
        right: panelOpen ? 0 : -panelTotalWidth - 40,
        width: panelTotalWidth,
        height: '100vh',
        background: 'var(--bg-card)',
        borderLeft: '1px solid var(--border)',
        display: 'flex',
        flexDirection: 'row',
        zIndex: 200,
        transition: 'right .3s ease, width .3s ease',
      }}>

        {/* Conversation History Sidebar (left) */}
        <ConvHistorySidebar
          conversations={conversations}
          activeConvId={activeConvId}
          searchQuery={convSearchQuery}
          onSearchChange={setConvSearchQuery}
          onNewConversation={handleNewConversation}
          onSelectConversation={handleSelectConversation}
          onDeleteConversation={handleDeleteConversation}
        />

        {/* Main chat column */}
        <div style={{ width: chatColumnWidth, display: 'flex', flexDirection: 'column', minWidth: 0 }}>

          {/* Panel header */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '14px 18px', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
            <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
              <span className="status-dot active" style={{ width: 8, height: 8, animation: 'agentix-pulse-dot 2s infinite' }} />
              Agentic Assistant
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
              {/* Context dropdown */}
              <select
                value={contextMode}
                onChange={e => handleContextModeChange(e.target.value as ContextMode)}
                title="注入上下文"
                className="filter-select"
                style={{ fontSize: 11, color: contextMode === 'none' ? 'var(--text-muted)' : 'var(--accent-blue)' }}
              >
                <option value="none">📌 上下文: 无</option>
                <option value="alerts">📌 当前告警</option>
                <option value="incidents">📌 活跃事件</option>
                <option value="vulns">📌 漏洞情况</option>
              </select>
              {/* Context loaded badge */}
              {contextLoaded && contextLoaded.mode !== 'none' && (
                <span style={{
                  fontSize: 10,
                  background: 'rgba(47,176,122,.12)',
                  border: '1px solid rgba(47,176,122,.30)',
                  borderRadius: 10,
                  padding: '2px 8px',
                  color: 'var(--accent-green)',
                  whiteSpace: 'nowrap',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 3,
                }}>
                  ✓ 已加载 {contextLoaded.count} 条上下文
                </span>
              )}
              {/* Clear context link button */}
              {contextMode !== 'none' && (
                <button
                  onClick={() => { setContextMode('none'); setContextLoaded(null); }}
                  title="清除上下文"
                  style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: 10, padding: '0', cursor: 'pointer', whiteSpace: 'nowrap', textDecoration: 'underline', textUnderlineOffset: 2 }}
                >
                  清除上下文
                </button>
              )}
              {/* Saved analyses toggle */}
              <button
                onClick={() => setSavedOpen(v => !v)}
                title="已保存分析"
                className={savedOpen ? 'btn-secondary btn-xs' : 'btn-ghost btn-xs'}
              >
                📚{savedList.length > 0 ? ` ${savedList.length}` : ''}
              </button>
              <button onClick={handleClearHistory} className="btn-ghost btn-xs">
                清空对话
              </button>
              <button onClick={() => setPanelOpen(false)} className="btn-icon">✕</button>
            </div>
          </div>

          {/* Agent tabs */}
          <div style={{ display: 'flex', gap: 4, padding: '10px 18px 0', flexShrink: 0 }}>
            {(['threatIntel', 'caseInv', 'autoEng'] as AgentKey[]).map(key => (
              <button key={key} onClick={() => { setActiveAgent(key); setActivePanelTab(key); }} style={panelTabStyle(key)}>
                {AGENT_CONFIG[key].label}
              </button>
            ))}
            <button
              onClick={() => setActivePanelTab('xql')}
              style={{
                ...panelTabStyle('xql'),
                color: activePanelTab === 'xql' ? 'var(--accent-green)' : 'var(--text-muted)',
                borderColor: activePanelTab === 'xql' ? 'rgba(47,176,122,.4)' : 'var(--border)',
                background: activePanelTab === 'xql' ? 'rgba(47,176,122,.08)' : 'var(--bg-card)',
              }}
            >
              ⚡ XQL转换
            </button>
          </div>

          {/* ── NL2XQL Tab Panel ──────────────────────────────────────────── */}
          {activePanelTab === 'xql' ? (
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', padding: '18px', overflowY: 'auto', gap: 14 }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--accent-green)', display: 'flex', alignItems: 'center', gap: 6 }}>
                <span>⚡</span> 自然语言转 XQL
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.6 }}>
                输入自然语言描述，AI 将自动生成对应的 XQL 查询语句，可直接用于 QueryCenter。
              </div>

              {/* NL input */}
              <textarea
                value={xqlInput}
                onChange={e => setXqlInput(e.target.value)}
                placeholder="例如：查询过去24小时内来自中国IP的所有登录失败事件…"
                rows={4}
                onKeyDown={e => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); handleNl2Xql(); } }}
                className="form-textarea"
                style={{ width: '100%', fontSize: 12.5, padding: '10px 12px', minHeight: 90, borderRadius: 8 }}
              />

              <button
                onClick={handleNl2Xql}
                disabled={xqlLoading || !xqlInput.trim()}
                className="btn-primary"
                style={{ alignSelf: 'flex-start' }}
              >
                {xqlLoading ? (
                  <>
                    <span style={{ animation: 'agentix-blink 1.2s infinite' }}>⏳</span> 转换中…
                  </>
                ) : (
                  <>⚡ 转换为 XQL</>
                )}
              </button>

              {/* Error */}
              {xqlError && (
                <div style={{ background: 'rgba(224,80,80,.10)', border: '1px solid rgba(224,80,80,.30)', borderRadius: 6, padding: '10px 12px', fontSize: 12, color: 'var(--critical)', lineHeight: 1.5 }}>
                  ⚠️ {xqlError}
                </div>
              )}

              {/* XQL Result */}
              {xqlResult && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span>生成的 XQL</span>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button onClick={handleXqlCopyToClipboard} className="btn-secondary btn-xs">
                        {xqlCopied ? '✅ 已复制' : '📋 复制到剪贴板'}
                      </button>
                      <button onClick={handleXqlCopyToClipboard} title="复制到 QueryCenter" className="btn-ghost btn-xs">
                        🔗 复制到 QueryCenter
                      </button>
                    </div>
                  </div>
                  <pre className="code-block" style={{ fontSize: 14 }}>
                    {xqlResult}
                  </pre>
                </div>
              )}

              {/* Toast notification */}
              {xqlToast && (
                <div
                  style={{
                    position: 'fixed',
                    bottom: 32,
                    left: '50%',
                    transform: 'translateX(-50%)',
                    background: 'rgba(47,176,122,.15)',
                    border: '1px solid rgba(47,176,122,.35)',
                    borderRadius: 8,
                    padding: '10px 22px',
                    fontSize: 13,
                    color: 'var(--accent-green)',
                    fontWeight: 500,
                    zIndex: 9999,
                    boxShadow: '0 4px 24px rgba(0,0,0,.5)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                  }}
                >
                  ✅ XQL 已复制到剪贴板
                </div>
              )}
            </div>
          ) : (
            <>
              {/* 对话 area */}
              <div ref={chatScrollRef} style={{ flex: 1, overflowY: 'auto', padding: '16px 18px', display: 'flex', flexDirection: 'column', gap: 14 }}>
                {/* Greeting */}
                <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                  <strong style={{ color: 'var(--text-primary)' }}>{AGENT_CONFIG[activeAgent].greeting.split('.')[0]}.</strong>{' '}
                  {AGENT_CONFIG[activeAgent].greeting.slice(AGENT_CONFIG[activeAgent].greeting.indexOf('.') + 1).trim()}
                </div>

                {/* Alert AI Summary — shown when contextMode is 'alerts' */}
                {contextMode === 'alerts' && (
                  <div style={{ background: 'var(--bg-card)', border: '1px solid #0c4a6e', borderRadius: 8, padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 8 }}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--accent-blue)', display: 'flex', alignItems: 'center', gap: 6 }}>
                      🤖 <span>AI 分析摘要</span>
                      <span style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 400, marginLeft: 'auto' }}>基于最近告警</span>
                    </div>
                    {!alertSummaryKey ? (
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <button
                          onClick={() => fetchAlertSummary('latest')}
                          style={{ background: 'var(--bg-card2)', border: '1px solid #0369a1', color: 'var(--accent-blue)', fontSize: 11, padding: '5px 14px', borderRadius: 5, cursor: 'pointer', fontWeight: 500 }}
                        >
                          获取 AI 摘要
                        </button>
                        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>点击获取当前告警的 AI 智能分析</span>
                      </div>
                    ) : alertSummaryLoading ? (
                      <div style={{ fontSize: 12, color: 'var(--text-muted)', fontStyle: 'italic', display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span style={{ animation: 'agentix-blink 1.2s infinite' }}>⏳</span> AI 正在分析告警…
                      </div>
                    ) : alertSummaryError ? (
                      <div style={{ fontSize: 11, color: 'var(--critical)' }}>⚠️ {alertSummaryError}</div>
                    ) : alertSummaryKey && alertSummaryCache[alertSummaryKey] ? (
                      <div style={{ fontSize: 12.5, color: 'var(--text-primary)', lineHeight: 1.65, background: 'var(--bg-secondary)', borderRadius: 6, padding: '10px 12px', whiteSpace: 'pre-wrap' }}>
                        {alertSummaryCache[alertSummaryKey]}
                      </div>
                    ) : null}
                  </div>
                )}

                {/* Agent flow messages */}
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
                    return (
                      <对话Bubble
                        key={entry.id}
                        msg={entry.data}
                        onEdit={handleEditMessage}
                        onSave={handleSave}
                        onFollowUp={handleFollowUp}
                      />
                    );
                  }
                  return null;
                })}

                {/* Copilot (API) messages — persisted */}
                {copilotMessages.map((msg) => (
                  <对话Bubble
                    key={msg.id}
                    msg={msg}
                    onEdit={handleEditMessage}
                    onSave={handleSave}
                    onFollowUp={handleFollowUp}
                  />
                ))}

                {/* Loading / thinking indicator */}
                {loading && <ThinkingBubble text="AI is thinking" />}
              </div>

              {/* Input bar */}
              <div style={{ padding: '14px 18px', borderTop: '1px solid #1e2233', flexShrink: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, fontSize: 11, color: 'var(--text-muted)' }}>
                  <span>Agent:</span>
                  <div style={{ background: 'var(--bg-card2)', border: '1px solid #6366f1', borderRadius: 20, padding: '3px 12px', fontSize: 11, color: 'var(--text-primary)', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 5 }}>
                    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="12" cy="8" r="4" />
                      <path d="M6 20v-2a4 4 0 014-4h4a4 4 0 014 4v2" />
                    </svg>
                    <span>{AGENT_CONFIG[activeAgent].label}</span>
                  </div>
                  <div style={{ flex: 1 }} />
                  <ShortcutHelp />
                </div>

                {/* Textarea row */}
                <div style={{ display: 'flex', alignItems: 'flex-end', gap: 8 }}>
                  <div style={{ flex: 1, position: 'relative' }}>
                    <textarea
                      ref={textareaRef}
                      value={inputText}
                      onChange={e => {
                        if (e.target.value.length <= 2000) setInputText(e.target.value);
                      }}
                      onKeyDown={handleKeyDown}
                      placeholder="Ask Agentix…"
                      rows={1}
                      disabled={loading}
                      style={{ width: '100%', boxSizing: 'border-box', background: 'var(--bg-card)', border: '1px solid #2d3452', borderRadius: 8, color: 'var(--text-primary)', fontSize: 12.5, padding: '9px 12px', resize: 'none', outline: 'none', fontFamily: 'inherit', lineHeight: 1.4, height: 40, transition: 'border-color .2s', opacity: loading ? 0.6 : 1 }}
                    />
                  </div>

                  {/* File attach */}
                  <button
                    onClick={handleFileAttach}
                    title="附加文件"
                    style={{ background: 'var(--bg-card)', border: '1px solid #2d3452', color: 'var(--text-muted)', width: 36, height: 36, borderRadius: 7, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, fontSize: 16 }}
                  >
                    📎
                  </button>
                  <input ref={fileInputRef} type="file" accept=".txt,.log,.json,.csv" style={{ display: 'none' }} onChange={handleFileChange} />

                  <button
                    onClick={handle発送}
                    disabled={loading}
                    style={{ background: 'var(--accent-blue)', border: 'none', color: '#fff', width: 36, height: 36, borderRadius: 7, cursor: loading ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, opacity: loading ? 0.6 : 1 }}
                  >
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                      <line x1="22" y1="2" x2="11" y2="13" />
                      <polygon points="22 2 15 22 11 13 2 9 22 2" />
                    </svg>
                  </button>
                </div>

                {/* Context loaded badge below textarea */}
                {contextLoaded && contextLoaded.mode !== 'none' && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 4 }}>
                    <span style={{ fontSize: 10, background: 'rgba(47,176,122,.10)', border: '1px solid #166534', borderRadius: 10, padding: '2px 8px', color: 'var(--accent-green)', display: 'inline-flex', alignItems: 'center', gap: 3 }}>
                      ✓ 已加载 {contextLoaded.count} 条上下文
                    </span>
                    <button
                      onClick={() => { setContextMode('none'); setContextLoaded(null); }}
                      style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: 10, padding: 0, cursor: 'pointer', textDecoration: 'underline', textUnderlineOffset: 2 }}
                    >
                      清除上下文
                    </button>
                  </div>
                )}

                {/* Char count + template row */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 5 }}>
                  <span style={{ fontSize: 10, color: charCountColor }}>{charCount}/2000</span>
                  <select
                    value=""
                    onChange={e => {
                      const tpl = ANALYSIS_TEMPLATES.find(t => t.label === e.target.value);
                      if (tpl) setInputText(tpl.text);
                    }}
                    style={{ background: 'var(--bg-card)', border: '1px solid #2d3452', color: 'var(--text-muted)', fontSize: 10, padding: '2px 6px', borderRadius: 4, cursor: 'pointer', outline: 'none' }}
                  >
                    <option value="" disabled>使用模板 ▾</option>
                    {ANALYSIS_TEMPLATES.map(t => (
                      <option key={t.label} value={t.label}>{t.label}</option>
                    ))}
                  </select>
                </div>

                {/* Suggestion chips — shown when input empty and no messages */}
                {showChips && (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 10 }}>
                    {COPILOT_CHIPS.map(chip => (
                      <button
                        key={chip}
                        onClick={() => handleChipClick(chip)}
                        style={{
                          background: 'var(--bg-card)',
                          border: '1px solid #2d3452',
                          borderRadius: 16,
                          padding: '5px 12px',
                          fontSize: 11.5,
                          color: 'var(--text-secondary)',
                          cursor: 'pointer',
                          whiteSpace: 'nowrap',
                          transition: 'border-color .15s, color .15s',
                        }}
                        onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = 'var(--accent-blue)'; (e.currentTarget as HTMLButtonElement).style.color = 'var(--accent-blue)'; }}
                        onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.borderColor = 'var(--border-light)'; (e.currentTarget as HTMLButtonElement).style.color = 'var(--text-secondary)'; }}
                      >
                        {chip}
                      </button>
                    ))}
                  </div>
                )}

                {/* Quick Analysis prompt chips */}
                <div style={{ marginTop: 8 }}>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 500, marginBottom: 5, letterSpacing: '.04em' }}>快速分析</div>
                  <div
                    style={{
                      display: 'flex',
                      gap: 6,
                      overflowX: 'auto',
                      paddingBottom: 4,
                      scrollbarWidth: 'none',
                    }}
                  >
                    {QUICK_ANALYSIS_CHIPS.map(chip => (
                      <button
                        key={chip}
                        onClick={() => {
                          if (loading) return;
                          setInputText(chip);
                          setTimeout(() => {
                            sendMessage(chip);
                            setInputText('');
                          }, 0);
                        }}
                        disabled={loading}
                        style={{
                          background: 'var(--bg-card)',
                          border: '1px solid #3b4268',
                          borderRadius: 14,
                          padding: '4px 12px',
                          fontSize: 11,
                          color: 'var(--accent-blue)',
                          cursor: loading ? 'not-allowed' : 'pointer',
                          whiteSpace: 'nowrap',
                          flexShrink: 0,
                          opacity: loading ? 0.5 : 1,
                          transition: 'background .15s, border-color .15s, color .15s',
                        }}
                        onMouseEnter={e => {
                          if (!loading) {
                            (e.currentTarget as HTMLButtonElement).style.background = 'var(--bg-card2)';
                            (e.currentTarget as HTMLButtonElement).style.borderColor = 'var(--accent-blue)';
                            (e.currentTarget as HTMLButtonElement).style.color = 'var(--accent-blue)';
                          }
                        }}
                        onMouseLeave={e => {
                          (e.currentTarget as HTMLButtonElement).style.background = 'var(--bg-card)';
                          (e.currentTarget as HTMLButtonElement).style.borderColor = 'var(--border-light)';
                          (e.currentTarget as HTMLButtonElement).style.color = 'var(--accent-blue)';
                        }}
                      >
                        {chip}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Agent-specific suggestion chips (always shown) */}
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginTop: 8 }}>
                  {AGENT_CONFIG[activeAgent].suggestions.map(s => (
                    <button
                      key={s}
                      onClick={() => handleSuggestion(s)}
                      style={{ background: 'var(--bg-secondary)', border: '1px solid #2d3452', borderRadius: 4, padding: '4px 9px', fontSize: 10.5, color: 'var(--text-muted)', cursor: 'pointer', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 200 }}
                    >
                      {s}
                    </button>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>

        {/* Saved analyses sidebar (collapsible right column) */}
        {savedOpen && (
          <SavedSidebar
            savedList={savedList}
            onDelete={handleDeleteSaved}
            onClearAll={handleClearAllSaved}
            onClose={() => setSavedOpen(false)}
          />
        )}
      </div>
    </div>
  );
}
