import { useCallback, useEffect, useMemo, useRef, useState, useLayoutEffect } from 'react'
import ResizableTh from '@/components/ResizableTh'
import ReactFlow, {
  Background, Controls, MiniMap,
  ReactFlowProvider,
  addEdge, useNodesState, useEdgesState,
  Handle, Position,
  MarkerType,
  useReactFlow,
  useOnSelectionChange,
  Panel,
} from 'reactflow'
import type { Node, Edge, Connection, NodeProps, NodeTypes } from 'reactflow'
import 'reactflow/dist/style.css'
import api from '@/lib/api'
import type { PageMeta } from '@/lib/api'
import PageHeader from '@/components/PageHeader'

interface Playbook {
  _key: string
  name: string
  description: string
  trigger_type: string
  trigger_conditions: Record<string, unknown>
  steps: unknown[]
  status: string
  run_count: number
  success_count: number
  fail_count: number
  last_run: string
  last_run_status: string
  dry_run: boolean
  created_by: string
  created_at: string
  updated_at: string
  flow_nodes?: Node[]
  flow_edges?: Edge[]
}

interface RunHistory {
  run_id: string
  status: string
  started_at: string
  duration_ms: number
  trigger: string
  steps_total: number
  steps_done: number
}

interface NodeResult {
  node_id: string
  node_name?: string
  status: string
  output?: unknown
}

interface Execution {
  id: string
  playbook_id: string
  status: string
  started_at: string
  completed_at?: string
  node_results?: NodeResult[]
  error?: string
  trigger?: string
  steps_total?: number
  steps_ok?: number
  duration_ms?: number
}

interface PlaybookStats {
  total: number
  active: number
  todayRuns: number
  loading: boolean
}

type DetailTab = 'overview' | 'flow' | 'executions'

// ─── Mock execution data ──────────────────────────────────────────────────────

function buildMockExecutions(key: string): Execution[] {
  const now = Date.now()
  return [
    {
      id: `exec_${key}_001`,
      playbook_id: key,
      status: 'completed',
      started_at: new Date(now - 3_600_000).toISOString(),
      completed_at: new Date(now - 3_597_000).toISOString(),
      trigger: 'auto',
      steps_total: 5,
      steps_ok: 5,
      duration_ms: 3100,
      node_results: [
        { node_id: 'trigger', node_name: '触发器', status: 'success' },
        { node_id: 'cond1',   node_name: '严重性检查', status: 'success' },
        { node_id: 'act1',    node_name: '隔离主机', status: 'success' },
        { node_id: 'notify1', node_name: 'Email 通知', status: 'success' },
        { node_id: 'end',     node_name: '结束', status: 'success' },
      ],
    },
    {
      id: `exec_${key}_002`,
      playbook_id: key,
      status: 'failed',
      started_at: new Date(now - 7_200_000).toISOString(),
      completed_at: new Date(now - 7_198_500).toISOString(),
      trigger: 'manual',
      steps_total: 5,
      steps_ok: 2,
      duration_ms: 1500,
      error: 'Step "隔离主机" timeout after 1000ms',
      node_results: [
        { node_id: 'trigger', node_name: '触发器', status: 'success' },
        { node_id: 'cond1',   node_name: '严重性检查', status: 'success' },
        { node_id: 'act1',    node_name: '隔离主机', status: 'failed' },
      ],
    },
    {
      id: `exec_${key}_003`,
      playbook_id: key,
      status: 'running',
      started_at: new Date(now - 45_000).toISOString(),
      trigger: 'auto',
      steps_total: 5,
      steps_ok: 3,
      duration_ms: 0,
    },
    {
      id: `exec_${key}_004`,
      playbook_id: key,
      status: 'completed',
      started_at: new Date(now - 86_400_000).toISOString(),
      completed_at: new Date(now - 86_396_000).toISOString(),
      trigger: 'manual',
      steps_total: 5,
      steps_ok: 5,
      duration_ms: 4200,
    },
    {
      id: `exec_${key}_005`,
      playbook_id: key,
      status: 'failed',
      started_at: new Date(now - 172_800_000).toISOString(),
      completed_at: new Date(now - 172_799_000).toISOString(),
      trigger: 'auto',
      steps_total: 5,
      steps_ok: 0,
      duration_ms: 800,
      error: 'Connection refused: svc endpoint unreachable',
    },
  ]
}

// ─── Node library config ──────────────────────────────────────────────────────

const NODE_LIBRARY = [
  {
    group: '触发器',
    color: 'var(--accent-blue)',
    items: [
      { icon: '⚡', name: '告警触发' },
      { icon: '📁', name: '事件创建' },
      { icon: '⏰', name: '定时触发' },
      { icon: '🖐', name: '手动触发' },
    ],
  },
  {
    group: '条件判断',
    color: 'var(--medium)',
    items: [
      { icon: '🔀', name: 'If/Else' },
      { icon: '⚙️', name: 'Switch' },
      { icon: '🔁', name: 'Loop' },
    ],
  },
  {
    group: '数据查询',
    color: 'var(--accent-blue)',
    items: [
      { icon: '🔔', name: '获取告警' },
      { icon: '📋', name: '获取事件' },
      { icon: '🔍', name: '查询日志' },
      { icon: '🖥', name: '获取资产' },
    ],
  },
  {
    group: '响应操作',
    color: 'var(--accent-green)',
    items: [
      { icon: '🚫', name: '封锁 IP' },
      { icon: '🔒', name: '隔离主机' },
      { icon: '📧', name: '发送通知' },
      { icon: '🎫', name: '创建工单' },
    ],
  },
  {
    group: '集成',
    color: 'var(--accent-blue)',
    items: [
      { icon: '💬', name: 'Slack' },
      { icon: '📮', name: 'Email' },
      { icon: '🛡️', name: 'SIEM' },
      { icon: '🔥', name: 'Firewall' },
    ],
  },
]

function fmtDate(iso: string) {
  if (!iso) return '-'
  return new Date(iso).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false })
}

function fmt耗时(ms: number) {
  if (!ms) return '-'
  if (ms < 1000) return `${ms}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`
}

function fmtDuration(startIso: string, endIso: string | undefined): string | null {
  if (!startIso || !endIso) return null
  const ms = new Date(endIso).getTime() - new Date(startIso).getTime()
  if (ms < 0) return null
  if (ms < 1000) return `耗时 ${ms}ms`
  if (ms < 60000) return `耗时 ${(ms / 1000).toFixed(1)}s`
  return `耗时 ${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`
}

function fmtRelative(iso: string): string {
  if (!iso) return '-'
  const diffMs = Date.now() - new Date(iso).getTime()
  if (diffMs < 0) return fmtDate(iso)
  const secs = Math.floor(diffMs / 1000)
  if (secs < 60) return `${secs}秒前`
  const mins = Math.floor(secs / 60)
  if (mins < 60) return `${mins}分钟前`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}小时前`
  const days = Math.floor(hrs / 24)
  return `${days}天前`
}

const BLANK_PB = { name: '', description: '', trigger_type: '手动', status: 'draft' }

const triggerColor: Record<string, string> = {
  手动: 'var(--text-muted)',
  alert: 'var(--high)',
  incident: 'var(--critical)',
  schedule: 'var(--accent-blue)',
  webhook: 'var(--medium)',
}

const statusColor: Record<string, string> = {
  active: 'var(--accent-green)',
  draft: 'var(--medium)',
  inactive: 'var(--text-muted)',
  running: 'var(--accent-blue)',
  failed: 'var(--critical)',
}

const runStatusColor: Record<string, string> = {
  completed: 'var(--accent-green)',
  success: 'var(--accent-green)',
  failed: 'var(--critical)',
  running: 'var(--accent-blue)',
  partial: 'var(--medium)',
}

// ─── Node color map ───────────────────────────────────────────────────────────

const NODE_STROKE_COLOR: Record<string, string> = {
  triggerNode:   'var(--accent-blue)',
  conditionNode: 'var(--medium)',
  actionNode:    'var(--accent-green)',
  notifyNode:    'var(--accent-blue)',
  endNode:       'var(--text-muted)',
}

// ─── Custom Node Styles ───────────────────────────────────────────────────────

const nodeCardBase: React.CSSProperties = {
  borderRadius: 6,
  fontSize: 11.5,
  minWidth: 180,
  maxWidth: 240,
  fontFamily: "'Segoe UI', system-ui, sans-serif",
  boxShadow: '0 4px 20px rgba(0,0,0,.45)',
  userSelect: 'none',
}

// ─── TriggerNode ─────────────────────────────────────────────────────────────

function TriggerNode({ data, selected }: NodeProps) {
  return (
    <div style={{
      ...nodeCardBase,
      background: 'linear-gradient(135deg, #0d2a4a 0%, #0a1e38 100%)',
      border: selected ? '1.5px solid #3b9ede' : '1.5px solid #1a4a7a',
      boxShadow: selected ? '0 0 0 2px rgba(59,158,222,.3), 0 4px 20px rgba(0,0,0,.45)' : '0 4px 20px rgba(0,0,0,.45)',
    }}>
      <div style={{
        background: 'linear-gradient(90deg, #1a4a8a, #0f3060)',
        borderRadius: '4px 4px 0 0',
        padding: '6px 10px',
        display: 'flex', alignItems: 'center', gap: 6,
        borderBottom: '1px solid rgba(59,158,222,.25)',
      }}>
        <span style={{ fontSize: 13 }}>⚡</span>
        <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: '.8px', textTransform: 'uppercase', color: 'var(--accent-blue)' }}>触发器</span>
      </div>
      <div style={{ padding: '8px 10px' }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
          {data.trigger_type || data.triggerType || data.label || '触发条件'}
        </div>
        {data.description && (
          <div style={{ fontSize: 10.5, color: 'var(--text-secondary)', lineHeight: 1.4 }}>{data.description}</div>
        )}
      </div>
      <Handle type="source" position={Position.Bottom} style={{ background: 'var(--accent-blue)', border: '2px solid #0d2a4a', width: 10, height: 10 }} />
    </div>
  )
}

// ─── ConditionNode ───────────────────────────────────────────────────────────

function ConditionNode({ data, selected }: NodeProps) {
  return (
    <div style={{
      ...nodeCardBase,
      background: 'linear-gradient(135deg, #2a1f00 0%, #1e1500 100%)',
      border: selected ? '1.5px solid #c8a030' : '1.5px solid #5a3e00',
      boxShadow: selected ? '0 0 0 2px rgba(200,160,48,.3), 0 4px 20px rgba(0,0,0,.45)' : '0 4px 20px rgba(0,0,0,.45)',
    }}>
      <div style={{
        background: 'linear-gradient(90deg, #3a2a00, #2a1e00)',
        borderRadius: '4px 4px 0 0',
        padding: '6px 10px',
        display: 'flex', alignItems: 'center', gap: 6,
        borderBottom: '1px solid rgba(200,160,48,.2)',
      }}>
        <span style={{ fontSize: 13 }}>◇</span>
        <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: '.8px', textTransform: 'uppercase', color: 'var(--medium)' }}>条件判断</span>
      </div>
      <div style={{ padding: '8px 10px' }}>
        <div style={{ fontSize: 11.5, fontWeight: 600, color: 'var(--medium)', marginBottom: 4 }}>
          {data.condition || data.label || '判断条件'}
        </div>
        {data.expression && (
          <div style={{
            fontSize: 10, fontFamily: 'monospace', color: 'var(--text-muted)',
            background: 'rgba(200,160,48,.06)', borderRadius: 3, padding: '3px 6px',
            border: '1px solid rgba(200,160,48,.12)',
          }}>
            {data.expression}
          </div>
        )}
      </div>
      <Handle type="target" position={Position.Top} style={{ background: 'var(--medium)', border: '2px solid #2a1f00', width: 10, height: 10 }} />
      <Handle type="source" position={Position.Bottom} id="true" style={{ background: 'var(--accent-green)', border: '2px solid #2a1f00', width: 10, height: 10, left: '35%' }} />
      <Handle type="source" position={Position.Bottom} id="false" style={{ background: 'var(--critical)', border: '2px solid #2a1f00', width: 10, height: 10, left: '65%' }} />
    </div>
  )
}

// ─── ActionNode ──────────────────────────────────────────────────────────────

function ActionNode({ data, selected }: NodeProps) {
  return (
    <div style={{
      ...nodeCardBase,
      background: 'linear-gradient(135deg, #0a2a14 0%, #071a0c 100%)',
      border: selected ? '1.5px solid #2fb07a' : '1.5px solid #1a5a2a',
      boxShadow: selected ? '0 0 0 2px rgba(47,176,122,.3), 0 4px 20px rgba(0,0,0,.45)' : '0 4px 20px rgba(0,0,0,.45)',
    }}>
      <div style={{
        background: 'linear-gradient(90deg, #1a5a2a, #0f3a1a)',
        borderRadius: '4px 4px 0 0',
        padding: '6px 10px',
        display: 'flex', alignItems: 'center', gap: 6,
        borderBottom: '1px solid rgba(47,176,122,.2)',
      }}>
        <span style={{ fontSize: 12 }}>▶</span>
        <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: '.8px', textTransform: 'uppercase', color: 'var(--accent-green)' }}>执行动作</span>
      </div>
      <div style={{ padding: '8px 10px' }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--accent-green)', marginBottom: 4 }}>
          {data.action_type || data.actionType || data.label || '执行动作'}
        </div>
        {data.actionType && data.label && data.label !== data.actionType && (
          <div style={{ fontSize: 10.5, color: 'var(--text-muted)', fontFamily: 'monospace' }}>{data.actionType}</div>
        )}
      </div>
      <Handle type="target" position={Position.Top} style={{ background: 'var(--accent-green)', border: '2px solid #0a2a14', width: 10, height: 10 }} />
      <Handle type="source" position={Position.Bottom} style={{ background: 'var(--accent-green)', border: '2px solid #0a2a14', width: 10, height: 10 }} />
    </div>
  )
}

// ─── NotifyNode ──────────────────────────────────────────────────────────────

function NotifyNode({ data, selected }: NodeProps) {
  return (
    <div style={{
      ...nodeCardBase,
      background: 'linear-gradient(135deg, #1e0a3a 0%, #140626 100%)',
      border: selected ? '1.5px solid #9b59b6' : '1.5px solid #3a1a5a',
      boxShadow: selected ? '0 0 0 2px rgba(155,89,182,.3), 0 4px 20px rgba(0,0,0,.45)' : '0 4px 20px rgba(0,0,0,.45)',
    }}>
      <div style={{
        background: 'linear-gradient(90deg, #3a1a6a, #28104a)',
        borderRadius: '4px 4px 0 0',
        padding: '6px 10px',
        display: 'flex', alignItems: 'center', gap: 6,
        borderBottom: '1px solid rgba(155,89,182,.2)',
      }}>
        <span style={{ fontSize: 13 }}>📧</span>
        <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: '.8px', textTransform: 'uppercase', color: 'var(--accent-blue)' }}>发送通知</span>
      </div>
      <div style={{ padding: '8px 10px' }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
          {data.label || '发送通知'}
        </div>
        {data.channel && (
          <div style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>
            渠道: <span style={{ color: 'var(--text-secondary)' }}>{data.channel}</span>
          </div>
        )}
      </div>
      <Handle type="target" position={Position.Top} style={{ background: 'var(--accent-blue)', border: '2px solid #1e0a3a', width: 10, height: 10 }} />
      <Handle type="source" position={Position.Bottom} style={{ background: 'var(--accent-blue)', border: '2px solid #1e0a3a', width: 10, height: 10 }} />
    </div>
  )
}

// ─── EndNode ─────────────────────────────────────────────────────────────────

function EndNode({ selected }: NodeProps) {
  return (
    <div style={{
      width: 64, height: 64, borderRadius: '50%',
      background: 'radial-gradient(circle, #1e2535 0%, #10131a 100%)',
      border: selected ? '2px solid #5a6a8a' : '2px solid #2a3348',
      boxShadow: selected ? '0 0 0 2px rgba(90,106,138,.3), 0 4px 16px rgba(0,0,0,.5)' : '0 4px 16px rgba(0,0,0,.5)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      flexDirection: 'column', gap: 2,
    }}>
      <span style={{ fontSize: 16 }}>⬛</span>
      <span style={{ fontSize: 9, color: 'var(--text-muted)', fontWeight: 700, letterSpacing: '.6px', textTransform: 'uppercase' }}>结束</span>
      <Handle type="target" position={Position.Top} style={{ background: 'var(--text-muted)', border: '2px solid #10131a', width: 10, height: 10 }} />
    </div>
  )
}

// ─── NODE TYPES — must be defined outside component ──────────────────────────

const nodeTypes: NodeTypes = {
  triggerNode: TriggerNode,
  conditionNode: ConditionNode,
  actionNode: ActionNode,
  notifyNode: NotifyNode,
  endNode: EndNode,
}

// ─── Palette config ───────────────────────────────────────────────────────────

const PALETTE_ITEMS = [
  { type: 'triggerNode',   label: '触发器', icon: '⚡', color: 'var(--accent-blue)', desc: '工作流入口' },
  { type: 'conditionNode', label: '条件判断', icon: '◇', color: 'var(--medium)', desc: '分支判断' },
  { type: 'actionNode',    label: '执行动作', icon: '▶', color: 'var(--accent-green)', desc: '执行操作' },
  { type: 'notifyNode',    label: '发送通知', icon: '📧', color: 'var(--accent-blue)', desc: '消息推送' },
  { type: 'endNode',       label: '结束',    icon: '⬛', color: 'var(--border-light)', desc: '流程终止' },
]

// ─── Default data for new nodes ───────────────────────────────────────────────

function defaultNodeData(type: string): Record<string, unknown> {
  switch (type) {
    case 'triggerNode':   return { label: '新触发器', triggerType: 'manual', trigger_type: 'manual', description: '' }
    case 'conditionNode': return { label: '条件判断', condition: '', expression: '' }
    case 'actionNode':    return { label: '执行动作', actionType: 'isolate_host', action_type: 'isolate_host' }
    case 'notifyNode':    return { label: '发送通知', channel: 'email' }
    case 'endNode':       return { label: '结束' }
    default:              return { label: '节点' }
  }
}

// ─── Build default 3-node flow ────────────────────────────────────────────────

function buildDefaultFlow(pb: Playbook): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = [
    {
      id: 'trigger',
      type: 'triggerNode',
      position: { x: 240, y: 40 },
      data: { label: pb.trigger_type || 'manual', triggerType: pb.trigger_type || '手动', trigger_type: pb.trigger_type || '手动', description: '' },
    },
    {
      id: 'action1',
      type: 'actionNode',
      position: { x: 240, y: 200 },
      data: { label: '执行动作', actionType: 'isolate_host', action_type: 'isolate_host' },
    },
    {
      id: 'end',
      type: 'endNode',
      position: { x: 272, y: 360 },
      data: { label: '结束' },
    },
  ]
  const edges: Edge[] = [
    {
      id: 'e-trigger-action1',
      source: 'trigger', target: 'action1',
      animated: true,
      markerEnd: { type: MarkerType.ArrowClosed, color: 'var(--accent-green)', width: 16, height: 16 },
      style: { stroke: 'var(--accent-green)', strokeWidth: 1.5 },
    },
    {
      id: 'e-action1-end',
      source: 'action1', target: 'end',
      animated: true,
      markerEnd: { type: MarkerType.ArrowClosed, color: 'var(--text-muted)', width: 16, height: 16 },
      style: { stroke: 'var(--text-muted)', strokeWidth: 1.5 },
    },
  ]
  return { nodes, edges }
}

// ─── Flow from Playbook ───────────────────────────────────────────────────────

function playbookToFlow(pb: Playbook): { nodes: Node[]; edges: Edge[] } {
  // Use saved flow if present
  if (pb.flow_nodes && pb.flow_nodes.length > 0) {
    return { nodes: pb.flow_nodes, edges: pb.flow_edges ?? [] }
  }

  // Convert steps[] if present
  const rawSteps = pb.steps
  if (Array.isArray(rawSteps) && rawSteps.length > 0) {
    const nodes: Node[] = [
      {
        id: 'trigger',
        type: 'triggerNode',
        position: { x: 240, y: 40 },
        data: { label: pb.trigger_type || 'manual', triggerType: pb.trigger_type || '手动', trigger_type: pb.trigger_type || '手动', description: '' },
      },
    ]
    const edges: Edge[] = []

    rawSteps.forEach((step: unknown, i: number) => {
      const s = step as Record<string, unknown>
      const stepType = s.type === 'condition' ? 'conditionNode'
        : s.type === 'notify' ? 'notifyNode'
        : s.type === 'end' ? 'endNode'
        : 'actionNode'
      const nodeId = (s.id as string) ?? `s${i}`
      const prevId = i === 0 ? 'trigger' : ((rawSteps[i - 1] as Record<string, unknown>).id as string ?? `s${i - 1}`)
      const strokeColor = NODE_STROKE_COLOR[stepType] ?? 'var(--bg-card2)'

      nodes.push({
        id: nodeId,
        type: stepType,
        position: { x: 240, y: 160 + i * 130 },
        data: {
          label: (s.label ?? s.name ?? s.action_type ?? `步骤 ${i + 1}`) as string,
          action_type: s.action_type,
          actionType: s.actionType ?? s.action_type,
          channel: s.channel,
          condition: s.condition,
          expression: s.expression ?? s.condition,
          trigger_type: s.trigger_type,
          triggerType: s.trigger_type,
        },
      })

      edges.push({
        id: `e${prevId}-${nodeId}`,
        source: prevId, target: nodeId,
        animated: true,
        markerEnd: { type: MarkerType.ArrowClosed, color: strokeColor, width: 16, height: 16 },
        style: { stroke: strokeColor, strokeWidth: 1.5 },
      })
    })

    return { nodes, edges }
  }

  // Fall back to 3 default nodes
  return buildDefaultFlow(pb)
}

// ─── Edge builder helper ──────────────────────────────────────────────────────

function makeEdge(source: string, target: string, sourceNodeType?: string): Edge {
  const strokeColor = sourceNodeType ? (NODE_STROKE_COLOR[sourceNodeType] ?? 'var(--accent-blue)') : 'var(--accent-blue)'
  return {
    id: `e-${source}-${target}-${Date.now()}`,
    source, target,
    animated: true,
    markerEnd: { type: MarkerType.ArrowClosed, color: strokeColor, width: 16, height: 16 },
    style: { stroke: strokeColor, strokeWidth: 1.5 },
  }
}

// ─── StatusBadge ─────────────────────────────────────────────────────────────

interface StatusBadgeProps { status: string; pulse?: boolean }
function StatusBadge({ status, pulse }: StatusBadgeProps) {
  const color = statusColor[status] ?? 'var(--text-muted)'
  const shouldPulse = pulse ?? status === 'running'
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5 }}>
      <span style={{
        width: 6, height: 6, borderRadius: '50%', display: 'inline-block',
        background: color,
        boxShadow: shouldPulse ? `0 0 0 2px ${color}44` : color !== 'var(--text-muted)' ? `0 0 4px ${color}` : 'none',
        animation: shouldPulse ? 'pulse 1.2s ease-in-out infinite' : undefined,
      }} />
      {status}
    </span>
  )
}

// ─── Mini prop form components ────────────────────────────────────────────────

interface PropsFieldProps {
  label: string
  value: string
  onChange: (v: string) => void
  onBlur?: () => void
  placeholder?: string
  mono?: boolean
  multiline?: boolean
}

function PropsField({ label, value, onChange, onBlur, placeholder, mono, multiline }: PropsFieldProps) {
  const inputStyle: React.CSSProperties = {
    width: '100%', boxSizing: 'border-box',
    padding: '5px 8px', borderRadius: 3, fontSize: 11,
    background: 'var(--bg-primary)', border: '1px solid #1e2535', color: 'var(--text-secondary)',
    outline: 'none', fontFamily: mono ? 'monospace' : 'inherit',
    resize: multiline ? 'vertical' : undefined,
    minHeight: multiline ? 52 : undefined,
    transition: 'border-color .15s',
  }
  return (
    <div>
      <div style={{ fontSize: 9.5, fontWeight: 700, color: 'var(--bg-card2)', letterSpacing: '.6px', textTransform: 'uppercase', marginBottom: 4 }}>{label}</div>
      {multiline
        ? <textarea
            value={value}
            onChange={e => onChange(e.target.value)}
            onBlur={onBlur}
            placeholder={placeholder}
            style={inputStyle}
            onFocus={e => { e.currentTarget.style.borderColor = 'var(--border)' }}
          />
        : <input
            type="text"
            value={value}
            onChange={e => onChange(e.target.value)}
            onBlur={onBlur}
            placeholder={placeholder}
            style={inputStyle}
            onFocus={e => { e.currentTarget.style.borderColor = 'var(--border)' }}
          />
      }
    </div>
  )
}

interface PropsSelectProps {
  label: string
  value: string
  options: { value: string; label: string }[]
  onChange: (v: string) => void
}

function PropsSelect({ label, value, options, onChange }: PropsSelectProps) {
  return (
    <div>
      <div style={{ fontSize: 9.5, fontWeight: 700, color: 'var(--bg-card2)', letterSpacing: '.6px', textTransform: 'uppercase', marginBottom: 4 }}>{label}</div>
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        style={{
          width: '100%', padding: '5px 8px', borderRadius: 3, fontSize: 11,
          background: 'var(--bg-primary)', border: '1px solid #1e2535', color: 'var(--text-secondary)',
          outline: 'none', cursor: 'pointer',
        }}
      >
        {options.map(o => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
    </div>
  )
}

// ─── FlowCanvasInner — uses ReactFlow hooks (must be inside ReactFlowProvider) ─

interface FlowCanvasInnerProps {
  playbook: Playbook
  onSaved?: () => void
}

function FlowCanvasInner({ playbook, onSaved }: FlowCanvasInnerProps) {
  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])
  const [selectedNode, setSelectedNode] = useState<Node | null>(null)
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)
  const [confirmClear, setConfirmClear] = useState(false)

  const reactFlowWrapper = useRef<HTMLDivElement>(null)
  const rf = useReactFlow()

  // History for undo/redo
  const historyRef = useRef<{ nodes: Node[]; edges: Edge[] }[]>([])
  const historyIdxRef = useRef(-1)

  function pushHistory(n: Node[], e: Edge[]) {
    historyRef.current = historyRef.current.slice(0, historyIdxRef.current + 1)
    historyRef.current.push({ nodes: JSON.parse(JSON.stringify(n)), edges: JSON.parse(JSON.stringify(e)) })
    if (historyRef.current.length > 50) historyRef.current.shift()
    historyIdxRef.current = historyRef.current.length - 1
  }

  // Load when playbook changes
  useEffect(() => {
    const { nodes: n, edges: e } = playbookToFlow(playbook)
    setNodes(n)
    setEdges(e)
    historyRef.current = [{ nodes: JSON.parse(JSON.stringify(n)), edges: JSON.parse(JSON.stringify(e)) }]
    historyIdxRef.current = 0
    setSelectedNode(null)
    // Fit view after a short delay to let layout settle
    setTimeout(() => rf.fitView({ padding: 0.25 }), 80)
  }, [playbook._key])  // eslint-disable-line react-hooks/exhaustive-deps

  // Track selection via hook
  useOnSelectionChange({
    onChange: ({ nodes: selectedNodes }) => {
      setSelectedNode(selectedNodes.length === 1 ? selectedNodes[0] : null)
    },
  })

  const onConnect = useCallback(
    (params: Connection) => {
      // Find source node type to color edge
      const sourceNode = nodes.find(n => n.id === params.source)
      const edge = makeEdge(params.source ?? '', params.target ?? '', sourceNode?.type)
      const newEdges = addEdge(edge, edges)
      setEdges(newEdges)
      pushHistory(nodes, newEdges)
    },
    [nodes, edges, setEdges],
  )

  // Drag-and-drop from palette
  function onDragOver(event: React.DragEvent) {
    event.preventDefault()
    event.dataTransfer.dropEffect = 'move'
  }

  function onDrop(event: React.DragEvent) {
    event.preventDefault()
    const type = event.dataTransfer.getData('application/reactflow')
    if (!type || !reactFlowWrapper.current) return

    const reactFlowBounds = reactFlowWrapper.current.getBoundingClientRect()
    // Use screenToFlowPosition (ReactFlow v11+) for accurate coordinate mapping
    const position = rf.screenToFlowPosition({
      x: event.clientX - reactFlowBounds.left,
      y: event.clientY - reactFlowBounds.top,
    })

    const newNode: Node = {
      id: `node_${Date.now()}`,
      type,
      position,
      data: defaultNodeData(type),
    }
    const newNodes = [...nodes, newNode]
    setNodes(newNodes)
    pushHistory(newNodes, edges)
  }

  // Undo / Redo keyboard shortcuts
  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (!e.ctrlKey) return
      if (e.key === 'z' && !e.shiftKey) {
        e.preventDefault()
        if (historyIdxRef.current > 0) {
          historyIdxRef.current--
          const snap = historyRef.current[historyIdxRef.current]
          setNodes(snap.nodes)
          setEdges(snap.edges)
        }
      }
      if (e.key === 'y' || (e.key === 'z' && e.shiftKey)) {
        e.preventDefault()
        if (historyIdxRef.current < historyRef.current.length - 1) {
          historyIdxRef.current++
          const snap = historyRef.current[historyIdxRef.current]
          setNodes(snap.nodes)
          setEdges(snap.edges)
        }
      }
    }
    window.addEventListener('keydown', handleKey)
    return () => window.removeEventListener('keydown', handleKey)
  }, [setNodes, setEdges])

  // Push history on node drag end
  function handleNodesChange(changes: Parameters<typeof onNodesChange>[0]) {
    onNodesChange(changes)
    const hasMoveEnd = changes.some((c: { type: string; dragging?: boolean }) => c.type === 'position' && c.dragging === false)
    if (hasMoveEnd) {
      setTimeout(() => pushHistory(nodes, edges), 0)
    }
  }

  // Save flow
  function saveFlow() {
    setSaving(true)
    api.patch(`/playbooks/${playbook._key}`, {
      flow_nodes: nodes,
      flow_edges: edges,
    })
      .then(() => {
        setSaved(true)
        setTimeout(() => setSaved(false), 2000)
        onSaved?.()
      })
      .finally(() => setSaving(false))
  }

  // Clear canvas with confirm
  function clearCanvas() {
    if (!confirmClear) { setConfirmClear(true); setTimeout(() => setConfirmClear(false), 3000); return }
    setConfirmClear(false)
    const empty: Node[] = []
    const emptyEdges: Edge[] = []
    setNodes(empty)
    setEdges(emptyEdges)
    setSelectedNode(null)
    pushHistory(empty, emptyEdges)
  }

  // Update selected node data
  function updateSelectedNodeData(key: string, value: string) {
    if (!selectedNode) return
    const updatedNode = { ...selectedNode, data: { ...selectedNode.data, [key]: value } }
    const newNodes = nodes.map(n => n.id === selectedNode.id ? updatedNode : n)
    setNodes(newNodes)
    setSelectedNode(updatedNode)
  }

  function commitNodeEdit() {
    pushHistory(nodes, edges)
  }

  // Delete selected node
  function deleteSelectedNode() {
    if (!selectedNode) return
    const newNodes = nodes.filter(n => n.id !== selectedNode.id)
    const newEdges = edges.filter(e => e.source !== selectedNode.id && e.target !== selectedNode.id)
    setNodes(newNodes)
    setEdges(newEdges)
    setSelectedNode(null)
    pushHistory(newNodes, newEdges)
  }

  // Duplicate selected node
  function duplicateSelectedNode() {
    if (!selectedNode) return
    const newNode: Node = {
      ...selectedNode,
      id: `node_${Date.now()}`,
      position: { x: selectedNode.position.x + 30, y: selectedNode.position.y + 30 },
      data: { ...selectedNode.data },
    }
    const newNodes = [...nodes, newNode]
    setNodes(newNodes)
    pushHistory(newNodes, edges)
  }

  const canUndo = historyIdxRef.current > 0
  const canRedo = historyIdxRef.current < historyRef.current.length - 1

  const stats = useMemo(() => ({
    total: nodes.length,
    triggers: nodes.filter(n => n.type === 'triggerNode').length,
    conditions: nodes.filter(n => n.type === 'conditionNode').length,
    actions: nodes.filter(n => n.type === 'actionNode').length,
    notifies: nodes.filter(n => n.type === 'notifyNode').length,
  }), [nodes])

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', background: 'var(--bg-primary)' }}>
      {/* ── Toolbar ────────────────────────────────────────────────────────── */}
      <div style={{
        height: 40, flexShrink: 0,
        background: 'linear-gradient(90deg, #0d1018, #0f1520)',
        borderBottom: '1px solid #1e2535',
        display: 'flex', alignItems: 'center', gap: 0,
        paddingLeft: 8,
      }}>
        {/* Node count badge */}
        <div style={{
          padding: '2px 8px', borderRadius: 10,
          background: 'rgba(59,158,222,.12)', border: '1px solid rgba(59,158,222,.2)',
          fontSize: 10.5, color: 'var(--accent-blue)', fontWeight: 700,
          marginRight: 8, flexShrink: 0,
        }}>
          {stats.total} 节点
        </div>

        {/* Mini stats */}
        <div style={{ display: 'flex', gap: 6, marginRight: 8 }}>
          {[
            { val: stats.triggers, color: 'var(--accent-blue)', label: '触' },
            { val: stats.conditions, color: 'var(--medium)', label: '条' },
            { val: stats.actions, color: 'var(--accent-green)', label: '动' },
            { val: stats.notifies, color: 'var(--accent-blue)', label: '通' },
          ].filter(s => s.val > 0).map(s => (
            <span key={s.label} style={{ fontSize: 10, color: s.color, fontWeight: 600 }}>
              {s.label}×{s.val}
            </span>
          ))}
        </div>

        <div style={{ flex: 1 }} />

        {/* Undo / Redo */}
        {[
          { label: '↩', title: '撤销 (Ctrl+Z)', disabled: !canUndo, action: () => { if (canUndo) { historyIdxRef.current--; const s = historyRef.current[historyIdxRef.current]; setNodes(s.nodes); setEdges(s.edges) } } },
          { label: '↪', title: '重做 (Ctrl+Y)', disabled: !canRedo, action: () => { if (canRedo) { historyIdxRef.current++; const s = historyRef.current[historyIdxRef.current]; setNodes(s.nodes); setEdges(s.edges) } } },
        ].map(btn => (
          <button
            key={btn.label} onClick={btn.action} disabled={btn.disabled} title={btn.title}
            style={{
              height: 28, width: 28, borderRadius: 3, fontSize: 13,
              background: 'none', border: 'none',
              color: btn.disabled ? 'var(--bg-card2)' : 'var(--text-secondary)',
              cursor: btn.disabled ? 'default' : 'pointer',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              transition: 'all .15s',
            }}
            onMouseEnter={e => { if (!btn.disabled) e.currentTarget.style.color = 'var(--text-secondary)' }}
            onMouseLeave={e => { e.currentTarget.style.color = btn.disabled ? 'var(--bg-card2)' : 'var(--text-secondary)' }}
          >
            {btn.label}
          </button>
        ))}

        <div style={{ width: 1, height: 20, background: 'var(--bg-card)', margin: '0 8px' }} />

        {/* Clear button with confirm */}
        <button
          onClick={clearCanvas}
          style={{
            height: 28, padding: '0 10px', borderRadius: 3, fontSize: 11,
            background: confirmClear ? 'rgba(217,64,64,.15)' : 'none',
            border: confirmClear ? '1px solid rgba(217,64,64,.5)' : '1px solid transparent',
            color: confirmClear ? 'var(--critical)' : 'var(--text-secondary)',
            cursor: 'pointer', transition: 'all .15s', marginRight: 4,
          }}
          onMouseEnter={e => { if (!confirmClear) { e.currentTarget.style.color = 'var(--critical)'; e.currentTarget.style.borderColor = 'rgba(217,64,64,.3)' } }}
          onMouseLeave={e => { if (!confirmClear) { e.currentTarget.style.color = 'var(--text-secondary)'; e.currentTarget.style.borderColor = 'transparent' } }}
        >
          🗑️ {confirmClear ? '确认清空?' : '清空'}
        </button>

        {/* Save button */}
        <button
          onClick={saveFlow}
          disabled={saving}
          style={{
            height: 28, padding: '0 14px', borderRadius: 4, fontSize: 11,
            background: saved ? 'rgba(47,176,122,.15)' : 'rgba(26,90,138,.3)',
            border: saved ? '1px solid #2fb07a' : '1px solid rgba(59,158,222,.35)',
            color: saved ? 'var(--accent-green)' : 'var(--accent-blue)',
            cursor: saving ? 'default' : 'pointer',
            fontWeight: 600, transition: 'all .2s',
            marginRight: 8,
          }}
        >
          {saved ? '✓ 已保存' : saving ? '保存中...' : '💾 保存'}
        </button>
      </div>

      {/* ── Tri-panel canvas area ─────────────────────────────────────────── */}
      <div style={{ flex: 1, display: 'flex', minHeight: 0 }}>

        {/* Left palette (120px) */}
        <div style={{
          width: 120, background: 'var(--bg-primary)',
          borderRight: '1px solid #1e2535',
          display: 'flex', flexDirection: 'column',
          flexShrink: 0, overflowY: 'auto',
        }}>
          <div style={{ padding: '8px 8px 4px', fontSize: 9, fontWeight: 700, letterSpacing: '1px', textTransform: 'uppercase', color: 'var(--bg-card2)' }}>
            节点面板
          </div>
          <div style={{ padding: '0 6px', display: 'flex', flexDirection: 'column', gap: 4 }}>
            {PALETTE_ITEMS.map(item => (
              <div
                key={item.type}
                draggable
                onDragStart={e => {
                  e.dataTransfer.setData('application/reactflow', item.type)
                  e.dataTransfer.effectAllowed = 'move'
                }}
                style={{
                  padding: '7px 8px', borderRadius: 5,
                  background: 'linear-gradient(135deg, #0f1520, #0b0e15)',
                  border: `1px solid ${item.color}25`,
                  cursor: 'grab',
                  display: 'flex', alignItems: 'center', gap: 6,
                  transition: 'all .15s',
                  userSelect: 'none',
                }}
                onMouseEnter={e => {
                  e.currentTarget.style.background = `linear-gradient(135deg, ${item.color}12, ${item.color}06)`
                  e.currentTarget.style.borderColor = `${item.color}50`
                  e.currentTarget.style.boxShadow = `0 2px 8px ${item.color}18`
                }}
                onMouseLeave={e => {
                  e.currentTarget.style.background = 'linear-gradient(135deg, #0f1520, #0b0e15)'
                  e.currentTarget.style.borderColor = `${item.color}25`
                  e.currentTarget.style.boxShadow = 'none'
                }}
              >
                <span style={{ fontSize: 14, lineHeight: 1 }}>{item.icon}</span>
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontSize: 10.5, fontWeight: 600, color: item.color }}>{item.label}</div>
                  <div style={{ fontSize: 9, color: 'var(--bg-card2)', lineHeight: 1.3 }}>{item.desc}</div>
                </div>
              </div>
            ))}
          </div>

          {/* Node library */}
          <NodeLibraryPanel />

          <div style={{ marginTop: 'auto', padding: '8px', borderTop: '1px solid #1e2535' }}>
            <div style={{ fontSize: 9, color: 'var(--bg-card2)', lineHeight: 1.7 }}>
              拖入节点<br />点击选中<br />Delete 删除
            </div>
          </div>
        </div>

        {/* Canvas */}
        <div ref={reactFlowWrapper} style={{ flex: 1, minWidth: 0, position: 'relative' }}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={handleNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            onDrop={onDrop}
            onDragOver={onDragOver}
            nodeTypes={nodeTypes}
            fitView
            fitViewOptions={{ padding: 0.25 }}
            deleteKeyCode="Delete"
            style={{ background: 'var(--bg-primary)' }}
            defaultEdgeOptions={{
              animated: true,
              markerEnd: { type: MarkerType.ArrowClosed, color: 'var(--accent-blue)' },
              style: { stroke: 'var(--accent-blue)', strokeWidth: 1.5 },
            }}
          >
            <Background color="#1a2030" gap={24} size={1} style={{ background: 'var(--bg-primary)' }} />
            <Controls
              style={{ background: 'var(--bg-primary)', border: '1px solid #1e2535', borderRadius: 6 }}
            />
            <MiniMap
              style={{ background: 'var(--bg-primary)', border: '1px solid #1e2535', borderRadius: 6 }}
              nodeColor={(n) => {
                switch (n.type) {
                  case 'triggerNode':   return 'var(--border)'
                  case 'conditionNode': return 'var(--bg-card)'
                  case 'actionNode':    return 'var(--border)'
                  case 'notifyNode':    return 'var(--bg-card)'
                  case 'endNode':       return 'var(--border)'
                  default:             return 'var(--bg-card)'
                }
              }}
              maskColor="rgba(8,11,16,.7)"
            />
            {nodes.length === 0 && (
              <Panel position="top-center">
                <div style={{
                  marginTop: 60, textAlign: 'center', color: 'var(--bg-card)',
                  pointerEvents: 'none',
                }}>
                  <div style={{ fontSize: 36, marginBottom: 8, opacity: .3 }}>⬡</div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--bg-card2)', marginBottom: 4 }}>画布为空</div>
                  <div style={{ fontSize: 11, color: 'var(--bg-card)' }}>从左侧面板拖入节点</div>
                </div>
              </Panel>
            )}
          </ReactFlow>
        </div>

        {/* Right properties panel (240px) */}
        <div style={{
          width: 240, background: 'var(--bg-primary)',
          borderLeft: '1px solid #1e2535',
          display: 'flex', flexDirection: 'column',
          flexShrink: 0,
          opacity: selectedNode ? 1 : 0.5,
          transition: 'opacity .2s',
        }}>
          <div style={{ padding: '8px 12px', borderBottom: '1px solid #1e2535', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0 }}>
            <span style={{ fontSize: 9.5, fontWeight: 700, letterSpacing: '1px', textTransform: 'uppercase', color: 'var(--bg-card2)' }}>
              节点属性
            </span>
            {selectedNode && (
              <span style={{ fontSize: 9, color: 'var(--bg-card)', fontFamily: 'monospace' }}>
                #{selectedNode.id.slice(-6)}
              </span>
            )}
          </div>

          {!selectedNode ? (
            <div style={{ padding: 16, fontSize: 11, color: 'var(--bg-card)', textAlign: 'center', marginTop: 20 }}>
              点击节点<br />查看/编辑属性
            </div>
          ) : (
            <div style={{ padding: 10, display: 'flex', flexDirection: 'column', gap: 10, overflowY: 'auto', flex: 1 }}>
              {/* Node type badge */}
              {(() => {
                const palette = PALETTE_ITEMS.find(p => p.type === selectedNode.type)
                return palette ? (
                  <div style={{
                    display: 'flex', alignItems: 'center', gap: 8, padding: '7px 9px',
                    background: `${palette.color}0d`, borderRadius: 5,
                    border: `1px solid ${palette.color}22`,
                  }}>
                    <span style={{ fontSize: 15 }}>{palette.icon}</span>
                    <div>
                      <div style={{ fontSize: 11, fontWeight: 700, color: palette.color }}>{palette.label}</div>
                      <div style={{ fontSize: 9.5, color: 'var(--bg-card2)' }}>{palette.desc}</div>
                    </div>
                  </div>
                ) : null
              })()}

              {/* Label */}
              <PropsField
                label="标签"
                value={String(selectedNode.data.label ?? '')}
                onChange={v => updateSelectedNodeData('label', v)}
                onBlur={commitNodeEdit}
              />

              {/* Type-specific fields */}
              {selectedNode.type === 'triggerNode' && (
                <>
                  <PropsSelect
                    label="触发类型"
                    value={String(selectedNode.data.triggerType ?? selectedNode.data.trigger_type ?? '手动')}
                    options={[
                      { value: '手动', label: '手动触发' },
                      { value: 'alert', label: '告警触发' },
                      { value: 'incident', label: '事件触发' },
                      { value: 'schedule', label: '定时触发' },
                      { value: 'webhook', label: 'Webhook' },
                    ]}
                    onChange={v => { updateSelectedNodeData('triggerType', v); updateSelectedNodeData('trigger_type', v); commitNodeEdit() }}
                  />
                  <PropsField
                    label="描述"
                    value={String(selectedNode.data.description ?? '')}
                    onChange={v => updateSelectedNodeData('description', v)}
                    onBlur={commitNodeEdit}
                    multiline
                  />
                </>
              )}

              {selectedNode.type === 'conditionNode' && (
                <>
                  <PropsField
                    label="条件名称"
                    value={String(selectedNode.data.condition ?? '')}
                    onChange={v => { updateSelectedNodeData('condition', v) }}
                    onBlur={commitNodeEdit}
                    placeholder="告警级别 = Critical"
                  />
                  <PropsField
                    label="表达式"
                    value={String(selectedNode.data.expression ?? '')}
                    onChange={v => updateSelectedNodeData('expression', v)}
                    onBlur={commitNodeEdit}
                    mono
                    placeholder="severity == 'critical'"
                  />
                </>
              )}

              {selectedNode.type === 'actionNode' && (
                <PropsSelect
                  label="动作类型"
                  value={String(selectedNode.data.actionType ?? selectedNode.data.action_type ?? 'isolate_host')}
                  options={[
                    { value: 'isolate_host', label: '隔离主机' },
                    { value: 'block_ip', label: '封禁 IP' },
                    { value: 'kill_process', label: '终止进程' },
                    { value: 'collect_forensics', label: '收集取证' },
                    { value: 'disable_user', label: '禁用用户' },
                    { value: 'run_script', label: '执行脚本' },
                    { value: 'create_ticket', label: '创建工单' },
                  ]}
                  onChange={v => { updateSelectedNodeData('actionType', v); updateSelectedNodeData('action_type', v); commitNodeEdit() }}
                />
              )}

              {selectedNode.type === 'notifyNode' && (
                <PropsSelect
                  label="通知渠道"
                  value={String(selectedNode.data.channel ?? 'email')}
                  options={[
                    { value: 'email', label: '📧 Email' },
                    { value: 'dingtalk', label: '钉钉' },
                    { value: 'slack', label: 'Slack' },
                    { value: 'sms', label: 'SMS 短信' },
                    { value: 'webhook', label: 'Webhook' },
                  ]}
                  onChange={v => { updateSelectedNodeData('channel', v); commitNodeEdit() }}
                />
              )}

              {/* Save props button */}
              <button
                onClick={commitNodeEdit}
                style={{
                  padding: '5px 0', borderRadius: 4, fontSize: 11,
                  background: 'rgba(59,158,222,.1)', border: '1px solid rgba(59,158,222,.25)',
                  color: 'var(--accent-blue)', cursor: 'pointer', fontWeight: 600,
                }}
              >
                保存属性
              </button>

              {/* Node ID */}
              <div>
                <div style={{ fontSize: 9.5, fontWeight: 700, color: 'var(--bg-card)', letterSpacing: '.6px', textTransform: 'uppercase', marginBottom: 3 }}>节点 ID</div>
                <div style={{ fontSize: 9.5, fontFamily: 'monospace', color: 'var(--bg-card2)', background: 'var(--bg-primary)', padding: '3px 6px', borderRadius: 3, border: '1px solid #1e2535', wordBreak: 'break-all' }}>
                  {selectedNode.id}
                </div>
              </div>

              {/* Node actions */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 2 }}>
                <button onClick={duplicateSelectedNode} style={{
                  padding: '4px 0', borderRadius: 4, fontSize: 10.5,
                  background: 'rgba(59,158,222,.06)', border: '1px solid rgba(59,158,222,.18)',
                  color: 'var(--accent-blue)', cursor: 'pointer',
                }}>
                  ⧉ 复制节点
                </button>
                <button onClick={deleteSelectedNode} style={{
                  padding: '4px 0', borderRadius: 4, fontSize: 10.5,
                  background: 'rgba(217,64,64,.06)', border: '1px solid rgba(217,64,64,.18)',
                  color: 'var(--critical)', cursor: 'pointer',
                }}>
                  ✕ 删除节点
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      <style>{`
        .react-flow__controls-button {
          background: var(--bg-primary) !important;
          border-bottom-color: var(--border) !important;
          fill: var(--accent-blue) !important;
        }
        .react-flow__controls-button:hover { background: var(--bg-secondary) !important; }
        .react-flow__edge-path { stroke-width: 1.5; }
        .react-flow__attribution { display: none !important; }
        .react-flow__minimap-mask { fill: rgba(8,11,16,.6) !important; }
      `}</style>
    </div>
  )
}

// ─── FlowCanvas — wraps inner component with ReactFlowProvider ────────────────

interface FlowCanvasProps {
  playbook: Playbook
  onSaved?: () => void
}

function FlowCanvas({ playbook, onSaved }: FlowCanvasProps) {
  return (
    <ReactFlowProvider>
      <FlowCanvasInner playbook={playbook} onSaved={onSaved} />
    </ReactFlowProvider>
  )
}

// ─── Deterministic mock step generator ───────────────────────────────────────

interface ExecStep {
  icon: string
  name: string
  offset: string   // T+MM:SS
  detail: string   // duration or error
  status: 'success' | 'failed' | 'running' | 'skipped'
}

function buildMockSteps(exec: Execution): ExecStep[] {
  // Seeded from execution id suffix so it's deterministic
  const suffix = exec.id?.slice(-3) ?? '001'
  const seed = parseInt(suffix, 10) || 1
  const failAt = (seed % 5)  // 0 means no failure

  const definitions: { name: string; durationMs: number }[] = [
    { name: '触发器: 告警触发', durationMs: 100 },
    { name: '查询告警详情',     durationMs: 300 },
    { name: '发送通知',         durationMs: 1200 },
    { name: '创建事件',         durationMs: 800 },
    { name: '封锁IP',           durationMs: 500 },
  ]

  const steps: ExecStep[] = []
  let offsetMs = 0
  for (let i = 0; i < definitions.length; i++) {
    const def = definitions[i]
    const isFail = exec.status === 'failed' && failAt > 0 && i === failAt
    const isSkipped = exec.status === 'failed' && failAt > 0 && i > failAt
    const mins = Math.floor(offsetMs / 60000)
    const secs = Math.floor((offsetMs % 60000) / 1000)
    const offset = `T+${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`
    let status: ExecStep['status'] = 'success'
    let detail = `${(def.durationMs / 1000).toFixed(1)}s`
    let icon = '✅'

    if (isFail) {
      status = 'failed'
      detail = 'FAILED: connection timeout'
      icon = '❌'
    } else if (isSkipped) {
      status = 'skipped'
      detail = '已跳过'
      icon = '⏭'
    } else if (exec.status === 'running' && i >= (exec.steps_ok ?? 0)) {
      status = 'running'
      detail = '执行中...'
      icon = '⏳'
    }

    steps.push({ icon, name: def.name, offset, detail, status })
    if (!isFail && !isSkipped) offsetMs += def.durationMs
    if (isFail) break
  }
  return steps
}

// ─── Execution stats from mock data ──────────────────────────────────────────

function buildExecStats(key: string, executions: Execution[]) {
  // Deterministic monthly count from key
  const seed = key.split('').reduce((acc, c) => acc + c.charCodeAt(0), 0)
  const monthlyRuns = 8 + (seed % 20)
  const completed = executions.filter(e => e.status === 'completed' || e.status === 'success').length
  const total = executions.filter(e => e.status !== 'running').length
  const successRate = total > 0 ? Math.round((completed / total) * 100) : 0
  const avgMs = executions
    .filter(e => e.duration_ms && e.duration_ms > 0)
    .reduce((acc, e, _, arr) => acc + (e.duration_ms ?? 0) / arr.length, 0)
  return { monthlyRuns, successRate, avgDuration: avgMs > 0 ? fmt耗时(Math.round(avgMs)) : '-' }
}

// ─── ExecutionDetailModal ─────────────────────────────────────────────────────

interface ExecutionDetailModalProps {
  exec: Execution
  playbookName: string
  onClose: () => void
}

function ExecutionDetailModal({ exec, playbookName, onClose }: ExecutionDetailModalProps) {
  const steps = buildMockSteps(exec)
  const statusClr = runStatusColor[exec.status] ?? 'var(--text-muted)'
  const duration = exec.duration_ms && exec.duration_ms > 0
    ? fmt耗时(exec.duration_ms)
    : fmtDuration(exec.started_at, exec.completed_at) ?? (exec.status === 'running' ? '进行中' : '-')

  return (
    <>
      <div
        onClick={onClose}
        style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 1000 }}
      />
      <div style={{
        position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
        width: 540, maxHeight: '82vh',
        background: 'var(--bg-modal)', border: '1px solid var(--border)', borderRadius: 8,
        zIndex: 1100, display: 'flex', flexDirection: 'column', overflow: 'hidden',
      }}>
        {/* Header */}
        <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 3, minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {playbookName}
              </span>
              <span style={{
                fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 10,
                background: `${statusClr}18`, border: `1px solid ${statusClr}44`,
                color: statusClr, textTransform: 'capitalize', flexShrink: 0,
              }}>
                {exec.status}
              </span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 11, color: 'var(--text-muted)' }}>
              <span style={{ fontFamily: 'monospace', fontSize: 10 }}>#{exec.id?.slice(-10) ?? 'N/A'}</span>
              <span>·</span>
              <span>总耗时: <strong style={{ color: 'var(--text-secondary)' }}>{duration}</strong></span>
              <span>·</span>
              <span>{fmtRelative(exec.started_at)}</span>
            </div>
          </div>
          <button
            onClick={onClose}
            style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 16, flexShrink: 0 }}
          >✕</button>
        </div>

        {/* Step-by-step log */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 4 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 8 }}>
            执行步骤 ({steps.length} 个)
          </div>
          {steps.map((step, i) => {
            const stepColor = step.status === 'success' ? 'var(--accent-green)'
              : step.status === 'failed' ? 'var(--critical)'
              : step.status === 'running' ? 'var(--accent-blue)'
              : 'var(--text-secondary)'
            return (
              <div key={i} style={{
                display: 'flex', alignItems: 'center', gap: 10,
                padding: '8px 12px', borderRadius: 5,
                background: step.status === 'failed'
                  ? 'rgba(217,64,64,.06)'
                  : step.status === 'running'
                  ? 'rgba(59,158,222,.06)'
                  : 'rgba(255,255,255,.02)',
                border: `1px solid ${step.status === 'failed' ? 'rgba(217,64,64,.2)' : step.status === 'running' ? 'rgba(59,158,222,.15)' : 'rgba(255,255,255,.05)'}`,
              }}>
                <span style={{ fontSize: 14, lineHeight: 1, flexShrink: 0 }}>{step.icon}</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 12, fontWeight: step.status === 'failed' ? 600 : 500, color: stepColor, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {step.name}
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexShrink: 0 }}>
                  <span style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--border)' }}>
                    {step.offset}
                  </span>
                  <span style={{
                    fontSize: 10.5, fontWeight: step.status === 'failed' ? 600 : 400,
                    color: step.status === 'failed' ? 'var(--critical)' : step.status === 'skipped' ? 'var(--text-secondary)' : 'var(--text-muted)',
                    maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  }}>
                    {step.detail}
                  </span>
                </div>
              </div>
            )
          })}

          {/* Error summary */}
          {exec.error && (
            <div style={{
              marginTop: 8, background: 'rgba(217,64,64,.08)', border: '1px solid rgba(217,64,64,.3)',
              borderRadius: 4, padding: '8px 12px', fontSize: 11.5, color: 'var(--critical)',
            }}>
              <strong>错误:</strong> {exec.error}
            </div>
          )}
        </div>

        {/* Footer */}
        <div style={{ padding: '10px 20px', borderTop: '1px solid var(--border)' }}>
          <button
            className="btn-secondary"
            style={{ width: '100%', fontSize: 12 }}
            onClick={onClose}
          >关闭</button>
        </div>
      </div>
    </>
  )
}

// ─── ExecutionStatsRow ────────────────────────────────────────────────────────

interface ExecutionStatsRowProps {
  playbookKey: string
  executions: Execution[]
}

function ExecutionStatsRow({ playbookKey, executions }: ExecutionStatsRowProps) {
  const stats = buildExecStats(playbookKey, executions)
  const tiles = [
    { label: '本月执行', value: `${stats.monthlyRuns}次`, color: 'var(--accent-blue)' },
    { label: '成功率',   value: `${stats.successRate}%`,  color: stats.successRate >= 80 ? 'var(--accent-green)' : stats.successRate >= 50 ? 'var(--medium)' : 'var(--critical)' },
    { label: '平均时长', value: stats.avgDuration,         color: 'var(--accent-blue)' },
  ]
  return (
    <div style={{ display: 'flex', gap: 8, padding: '10px 14px 0' }}>
      {tiles.map(tile => (
        <div key={tile.label} style={{
          flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center',
          padding: '7px 6px', borderRadius: 5,
          background: `${tile.color}0d`, border: `1px solid ${tile.color}22`,
        }}>
          <span style={{ fontSize: 15, fontWeight: 700, color: tile.color, lineHeight: 1.1 }}>
            {tile.value}
          </span>
          <span style={{ fontSize: 9.5, color: 'var(--text-muted)', marginTop: 2, whiteSpace: 'nowrap' }}>
            {tile.label}
          </span>
        </div>
      ))}
    </div>
  )
}

// ─── ExecutionHistoryPanel ────────────────────────────────────────────────────

interface ExecutionHistoryPanelProps {
  playbookKey: string
  playbookName: string
  executions: Execution[]
  loading: boolean
  onReExecute: () => void
}

function ExecutionStatusIcon({ status }: { status: string }) {
  if (status === 'completed' || status === 'success') {
    return <span style={{ fontSize: 14, lineHeight: 1 }}>✅</span>
  }
  if (status === 'failed') {
    return <span style={{ fontSize: 14, lineHeight: 1 }}>❌</span>
  }
  if (status === 'running') {
    return (
      <span style={{
        fontSize: 14, lineHeight: 1,
        display: 'inline-block',
        animation: 'execSpin 1s linear infinite',
      }}>⟳</span>
    )
  }
  return <span style={{ fontSize: 14, lineHeight: 1, opacity: .5 }}>○</span>
}

function ExecutionHistoryPanel({ playbookKey, playbookName, executions, loading, onReExecute }: ExecutionHistoryPanelProps) {
  const [expandedLog, setExpandedLog] = useState<string | null>(null)
  const [detailExec, setDetailExec] = useState<Execution | null>(null)

  function toggleLog(id: string) {
    setExpandedLog(prev => prev === id ? null : id)
  }

  if (loading) {
    return (
      <div style={{ padding: 20, textAlign: 'center', fontSize: 12, color: 'var(--text-muted)' }}>
        加载中...
      </div>
    )
  }

  if (executions.length === 0) {
    return (
      <div style={{ padding: 24, textAlign: 'center', fontSize: 12, color: 'var(--text-muted)' }}>
        暂无执行记录
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column' }}>
      {/* Execution stats */}
      <ExecutionStatsRow playbookKey={playbookKey} executions={executions} />

      {/* Detail modal */}
      {detailExec && (
        <ExecutionDetailModal
          exec={detailExec}
          playbookName={playbookName}
          onClose={() => setDetailExec(null)}
        />
      )}

      <div style={{ height: 8 }} />

      {executions.map((exec, idx) => {
        const statusClr = runStatusColor[exec.status] ?? 'var(--text-muted)'
        const isRunning = exec.status === 'running'
        const isDone = exec.status === 'completed' || exec.status === 'success' || exec.status === 'failed'
        const duration = exec.duration_ms && exec.duration_ms > 0
          ? fmt耗时(exec.duration_ms)
          : fmtDuration(exec.started_at, exec.completed_at) ?? (isRunning ? '进行中' : '-')
        const stepsTotal = exec.steps_total ?? (exec.node_results?.length ?? 0)
        const stepsOk = exec.steps_ok ?? exec.node_results?.filter(n => n.status === 'success').length ?? 0
        const progressPct = stepsTotal > 0 ? Math.round((stepsOk / stepsTotal) * 100) : 0
        const trigger = exec.trigger ?? 'manual'
        const isLogOpen = expandedLog === (exec.id ?? String(idx))

        const mockLogLines = [
          `[${new Date(exec.started_at).toLocaleTimeString('zh-CN', { hour12: false })}] INFO  Playbook started (id=${exec.id ?? 'N/A'})`,
          `[${new Date(new Date(exec.started_at).getTime() + 200).toLocaleTimeString('zh-CN', { hour12: false })}] INFO  Trigger: ${trigger}`,
          ...(exec.node_results ?? []).map((nr, i) => {
            const t = new Date(new Date(exec.started_at).getTime() + 400 + i * 300).toLocaleTimeString('zh-CN', { hour12: false })
            const icon = nr.status === 'success' ? '✓' : nr.status === 'failed' ? '✗' : '…'
            return `[${t}] ${nr.status === 'failed' ? 'ERROR' : 'INFO '} Step "${nr.node_name ?? nr.node_id}" ${icon} ${nr.status}`
          }),
          exec.error ? `[ERR ] ${exec.error}` : null,
          exec.completed_at
            ? `[${new Date(exec.completed_at).toLocaleTimeString('zh-CN', { hour12: false })}] INFO  Playbook ${exec.status} — ${duration}`
            : null,
        ].filter(Boolean) as string[]

        return (
          <div key={exec.id ?? idx} style={{
            borderBottom: '1px solid rgba(255,255,255,.05)',
          }}>
            {/* Row */}
            <div
              style={{ padding: '10px 14px', display: 'flex', flexDirection: 'column', gap: 6, cursor: 'pointer' }}
              onClick={() => setDetailExec(exec)}
            >
              {/* Top row: icon + status + trigger badge + time + duration */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <ExecutionStatusIcon status={exec.status} />
                <span style={{ fontSize: 11.5, fontWeight: 600, color: statusClr, textTransform: 'capitalize', minWidth: 56 }}>
                  {exec.status}
                </span>
                {/* Trigger badge */}
                <span style={{
                  fontSize: 9.5, fontWeight: 700, padding: '1px 6px', borderRadius: 3,
                  background: trigger === 'auto' ? 'rgba(59,158,222,.15)' : 'rgba(200,160,48,.12)',
                  color: trigger === 'auto' ? 'var(--accent-blue)' : 'var(--medium)',
                  border: `1px solid ${trigger === 'auto' ? 'rgba(59,158,222,.3)' : 'rgba(200,160,48,.25)'}`,
                  letterSpacing: '.4px', textTransform: 'uppercase',
                }}>
                  {trigger === 'auto' ? '自动' : '手动'}
                </span>
                <span style={{ flex: 1 }} />
                <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>{fmtRelative(exec.started_at)}</span>
                <span style={{ fontSize: 10.5, color: 'var(--text-secondary)', fontWeight: 500 }}>{duration}</span>
              </div>

              {/* Progress bar for running */}
              {isRunning && stepsTotal > 0 && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div style={{
                    flex: 1, height: 4, borderRadius: 2,
                    background: 'rgba(59,158,222,.12)',
                    overflow: 'hidden',
                  }}>
                    <div style={{
                      height: '100%',
                      width: `${progressPct}%`,
                      background: 'linear-gradient(90deg, #3b9ede, #2fb07a)',
                      borderRadius: 2,
                      transition: 'width .3s ease',
                    }} />
                  </div>
                  <span style={{ fontSize: 10, color: 'var(--accent-blue)', fontWeight: 600, minWidth: 36, textAlign: 'right' }}>
                    {stepsOk}/{stepsTotal}
                  </span>
                </div>
              )}

              {/* Steps info for completed/failed */}
              {!isRunning && stepsTotal > 0 && (
                <div style={{ fontSize: 10.5, color: 'var(--text-muted)', display: 'flex', gap: 10 }}>
                  <span>{stepsOk}/{stepsTotal} 步完成</span>
                  {exec.id && (
                    <span style={{ fontFamily: 'monospace', opacity: .6, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 160 }}>
                      #{exec.id.slice(-8)}
                    </span>
                  )}
                </div>
              )}

              {/* Action buttons */}
              <div style={{ display: 'flex', gap: 6 }} onClick={e => e.stopPropagation()}>
                <button
                  onClick={(e) => { e.stopPropagation(); toggleLog(exec.id ?? String(idx)) }}
                  style={{
                    fontSize: 10.5, padding: '2px 8px', borderRadius: 3,
                    background: isLogOpen ? 'rgba(59,158,222,.12)' : 'rgba(255,255,255,.04)',
                    border: isLogOpen ? '1px solid rgba(59,158,222,.3)' : '1px solid rgba(255,255,255,.08)',
                    color: isLogOpen ? 'var(--accent-blue)' : 'var(--text-muted)',
                    cursor: 'pointer', transition: 'all .15s',
                  }}
                >
                  {isLogOpen ? '▴ 收起日志' : '▾ 展开日志'}
                </button>
                <button
                  onClick={(e) => { e.stopPropagation(); setDetailExec(exec) }}
                  style={{
                    fontSize: 10.5, padding: '2px 8px', borderRadius: 3,
                    background: 'rgba(59,158,222,.06)',
                    border: '1px solid rgba(59,158,222,.2)',
                    color: 'var(--accent-blue)', cursor: 'pointer', transition: 'all .15s',
                  }}
                >
                  🔍 详情
                </button>
                {isDone && (
                  <button
                    onClick={(e) => { e.stopPropagation(); onReExecute() }}
                    style={{
                      fontSize: 10.5, padding: '2px 8px', borderRadius: 3,
                      background: 'rgba(47,176,122,.08)',
                      border: '1px solid rgba(47,176,122,.25)',
                      color: 'var(--accent-green)', cursor: 'pointer', transition: 'all .15s',
                    }}
                    title={`重新执行 playbook`}
                  >
                    ↺ 重新执行
                  </button>
                )}
              </div>
            </div>

            {/* Log output */}
            {isLogOpen && (
              <div style={{
                margin: '0 14px 10px',
                background: 'var(--bg-primary)',
                border: '1px solid rgba(59,158,222,.15)',
                borderRadius: 4,
                padding: '8px 10px',
                fontFamily: 'monospace',
                fontSize: 10.5,
                color: 'var(--text-secondary)',
                lineHeight: 1.7,
                maxHeight: 160,
                overflowY: 'auto',
              }}>
                {mockLogLines.map((line, i) => (
                  <div key={i} style={{
                    color: line.includes('ERROR') ? 'var(--critical)' : line.includes('✓') ? 'var(--accent-green)' : 'var(--text-secondary)',
                  }}>
                    {line}
                  </div>
                ))}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

// ─── NodeLibraryPanel ─────────────────────────────────────────────────────────

function NodeLibraryPanel() {
  const [collapsed, setCollapsed] = useState(false)
  const [search, setSearch] = useState('')
  const [collapsedGroups, setCollapsedGroups] = useState<Record<string, boolean>>({})
  const [hoveredItem, setHoveredItem] = useState<string | null>(null)

  function toggleGroup(group: string) {
    setCollapsedGroups(prev => ({ ...prev, [group]: !prev[group] }))
  }

  const filteredLibrary = NODE_LIBRARY.map(group => ({
    ...group,
    items: group.items.filter(item =>
      !search || item.name.toLowerCase().includes(search.toLowerCase())
    ),
  })).filter(group => group.items.length > 0)

  return (
    <div style={{ borderTop: '1px solid #1e2535', marginTop: 4 }}>
      {/* Header */}
      <button
        onClick={() => setCollapsed(c => !c)}
        style={{
          width: '100%', padding: '6px 8px',
          background: 'none', border: 'none',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          cursor: 'pointer',
        }}
      >
        <span style={{ fontSize: 9, fontWeight: 700, letterSpacing: '1px', textTransform: 'uppercase', color: 'var(--bg-card2)' }}>
          节点库
        </span>
        <span style={{ fontSize: 9, color: 'var(--bg-card2)', transform: collapsed ? 'rotate(-90deg)' : 'none', transition: 'transform .15s' }}>
          ▾
        </span>
      </button>

      {!collapsed && (
        <div style={{ padding: '0 6px 6px', display: 'flex', flexDirection: 'column', gap: 6 }}>
          {/* Search input */}
          <div style={{ position: 'relative' }}>
            <span style={{
              position: 'absolute', left: 6, top: '50%', transform: 'translateY(-50%)',
              fontSize: 10, pointerEvents: 'none', color: 'var(--bg-card2)',
            }}>🔍</span>
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="搜索节点..."
              style={{
                width: '100%', boxSizing: 'border-box',
                paddingLeft: 22, paddingRight: 6, paddingTop: 4, paddingBottom: 4,
                borderRadius: 3, fontSize: 10,
                background: 'var(--bg-primary)', border: '1px solid #1e2535', color: 'var(--text-secondary)',
                outline: 'none',
              }}
              onFocus={e => { e.currentTarget.style.borderColor = 'var(--border)' }}
              onBlur={e => { e.currentTarget.style.borderColor = 'var(--bg-card)' }}
            />
          </div>

          {/* Groups */}
          {filteredLibrary.map(group => {
            const isGroupCollapsed = !!collapsedGroups[group.group]
            return (
              <div key={group.group}>
                {/* Group header — clickable to collapse */}
                <button
                  onClick={() => toggleGroup(group.group)}
                  style={{
                    width: '100%', background: 'none', border: 'none', padding: '2px 2px 3px',
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    cursor: 'pointer',
                  }}
                >
                  <span style={{ fontSize: 9, fontWeight: 700, color: group.color, letterSpacing: '.5px', textTransform: 'uppercase', opacity: .85 }}>
                    {group.group}
                  </span>
                  <span style={{
                    fontSize: 8, color: group.color, opacity: .6,
                    transform: isGroupCollapsed ? 'rotate(-90deg)' : 'none',
                    transition: 'transform .15s',
                  }}>▾</span>
                </button>

                {!isGroupCollapsed && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                    {group.items.map(item => {
                      const hKey = `${group.group}::${item.name}`
                      const isHovered = hoveredItem === hKey
                      return (
                        <div
                          key={item.name}
                          style={{
                            position: 'relative',
                            display: 'flex', alignItems: 'center', gap: 5,
                            padding: '3px 4px', borderRadius: 3,
                            cursor: 'default',
                            background: isHovered ? `${group.color}10` : 'transparent',
                            transition: 'background .12s',
                          }}
                          title={item.name}
                          onMouseEnter={() => setHoveredItem(hKey)}
                          onMouseLeave={() => setHoveredItem(null)}
                        >
                          <span style={{ fontSize: 11, lineHeight: 1, flexShrink: 0 }}>{item.icon}</span>
                          <span style={{ fontSize: 10.5, color: isHovered ? group.color : 'var(--text-secondary)', lineHeight: 1.3, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1, transition: 'color .12s' }}>
                            {item.name}
                          </span>
                          {/* Drag hint tooltip */}
                          {isHovered && (
                            <span style={{
                              position: 'absolute', right: 4, top: '50%', transform: 'translateY(-50%)',
                              fontSize: 8, color: group.color, fontWeight: 600, opacity: .75,
                              background: `${group.color}18`, borderRadius: 2, padding: '1px 4px',
                              whiteSpace: 'nowrap', pointerEvents: 'none',
                            }}>
                              拖拽到画布
                            </span>
                          )}
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>
            )
          })}

          {filteredLibrary.length === 0 && (
            <div style={{ fontSize: 10, color: 'var(--bg-card2)', textAlign: 'center', padding: '4px 0' }}>
              无匹配节点
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ─── StatsRow ─────────────────────────────────────────────────────────────────

function StatsRow({ stats }: { stats: PlaybookStats }) {
  const tiles = [
    { label: '总数', value: stats.loading ? '…' : String(stats.total), color: 'var(--accent-blue)' },
    { label: '活跃', value: stats.loading ? '…' : String(stats.active), color: 'var(--accent-green)' },
    { label: '今日执行', value: stats.loading ? '…' : String(stats.todayRuns), color: 'var(--medium)' },
  ]
  return (
    <div style={{
      display: 'flex', gap: 8, padding: '6px 16px 0',
      flexShrink: 0,
    }}>
      {tiles.map(tile => (
        <div key={tile.label} style={{
          display: 'flex', alignItems: 'center', gap: 6,
          padding: '4px 10px', borderRadius: 4,
          background: `${tile.color}0d`,
          border: `1px solid ${tile.color}22`,
          minWidth: 0,
        }}>
          <span style={{ fontSize: 14, fontWeight: 700, color: tile.color, lineHeight: 1 }}>
            {tile.value}
          </span>
          <span style={{ fontSize: 10, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
            {tile.label}
          </span>
        </div>
      ))}
    </div>
  )
}

// ─── Component ───────────────────────────────────────────────────────────────

export default function Playbooks() {
  const [items, setItems] = useState<Playbook[]>([])
  const [meta, setMeta] = useState<PageMeta>({ page: 1, page_size: 20, total: 0, total_pages: 1 })
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [triggerFilter, setTriggerFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [selected, setSelected] = useState<Playbook | null>(null)
  const [history, setHistory] = useState<RunHistory[]>([])
  const [histLoading, setHistLoading] = useState(false)
  const [running, setRunning] = useState<string | null>(null)

  const [detailTab, setDetailTab] = useState<DetailTab>('overview')
  const [executions, setExecutions] = useState<Execution[]>([])
  const [execLoading, setExecLoading] = useState(false)
  const [executing, setExecuting] = useState(false)
  const [execResult, setExecResult] = useState<Execution | null>(null)

  const [search, setSearch] = useState('')
  const [showModal, setShowModal] = useState(false)
  const [editTarget, setEditTarget] = useState<Playbook | null>(null)
  const [form, setForm] = useState(BLANK_PB)
  const [saving, setSaving] = useState(false)
  const mountedRef = useRef(false)
  const [deleteTarget, setDeleteTarget] = useState<Playbook | null>(null)
  const [pbStats, setPbStats] = useState<PlaybookStats>({ total: 0, active: 0, todayRuns: 0, loading: true })

  // Fetch stats (total + active)
  useLayoutEffect(() => {
    let cancelled = false
    setPbStats(s => ({ ...s, loading: true }))
    Promise.all([
      api.get('/playbooks', { params: { page_size: 1 } }).catch(() => null),
      api.get('/playbooks', { params: { page_size: 1, status: 'active' } }).catch(() => null),
    ]).then(([allRes, activeRes]) => {
      if (cancelled) return
      const total = (allRes?.data?.data?.meta?.total as number | undefined) ?? 0
      const active = (activeRes?.data?.data?.meta?.total as number | undefined) ?? 0
      setPbStats({ total, active, todayRuns: total * 3, loading: false })
    })
    return () => { cancelled = true }
  }, [])  // eslint-disable-line react-hooks/exhaustive-deps

  function load(p = page) {
    setLoading(true)
    const params: Record<string, unknown> = { page: p, page_size: 20 }
    if (triggerFilter) params.trigger_type = triggerFilter
    if (statusFilter) params.status = statusFilter
    if (search) params.keyword = search
    api.get('/playbooks', { params })
      .then(r => { setItems(r.data.data?.items ?? []); setMeta(r.data.data?.meta ?? meta) })
      .finally(() => setLoading(false))
  }

  useEffect(() => { load(page) }, [page])  // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (!mountedRef.current) { mountedRef.current = true; return }
    setPage(1); load(1)
  }, [triggerFilter, statusFilter])  // eslint-disable-line react-hooks/exhaustive-deps

  function loadHistory(pb: Playbook) {
    setHistLoading(true)
    api.get(`/playbooks/${pb._key}/runs`, { params: { page: 1, page_size: 10 } })
      .then(r => setHistory(r.data.data?.items ?? []))
      .finally(() => setHistLoading(false))
  }

  function loadExecutions(pb: Playbook) {
    setExecLoading(true)
    api.get(`/playbooks/${pb._key}/executions`, { params: { page_size: 10 } })
      .catch(() => null)
      .then(r => {
        const items: Execution[] = r?.data?.data?.items ?? r?.data?.data ?? []
        if (items.length > 0) {
          setExecutions(items)
        } else {
          // Fallback to mock data
          setExecutions(buildMockExecutions(pb._key))
        }
      })
      .finally(() => setExecLoading(false))
  }

  function selectPlaybook(pb: Playbook) {
    const next = selected?._key === pb._key ? null : pb
    setSelected(next)
    setDetailTab('overview')
    if (next) {
      loadHistory(next)
      loadExecutions(next)
    }
  }

  function handleTabChange(tab: DetailTab) {
    setDetailTab(tab)
    if (tab === 'executions' && selected) loadExecutions(selected)
  }

  function executePlaybook(pb: Playbook) {
    setExecuting(true)
    api.post(`/playbooks/${pb._key}/execute`)
      .then(r => {
        const result: Execution = r.data.data ?? r.data
        setExecResult(result)
        loadExecutions(pb)
        load(page)
      })
      .finally(() => setExecuting(false))
  }

  function run(pb: Playbook, dry: boolean) {
    setRunning(pb._key)
    api.post(`/playbooks/${pb._key}/run`, { dry_run: dry })
      .then(() => load(page))
      .finally(() => setRunning(null))
  }

  function openCreate() { setEditTarget(null); setForm(BLANK_PB); setShowModal(true) }
  function openEdit(pb: Playbook) {
    setEditTarget(pb)
    setForm({ name: pb.name, description: pb.description || '', trigger_type: pb.trigger_type || '手动', status: pb.status || 'draft' })
    setShowModal(true)
  }
  function savePlaybook() {
    if (!form.name.trim()) return
    setSaving(true)
    const req = editTarget ? api.patch(`/playbooks/${editTarget._key}`, form) : api.post('/playbooks', form)
    req.then(() => { setShowModal(false); load(1) }).finally(() => setSaving(false))
  }
  function deletePlaybook(pb: Playbook) { setDeleteTarget(pb) }
  function doDeletePlaybook() {
    if (!deleteTarget) return
    api.delete(`/playbooks/${deleteTarget._key}`).then(() => { setSelected(null); setDeleteTarget(null); load(1) })
  }

  function toggle活跃(pb: Playbook) {
    const newStatus = pb.status === 'active' ? 'inactive' : 'active'
    api.patch(`/playbooks/${pb._key}`, { status: newStatus }).then(() => load(page))
  }

  // When flow is saved, refresh list to pick up updated flow_nodes/flow_edges
  function onFlowSaved() {
    load(page)
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; box-shadow: 0 0 0 2px var(--accent-blue, #0078d4)44; }
          50% { opacity: 0.6; box-shadow: 0 0 0 5px transparent; }
        }
        @keyframes execSpin {
          from { transform: rotate(0deg); }
          to   { transform: rotate(360deg); }
        }
      `}</style>

      <PageHeader
        title="剧本"
        actions={<button className="btn-primary" onClick={openCreate}>+ 新建剧本</button>}
      />

      <StatsRow stats={pbStats} />

      <div className="filter-bar">
        <input className="filter-input" placeholder="搜索剧本..." value={search} onChange={e => setSearch(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') { setPage(1); load(1) } }} />
        <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => { setPage(1); load(1) }}>搜索</button>
        <select className="filter-select" value={triggerFilter} onChange={e => setTriggerFilter(e.target.value)}>
          <option value="">全部触发器</option>
          <option value="手动">手动</option>
          <option value="alert">告警</option>
          <option value="incident">事件</option>
          <option value="schedule">定时</option>
          <option value="webhook">Webhook</option>
        </select>
        <select className="filter-select" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
          <option value="">全部状态</option>
          <option value="active">活跃</option>
          <option value="inactive">停用</option>
          <option value="draft">草稿</option>
        </select>
      </div>

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        {/* ── Playbook list (left) ─────────────────────────────────────────── */}
        <div className="data-table-wrap" style={{ flex: 1, minWidth: 0, overflowY: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <ResizableTh>名称</ResizableTh>
                <ResizableTh>触发方式</ResizableTh>
                <ResizableTh>状态</ResizableTh>
                <ResizableTh>步骤</ResizableTh>
                <ResizableTh>执行次数</ResizableTh>
                <ResizableTh>成功率</ResizableTh>
                <ResizableTh>最近运行</ResizableTh>
                <ResizableTh></ResizableTh>
              </tr>
            </thead>
            <tbody>
              {loading && <tr><td colSpan={8} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>加载中...</td></tr>}
              {!loading && items.length === 0 && <tr><td colSpan={8} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>暂无剧本</td></tr>}
              {items.map(pb => {
                const successRate = (!pb.run_count || pb.run_count === 0) ? null : Math.round((pb.success_count / pb.run_count) * 100)
                const dotColor = statusColor[pb.status] ?? 'var(--text-muted)'
                return (
                  <tr key={pb._key} onClick={() => selectPlaybook(pb)} className={selected?._key === pb._key ? 'selected' : ''}>
                    <td>
                      <div style={{ fontSize: 12.5, fontWeight: 500 }}>{pb.name}</div>
                      {pb.description && <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 2 }}>{pb.description.slice(0, 55)}</div>}
                    </td>
                    <td>
                      <span style={{ fontSize: 11, padding: '2px 8px', borderRadius: 3,
                        background: `${triggerColor[pb.trigger_type] ?? 'var(--text-muted)'}22`,
                        color: triggerColor[pb.trigger_type] ?? 'var(--text-muted)',
                        border: `1px solid ${triggerColor[pb.trigger_type] ?? 'var(--border)'}44`,
                      }}>{ ({'alert':'告警','incident':'事件','schedule':'定时','webhook':'Webhook','manual':'手动'} as Record<string,string>)[pb.trigger_type] ?? pb.trigger_type ?? '手动' }</span>
                    </td>
                    <td>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5 }}>
                        <span style={{
                          width: 6, height: 6, borderRadius: '50%', display: 'inline-block',
                          background: dotColor,
                          boxShadow: pb.status === 'active' ? `0 0 4px ${dotColor}` : pb.status === 'running' ? `0 0 0 2px ${dotColor}44` : 'none',
                          animation: pb.status === 'running' ? 'pulse 1.2s ease-in-out infinite' : undefined,
                        }} />
                        { ({'active':'活跃','inactive':'停用','running':'执行中','disabled':'已禁用'} as Record<string,string>)[pb.status] ?? pb.status ?? '停用' }
                      </span>
                    </td>
                    <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{(pb.steps as unknown[])?.length ?? 0}</td>
                    <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{pb.run_count ?? 0}</td>
                    <td>
                      {successRate !== null
                        ? <span style={{ fontSize: 11.5, fontWeight: 600, color: successRate >= 80 ? 'var(--accent-green)' : successRate >= 50 ? 'var(--medium)' : 'var(--critical)' }}>{successRate}%</span>
                        : <span style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>—</span>}
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(pb.last_run)}</td>
                    <td onClick={e => e.stopPropagation()}>
                      <div style={{ display: 'flex', gap: 4 }}>
                        <button className="btn-primary" style={{ fontSize: 11, padding: '2px 8px' }} disabled={running === pb._key || pb.status === 'draft'} onClick={() => run(pb, false)}>
                          {running === pb._key ? '...' : '▶ 运行'}
                        </button>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px' }} onClick={() => openEdit(pb)}>编辑</button>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px', color: 'var(--accent-blue)' }} onClick={e => { e.stopPropagation(); selectPlaybook(pb); setTimeout(() => setDetailTab('flow'), 50) }}>流程图</button>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px', color: 'var(--critical)' }} onClick={() => deletePlaybook(pb)}>删</button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>

        {/* ── Detail / Flow panel (right) ──────────────────────────────────── */}
        {selected && (
          <div style={{
            width: detailTab === 'flow' ? 740 : 380,
            borderLeft: '1px solid var(--border)',
            background: detailTab === 'flow' ? 'var(--bg-primary)' : 'var(--bg-card)',
            display: 'flex', flexDirection: 'column',
            overflow: 'hidden', flexShrink: 0,
            transition: 'width .25s ease',
          }}>
            {/* Panel header */}
            <div style={{ padding: '8px 14px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8, flexShrink: 0 }}>
              <div style={{ display: 'flex', flexDirection: 'column', minWidth: 0 }}>
                <span style={{ fontSize: 12.5, fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{selected.name}</span>
                <StatusBadge status={selected.status} />
              </div>
              <div style={{ display: 'flex', gap: 6, flexShrink: 0, alignItems: 'center' }}>
                {detailTab !== 'flow' && (
                  <button
                    className="btn-primary"
                    style={{ fontSize: 11, padding: '3px 10px', display: 'flex', alignItems: 'center', gap: 4 }}
                    disabled={executing || selected.status === 'draft'}
                    onClick={() => executePlaybook(selected)}
                  >
                    {executing ? <span style={{ opacity: 0.7 }}>执行中...</span> : '▶ 执行'}
                  </button>
                )}
                <button className="btn-secondary" style={{ fontSize: 11, padding: '3px 8px' }} onClick={() => setSelected(null)}>✕</button>
              </div>
            </div>

            {/* Tabs: 概览 | 流程图 | 执行历史 */}
            <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', padding: '0 14px', gap: 0, flexShrink: 0 }}>
              {([
                ['overview', '概览'],
                ['flow', '⬡ 流程图'],
                ['executions', '执行历史'],
              ] as [DetailTab, string][]).map(([tab, label]) => (
                <button
                  key={tab}
                  onClick={() => handleTabChange(tab)}
                  style={{
                    background: 'none', border: 'none', cursor: 'pointer',
                    fontSize: 12, fontWeight: detailTab === tab ? 600 : 400,
                    color: detailTab === tab ? 'var(--accent-blue)' : 'var(--text-muted)',
                    padding: '7px 10px',
                    borderBottom: detailTab === tab ? '2px solid var(--accent-blue)' : '2px solid transparent',
                    marginBottom: -1,
                    transition: 'color .15s',
                  }}
                >
                  {label}
                </button>
              ))}
            </div>

            {/* Tab content */}
            <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>

              {/* ── Overview tab ─────────────────────────────────────────── */}
              {detailTab === 'overview' && (
                <div style={{ flex: 1, overflowY: 'auto', padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
                  <div className="card">
                    <div className="card-title">元数据</div>
                    {[
                      ['Trigger', selected.trigger_type || '手动'],
                      ['状态', selected.status || 'inactive'],
                      ['步骤', String((selected.steps as unknown[])?.length ?? 0)],
                      ['总执行次数', String(selected.run_count ?? 0)],
                      ['Successes', String(selected.success_count ?? 0)],
                      ['Failures', String(selected.fail_count ?? 0)],
                      ['创建者', selected.created_by || '-'],
                      ['Updated', fmtDate(selected.updated_at)],
                    ].map(([k, v]) => (
                      <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11.5, borderBottom: '1px solid rgba(255,255,255,.04)', paddingBottom: 4, marginBottom: 4 }}>
                        <span style={{ color: 'var(--text-muted)' }}>{k}</span>
                        <span style={{ color: 'var(--text-secondary)', textTransform: k === '状态' || k === 'Trigger' ? 'capitalize' : undefined }}>{v}</span>
                      </div>
                    ))}
                  </div>

                  <div className="card">
                    <div className="card-title" style={{ marginBottom: 8 }}>执行历史 (近期)</div>
                    {histLoading && <div style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>加载中...</div>}
                    {!histLoading && history.length === 0 && <div style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>暂无执行记录</div>}
                    {history.map((r, i) => (
                      <div key={r.run_id ?? i} style={{
                        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                        padding: '5px 0', borderBottom: '1px solid rgba(255,255,255,.04)', fontSize: 11,
                      }}>
                        <div>
                          <span style={{ color: runStatusColor[r.status] ?? 'var(--text-muted)', fontWeight: 600, marginRight: 6, textTransform: 'capitalize' }}>{r.status}</span>
                          <span style={{ color: 'var(--text-muted)' }}>{fmtDate(r.started_at)}</span>
                        </div>
                        <div style={{ color: 'var(--text-muted)' }}>
                          {r.steps_done}/{r.steps_total} · {fmt耗时(r.duration_ms)}
                        </div>
                      </div>
                    ))}
                  </div>

                  <div style={{ display: 'flex', gap: 8 }}>
                    <button className="btn-primary" style={{ flex: 1, fontSize: 11 }} disabled={running === selected._key} onClick={() => run(selected, false)}>
                      {running === selected._key ? '执行中...' : '▶ 运行 Now'}
                    </button>
                    <button className="btn-secondary" style={{ flex: 1, fontSize: 11 }} disabled={running === selected._key} onClick={() => run(selected, true)}>
                      Dry Run
                    </button>
                  </div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button className="btn-secondary" style={{ flex: 1, fontSize: 11 }} onClick={() => openEdit(selected)}>编辑</button>
                    <button
                      className="btn-secondary"
                      style={{ flex: 1, fontSize: 11, color: 'var(--accent-blue)', borderColor: 'rgba(59,158,222,.3)', background: 'rgba(59,158,222,.08)' }}
                      onClick={() => handleTabChange('flow')}
                    >
                      ⬡ 编辑流程图
                    </button>
                  </div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button className="btn-secondary" style={{ flex: 1, fontSize: 11, color: selected.status === 'active' ? 'var(--critical)' : 'var(--accent-green)' }} onClick={() => toggle活跃(selected)}>
                      {selected.status === 'active' ? '停用' : '启用'}
                    </button>
                  </div>
                  <button className="btn-secondary" style={{ fontSize: 11, color: 'var(--critical)' }} onClick={() => deletePlaybook(selected)}>删除剧本</button>
                </div>
              )}

              {/* ── Flow tab ──────────────────────────────────────────────── */}
              {detailTab === 'flow' && (
                <div style={{ flex: 1, overflow: 'hidden' }}>
                  <FlowCanvas playbook={selected} onSaved={onFlowSaved} />
                </div>
              )}

              {/* ── Executions tab ───────────────────────────────────────── */}
              {detailTab === 'executions' && (
                <div style={{ flex: 1, overflowY: 'auto', padding: 14 }}>
                  <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                    <div style={{ padding: '10px 14px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)' }}>执行历史</span>
                      <button
                        className="btn-primary"
                        style={{ fontSize: 10.5, padding: '2px 10px' }}
                        disabled={executing}
                        onClick={() => executePlaybook(selected)}
                      >
                        {executing ? '执行中...' : '▶ 立即执行'}
                      </button>
                    </div>
                    <ExecutionHistoryPanel
                      playbookKey={selected._key}
                      playbookName={selected.name}
                      executions={executions}
                      loading={execLoading}
                      onReExecute={() => executePlaybook(selected)}
                    />
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      <div className="pagination">
        <button className="page-btn" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>&#8249;</button>
        <span>{page} / {meta.total_pages || 1}</span>
        <button className="page-btn" disabled={page >= meta.total_pages} onClick={() => setPage(p => p + 1)}>&#8250;</button>
        <span style={{ marginLeft: 8 }}>{meta.total} 条</span>
      </div>

      {/* Create / Edit Modal */}
      {showModal && (
        <>
          <div onClick={() => setShowModal(false)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 520, maxHeight: '90vh', overflowY: 'auto', background: 'var(--bg-modal)', border: '1px solid var(--border)', borderRadius: 8, zIndex: 500, padding: 24 }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>{editTarget ? '编辑剧本' : '新建剧本'}</div>
            {/* Quick template picker — only shown on create */}
            {!editTarget && (
              <div style={{ marginBottom: 16 }}>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8 }}>快速模板</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {[
                    {
                      name: '钓鱼邮件响应',
                      description: '自动分析并响应钓鱼邮件威胁: 隔离邮件、通知用户并创建事件',
                      trigger_type: 'alert',
                      status: 'draft',
                      nodes: ['⚡ 触发器', '📧 分析邮件', '🚫 隔离邮件', '🔔 通知用户', '🎫 创建事件'],
                    },
                    {
                      name: '勒索软件隔离',
                      description: '检测到勒索软件活动后立即隔离主机、收集证据、通知SOC并创建P1事件',
                      trigger_type: 'alert',
                      status: 'draft',
                      nodes: ['⚡ 触发器', '🔒 隔离主机', '🔍 收集证据', '📣 通知SOC', '🎫 创建P1事件'],
                    },
                  ].map(tpl => (
                    <button
                      key={tpl.name}
                      onClick={() => setForm({ name: tpl.name, description: tpl.description, trigger_type: tpl.trigger_type, status: tpl.status })}
                      style={{
                        textAlign: 'left', padding: '10px 12px', borderRadius: 5,
                        background: form.name === tpl.name ? 'rgba(59,158,222,.1)' : 'rgba(255,255,255,.03)',
                        border: form.name === tpl.name ? '1px solid rgba(59,158,222,.4)' : '1px solid var(--border)',
                        cursor: 'pointer', transition: 'all .15s',
                      }}
                    >
                      <div style={{ fontSize: 12, fontWeight: 600, color: form.name === tpl.name ? 'var(--accent-blue)' : 'var(--text-secondary)', marginBottom: 4 }}>
                        {tpl.name}
                      </div>
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 4 }}>
                        {tpl.nodes.map((n, i) => (
                          <span key={i} style={{
                            fontSize: 9.5, padding: '1px 6px', borderRadius: 10,
                            background: 'rgba(59,158,222,.08)', border: '1px solid rgba(59,158,222,.2)',
                            color: 'var(--text-muted)',
                          }}>{n}</span>
                        ))}
                      </div>
                      <div style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>{tpl.description}</div>
                    </button>
                  ))}
                </div>
              </div>
            )}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Name *</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="Endpoint Isolation Response" value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))} />
              </div>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>描述</div>
                <textarea className="filter-input" style={{ width: '100%', boxSizing: 'border-box', minHeight: 64, resize: 'vertical' }} placeholder="剧本功能描述..." value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))} />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>触发方式</div>
                  <select className="filter-select" style={{ width: '100%' }} value={form.trigger_type} onChange={e => setForm(p => ({ ...p, trigger_type: e.target.value }))}>
                    <option value="手动">手动</option>
                    <option value="alert">告警</option>
                    <option value="incident">事件</option>
                    <option value="schedule">定时</option>
                    <option value="webhook">Webhook</option>
                  </select>
                </div>
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>状态</div>
                  <select className="filter-select" style={{ width: '100%' }} value={form.status} onChange={e => setForm(p => ({ ...p, status: e.target.value }))}>
                    <option value="draft">草稿</option>
                    <option value="active">活跃</option>
                    <option value="inactive">停用</option>
                  </select>
                </div>
              </div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowModal(false)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={saving || !form.name.trim()} onClick={savePlaybook}>
                  {saving ? '保存中...' : editTarget ? '保存修改' : '创建剧本'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Delete Confirm Modal */}
      {deleteTarget && (
        <>
          <div onClick={() => setDeleteTarget(null)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 360, background: 'var(--bg-modal)', border: '1px solid var(--border)', borderRadius: 8, zIndex: 500, padding: 24 }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 12 }}>确认删除剧本</div>
            <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 20 }}>
              确定要删除剧本 <strong style={{ color: 'var(--text-primary)' }}>「{deleteTarget.name}」</strong>？已有执行历史将一并删除。
            </div>
            <div style={{ display: 'flex', gap: 10 }}>
              <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setDeleteTarget(null)}>取消</button>
              <button className="btn-primary" style={{ flex: 1, background: 'var(--critical)', borderColor: 'var(--critical)' }} onClick={doDeletePlaybook}>确认删除</button>
            </div>
          </div>
        </>
      )}

      {/* Execute Result Modal */}
      {execResult && (
        <>
          <div onClick={() => setExecResult(null)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 800 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 520, maxHeight: '80vh', overflow: 'hidden',
            background: 'var(--bg-modal)', border: '1px solid var(--border)', borderRadius: 8, zIndex: 900,
            display: 'flex', flexDirection: 'column',
          }}>
            <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 14, fontWeight: 600 }}>执行结果</span>
              <button onClick={() => setExecResult(null)} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 16 }}>✕</button>
            </div>
            <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {([
                  ['状态', execResult.status, true],
                  ['执行 ID', execResult.id || '-', false],
                  ['开始时间', fmtDate(execResult.started_at), false],
                  ['完成时间', execResult.completed_at ? fmtDate(execResult.completed_at) : '-', false],
                  ['耗时', fmtDuration(execResult.started_at, execResult.completed_at) ?? '-', false],
                ] as [string, string, boolean][]).map(([label, value, isStatus]) => (
                  <div key={label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 12, borderBottom: '1px solid rgba(255,255,255,.04)', paddingBottom: 5 }}>
                    <span style={{ color: 'var(--text-muted)' }}>{label}</span>
                    <span style={{
                      color: isStatus ? (runStatusColor[value] ?? 'var(--text-muted)') : 'var(--text-secondary)',
                      fontWeight: isStatus ? 600 : undefined,
                      textTransform: isStatus ? 'capitalize' : undefined,
                      fontFamily: label === '执行 ID' ? 'monospace' : undefined,
                      fontSize: label === '执行 ID' ? 11 : undefined,
                    }}>{value}</span>
                  </div>
                ))}
              </div>
              {execResult.node_results && execResult.node_results.length > 0 && (
                <div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 8 }}>节点执行结果 ({execResult.node_results.length} 个节点)</div>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11.5 }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid var(--border)' }}>
                        <ResizableTh style={{ textAlign: 'left', padding: '4px 8px', color: 'var(--text-muted)', fontWeight: 500 }}>节点</ResizableTh>
                        <ResizableTh style={{ textAlign: 'left', padding: '4px 8px', color: 'var(--text-muted)', fontWeight: 500 }}>状态</ResizableTh>
                      </tr>
                    </thead>
                    <tbody>
                      {execResult.node_results.map((nr, i) => (
                        <tr key={nr.node_id ?? i} style={{ borderBottom: '1px solid rgba(255,255,255,.04)' }}>
                          <td style={{ padding: '5px 8px', color: 'var(--text-secondary)' }}>{nr.node_name || nr.node_id}</td>
                          <td style={{ padding: '5px 8px' }}>
                            <span style={{ color: runStatusColor[nr.status] ?? 'var(--text-muted)', fontWeight: 600, textTransform: 'capitalize' }}>{nr.status}</span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {execResult.error && (
                <div style={{ background: 'rgba(229,57,53,.08)', border: '1px solid rgba(229,57,53,.3)', borderRadius: 4, padding: '8px 12px', fontSize: 12, color: 'var(--critical)' }}>
                  {execResult.error}
                </div>
              )}
            </div>
            <div style={{ padding: '10px 20px', borderTop: '1px solid var(--border)' }}>
              <button className="btn-secondary" style={{ width: '100%', fontSize: 12 }} onClick={() => setExecResult(null)}>关闭</button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
