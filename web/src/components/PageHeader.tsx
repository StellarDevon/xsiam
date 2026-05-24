import React from 'react'

interface Props {
  /** 页面主标题 */
  title: string
  /** 右侧小字说明，如计数、状态 */
  subtitle?: React.ReactNode
  /** 右侧操作按钮区 */
  actions?: React.ReactNode
}

/**
 * PageHeader — 统一的内容页头部导航栏。
 * 高度固定 46px，背景 'var(--bg-sidebar)'，下边框 'var(--border)'。
 * 所有内容页都使用此组件，确保视觉一致性。
 */
export default function PageHeader({ title, subtitle, actions }: Props) {
  return (
    <div style={{
      height: 46,
      flexShrink: 0,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 20px',
      background: 'var(--bg-card)',
      borderBottom: '1px solid var(--border)',
      gap: 12,
    }}>
      {/* 左侧：标题 + 副标题 */}
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, minWidth: 0 }}>
        <span style={{
          fontSize: 14,
          fontWeight: 600,
          color: 'var(--text-primary)',
          whiteSpace: 'nowrap',
          letterSpacing: -0.2,
        }}>
          {title}
        </span>
        {subtitle && (
          <span style={{
            fontSize: 11.5,
            color: 'var(--text-muted)',
            whiteSpace: 'nowrap',
          }}>
            {subtitle}
          </span>
        )}
      </div>

      {/* 右侧：操作区 */}
      {actions && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
          {actions}
        </div>
      )}
    </div>
  )
}
