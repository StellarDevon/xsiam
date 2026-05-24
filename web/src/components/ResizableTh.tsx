import { useRef, useCallback } from 'react'

interface Props extends React.ThHTMLAttributes<HTMLTableCellElement> {
  children?: React.ReactNode
  defaultWidth?: number
  minWidth?: number
}

/**
 * ResizableTh — a <th> with a clearly visible drag-handle on its right edge.
 *
 * Visual design:
 *   • Always shows a 2px-wide coloured stripe at the very right of the header cell
 *   • Stripe colour: var(--border-light) at rest → var(--accent-blue) on hover/drag
 *   • 10px-wide invisible hit area around the stripe catches mouse events
 *   • cursor: col-resize while hovering or dragging
 */
export default function ResizableTh({
  children, defaultWidth, minWidth = 40, style, ...rest
}: Props) {
  const thRef     = useRef<HTMLTableCellElement>(null)
  const stripeRef = useRef<HTMLSpanElement>(null)
  const startX    = useRef(0)
  const startW    = useRef(0)

  const onMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    const th = thRef.current
    if (!th) return
    startX.current = e.clientX
    startW.current = th.offsetWidth

    const stripe = stripeRef.current
    if (stripe) { stripe.style.opacity = '1' }

    function onMove(ev: MouseEvent) {
      const delta = ev.clientX - startX.current
      const newW  = Math.max(minWidth, startW.current + delta)
      if (thRef.current) thRef.current.style.width = `${newW}px`
    }
    function onUp() {
      document.removeEventListener('mousemove', onMove)
      document.removeEventListener('mouseup',   onUp)
      document.body.style.cursor     = ''
      document.body.style.userSelect = ''
      if (stripeRef.current) stripeRef.current.style.opacity = '0'
    }
    document.body.style.cursor     = 'col-resize'
    document.body.style.userSelect = 'none'
    document.addEventListener('mousemove', onMove)
    document.addEventListener('mouseup',   onUp)
  }, [minWidth])

  return (
    <th
      ref={thRef}
      style={{ position: 'relative', width: defaultWidth, ...style }}
      {...rest}
    >
      {/* Label — clipped within the th */}
      <span className="th-label">{children}</span>

      {/*
        Resize handle:
          · Outer layer  : 14px wide hit-zone, sits at right edge of th
          · Inner stripe : 2px visible divider line centred in the hit-zone
          · Extends slightly above/below the th via top:-2/bottom:-2
            so clicking near a row border also works
      */}
      <span
        onMouseDown={onMouseDown}
        onMouseEnter={() => {
          if (stripeRef.current) stripeRef.current.style.opacity = '1'
        }}
        onMouseLeave={() => {
          if (stripeRef.current) stripeRef.current.style.opacity = '0'
        }}
        style={{
          position: 'absolute',
          top: 0, bottom: 0, right: 0,
          width: 14,
          cursor: 'col-resize',
          zIndex: 3,
          display: 'flex',
          alignItems: 'stretch',
          justifyContent: 'center',
          userSelect: 'none',
        }}
      >
        <span
          ref={stripeRef}
          style={{
            width: 2,
            background: 'var(--accent-blue)',
            borderRadius: 1,
            opacity: 0,
            transition: 'opacity .15s',
            pointerEvents: 'none',
          }}
        />
      </span>
    </th>
  )
}
