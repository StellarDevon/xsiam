import { useRef, useCallback } from 'react'

interface Props extends React.ThHTMLAttributes<HTMLTableCellElement> {
  children?: React.ReactNode
  defaultWidth?: number
  minWidth?: number
}

/**
 * ResizableTh — a <th> that has a drag handle on its right edge
 * to resize the column width. Stores width in local state.
 */
export default function ResizableTh({
  children, defaultWidth, minWidth = 40, style, ...rest
}: Props) {
  const thRef = useRef<HTMLTableCellElement>(null)
  const startX = useRef(0)
  const startW = useRef(0)

  const onMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    const th = thRef.current
    if (!th) return
    startX.current = e.clientX
    startW.current = th.offsetWidth

    function onMove(ev: MouseEvent) {
      const delta = ev.clientX - startX.current
      const newW = Math.max(minWidth, startW.current + delta)
      if (thRef.current) thRef.current.style.width = `${newW}px`
    }
    function onUp() {
      document.removeEventListener('mousemove', onMove)
      document.removeEventListener('mouseup', onUp)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }
    document.body.style.cursor = 'col-resize'
    document.body.style.userSelect = 'none'
    document.addEventListener('mousemove', onMove)
    document.addEventListener('mouseup', onUp)
  }, [minWidth])

  return (
    <th
      ref={thRef}
      style={{
        position: 'relative',
        width: defaultWidth,
        ...style,
      }}
      {...rest}
    >
      {children}
      {/* Drag handle */}
      <span
        onMouseDown={onMouseDown}
        style={{
          position: 'absolute',
          top: 0, right: 0, bottom: 0,
          width: 6,
          cursor: 'col-resize',
          zIndex: 1,
          // Subtle visual indicator on hover
        }}
        onMouseEnter={e => (e.currentTarget.style.background = 'rgba(79,163,224,.35)')}
        onMouseLeave={e => (e.currentTarget.style.background = 'none')}
      />
    </th>
  )
}
