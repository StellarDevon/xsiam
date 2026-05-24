import { createContext, useContext, useState, useCallback } from 'react'
import type { ReactNode } from 'react'

type ToastType = 'success' | 'error' | 'info'

interface Toast {
  id: number
  message: string
  type: ToastType
}

interface ToastContextValue {
  showToast: (message: string, type?: ToastType) => void
}

const ToastContext = createContext<ToastContextValue | null>(null)

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast must be used within a ToastProvider')
  return ctx
}

const TYPE_STYLES: Record<ToastType, { background: string; border: string; icon: string }> = {
  success: { background: 'var(--color-success, #16a34a)', border: 'var(--accent-green)', icon: '✓' },
  error:   { background: 'var(--color-error, #dc2626)',   border: 'var(--critical)', icon: '✕' },
  info:    { background: 'var(--color-info, #2563eb)',    border: 'var(--accent-blue)', icon: 'ℹ' },
}

let nextId = 0

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])

  const showToast = useCallback((message: string, type: ToastType = 'info') => {
    const id = ++nextId
    setToasts(prev => [...prev, { id, message, type }])
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id))
    }, 3000)
  }, [])

  return (
    <ToastContext.Provider value={{ showToast }}>
      {children}
      <div
        style={{
          position: 'fixed',
          top: 16,
          right: 16,
          zIndex: 9999,
          display: 'flex',
          flexDirection: 'column',
          gap: 8,
          pointerEvents: 'none',
        }}
      >
        {toasts.map(toast => {
          const s = TYPE_STYLES[toast.type]
          return (
            <div
              key={toast.id}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '10px 16px',
                borderRadius: 6,
                background: s.background,
                border: `1px solid ${s.border}`,
                color: '#fff',
                fontSize: 14,
                boxShadow: '0 4px 12px rgba(0,0,0,0.3)',
                pointerEvents: 'auto',
                minWidth: 220,
                maxWidth: 360,
                animation: 'toast-in 0.2s ease',
              }}
            >
              <span style={{ fontWeight: 700, flexShrink: 0 }}>{s.icon}</span>
              <span style={{ flex: 1 }}>{toast.message}</span>
            </div>
          )
        })}
      </div>
      <style>{`
        @keyframes toast-in {
          from { opacity: 0; transform: translateX(40px); }
          to   { opacity: 1; transform: translateX(0); }
        }
      `}</style>
    </ToastContext.Provider>
  )
}
