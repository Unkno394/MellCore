import { useEffect, useState } from 'react'

export type ToastKind = 'success' | 'info' | 'error'

export type ToastItem = {
  id: number
  kind: ToastKind
  title: string
  message: string
}

type Props = {
  toasts: ToastItem[]
  onDismiss: (id: number) => void
}

function ToastCard({
  toast,
  onDismiss,
}: {
  toast: ToastItem
  onDismiss: (id: number) => void
}) {
  const [closing, setClosing] = useState(false)

  useEffect(() => {
    const closeTimer = window.setTimeout(() => {
      setClosing(true)
    }, 5000)

    const removeTimer = window.setTimeout(() => {
      onDismiss(toast.id)
    }, 5350)

    return () => {
      window.clearTimeout(closeTimer)
      window.clearTimeout(removeTimer)
    }
  }, [toast.id, onDismiss])

  const styles: Record<ToastKind, { border: string; icon: string; symbol: string }> = {
    success: { border: 'border-emerald-400/50 shadow-emerald-500/10', icon: 'text-emerald-300', symbol: '✓' },
    info: { border: 'border-orange-400/50 shadow-orange-500/10', icon: 'text-orange-300', symbol: '↻' },
    error: { border: 'border-red-500/60 shadow-red-500/10', icon: 'text-red-300', symbol: '!' },
  }

  const style = styles[toast.kind]

  return (
    <article
      className={`pointer-events-auto rounded-xl border ${style.border} ${
        closing
          ? 'animate-[toast-out_0.35s_ease-in_forwards]'
          : 'animate-[toast-in_0.35s_ease-out]'
      } bg-[#160e0c]/90 p-4 shadow-2xl backdrop-blur-xl`}
    >
      <div className="flex items-start gap-3">
        <span className={`mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-white/5 text-sm font-bold ${style.icon} ${toast.kind === 'info' ? 'animate-spin' : ''}`}>{style.symbol}</span>

        <div className="min-w-0 flex-1">
          <h3 className="text-sm font-semibold text-white">{toast.title}</h3>
          <p className="mt-1.5 text-xs leading-5 text-white/60">
            {toast.message}
          </p>
        </div>

        <button
          type="button"
          aria-label="Закрыть уведомление"
          className="text-lg leading-none text-white/40 transition hover:text-orange-300"
          onClick={() => {
            setClosing(true)
            window.setTimeout(() => onDismiss(toast.id), 350)
          }}
        >
          ×
        </button>
      </div>
    </article>
  )
}

export default function ToastNotifications({
  toasts,
  onDismiss,
}: Props) {
  if (toasts.length === 0) return null

  return (
    <div className="pointer-events-none fixed bottom-5 right-5 z-[100] flex w-[min(360px,calc(100vw-2.5rem))] flex-col gap-3">
      {toasts.map((toast) => (
        <ToastCard
          key={toast.id}
          toast={toast}
          onDismiss={onDismiss}
        />
      ))}
    </div>
  )
}
