
import { useEffect, useState } from 'react'

export type ThreatLevel = 'Low' | 'Medium' | 'High'

export type ToastItem = {
  id: number
  level: ThreatLevel
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

  const styles: Record<
    ThreatLevel,
    {
      border: string
      indicator: string
      text: string
      message: string
    }
  > = {
    Low: {
      border: 'border-emerald-400/70 shadow-emerald-500/10',
      indicator: 'bg-emerald-400',
      text: 'text-emerald-400',
      message: 'Low security level',
    },
    Medium: {
      border: 'border-orange-400/80 shadow-orange-500/10',
      indicator: 'bg-orange-400',
      text: 'text-orange-400',
      message: 'Medium security level',
    },
    High: {
      border: 'border-red-500/80 shadow-red-500/10',
      indicator: 'bg-red-500',
      text: 'text-red-400',
      message: 'High security level',
    },
  }

  const style = styles[toast.level]

  return (
    <article
      className={`pointer-events-auto rounded-xl border ${style.border} ${
        closing
          ? 'animate-[toast-out_0.35s_ease-in_forwards]'
          : 'animate-[toast-in_0.35s_ease-out]'
      } bg-[#160e0c]/90 p-4 shadow-2xl backdrop-blur-xl`}
    >
      <div className="flex items-start gap-3">
        <span
          className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${style.indicator}`}
        />

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold text-white">
              {toast.title}
            </h3>

            <span
              className={`text-[9px] uppercase tracking-[0.18em] ${style.text}`}
            >
              {toast.level}
            </span>
          </div>

          <p className="mt-1.5 text-xs leading-5 text-white/60">
            {toast.message}
          </p>

          <p className={`mt-2 text-[10px] ${style.text}`}>
            {style.message}
          </p>
        </div>

        <button
          type="button"
          aria-label="Close notification"
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
