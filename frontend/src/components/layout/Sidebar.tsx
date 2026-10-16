import {
  Activity,
  ArrowUpRight,
  Bug,
  Crosshair,
  LayoutDashboard,
  Server,
  Settings,
  ShieldCheck,
  Terminal,
  type LucideIcon,
} from 'lucide-react'
import { useState } from 'react'
import FuzzyText from '../FuzzyText'
import LocalCliPanel from './LocalCliPanel'

export type PageName =
  | 'Dashboard'
  | 'Infrastructure'
  | 'Baits'
  | 'Vulnerabilities'
  | 'LiveFeed'
  | 'Settings'

const navItems = [
  { page: 'Dashboard', label: 'Обзор', icon: LayoutDashboard },
  { page: 'Infrastructure', label: 'Инфраструктура', icon: Server },
  { page: 'Baits', label: 'Приманки', icon: Crosshair },
  { page: 'Vulnerabilities', label: 'Уязвимости', icon: Bug },
  { page: 'LiveFeed', label: 'События', icon: Activity },
  { page: 'Settings', label: 'Настройки', icon: Settings },
] as const satisfies ReadonlyArray<{ page: PageName; label: string; icon: LucideIcon }>

type SidebarProps = {
  activePage: PageName
  permissions: string[]
  onNavigate: (page: PageName) => void
}

export default function Sidebar({
  activePage,
  permissions,
  onNavigate,
}: SidebarProps) {
  const [isCliPanelOpen, setIsCliPanelOpen] = useState(false)
  const visible = (page: PageName) => {
    if (page === 'Infrastructure') return permissions.includes('servers.view') || permissions.includes('traps.view')
    if (page === 'Baits' || page === 'Vulnerabilities') return permissions.includes('traps.view')
    if (page === 'LiveFeed') return permissions.includes('attacks.view')
    return true
  }
  return (
    <aside className="flex w-60 shrink-0 flex-col border-r border-white/10 bg-[#100a09]/85 p-5 backdrop-blur-xl">
      <div className="mb-10 flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-orange-500/40 bg-orange-500/10 text-orange-400">
          <ShieldCheck aria-hidden="true" className="h-5 w-5" strokeWidth={1.8} />
        </div>

        <div>
          <div className="text-sm font-bold tracking-[0.2em] text-[#f1a36b]">
            MellCore
          </div>

          <div className="mt-1 text-[10px] uppercase tracking-widest text-white/40">
            Мониторинг угроз
          </div>
        </div>
      </div>

      <div className="mb-3 px-3 text-[10px] font-semibold uppercase tracking-[0.2em] text-white/35">
        РАБОЧАЯ ОБЛАСТЬ
      </div>

      <nav className="flex flex-col gap-1">
        {navItems.filter((item) => visible(item.page)).map((item) => {
          const isActive = item.page === activePage
          const Icon = item.icon

          return (
            <button
              key={item.label}
              type="button"
              onClick={() => onNavigate(item.page)}
              className={`flex items-center gap-3 rounded-lg px-3 py-3 text-left text-sm transition ${
                isActive
                  ? 'border border-orange-500/20 bg-orange-500/10 text-[#f1a36b]'
                  : 'text-[#e8dfda]/65 hover:bg-white/5 hover:text-white'
              }`}
            >
              <span className="inline-flex w-5 shrink-0 justify-center">
                <Icon aria-hidden="true" className="h-[18px] w-[18px]" strokeWidth={1.8} />
              </span>

              {isActive ? (
                <FuzzyText
                  fontSize={14}
                  fontWeight={600}
                  color="#f1a36b"
                  baseIntensity={0.2}
                  hoverIntensity={0.5}
                  fuzzRange={8}
                  fps={30}
                  enableHover
                  className="block"
                >
                  {item.label}
                </FuzzyText>
              ) : (
                <span>{item.label}</span>
              )}

            </button>
          )
        })}
      </nav>

      <button
        type="button"
        onClick={() => setIsCliPanelOpen(true)}
        aria-haspopup="dialog"
        aria-expanded={isCliPanelOpen}
        className="mt-auto rounded-xl border border-orange-500/25 bg-orange-500/[0.07] p-4 text-left transition hover:border-orange-400/50 hover:bg-orange-500/[0.12] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-orange-400"
      >
        <div className="flex items-start justify-between gap-3">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-orange-400/20 bg-orange-400/10 text-orange-300">
            <Terminal aria-hidden="true" className="h-[18px] w-[18px]" />
          </span>
          <ArrowUpRight aria-hidden="true" className="mt-1 h-4 w-4 text-white/35" />
        </div>

        <div className="mt-3 text-sm font-semibold text-white">
          Попробуйте CLI-агента
        </div>
        <div className="mt-1 text-xs leading-relaxed text-white/45">
          Разверните ловушки прямо на своём сервере
        </div>
      </button>

      <LocalCliPanel
        open={isCliPanelOpen}
        onClose={() => setIsCliPanelOpen(false)}
      />
    </aside>
  )
}
