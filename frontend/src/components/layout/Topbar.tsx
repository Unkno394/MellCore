import { statusLabel } from '../../i18n/labels'
import type { User } from '../../api/types'
import type { PageName } from './Sidebar'

type Props = { currentPage: PageName; user: User; onLogout: () => void }

const labels: Record<PageName, string> = {
  Dashboard: 'Обзор', Infrastructure: 'Инфраструктура', Profiles: 'Профили',
  LiveFeed: 'События', Settings: 'Настройки',
}

export default function Topbar({ currentPage, user, onLogout }: Props) {
  const initials = user.name.split(/\s+/).filter(Boolean).slice(0, 2).map((part) => part[0]).join('').toUpperCase() || 'MC'
  return <header className="flex min-h-[72px] items-center justify-between gap-4 border-b border-white/10 bg-[#100a09]/55 px-6 backdrop-blur-xl">
    <div><div className="text-xs uppercase tracking-[0.18em] text-white/35">Безопасность / API управления</div><h1 className="mt-1 text-xl font-semibold text-[#e8dfda]">{labels[currentPage]}</h1></div>
    <div className="flex items-center gap-3"><div className="hidden text-right sm:block"><p className="text-xs text-white/65">{user.email ?? user.username}</p><p className="mt-1 text-[10px] uppercase tracking-wider text-white/35">{statusLabel(user.role)}</p></div><div title={user.name} className="flex h-9 w-9 items-center justify-center rounded-full border border-orange-500/30 bg-orange-500/10 text-sm font-semibold text-[#f1a36b]">{initials}</div><button type="button" onClick={onLogout} className="rounded-lg border border-white/10 px-3 py-2 text-xs text-white/55 transition hover:border-orange-500/30 hover:text-orange-300">Выйти</button></div>
  </header>
}
