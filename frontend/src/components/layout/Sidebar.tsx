
import FuzzyText from '../FuzzyText'

export type PageName =
  | 'Dashboard'
  | 'Honeypots'
  | 'Profiles'
  | 'ConnectServer'
  | 'CreateHoneypot'
  | 'LiveFeed'
  | 'Settings'

const navItems = [
  { page: 'Dashboard', label: 'Обзор', icon: '◫' },
  { page: 'ConnectServer', label: 'Добавить сервер', icon: '+' },
  { page: 'CreateHoneypot', label: 'Создать ловушку', icon: '++' },
  { page: 'Honeypots', label: 'Ловушки', icon: '⌘' },
  { page: 'Profiles', label: 'Профили', icon: '◎' },
  { page: 'LiveFeed', label: 'Атаки', icon: '⌁' },
  { page: 'Settings', label: 'Настройки', icon: '⚙' },
] as const satisfies ReadonlyArray<{ page: PageName; label: string; icon: string }>

type SidebarProps = {
  activePage: PageName
  onNavigate: (page: PageName) => void
}

export default function Sidebar({
  activePage,
  onNavigate,
}: SidebarProps) {
  return (
    <aside className="flex w-60 shrink-0 flex-col border-r border-white/10 bg-[#100a09]/85 p-5 backdrop-blur-xl">
      <div className="mb-10 flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-orange-500/40 bg-orange-500/10 text-xl text-orange-400">
          ⌘
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
        {navItems.map((item) => {
          const isActive = item.page === activePage

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
              <span className="w-5 text-center text-base">
                {item.icon}
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

      <div className="mt-auto rounded-xl border border-white/10 bg-black/20 p-4">
        <div className="mb-2 flex items-center gap-2 text-xs text-white/60">
          <span className="h-2 w-2 rounded-full bg-emerald-400" />
          Состояние системы
        </div>

        <div className="text-sm font-medium text-white">
          API управления
        </div>

        <div className="mt-1 text-xs text-white/40">
          Сеанс авторизован
        </div>
      </div>
    </aside>
  )
}
