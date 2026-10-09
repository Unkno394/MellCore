
const navItems = [
    { label: 'Dashboard', icon: '◫', active: true },
    { label: 'Honeypots', icon: '⌘', active: false },
    { label: 'Profiles', icon: '◎', active: false },
    { label: 'Live Feed', icon: '⌁', active: false },
    { label: 'Sessions', icon: '▤', active: false },
    { label: 'Settings', icon: '⚙', active: false },
  ]
  
  export default function Sidebar() {
    return (
      <aside className="flex w-60 shrink-0 flex-col border-r border-white/10 bg-[#100a09]/85 p-5 backdrop-blur-xl">
        <div className="mb-10 flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-orange-500/40 bg-orange-500/10 text-xl text-orange-400">
            ⌘
          </div>
          <div>
            <div className="text-sm font-bold tracking-[0.2em] text-[#f1a36b]">
              HONEYPOT
            </div>
            <div className="mt-1 text-[10px] uppercase tracking-widest text-white/40">
              Threat monitoring
            </div>
          </div>
        </div>
  
        <div className="mb-3 px-3 text-[10px] font-semibold uppercase tracking-[0.2em] text-white/35">
          Workspace
        </div>
  
        <nav className="flex flex-col gap-1">
          {navItems.map((item) => (
            <button
              key={item.label}
              type="button"
              className={`flex items-center gap-3 rounded-lg px-3 py-3 text-left text-sm transition ${
                item.active
                  ? 'border border-orange-500/20 bg-orange-500/10 text-[#f1a36b]'
                  : 'text-[#e8dfda]/65 hover:bg-white/5 hover:text-white'
              }`}
            >
              <span className="w-5 text-center text-base">{item.icon}</span>
              {item.label}
            </button>
          ))}
        </nav>
  
        <div className="mt-auto rounded-xl border border-white/10 bg-black/20 p-4">
          <div className="mb-2 flex items-center gap-2 text-xs text-white/60">
            <span className="h-2 w-2 rounded-full bg-emerald-400" />
            System status
          </div>
          <div className="text-sm font-medium text-white">Monitoring active</div>
          <div className="mt-1 text-xs text-white/40">All services connected</div>
        </div>
      </aside>
    )
  }