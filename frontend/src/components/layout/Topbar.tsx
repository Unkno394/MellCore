
export default function Topbar() {
    return (
      <header className="flex min-h-[72px] items-center justify-between gap-4 border-b border-white/10 bg-[#100a09]/55 px-6 backdrop-blur-xl">
        <div>
          <div className="text-xs uppercase tracking-[0.18em] text-white/35">
            Security / Overview
          </div>
          <h1 className="mt-1 text-xl font-semibold text-[#e8dfda]">
            Dashboard
          </h1>
        </div>
  
        <div className="flex items-center gap-4">
          <div className="hidden items-center gap-2 rounded-full border border-white/10 bg-black/20 px-3 py-2 sm:flex">
            <span className="h-2 w-2 animate-pulse rounded-full bg-orange-400" />
            <span className="text-xs text-white/60">Live monitoring</span>
          </div>
  
          <div className="flex h-9 w-9 items-center justify-center rounded-full border border-orange-500/30 bg-orange-500/10 text-sm font-semibold text-[#f1a36b]">
            OP
          </div>
        </div>
      </header>
    )
  }