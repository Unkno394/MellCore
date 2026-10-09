
import { useMemo, useState } from 'react'

type Status = 'Active' | 'Inactive' | 'Warning'

type Honeypot = {
  id: string
  name: string
  ip: string
  type: string
  profile: string
  status: Status
  lastActivity: string
  sessions: number
  location: string
  description: string
}

const honeypots: Honeypot[] = [
  {
    id: 'HP-001',
    name: 'SSH Honeypot 01',
    ip: '192.0.2.10',
    type: 'SSH',
    profile: 'Linux Server',
    status: 'Active',
    lastActivity: '2 min ago',
    sessions: 12,
    location: 'DMZ / Zone A',
    description: 'Emulates a Linux server and records SSH login attempts.',
  },
  {
    id: 'HP-002',
    name: 'Web Honeypot 02',
    ip: '192.0.2.20',
    type: 'Web',
    profile: 'Web Application',
    status: 'Active',
    lastActivity: '5 min ago',
    sessions: 8,
    location: 'DMZ / Zone A',
    description: 'Simulates a web application to observe suspicious requests.',
  },
  {
    id: 'HP-003',
    name: 'Network Sensor 03',
    ip: '192.0.2.30',
    type: 'Network',
    profile: 'Network Monitor',
    status: 'Warning',
    lastActivity: '1 min ago',
    sessions: 4,
    location: 'DMZ / Zone B',
    description: 'Monitors simulated network scans and connection attempts.',
  },
  {
    id: 'HP-004',
    name: 'Database Trap 04',
    ip: '192.0.2.40',
    type: 'Database',
    profile: 'SQL Server',
    status: 'Inactive',
    lastActivity: '3 hours ago',
    sessions: 0,
    location: 'DMZ / Zone B',
    description: 'Emulates a database endpoint for observing access attempts.',
  },
  {
    id: 'HP-005',
    name: 'SSH Honeypot 05',
    ip: '192.0.2.50',
    type: 'SSH',
    profile: 'Linux Server',
    status: 'Active',
    lastActivity: '12 min ago',
    sessions: 6,
    location: 'DMZ / Zone C',
    description: 'Collects simulated authentication attempts and session activity.',
  },
  {
    id: 'HP-006',
    name: 'Web Honeypot 06',
    ip: '192.0.2.60',
    type: 'Web',
    profile: 'Admin Panel',
    status: 'Active',
    lastActivity: '18 min ago',
    sessions: 3,
    location: 'DMZ / Zone C',
    description: 'Simulates an administration panel for testing detection workflows.',
  },
]

const statusStyles: Record<Status, string> = {
  Active: 'border-emerald-500/25 bg-emerald-500/10 text-emerald-400',
  Inactive: 'border-white/10 bg-white/5 text-white/45',
  Warning: 'border-orange-500/25 bg-orange-500/10 text-orange-300',
}

function Honeypots() {
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('All statuses')
  const [typeFilter, setTypeFilter] = useState('All types')
  const [selectedId, setSelectedId] = useState('HP-001')

  const filteredHoneypots = useMemo(() => {
    return honeypots.filter((honeypot) => {
      const query = search.toLowerCase()

      const matchesSearch =
        honeypot.name.toLowerCase().includes(query) ||
        honeypot.ip.includes(query) ||
        honeypot.id.toLowerCase().includes(query)

      const matchesStatus =
        statusFilter === 'All statuses' ||
        honeypot.status === statusFilter

      const matchesType =
        typeFilter === 'All types' || honeypot.type === typeFilter

      return matchesSearch && matchesStatus && matchesType
    })
  }, [search, statusFilter, typeFilter])

  const selectedHoneypot =
    filteredHoneypots.find((item) => item.id === selectedId) ??
    filteredHoneypots[0]

  const activeCount = honeypots.filter(
    (item) => item.status === 'Active',
  ).length

  const warningCount = honeypots.filter(
    (item) => item.status === 'Warning',
  ).length

  return (
    <section className="space-y-6 p-4 sm:p-6">
      <div>
        <p className="text-sm text-white/40">
          Workspace / Honeypots
        </p>
        <div className="mt-2 flex flex-wrap items-end justify-between gap-3">
          <div>
            <h2 className="text-2xl font-semibold tracking-tight">
              Honeypots
            </h2>
            <p className="mt-2 text-sm text-white/45">
              Manage your traps, monitor their status and inspect details.
            </p>
          </div>

          <span className="rounded-lg border border-orange-500/20 bg-orange-500/10 px-3 py-2 text-xs text-orange-300">
            DEMO DATA
          </span>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <article className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-5 backdrop-blur-xl">
          <p className="text-sm text-white/45">Total honeypots</p>
          <p className="mt-3 text-3xl font-semibold">{honeypots.length.toString().padStart(2, '0')}</p>
          <p className="mt-2 text-xs text-white/35">Registered traps</p>
        </article>

        <article className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-5 backdrop-blur-xl">
          <p className="text-sm text-white/45">Active</p>
          <p className="mt-3 text-3xl font-semibold text-emerald-400">
            {activeCount.toString().padStart(2, '0')}
          </p>
          <p className="mt-2 text-xs text-white/35">Currently enabled in demo</p>
        </article>

        <article className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-5 backdrop-blur-xl">
          <p className="text-sm text-white/45">Needs attention</p>
          <p className="mt-3 text-3xl font-semibold text-orange-300">
            {warningCount.toString().padStart(2, '0')}
          </p>
          <p className="mt-2 text-xs text-white/35">Demo warning status</p>
        </article>
      </div>

      {/* Search and filters */}
      <div className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-4 backdrop-blur-xl">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-[minmax(0,1fr)_180px_180px]">
          <label className="relative block">
            <span className="sr-only">Search honeypots</span>
            <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-white/35">
              ⌕
            </span>
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search by name, ID or IP..."
              className="w-full rounded-lg border border-white/10 bg-black/20 py-3 pl-9 pr-3 text-sm text-white outline-none transition placeholder:text-white/30 focus:border-orange-500/50"
            />
          </label>

          <select
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value)}
            aria-label="Filter by status"
            className="rounded-lg border border-white/10 bg-[#160e0c] px-3 py-3 text-sm text-white/70 outline-none focus:border-orange-500/50"
          >
            <option>All statuses</option>
            <option>Active</option>
            <option>Inactive</option>
            <option>Warning</option>
          </select>

          <select
            value={typeFilter}
            onChange={(event) => setTypeFilter(event.target.value)}
            aria-label="Filter by type"
            className="rounded-lg border border-white/10 bg-[#160e0c] px-3 py-3 text-sm text-white/70 outline-none focus:border-orange-500/50"
          >
            <option>All types</option>
            <option>SSH</option>
            <option>Web</option>
            <option>Network</option>
            <option>Database</option>
          </select>
        </div>

        <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-white/35">
          <span>{filteredHoneypots.length} honeypots found</span>
          <button
            type="button"
            onClick={() => {
              setSearch('')
              setStatusFilter('All statuses')
              setTypeFilter('All types')
            }}
            className="transition hover:text-orange-300"
          >
            Clear filters
          </button>
        </div>
      </div>

      {/* Honeypot list and selected details */}
      <div className="grid grid-cols-1 items-start gap-4 2xl:grid-cols-[minmax(0,1.6fr)_minmax(280px,0.8fr)]">
        <section className="min-w-0 overflow-hidden rounded-xl border border-white/10 bg-[#160e0c]/80 backdrop-blur-xl">
          <div className="border-b border-white/10 p-5">
            <h3 className="font-semibold">Honeypot inventory</h3>
            <p className="mt-1 text-xs text-white/40">
              Select a trap to view its details
            </p>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full min-w-[680px] text-left text-sm">
              <thead className="border-b border-white/10 bg-black/10 text-[11px] uppercase tracking-wider text-white/35">
                <tr>
                  <th className="px-5 py-4 font-medium">Honeypot</th>
                  <th className="px-4 py-4 font-medium">Type</th>
                  <th className="px-4 py-4 font-medium">Status</th>
                  <th className="px-4 py-4 font-medium">Last activity</th>
                </tr>
              </thead>

              <tbody className="divide-y divide-white/5">
                {filteredHoneypots.map((honeypot) => {
                  const isSelected = selectedHoneypot?.id === honeypot.id

                  return (
                    <tr
                      key={honeypot.id}
                      onClick={() => setSelectedId(honeypot.id)}
                      onKeyDown={(event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault()
                          setSelectedId(honeypot.id)
                        }
                      }}
                      tabIndex={0}
                      aria-selected={isSelected}
                      className={`cursor-pointer outline-none transition hover:bg-white/[0.04] focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-orange-400 ${
                        isSelected ? 'bg-orange-500/[0.07]' : ''
                      }`}
                    >
                      <td className="px-5 py-4">
                        <div className="flex items-center gap-3">
                          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-orange-500/20 bg-orange-500/[0.08] text-orange-300">
                            ⌘
                          </span>
                          <div>
                            <p className="whitespace-nowrap font-medium text-white/90">
                              {honeypot.name}
                            </p>
                            <p className="mt-1 text-xs text-white/35">
                              {honeypot.ip}
                            </p>
                          </div>
                        </div>
                      </td>

                      <td className="px-4 py-4 text-white/60">
                        {honeypot.type}
                      </td>

                      <td className="px-4 py-4">
                        <span className={`inline-flex items-center gap-2 whitespace-nowrap rounded-full border px-2.5 py-1 text-[11px] ${statusStyles[honeypot.status]}`}>
                          <span className="h-1.5 w-1.5 rounded-full bg-current" />
                          {honeypot.status}
                        </span>
                      </td>

                      <td className="whitespace-nowrap px-4 py-4 text-xs text-white/40">
                        {honeypot.lastActivity}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          {filteredHoneypots.length === 0 && (
            <div className="p-10 text-center">
              <p className="text-sm text-white/70">No honeypots found</p>
              <p className="mt-2 text-xs text-white/35">
                Try changing your search or filters.
              </p>
            </div>
          )}
        </section>

        {/* Selected honeypot details */}
        <aside className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-5 backdrop-blur-xl">
          {selectedHoneypot ? (
            <>
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="text-xs uppercase tracking-widest text-orange-300/70">
                    Selected honeypot
                  </p>
                  <h3 className="mt-2 text-lg font-semibold">
                    {selectedHoneypot.name}
                  </h3>
                  <p className="mt-1 text-xs text-white/35">
                    {selectedHoneypot.id}
                  </p>
                </div>
                <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-orange-500/20 bg-orange-500/10 text-xl text-orange-300">
                  ⌘
                </span>
              </div>

              <div className="mt-5">
                <span className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs ${statusStyles[selectedHoneypot.status]}`}>
                  <span className="h-1.5 w-1.5 rounded-full bg-current" />
                  {selectedHoneypot.status}
                </span>
              </div>

              <p className="mt-5 text-sm leading-6 text-white/55">
                {selectedHoneypot.description}
              </p>

              <div className="my-5 border-t border-white/10" />

              <div className="space-y-4">
                {[
                  ['IP address', selectedHoneypot.ip],
                  ['Type', selectedHoneypot.type],
                  ['Assigned profile', selectedHoneypot.profile],
                  ['Location', selectedHoneypot.location],
                  ['Last activity', selectedHoneypot.lastActivity],
                  ['Sessions', String(selectedHoneypot.sessions)],
                ].map(([label, value]) => (
                  <div key={label} className="flex items-start justify-between gap-4">
                    <span className="text-xs text-white/40">{label}</span>
                    <span className="text-right text-xs font-medium text-white/80">
                      {value}
                    </span>
                  </div>
                ))}
              </div>

              <div className="mt-6 rounded-lg border border-white/10 bg-black/20 p-3">
                <p className="text-xs text-white/55">Data source</p>
                <p className="mt-1 text-xs text-orange-300/80">
                  Local demo data · Backend not connected
                </p>
              </div>
            </>
          ) : (
            <div className="py-8 text-center">
              <p className="text-sm text-white/65">No honeypot selected</p>
              <p className="mt-2 text-xs text-white/35">
                Change the filters to see available traps.
              </p>
            </div>
          )}
        </aside>
      </div>
    </section>
  )
}

export default Honeypots