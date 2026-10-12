import { useMemo, useState } from 'react'
import type { AttackEvent, Trap } from '../api/types'

type Props = { events: AttackEvent[]; traps: Trap[]; loading: boolean; error: string }
type DerivedSession = { id: string; events: AttackEvent[]; first: string; last: string; trapId: string; sourceIp: string | null }

export default function Sessions({ events, traps, loading, error }: Props) {
  const [search, setSearch] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const trapNames = useMemo(() => new Map(traps.map((trap) => [trap.trap_id, trap.name])), [traps])
  const sessions = useMemo(() => {
    const grouped = new Map<string, AttackEvent[]>()
    for (const item of events) {
      const id = item.event.session_id
      if (id) grouped.set(id, [...(grouped.get(id) ?? []), item])
    }
    return [...grouped.entries()].map(([id, items]): DerivedSession => {
      const sorted = [...items].sort((a, b) => a.event.occurred_at.localeCompare(b.event.occurred_at))
      return { id, events: sorted, first: sorted[0].event.occurred_at, last: sorted.at(-1)!.event.occurred_at, trapId: sorted[0].event.trap_id, sourceIp: sorted.find((item) => item.event.source_ip)?.event.source_ip ?? null }
    }).sort((a, b) => b.last.localeCompare(a.last))
  }, [events])
  const filtered = sessions.filter((session) => `${session.id} ${session.sourceIp ?? ''} ${trapNames.get(session.trapId) ?? ''}`.toLowerCase().includes(search.toLowerCase()))
  const selected = sessions.find((session) => session.id === selectedId) ?? null

  return <section className="space-y-6 p-6"><div><p className="text-sm text-white/45">SECURITY / DERIVED SESSIONS</p><h2 className="mt-1 text-2xl font-semibold">Sessions</h2><p className="mt-2 text-sm text-white/45">Event groups derived only when telemetry includes a session_id.</p></div>
    <div className="rounded-lg border border-orange-500/20 bg-orange-500/5 p-4 text-sm text-orange-100">The backend has no Sessions resource or active/completed status API. These rows are derived from the current event snapshot; duration and liveness cannot be determined reliably.</div>
    {error && <p role="alert" className="text-sm text-red-400">{error}</p>}
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">{[['Derived sessions', sessions.length], ['Events with session ID', events.filter((item) => item.event.session_id).length], ['Events without session ID', events.filter((item) => !item.event.session_id).length]].map(([label, value]) => <div key={String(label)} className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-5"><p className="text-sm text-white/50">{label}</p><p className="mt-4 text-3xl font-semibold">{value}</p></div>)}</div>
    <div className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-5"><div className="flex flex-wrap items-center justify-between gap-4"><div><h3 className="font-semibold">Derived session history</h3><p className="mt-1 text-xs text-white/40">Based on the currently loaded telemetry snapshot</p></div><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search sessions..." className="rounded-lg border border-white/10 bg-black/30 px-4 py-2 text-sm outline-none focus:border-orange-500/50"/></div>
      <div className="mt-6 overflow-x-auto"><table className="w-full min-w-[760px] text-left text-sm"><thead className="border-b border-white/10 text-xs text-white/40"><tr><th className="px-4 py-3">Session ID</th><th className="px-4 py-3">Honeypot</th><th className="px-4 py-3">Source IP</th><th className="px-4 py-3">First event</th><th className="px-4 py-3">Last event</th><th className="px-4 py-3">Events</th><th className="px-4 py-3">Action</th></tr></thead><tbody>{filtered.map((session) => <tr key={session.id} className="border-b border-white/5 hover:bg-white/5"><td className="max-w-52 truncate px-4 py-4 font-mono text-orange-300">{session.id}</td><td className="px-4 py-4">{trapNames.get(session.trapId) ?? session.trapId}</td><td className="px-4 py-4 font-mono text-white/50">{session.sourceIp ?? '—'}</td><td className="px-4 py-4 text-white/50">{new Date(session.first).toLocaleString()}</td><td className="px-4 py-4 text-white/50">{new Date(session.last).toLocaleString()}</td><td className="px-4 py-4">{session.events.length}</td><td className="px-4 py-4"><button type="button" onClick={() => setSelectedId(session.id)} className="rounded-lg border border-orange-500/30 px-3 py-2 text-xs text-orange-300">View events</button></td></tr>)}</tbody></table>{!loading && filtered.length === 0 && <p className="py-8 text-center text-sm text-white/40">No session identifiers were returned in this snapshot.</p>}</div>
    </div>
    {selected && <div className="rounded-xl border border-orange-500/20 bg-[#160e0c]/90 p-6"><div className="flex justify-between gap-4"><div><p className="text-xs text-orange-400">DERIVED EVENT GROUP</p><h3 className="mt-2 break-all font-mono text-lg">{selected.id}</h3></div><button type="button" onClick={() => setSelectedId(null)} className="rounded-lg border border-white/10 px-4 py-2 text-sm text-white/60">Close</button></div><div className="mt-6 space-y-4">{selected.events.map(({ event }) => <div key={event.event_id} className="border-l border-orange-500/30 pl-4"><p className="text-sm">{event.event_type}</p><p className="mt-1 text-xs text-white/40">{new Date(event.occurred_at).toLocaleString()} · {event.protocol}/{event.service_type}</p></div>)}</div></div>}
  </section>
}
