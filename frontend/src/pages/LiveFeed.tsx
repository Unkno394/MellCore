import { useMemo, useState } from 'react'
import type { AttackEvent, Trap } from '../api/types'

type Props = {
  events: AttackEvent[]
  traps: Trap[]
  loading: boolean
  error: string
  onRefresh: () => Promise<void>
}

export default function LiveFeed({ events, traps, loading, error, onRefresh }: Props) {
  const [search, setSearch] = useState('')
  const [service, setService] = useState('All')
  const trapNames = useMemo(() => new Map(traps.map((trap) => [trap.trap_id, trap.name])), [traps])
  const services = useMemo(() => [...new Set(events.map((item) => item.event.service_type))].sort(), [events])
  const filtered = useMemo(() => events.filter(({ event }) => {
    const haystack = `${event.event_type} ${event.source_ip ?? ''} ${trapNames.get(event.trap_id) ?? event.trap_id} ${event.service_type}`.toLowerCase()
    return haystack.includes(search.toLowerCase()) && (service === 'All' || event.service_type === service)
  }), [events, search, service, trapNames])

  return <section className="space-y-6 p-6">
    <div className="flex flex-wrap items-end justify-between gap-4"><div><p className="text-sm text-white/45">SECURITY / TELEMETRY</p><h2 className="mt-1 text-2xl font-semibold">Live Feed</h2><p className="mt-2 text-sm text-white/45">Latest persisted events returned by each trap's management endpoint.</p></div><button type="button" disabled={loading} onClick={() => void onRefresh()} className="rounded-lg border border-orange-500/30 px-4 py-2 text-sm text-orange-300 disabled:opacity-50">{loading ? 'Loading…' : 'Refresh snapshot'}</button></div>
    <div className="rounded-lg border border-orange-500/20 bg-orange-500/5 p-4 text-sm text-orange-100">This is a fetched snapshot, not a streaming connection. MellCore exposes events per trap; there is no global live-feed or severity field, so the UI does not invent threat levels.</div>
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">{[
      ['Loaded events', events.length],
      ['Sensors represented', new Set(events.map((item) => item.event.trap_id)).size],
      ['Sessions represented', new Set(events.flatMap((item) => item.event.session_id ? [item.event.session_id] : [])).size],
    ].map(([label, value]) => <div key={String(label)} className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-5 backdrop-blur-xl"><p className="text-sm text-white/50">{label}</p><p className="mt-4 text-3xl font-semibold">{value}</p></div>)}</div>
    <div className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-5 backdrop-blur-xl">
      <div className="flex flex-wrap items-center justify-between gap-4"><div><h3 className="font-semibold">Event snapshot</h3><p className="mt-1 text-xs text-white/40">Up to 100 API results loaded per trap</p></div><div className="flex flex-wrap gap-3"><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search events..." className="rounded-lg border border-white/10 bg-black/30 px-4 py-2 text-sm outline-none focus:border-orange-500/50"/><select value={service} onChange={(event) => setService(event.target.value)} className="rounded-lg border border-white/10 bg-[#160e0c] px-4 py-2 text-sm"><option>All</option>{services.map((item) => <option key={item}>{item}</option>)}</select></div></div>
      {error && <p role="alert" className="mt-4 text-sm text-red-400">{error}</p>}
      <div className="mt-6 overflow-x-auto"><table className="w-full min-w-[820px] text-left text-sm"><thead className="border-b border-white/10 text-xs text-white/40"><tr><th className="px-4 py-3">Occurred</th><th className="px-4 py-3">Event</th><th className="px-4 py-3">Honeypot</th><th className="px-4 py-3">Source</th><th className="px-4 py-3">Protocol / Service</th><th className="px-4 py-3">Session</th></tr></thead><tbody>{filtered.map(({ event }) => <tr key={event.event_id} className="border-b border-white/5 hover:bg-white/5"><td className="px-4 py-4 text-white/50">{new Date(event.occurred_at).toLocaleString()}</td><td className="px-4 py-4">{event.event_type}</td><td className="px-4 py-4 text-white/60">{trapNames.get(event.trap_id) ?? event.trap_id}</td><td className="px-4 py-4 font-mono text-white/50">{event.source_ip ?? '—'}{event.source_port ? `:${event.source_port}` : ''}</td><td className="px-4 py-4 text-white/60">{event.protocol} / {event.service_type}</td><td className="max-w-48 truncate px-4 py-4 font-mono text-xs text-white/45">{event.session_id ?? '—'}</td></tr>)}</tbody></table>{!loading && filtered.length === 0 && <p className="py-8 text-center text-sm text-white/40">No matching persisted events were returned.</p>}</div>
      <div className="mt-4 text-xs text-white/40">Showing {filtered.length} of {events.length} real API events in the current snapshot.</div>
    </div>
  </section>
}
