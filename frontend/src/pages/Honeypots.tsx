import { useMemo, useState } from 'react'
import { apiErrorMessage } from '../api/client'
import type { MellCoreApi } from '../api/services'
import type { Trap, TrapDesiredState } from '../api/types'

type Props = { api: MellCoreApi; traps: Trap[]; readOnly: boolean; onChanged: () => Promise<void> }

const statusStyles: Record<Trap['actual_state'], string> = {
  running: 'border-emerald-500/25 bg-emerald-500/10 text-emerald-400',
  installing: 'border-orange-500/25 bg-orange-500/10 text-orange-300',
  failed: 'border-red-500/25 bg-red-500/10 text-red-300',
  unknown: 'border-white/10 bg-white/5 text-white/45', stopped: 'border-white/10 bg-white/5 text-white/45', removed: 'border-white/10 bg-white/5 text-white/45',
}

export default function Honeypots({ api, traps, readOnly, onChanged }: Props) {
  const [search, setSearch] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(traps[0]?.trap_id ?? null)
  const [desired, setDesired] = useState<TrapDesiredState>('stopped')
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const filtered = useMemo(() => traps.filter((trap) => `${trap.name} ${trap.trap_id} ${trap.profile_snapshot.honeypot_type}`.toLowerCase().includes(search.toLowerCase())), [traps, search])
  const selected = filtered.find((trap) => trap.trap_id === selectedId) ?? filtered[0] ?? null

  function select(trap: Trap) { setSelectedId(trap.trap_id); setDesired(trap.desired_state); setError(''); setMessage('') }

  async function saveDesired() {
    if (!selected) return
    setError(''); setMessage('')
    try {
      await api.traps.update(selected, { name: selected.name, profile_id: selected.profile_id, config: selected.config, desired_state: desired, ports: selected.ports })
      setMessage(`Desired state saved as “${desired}”. This API did not execute a deployment command.`)
      await onChanged()
    } catch (requestError) { setError(apiErrorMessage(requestError)) }
  }

  async function remove() {
    if (!selected || !window.confirm(`Delete registration for ${selected.name}?`)) return
    setError('')
    try { await api.traps.delete(selected.trap_id); setSelectedId(null); await onChanged() }
    catch (requestError) { setError(apiErrorMessage(requestError)) }
  }

  const running = traps.filter((trap) => trap.actual_state === 'running').length
  const attention = traps.filter((trap) => trap.actual_state === 'failed').length
  return <section className="space-y-6 p-4 sm:p-6"><div><p className="text-sm text-white/40">Workspace / Honeypots</p><div className="mt-2 flex items-end justify-between"><div><h2 className="text-2xl font-semibold">Honeypots</h2><p className="mt-2 text-sm text-white/45">Backend trap registrations and reported actual state.</p></div><span className="rounded-lg border border-emerald-500/20 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-300">MANAGEMENT API</span></div></div>
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">{[['Total honeypots', traps.length, 'Registered configurations'], ['Actually running', running, 'Backend actual_state'], ['Failed', attention, 'Reported failures']].map(([label, value, detail]) => <article key={String(label)} className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-5"><p className="text-sm text-white/45">{label}</p><p className="mt-3 text-3xl font-semibold">{String(value).padStart(2, '0')}</p><p className="mt-2 text-xs text-white/35">{detail}</p></article>)}</div>
    <div className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-4"><input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search by name, ID or type..." className="w-full rounded-lg border border-white/10 bg-black/20 px-4 py-3 text-sm outline-none focus:border-orange-500/50" /></div>
    <div className="grid grid-cols-1 items-start gap-4 2xl:grid-cols-[1.6fr_0.8fr]"><section className="overflow-hidden rounded-xl border border-white/10 bg-[#160e0c]/80"><table className="w-full min-w-[680px] text-left text-sm"><thead className="border-b border-white/10 text-xs text-white/40"><tr><th className="px-5 py-4">Honeypot</th><th className="px-4 py-4">Profile</th><th className="px-4 py-4">Desired</th><th className="px-4 py-4">Actual</th></tr></thead><tbody>{filtered.map((trap) => <tr key={trap.trap_id} onClick={() => select(trap)} className="cursor-pointer border-b border-white/5 hover:bg-white/[0.04]"><td className="px-5 py-4"><p className="font-medium">{trap.name}</p><p className="mt-1 font-mono text-xs text-white/35">{trap.trap_id}</p></td><td className="px-4 py-4"><p>{trap.profile_snapshot.name}</p><p className="text-xs text-white/40">{trap.profile_snapshot.level}</p></td><td className="px-4 py-4 capitalize text-white/60">{trap.desired_state}</td><td className="px-4 py-4"><span className={`rounded-full border px-3 py-1 text-xs capitalize ${statusStyles[trap.actual_state]}`}>{trap.actual_state}</span></td></tr>)}</tbody></table>{filtered.length === 0 && <p className="p-10 text-center text-sm text-white/40">No honeypots found.</p>}</section>
      <aside className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-5">{selected ? <><p className="text-xs uppercase tracking-widest text-orange-300/70">Selected honeypot</p><h3 className="mt-2 text-lg font-semibold">{selected.name}</h3><p className="mt-4 text-sm text-white/55">{selected.profile_snapshot.description || 'No profile description.'}</p><div className="my-5 border-t border-white/10" /><div className="space-y-3 text-xs">{[['Type', selected.profile_snapshot.honeypot_type], ['Service', selected.profile_snapshot.service_type], ['Level', selected.profile_snapshot.level], ['Actual state', selected.actual_state], ['Version', String(selected.version)]].map(([label, value]) => <div key={label} className="flex justify-between gap-3"><span className="text-white/40">{label}</span><span className="text-right capitalize">{value}</span></div>)}</div><div className="mt-6 rounded-lg border border-orange-500/15 bg-orange-500/5 p-3 text-xs text-orange-100">Desired state is configuration only until backend-to-agent orchestration is implemented.</div>{!readOnly && <div className="mt-5 space-y-3"><select value={desired} onChange={(e) => setDesired(e.target.value as TrapDesiredState)} className="w-full rounded-lg border border-white/10 bg-[#100a09] px-3 py-3 text-sm"><option value="stopped">Stopped</option><option value="running">Running (desired only)</option></select><div className="flex gap-2"><button type="button" onClick={saveDesired} className="flex-1 rounded-lg bg-orange-600 px-3 py-2 text-sm">Save desired state</button><button type="button" onClick={remove} className="rounded-lg border border-red-500/30 px-3 py-2 text-sm text-red-300">Delete</button></div></div>}{error && <p className="mt-4 text-xs text-red-400">{error}</p>}{message && <p className="mt-4 text-xs text-emerald-300">{message}</p>}</> : <p className="text-sm text-white/40">No honeypot selected.</p>}</aside>
    </div></section>
}
