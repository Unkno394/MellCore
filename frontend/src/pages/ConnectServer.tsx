import { useEffect, useState, type FormEvent } from 'react'
import { apiErrorMessage } from '../api/client'
import type { MellCoreApi } from '../api/services'
import type { PortReservation, Server, ServerInput } from '../api/types'

type Props = {
  api: MellCoreApi
  servers: Server[]
  readOnly: boolean
  onChanged: () => Promise<void>
}

const emptyServer: ServerInput = {
  name: '', host: '', ssh_port: 22, ssh_user: '', credential_ref: null,
  dispatcher_port: null, settings: {},
}

export default function ConnectServer({ api, servers, readOnly, onChanged }: Props) {
  const [selected, setSelected] = useState<Server | null>(null)
  const [form, setForm] = useState<ServerInput>(emptyServer)
  const [ports, setPorts] = useState<PortReservation[]>([])
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!selected) return
    void api.servers.ports(selected.server_id).then(setPorts).catch((requestError: unknown) => setError(apiErrorMessage(requestError)))
  }, [api, selected])

  function choose(server: Server | null) {
    setSelected(server)
    setForm(server ? {
      name: server.name, host: server.host, ssh_port: server.ssh_port,
      ssh_user: server.ssh_user, credential_ref: server.credential_ref,
      dispatcher_port: server.dispatcher_port, settings: server.settings,
    } : emptyServer)
    setMessage('')
    setError('')
  }

  async function save(event: FormEvent) {
    event.preventDefault()
    setBusy(true); setError(''); setMessage('')
    try {
      const wasEditing = Boolean(selected)
      if (selected) await api.servers.update(selected, form)
      else await api.servers.create(form)
      setSelected(null)
      setForm(emptyServer)
      setPorts([])
      setMessage(wasEditing ? 'Server registration updated.' : 'Server metadata registered. No SSH connection or deployment was performed.')
      await onChanged()
    } catch (requestError) { setError(apiErrorMessage(requestError)) }
    finally { setBusy(false) }
  }

  async function remove() {
    if (!selected || !window.confirm(`Delete registration for ${selected.name}?`)) return
    setBusy(true); setError('')
    try { await api.servers.delete(selected.server_id); choose(null); await onChanged() }
    catch (requestError) { setError(apiErrorMessage(requestError)) }
    finally { setBusy(false) }
  }

  const update = <K extends keyof ServerInput>(key: K, value: ServerInput[K]) => setForm((current) => ({ ...current, [key]: value }))

  return <section className="space-y-6 p-6">
    <div><p className="text-sm text-white/40">INFRASTRUCTURE</p><h1 className="mt-2 text-2xl font-semibold">Servers</h1><p className="mt-2 text-sm text-white/45">Register server metadata used by the management API.</p></div>
    <div className="rounded-xl border border-orange-500/20 bg-orange-500/5 p-4 text-sm text-orange-100"><strong>Registration only.</strong> MellCore does not test SSH or deploy an agent from this API. Credentials are never collected by this page.</div>
    <div className="grid gap-6 xl:grid-cols-[1.35fr_1fr]">
      <form onSubmit={save} className="space-y-5 rounded-xl border border-white/10 bg-[#160e0c]/85 p-6 backdrop-blur-xl">
        <div className="flex items-center justify-between"><div><h2 className="font-semibold">{selected ? 'Edit server' : 'Register server'}</h2><p className="mt-1 text-xs text-white/40">Stored in your owner-scoped server inventory.</p></div>{selected && <button type="button" onClick={() => choose(null)} className="text-xs text-orange-300">New server</button>}</div>
        <label className="block text-sm text-white/60">Display name<input required disabled={readOnly} value={form.name} onChange={(e) => update('name', e.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 outline-none focus:border-orange-500/60" /></label>
        <label className="block text-sm text-white/60">Server IP or hostname<input required disabled={readOnly} value={form.host} onChange={(e) => update('host', e.target.value)} placeholder="192.0.2.10" className="mt-2 w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 outline-none focus:border-orange-500/60" /></label>
        <div className="grid gap-4 sm:grid-cols-2"><label className="text-sm text-white/60">SSH username<input required disabled={readOnly} value={form.ssh_user} onChange={(e) => update('ssh_user', e.target.value)} placeholder="root" className="mt-2 w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 outline-none focus:border-orange-500/60" /></label><label className="text-sm text-white/60">SSH port<input required disabled={readOnly} type="number" min="1" max="65535" value={form.ssh_port} onChange={(e) => update('ssh_port', Number(e.target.value))} className="mt-2 w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 outline-none focus:border-orange-500/60" /></label></div>
        <div className="grid gap-4 sm:grid-cols-3"><label className="text-sm text-white/60">Dispatcher port<input disabled={readOnly} type="number" min="1" max="65535" value={form.dispatcher_port ?? ''} onChange={(e) => update('dispatcher_port', e.target.value ? Number(e.target.value) : null)} placeholder="Optional" className="mt-2 w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 outline-none" /></label><label className="text-sm text-white/60">CPU limit<input disabled={readOnly} type="number" min="1" max="1024" value={form.settings.cpu_limit ?? ''} onChange={(e) => update('settings', { ...form.settings, cpu_limit: e.target.value ? Number(e.target.value) : null })} placeholder="Optional" className="mt-2 w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 outline-none" /></label><label className="text-sm text-white/60">Memory MB<input disabled={readOnly} type="number" min="16" max="1048576" value={form.settings.memory_limit_mb ?? ''} onChange={(e) => update('settings', { ...form.settings, memory_limit_mb: e.target.value ? Number(e.target.value) : null })} placeholder="Optional" className="mt-2 w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 outline-none" /></label></div>
        {readOnly && <p className="text-sm text-white/45">Viewer role is read-only.</p>}{error && <p role="alert" className="text-sm text-red-400">{error}</p>}{message && <p role="status" className="text-sm text-emerald-300">{message}</p>}
        {!readOnly && <div className="flex gap-3"><button disabled={busy} className="rounded-lg bg-orange-600 px-5 py-3 text-sm font-semibold disabled:opacity-50">{selected ? 'Save changes' : 'Register server'}</button>{selected && <button type="button" disabled={busy} onClick={remove} className="rounded-lg border border-red-500/30 px-5 py-3 text-sm text-red-300">Delete</button>}</div>}
      </form>
      <aside className="space-y-4 rounded-xl border border-white/10 bg-[#160e0c]/85 p-5"><div className="flex items-center justify-between"><h2 className="font-semibold">Registered servers</h2><span className="text-xs text-white/40">{servers.length}</span></div>{servers.length === 0 ? <p className="text-sm text-white/40">No servers registered.</p> : servers.map((server) => <button type="button" key={server.server_id} onClick={() => choose(server)} className={`w-full rounded-lg border p-4 text-left ${selected?.server_id === server.server_id ? 'border-orange-500/40 bg-orange-500/10' : 'border-white/10 bg-black/10'}`}><div className="flex justify-between gap-3"><span className="font-medium">{server.name}</span><span className="text-xs text-white/40">{server.status}</span></div><p className="mt-2 font-mono text-xs text-white/45">{server.host}:{server.ssh_port}</p></button>)}{selected && <div className="border-t border-white/10 pt-4"><h3 className="text-sm font-medium">Reserved ports</h3>{ports.length === 0 ? <p className="mt-2 text-xs text-white/35">No reservations returned.</p> : <div className="mt-3 space-y-2">{ports.map((port) => <div key={`${port.transport}-${port.host_port}`} className="flex justify-between text-xs text-white/55"><span>{port.transport.toUpperCase()} {port.host_port}</span><span>{port.purpose}</span></div>)}</div>}</div>}</aside>
    </div>
  </section>
}
