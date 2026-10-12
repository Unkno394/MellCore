import { useMemo, useState, type FormEvent } from 'react'
import FuzzyText from '../components/FuzzyText'
import { apiErrorMessage } from '../api/client'
import type { MellCoreApi } from '../api/services'
import type { Profile, Server, TrapDesiredState } from '../api/types'

type Props = { api: MellCoreApi; profiles: Profile[]; servers: Server[]; readOnly: boolean; onCreated: () => Promise<void> }

export default function CreateHoneypot({ api, profiles, servers, readOnly, onCreated }: Props) {
  const supported = useMemo(() => profiles.filter((profile) => profile.level === 'low' || profile.level === 'medium'), [profiles])
  const [name, setName] = useState('')
  const [serverId, setServerId] = useState('')
  const [profileId, setProfileId] = useState('')
  const [hostPort, setHostPort] = useState('2222')
  const [targetPort, setTargetPort] = useState('2222')
  const [desiredState, setDesiredState] = useState<TrapDesiredState>('stopped')
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const profile = supported.find((item) => item.id === profileId)

  async function submit(event: FormEvent) {
    event.preventDefault(); setError(''); setMessage('')
    if (!serverId || !profile) return setError('Select a registered server and a supported profile.')
    setBusy(true)
    try {
      await api.traps.create(serverId, { name, profile_id: profile.id, config: {}, desired_state: desiredState, ports: [{ transport: 'tcp', host_port: Number(hostPort), target_port: Number(targetPort), route_mode: 'direct' }] })
      setMessage(`Trap configuration saved with desired state “${desiredState}”. No deployment command was executed.`)
      setName('')
      await onCreated()
    } catch (requestError) { setError(apiErrorMessage(requestError)) }
    finally { setBusy(false) }
  }

  return <section className="space-y-6 p-6"><div className="mx-auto max-w-4xl"><div className="mb-6 text-center"><p className="text-sm text-white/45">Configuration</p><div className="mt-3 flex justify-center"><FuzzyText fontSize={28} fontWeight={600} color="#f1a36b" baseIntensity={0.2} hoverIntensity={0.5} fuzzRange={8} fps={30} enableHover className="block">Create Honeypot</FuzzyText></div><p className="mt-3 text-sm text-white/45">Save a Low or Medium trap configuration in MellCore.</p></div>
    <form onSubmit={submit} className="w-full space-y-6 rounded-xl border border-white/10 bg-[#160e0c]/80 p-6 backdrop-blur-xl">
      <div className="rounded-lg border border-orange-500/20 bg-orange-500/5 p-4 text-sm text-orange-100">High is intentionally unavailable: the management API currently supports only Low and Medium. Saving <code>desired_state</code> does not deploy the trap.</div>
      <label className="block text-sm text-white/70">Honeypot name<input required disabled={readOnly} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. SSH Honeypot 01" className="mt-2 w-full rounded-lg border border-white/10 bg-black/20 px-4 py-3 outline-none focus:border-orange-500/50" /></label>
      <div className="grid gap-4 sm:grid-cols-2"><label className="text-sm text-white/70">Server<select required disabled={readOnly} value={serverId} onChange={(e) => setServerId(e.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-[#100a09] px-4 py-3"><option value="">Select server</option>{servers.map((server) => <option key={server.server_id} value={server.server_id}>{server.name} — {server.host}</option>)}</select></label><label className="text-sm text-white/70">Profile<select required disabled={readOnly} value={profileId} onChange={(e) => { setProfileId(e.target.value); const selected = supported.find((item) => item.id === e.target.value); if (selected?.service_type === 'ssh') setTargetPort('2222') }} className="mt-2 w-full rounded-lg border border-white/10 bg-[#100a09] px-4 py-3"><option value="">Select Low/Medium profile</option>{supported.map((item) => <option key={item.id} value={item.id}>{item.name} ({item.level})</option>)}</select></label></div>
      {profile && <div className="grid grid-cols-3 gap-3">{[['Level', profile.level], ['Type', profile.honeypot_type], ['Service', profile.service_type]].map(([label, value]) => <div key={label} className="rounded-lg border border-white/10 bg-black/20 p-3"><p className="text-[10px] uppercase text-white/35">{label}</p><p className="mt-1 text-sm capitalize">{value}</p></div>)}</div>}
      <div className="grid gap-4 sm:grid-cols-3"><label className="text-sm text-white/70">Host port<input required disabled={readOnly} type="number" min="1" max="65535" value={hostPort} onChange={(e) => setHostPort(e.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-black/20 px-4 py-3" /></label><label className="text-sm text-white/70">Target port<input required disabled={readOnly} type="number" min="1" max="65535" value={targetPort} onChange={(e) => setTargetPort(e.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-black/20 px-4 py-3" /></label><label className="text-sm text-white/70">Desired state<select disabled={readOnly} value={desiredState} onChange={(e) => setDesiredState(e.target.value as TrapDesiredState)} className="mt-2 w-full rounded-lg border border-white/10 bg-[#100a09] px-4 py-3"><option value="stopped">Stopped</option><option value="running">Running (desired only)</option></select></label></div>
      {error && <p role="alert" className="text-sm text-red-400">{error}</p>}{message && <p role="status" className="text-sm text-emerald-300">{message}</p>}
      {!readOnly && <button disabled={busy || !servers.length || !supported.length} className="rounded-lg border border-orange-500/30 bg-orange-500/10 px-5 py-3 text-sm font-medium text-[#f1a36b] disabled:opacity-40">{busy ? 'Saving…' : 'Save trap configuration'}</button>}
    </form></div></section>
}
