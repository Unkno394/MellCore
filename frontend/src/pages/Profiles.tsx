import { useState } from 'react'
import { apiErrorMessage } from '../api/client'
import type { MellCoreApi } from '../api/services'
import type { Profile, ProfileInput } from '../api/types'

type Props = { api: MellCoreApi; profiles: Profile[]; isAdmin: boolean; onChanged: () => Promise<void> }

const emptyProfile: ProfileInput = { name: '', description: '', level: 'low', honeypot_type: 'kozyavka', service_type: 'ssh', config: {} }

export default function Profiles({ api, profiles, isAdmin, onChanged }: Props) {
  const [selectedId, setSelectedId] = useState<string | null>(profiles[0]?.id ?? null)
  const selected = profiles.find((profile) => profile.id === selectedId) ?? null
  const [form, setForm] = useState<ProfileInput>(emptyProfile)
  const [configText, setConfigText] = useState('{}')
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)

  function createNew() { setSelectedId(null); setForm(emptyProfile); setConfigText('{}'); setError(''); setMessage('') }
  function select(profile: Profile) {
    setSelectedId(profile.id)
    setForm({ name: profile.name, description: profile.description, level: profile.level, honeypot_type: profile.honeypot_type, service_type: profile.service_type, config: profile.config })
    setConfigText(JSON.stringify(profile.config, null, 2))
    setError(''); setMessage('')
  }
  function update<K extends keyof ProfileInput>(key: K, value: ProfileInput[K]) { setForm((current) => ({ ...current, [key]: value })); setMessage('') }

  async function save() {
    setError(''); setMessage(''); setBusy(true)
    try {
      const config = JSON.parse(configText) as unknown
      if (!config || Array.isArray(config) || typeof config !== 'object') throw new Error('Config must be a JSON object.')
      const input = { ...form, config: config as Record<string, unknown> }
      const saved = selected ? await api.profiles.update(selected, input) : await api.profiles.create(input)
      setSelectedId(saved.id)
      setMessage(selected ? 'Profile updated.' : 'Profile created.')
      await onChanged()
    } catch (requestError) { setError(requestError instanceof SyntaxError || requestError instanceof Error && requestError.message === 'Config must be a JSON object.' ? requestError.message : apiErrorMessage(requestError)) }
    finally { setBusy(false) }
  }

  async function remove() {
    if (!selected || !window.confirm(`Delete profile ${selected.name}?`)) return
    setBusy(true); setError('')
    try { await api.profiles.delete(selected.id); createNew(); await onChanged(); setMessage('Profile deleted.') }
    catch (requestError) { setError(apiErrorMessage(requestError)) }
    finally { setBusy(false) }
  }

  return <section className="space-y-6 p-6">
    <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end"><div><p className="text-xs font-semibold uppercase tracking-[0.25em] text-orange-400/70">Configuration / API</p><h2 className="mt-2 text-2xl font-semibold tracking-tight">Interaction Profiles</h2><p className="mt-2 max-w-xl text-sm leading-6 text-white/45">Shared backend templates. Low and Medium are supported; High is not sent to this API.</p></div>{isAdmin && <button type="button" onClick={createNew} className="rounded-lg border border-orange-400/30 bg-orange-500/10 px-4 py-3 text-sm text-orange-200">+ Create profile</button>}</div>
    {!isAdmin && <div className="rounded-lg border border-white/10 bg-white/5 p-4 text-sm text-white/55">Your role can read profiles. Only administrators can create, update, or delete them.</div>}
    <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-[0.85fr_1.5fr]">
      <section className="rounded-xl border border-white/10 bg-[#160e0c]/75 p-4 backdrop-blur-xl"><div className="mb-4 flex justify-between"><h3 className="font-semibold">Profile library</h3><span className="text-xs text-white/40">{profiles.length} items</span></div><div className="space-y-2">{profiles.map((profile) => <button key={profile.id} type="button" onClick={() => select(profile)} className={`w-full rounded-lg border p-4 text-left ${selectedId === profile.id ? 'border-orange-400/40 bg-orange-500/[0.08]' : 'border-white/[0.07] bg-black/10'}`}><div className="flex justify-between gap-3"><span className="truncate text-sm font-medium">{profile.name}</span><span className={`rounded-full border px-2 py-1 text-[9px] ${profile.level === 'medium' ? 'border-orange-500/30 text-orange-300' : 'border-emerald-500/30 text-emerald-300'}`}>{profile.level.toUpperCase()}</span></div><p className="mt-2 text-xs text-white/40">{profile.honeypot_type} · {profile.service_type}</p></button>)}</div>{profiles.length === 0 && <p className="py-8 text-center text-sm text-white/40">No profiles available.</p>}</section>
      <section className="rounded-xl border border-white/10 bg-[#160e0c]/75 p-5 backdrop-blur-xl"><div className="border-b border-white/10 pb-5"><p className="text-[10px] uppercase tracking-[0.2em] text-orange-300/70">{selected ? `Editing version ${selected.version}` : 'New profile'}</p><h3 className="mt-2 text-lg font-semibold">{form.name || 'Untitled profile'}</h3></div><div className="mt-5 space-y-5">
        <label className="block text-xs text-white/55">Profile name<input disabled={!isAdmin} value={form.name} onChange={(e) => update('name', e.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-black/20 px-3 py-3 text-sm outline-none" /></label>
        <label className="block text-xs text-white/55">Description<textarea disabled={!isAdmin} rows={3} value={form.description} onChange={(e) => update('description', e.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-black/20 px-3 py-3 text-sm outline-none" /></label>
        <div className="grid gap-4 sm:grid-cols-3"><label className="text-xs text-white/55">Interaction level<select disabled={!isAdmin} value={form.level} onChange={(e) => update('level', e.target.value as ProfileInput['level'])} className="mt-2 w-full rounded-lg border border-white/10 bg-[#100a09] px-3 py-3 text-sm"><option value="low">Low</option><option value="medium">Medium</option></select></label><label className="text-xs text-white/55">Honeypot type<input disabled={!isAdmin} value={form.honeypot_type} onChange={(e) => update('honeypot_type', e.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-black/20 px-3 py-3 text-sm" /></label><label className="text-xs text-white/55">Service type<input disabled={!isAdmin} value={form.service_type} onChange={(e) => update('service_type', e.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-black/20 px-3 py-3 text-sm" /></label></div>
        <label className="block text-xs text-white/55">Configuration JSON<textarea disabled={!isAdmin} rows={8} value={configText} onChange={(e) => { setConfigText(e.target.value); setMessage('') }} className="mt-2 w-full rounded-lg border border-white/10 bg-black/30 px-3 py-3 font-mono text-xs outline-none" /></label>
        {error && <p role="alert" className="text-sm text-red-400">{error}</p>}{message && <p role="status" className="text-sm text-emerald-300">{message}</p>}
        {isAdmin && <div className="flex gap-3"><button type="button" disabled={busy} onClick={save} className="rounded-lg bg-orange-500 px-5 py-3 text-sm font-semibold text-[#1a0d08] disabled:opacity-50">{selected ? 'Save changes' : 'Create profile'}</button>{selected && <button type="button" disabled={busy} onClick={remove} className="rounded-lg border border-red-500/30 px-5 py-3 text-sm text-red-300">Delete</button>}</div>}
      </div></section>
    </div>
  </section>
}
