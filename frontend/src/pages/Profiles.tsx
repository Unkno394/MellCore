import { profileNameLabel, statusLabel } from '../i18n/labels'
import { useState } from 'react'
import { apiErrorMessage } from '../api/client'
import type { MellCoreApi } from '../api/services'
import type { ContainerResourceLimits, Profile, ProfileInput } from '../api/types'

type Props = { api: MellCoreApi; profiles: Profile[]; isAdmin: boolean; onChanged: () => Promise<void> }

const defaultLimits: Record<ProfileInput['level'], ContainerResourceLimits> = {
  low: { cpu_cores: 0.5, memory_mb: 128, pids: 64 },
  medium: { cpu_cores: 1, memory_mb: 512, pids: 256 },
}
const typeForLevel: Record<ProfileInput['level'], string> = { low: 'kozyavka', medium: 'pritvoryashka' }
const emptyProfile: ProfileInput = { name: '', description: '', level: 'low', honeypot_type: typeForLevel.low, service_type: 'ssh', config: {}, resources: defaultLimits.low }

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
    setForm({ name: profileNameLabel(profile.name, profile.level), description: profile.description, level: profile.level, honeypot_type: typeForLevel[profile.level], service_type: profile.service_type, config: profile.config, resources: profile.resources ?? defaultLimits[profile.level] })
    setConfigText(JSON.stringify(profile.config, null, 2))
    setError(''); setMessage('')
  }
  function update<K extends keyof ProfileInput>(key: K, value: ProfileInput[K]) { setForm((current) => ({ ...current, [key]: value })); setMessage('') }
  function updateResource(key: keyof ContainerResourceLimits, value: number) { setForm((current) => ({ ...current, resources: { ...current.resources, [key]: value } })); setMessage('') }

  async function save() {
    setError(''); setMessage(''); setBusy(true)
    try {
      const config = JSON.parse(configText) as unknown
      if (!config || Array.isArray(config) || typeof config !== 'object') throw new Error('Конфигурация должна быть объектом JSON.')
      const input = { ...form, config: config as Record<string, unknown> }
      const saved = selected ? await api.profiles.update(selected, input) : await api.profiles.create(input)
      setSelectedId(saved.id)
      setMessage(selected ? 'Профиль обновлён.' : 'Профиль создан.')
      await onChanged()
    } catch (requestError) { setError(requestError instanceof SyntaxError || requestError instanceof Error && requestError.message === 'Конфигурация должна быть объектом JSON.' ? requestError.message : apiErrorMessage(requestError)) }
    finally { setBusy(false) }
  }

  async function remove() {
    if (!selected || !window.confirm(`Удалить профиль ${selected.name}?`)) return
    setBusy(true); setError('')
    try { await api.profiles.delete(selected.id); createNew(); await onChanged(); setMessage('Профиль удалён.') }
    catch (requestError) { setError(apiErrorMessage(requestError)) }
    finally { setBusy(false) }
  }

  return <section className="space-y-6 p-6">
    <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end"><div><p className="text-xs font-semibold uppercase tracking-[0.25em] text-orange-400/70">Конфигурация / API</p><h2 className="mt-2 text-2xl font-semibold tracking-tight">Профили взаимодействия</h2><p className="mt-2 max-w-xl text-sm leading-6 text-white/45">Шаблоны ловушек нижнего и среднего уровня.</p></div>{isAdmin && <button type="button" onClick={createNew} className="rounded-lg border border-orange-400/30 bg-orange-500/10 px-4 py-3 text-sm text-orange-200">+ Создать профиль</button>}</div>
    {!isAdmin && <div className="rounded-lg border border-white/10 bg-white/5 p-4 text-sm text-white/55">Ваша роль допускает просмотр. Создавать, изменять и удалять профили может только администратор.</div>}
    <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-[0.85fr_1.5fr]">
      <section className="rounded-xl border border-white/10 bg-[#160e0c]/75 p-4 backdrop-blur-xl"><div className="mb-4 flex justify-between"><h3 className="font-semibold">Список профилей</h3><span className="text-xs text-white/40">{profiles.length} шт.</span></div><div className="space-y-2">{profiles.map((profile) => <button key={profile.id} type="button" onClick={() => select(profile)} className={`w-full rounded-lg border p-4 text-left ${selectedId === profile.id ? 'border-orange-400/40 bg-orange-500/[0.08]' : 'border-white/[0.07] bg-black/10'}`}><div className="flex justify-between gap-3"><span className="truncate text-sm font-medium">{profileNameLabel(profile.name, profile.level)}</span><span className={`rounded-full border px-2 py-1 text-[9px] ${profile.level === 'medium' ? 'border-orange-500/30 text-orange-300' : 'border-emerald-500/30 text-emerald-300'}`}>{statusLabel(profile.level)}</span></div><p className="mt-2 text-xs text-white/40">{statusLabel(profile.level)} · {profile.service_type.toUpperCase()}</p></button>)}</div>{profiles.length === 0 && <p className="py-8 text-center text-sm text-white/40">Профилей пока нет.</p>}</section>
      <section className="rounded-xl border border-white/10 bg-[#160e0c]/75 p-5 backdrop-blur-xl"><div className="border-b border-white/10 pb-5"><p className="text-[10px] uppercase tracking-[0.2em] text-orange-300/70">{selected ? `Редактирование версии ${selected.version}` : 'Новый профиль'}</p><h3 className="mt-2 text-lg font-semibold">{form.name || 'Профиль без названия'}</h3></div><div className="mt-5 space-y-5">
        <label className="block text-xs text-white/55">Название профиля<input disabled={!isAdmin} value={form.name} onChange={(e) => update('name', e.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-black/20 px-3 py-3 text-sm outline-none" /></label>
        <label className="block text-xs text-white/55">Описание<textarea disabled={!isAdmin} rows={3} value={form.description} onChange={(e) => update('description', e.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-black/20 px-3 py-3 text-sm outline-none" /></label>
        <div className="grid gap-4 sm:grid-cols-2"><label className="text-xs text-white/55">Уровень взаимодействия<select disabled={!isAdmin} value={form.level} onChange={(e) => { const level = e.target.value as ProfileInput['level']; setForm((current) => ({ ...current, level, honeypot_type: typeForLevel[level], resources: defaultLimits[level] })); setMessage('') }} className="mt-2 w-full rounded-lg border border-white/10 bg-[#100a09] px-3 py-3 text-sm"><option value="low">Нижний</option><option value="medium">Средний</option></select></label><label className="text-xs text-white/55">Служба<input disabled={!isAdmin} value={form.service_type} onChange={(e) => update('service_type', e.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-black/20 px-3 py-3 text-sm" /></label></div>
        <section className="rounded-lg border border-white/10 bg-black/10 p-4"><h4 className="text-xs font-semibold uppercase tracking-wider text-white/45">Ресурсы по умолчанию</h4><p className="mt-1 text-[11px] text-white/35">Это исходный бюджет профиля. Для каждой ловушки его можно переопределить в допустимых пределах.</p><div className="mt-3 grid gap-3 sm:grid-cols-3"><ResourceInput label="CPU (ядра)" value={form.resources.cpu_cores} min={0.05} max={form.level === 'low' ? 0.5 : 1} step={0.05} disabled={!isAdmin} onChange={(value) => updateResource('cpu_cores', value)}/><ResourceInput label="RAM (МБ)" value={form.resources.memory_mb} min={32} max={form.level === 'low' ? 128 : 512} step={16} disabled={!isAdmin} onChange={(value) => updateResource('memory_mb', value)}/><ResourceInput label="Процессы" value={form.resources.pids} min={16} max={form.level === 'low' ? 64 : 256} step={1} disabled={!isAdmin} onChange={(value) => updateResource('pids', value)}/></div></section>
        <label className="block text-xs text-white/55">Конфигурация JSON<textarea disabled={!isAdmin} rows={8} value={configText} onChange={(e) => { setConfigText(e.target.value); setMessage('') }} className="mt-2 w-full rounded-lg border border-white/10 bg-black/30 px-3 py-3 font-mono text-xs outline-none" /></label>
        {error && <p role="alert" className="text-sm text-red-400">{error}</p>}{message && <p role="status" className="text-sm text-emerald-300">{message}</p>}
        {isAdmin && <div className="flex gap-3"><button type="button" disabled={busy} onClick={save} className="rounded-lg bg-orange-500 px-5 py-3 text-sm font-semibold text-[#1a0d08] disabled:opacity-50">{selected ? 'Сохранить изменения' : 'Создать профиль'}</button>{selected && <button type="button" disabled={busy} onClick={remove} className="rounded-lg border border-red-500/30 px-5 py-3 text-sm text-red-300">Удалить</button>}</div>}
      </div></section>
    </div>
  </section>
}

function ResourceInput({ label, value, min, max, step, disabled, onChange }: { label: string; value: number; min: number; max: number; step: number; disabled: boolean; onChange: (value: number) => void }) {
  return <label className="text-xs text-white/55">{label}<input type="number" min={min} max={max} step={step} required disabled={disabled} value={value} onChange={(event) => onChange(Number(event.target.value))} className="mt-2 w-full rounded-lg border border-white/10 bg-black/20 px-3 py-3 text-sm"/><span className="mt-1 block text-[10px] text-white/30">Максимум для {label.startsWith('CPU') ? 'уровня' : 'профиля'}: {max}</span></label>
}
