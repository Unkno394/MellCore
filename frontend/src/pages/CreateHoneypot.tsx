import { statusLabel } from '../i18n/labels'
import { useEffect, useMemo, useState, type FormEvent } from 'react'
import FuzzyText from '../components/FuzzyText'
import { apiErrorMessage } from '../api/client'
import type { MellCoreApi } from '../api/services'
import type { ContainerResourceLimits, Profile, Server } from '../api/types'

type Props = { api: MellCoreApi; profiles: Profile[]; servers: Server[]; readOnly: boolean; onCreated: () => Promise<void> }

export default function CreateHoneypot({ api, profiles, servers, readOnly, onCreated }: Props) {
  const availableServers = useMemo(() => servers.filter((server) => server.status === 'online'), [servers])
  const supported = useMemo(() => profiles.filter((profile) => profile.level === 'low' || profile.level === 'medium'), [profiles])
  const [name, setName] = useState('')
  const [serverId, setServerId] = useState('')
  const [profileId, setProfileId] = useState('')
  const [hostPort, setHostPort] = useState<number | null>(null)
  const [portError, setPortError] = useState('')
  const [resources, setResources] = useState<ContainerResourceLimits>({ cpu_cores: 0.5, memory_mb: 128, pids: 64 })
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const profile = supported.find((item) => item.id === profileId)

  useEffect(() => {
    if (!serverId) { setHostPort(null); setPortError(''); return }
    let active = true
    setHostPort(null); setPortError('')
    void api.servers.ports(serverId).then((reservations) => {
      if (!active) return
      const occupied = new Set(reservations.filter((item) => item.transport === 'tcp').map((item) => item.host_port))
      const free = Array.from({ length: 100 }, (_, index) => 30000 + index).find((port) => !occupied.has(port))
      if (free) setHostPort(free)
      else setPortError('Свободный публичный TCP-порт не найден.')
    }).catch((reason: unknown) => { if (active) setPortError(apiErrorMessage(reason)) })
    return () => { active = false }
  }, [api, serverId])

  const updateResource = (key: keyof ContainerResourceLimits, value: number) => setResources((current) => ({ ...current, [key]: value }))

  async function submit(event: FormEvent) {
    event.preventDefault(); setError(''); setMessage('')
    if (!serverId || !availableServers.some((server) => server.server_id === serverId) || !profile) return setError('Выберите подключённый сервер и поддерживаемый профиль.')
    setBusy(true)
    try {
      if (!hostPort) return setError('Не удалось выбрать свободный порт для ловушки.')
      await api.traps.create(serverId, { name, profile_id: profile.id, config: {}, resources, desired_state: 'stopped', ports: [{ transport: 'tcp', host_port: hostPort, target_port: 2222, route_mode: 'direct' }] })
      setMessage('Конфигурация ловушки создана.')
      setName('')
      await onCreated()
    } catch (requestError) { setError(apiErrorMessage(requestError)) }
    finally { setBusy(false) }
  }

  return <section className="space-y-6 p-6"><div className="mx-auto max-w-4xl"><div className="mb-6 text-center"><p className="text-sm text-white/45">КОНФИГУРАЦИЯ</p><div className="mt-3 flex justify-center"><FuzzyText fontSize={28} fontWeight={600} color="#f1a36b" baseIntensity={0.2} hoverIntensity={0.5} fuzzRange={8} fps={30} enableHover className="block">Добавить ловушку</FuzzyText></div><p className="mt-3 text-sm text-white/45">Задайте имя, сервер, профиль и публичный порт SSH.</p></div>
    <form onSubmit={submit} className="w-full space-y-6 rounded-xl border border-white/10 bg-[#160e0c]/80 p-6 backdrop-blur-xl">
      <label className="block text-sm text-white/70">Название ловушки<input required disabled={readOnly} value={name} onChange={(e) => setName(e.target.value)} placeholder="Например, SSH-ловушка 01" className="mt-2 w-full rounded-lg border border-white/10 bg-black/20 px-4 py-3 outline-none focus:border-orange-500/50" /></label>
      <div className="grid gap-4 sm:grid-cols-2"><label className="text-sm text-white/70">Сервер<select required disabled={readOnly || busy || availableServers.length === 0} value={serverId} onChange={(e) => setServerId(e.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-[#100a09] px-4 py-3"><option value="">{availableServers.length ? 'Выберите подключённый сервер' : 'Нет подключённых серверов'}</option>{availableServers.map((server) => <option key={server.server_id} value={server.server_id}>{server.name} — {server.host}</option>)}</select>{availableServers.length === 0 && <span className="mt-1 block text-xs text-white/40">Сервер появится здесь после успешного подключения агента.</span>}</label><label className="text-sm text-white/70">Профиль<select required disabled={readOnly || busy} value={profileId} onChange={(e) => { const next = supported.find((item) => item.id === e.target.value); setProfileId(e.target.value); if (next) setResources(next.resources) }} className="mt-2 w-full rounded-lg border border-white/10 bg-[#100a09] px-4 py-3"><option value="">Выберите профиль низкого или среднего уровня</option>{supported.map((item) => <option key={item.id} value={item.id}>{item.name} ({statusLabel(item.level)})</option>)}</select></label></div>
      {profile && <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">{[['Уровень', statusLabel(profile.level)], ['Тип', profile.honeypot_type], ['Служба', profile.service_type], ['По умолчанию', `${profile.resources.cpu_cores} CPU · ${profile.resources.memory_mb} МБ · ${profile.resources.pids} PID`]].map(([label, value]) => <div key={label} className="rounded-lg border border-white/10 bg-black/20 p-3"><p className="text-[10px] uppercase text-white/35">{label}</p><p className="mt-1 text-sm capitalize">{value}</p></div>)}</div>}
      {profile && <section className="rounded-xl border border-white/10 bg-black/10 p-4"><div><h3 className="text-sm font-medium text-white/80">Лимиты этого контейнера</h3><p className="mt-1 text-xs text-white/40">Не выше ограничений уровня ловушки: Low — 0,5 CPU / 128 МБ / 64 процесса; Middle — 1 CPU / 512 МБ / 256 процессов.</p></div><div className="mt-4 grid gap-3 sm:grid-cols-3"><ResourceInput label="CPU (ядра)" value={resources.cpu_cores} min={0.05} max={profile.level === 'low' ? 0.5 : 1} step={0.05} disabled={readOnly || busy} onChange={(value) => updateResource('cpu_cores', value)}/><ResourceInput label="RAM (МБ)" value={resources.memory_mb} min={32} max={profile.level === 'low' ? 128 : 512} step={16} disabled={readOnly || busy} onChange={(value) => updateResource('memory_mb', value)}/><ResourceInput label="Процессы" value={resources.pids} min={16} max={profile.level === 'low' ? 64 : 256} step={1} disabled={readOnly || busy} onChange={(value) => updateResource('pids', value)}/></div></section>}
      <div className="rounded-lg border border-white/10 bg-black/15 p-4"><p className="text-xs uppercase tracking-wider text-white/40">Публичный адрес доступа</p><p className="mt-2 font-mono text-lg text-orange-100/85">{availableServers.find((server) => server.server_id === serverId)?.host ?? 'Выберите сервер'}:{hostPort ?? '…'}</p><p className="mt-1 text-xs text-white/40">TCP · свободный порт назначается автоматически; внутри контейнера SSH слушает 2222.</p>{portError && <p role="alert" className="mt-2 text-xs text-red-300">Не удалось проверить порты: {portError}</p>}</div>
      {error && <p role="alert" className="text-sm text-red-400">{error}</p>}{message && <p role="status" className="text-sm text-emerald-300">{message}</p>}
      {!readOnly && <button disabled={busy || !availableServers.length || !supported.length || !hostPort || Boolean(portError)} className="rounded-lg border border-orange-500/30 bg-orange-500/10 px-5 py-3 text-sm font-medium text-[#f1a36b] disabled:opacity-40">{busy ? 'Сохранение…' : 'Создать ловушку'}</button>}
    </form></div></section>
}

function ResourceInput({ label, value, min, max, step, disabled, onChange }: { label: string; value: number; min: number; max: number; step: number; disabled: boolean; onChange: (value: number) => void }) {
  return <label className="text-xs text-white/55">{label}<input type="number" min={min} max={max} step={step} required disabled={disabled} value={value} onChange={(event) => onChange(Number(event.target.value))} className="mt-2 w-full rounded-lg border border-white/10 bg-black/20 px-3 py-3 text-sm"/></label>
}
