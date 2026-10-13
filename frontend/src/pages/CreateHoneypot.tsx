import { profileNameLabel, statusLabel } from '../i18n/labels'
import { useEffect, useMemo, useState, type FormEvent } from 'react'
import FuzzyText from '../components/FuzzyText'
import { ApiError, apiErrorMessage } from '../api/client'
import type { MellCoreApi } from '../api/services'
import type { ContainerResourceLimits, Profile, Server, Trap, TrapActionProgress } from '../api/types'

type Props = { api: MellCoreApi; profiles: Profile[]; servers: Server[]; traps: Trap[]; readOnly: boolean; onCreated: () => Promise<void> }

export default function CreateHoneypot({ api, profiles, servers, traps, readOnly, onCreated }: Props) {
  const availableServers = useMemo(() => servers.filter((server) => server.status === 'online'), [servers])
  const supported = useMemo(() => profiles.filter((profile) => profile.level === 'low' || profile.level === 'medium'), [profiles])
  const [name, setName] = useState('')
  const [serverId, setServerId] = useState('')
  const [profileId, setProfileId] = useState('')
  const [hostPort, setHostPort] = useState<number | null>(null)
  const [sharedPort, setSharedPort] = useState<number | null>(null)
  const [newWeight, setNewWeight] = useState(50)
  const [portError, setPortError] = useState('')
  const [resources, setResources] = useState<ContainerResourceLimits>({ cpu_cores: 0.5, memory_mb: 128, pids: 64 })
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const profile = supported.find((item) => item.id === profileId)
  const selectedServer = availableServers.find((server) => server.server_id === serverId)
  const shareablePorts = useMemo(() => {
    const candidates = traps.filter((trap) => trap.server_id === serverId && trap.actual_state === 'running'
      && (trap.profile_snapshot.honeypot_type === 'kozyavka' || trap.profile_snapshot.honeypot_type === 'pritvoryashka')
      && trap.ports.length === 1)
    const ports = new Set(candidates.flatMap((trap) => trap.ports
      .filter((port) => port.transport === 'tcp' && (selectedServer?.dispatcher_port == null || port.host_port === selectedServer.dispatcher_port))
      .map((port) => port.host_port)))
    return [...ports].filter((port) => !traps.some((trap) => trap.server_id === serverId && trap.actual_state !== 'running'
      && trap.ports.some((binding) => binding.host_port === port && binding.route_mode === 'dispatcher_backend'))).sort((a, b) => a - b)
  }, [traps, serverId, selectedServer])
  const sharedMemberCount = sharedPort === null ? 0 : traps.filter((trap) => trap.server_id === serverId && trap.actual_state === 'running'
    && trap.ports.some((port) => port.transport === 'tcp' && port.host_port === sharedPort)).length
  const maxNewWeight = 100 - sharedMemberCount

  async function awaitAction(trapId: string, queued: TrapActionProgress): Promise<void> {
    let progress = queued
    const deadline = Date.now() + 120_000
    while (progress.status === 'queued' && Date.now() < deadline) {
      await new Promise<void>((resolve) => window.setTimeout(resolve, 2000))
      progress = await api.traps.actionStatus(trapId, queued.action_id)
    }
    if (progress.status === 'failed') throw new Error(progress.detail || 'Агент не смог выполнить команду.')
    if (progress.status === 'queued') throw new Error('Команда ещё выполняется. Проверьте состояние на странице «Ловушки».')
  }

  function groupWeights(existing: Trap[], freshId: string) {
    const remaining = 100 - newWeight
    if (newWeight < 1 || remaining < existing.length) throw new Error('Сумма весов должна быть 100%, каждому участнику нужен минимум 1%.')
    const shares = existing.map((trap) => trap.ports.find((port) => port.host_port === sharedPort)?.weight || 1)
    const total = shares.reduce((sum, weight) => sum + weight, 0)
    const weights = shares.map((weight) => Math.max(1, Math.floor(remaining * weight / total)))
    let difference = remaining - weights.reduce((sum, weight) => sum + weight, 0)
    for (let index = 0; difference > 0; index = (index + 1) % weights.length) { weights[index] += 1; difference -= 1 }
    for (let index = weights.length - 1; difference < 0; index = (index - 1 + weights.length) % weights.length) {
      if (weights[index] > 1) { weights[index] -= 1; difference += 1 }
    }
    return [...existing.map((trap, index) => ({ trap_id: trap.trap_id, weight: weights[index] })), { trap_id: freshId, weight: newWeight }]
  }

  function nextFreePort(reservations: Awaited<ReturnType<MellCoreApi['servers']['ports']>>, excluded: number[] = []) {
    const occupied = new Set([...reservations.filter((item) => item.transport === 'tcp').map((item) => item.host_port), ...excluded])
    return Array.from({ length: 100 }, (_, index) => 30000 + index).find((port) => !occupied.has(port)) ?? null
  }

  useEffect(() => {
    if (!serverId) { setHostPort(null); setSharedPort(null); setPortError(''); return }
    let active = true
    setHostPort(null); setSharedPort(null); setPortError('')
    void api.servers.ports(serverId).then((reservations) => {
      if (!active) return
      const free = nextFreePort(reservations)
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
    let createdTrapId: string | null = null
    try {
      if (!hostPort) return setError('Не удалось выбрать свободный порт для ловушки.')
      const freshReservations = await api.servers.ports(serverId)
      const freshPort = nextFreePort(freshReservations)
      if (!freshPort) return setError('Свободный публичный TCP-порт не найден.')
      setHostPort(freshPort)
      const input = { name, profile_id: profile.id, config: {}, resources, desired_state: 'stopped' as const, ports: [{ transport: 'tcp' as const, host_port: freshPort, target_port: 2222, route_mode: 'direct' as const }] }
      try {
        const created = await api.traps.create(serverId, input)
        createdTrapId = created.trap_id
      } catch (createError) {
        if (!(createError instanceof ApiError) || createError.status !== 409 || createError.message !== 'Public port is already reserved on this server') throw createError
        const refreshed = await api.servers.ports(serverId)
        const retryPort = nextFreePort(refreshed, [freshPort])
        if (!retryPort) throw createError
        setHostPort(retryPort)
        const created = await api.traps.create(serverId, { ...input, ports: [{ ...input.ports[0], host_port: retryPort }] })
        createdTrapId = created.trap_id
      }
      if (!createdTrapId) throw new Error('Не удалось определить созданную ловушку.')
      setMessage('Ловушка создана. Ожидаю запуска на сервере…')
      const queued = await api.traps.action(createdTrapId, 'start')
      await awaitAction(createdTrapId, queued)
      if (sharedPort !== null) {
        const existing = traps.filter((trap) => trap.server_id === serverId && trap.actual_state === 'running'
          && trap.ports.some((port) => port.host_port === sharedPort && port.transport === 'tcp'))
        if (!existing.length) throw new Error('На выбранном общем порту больше нет работающих ловушек.')
        setMessage('Перевожу ловушки на общий порт…')
        await awaitAction(createdTrapId, await api.traps.sharePort(createdTrapId, sharedPort, groupWeights(existing, createdTrapId)))
      }
      setMessage(sharedPort === null ? 'Ловушка запущена на сервере.' : `Ловушки доступны через общий порт ${sharedPort}.`)
      setName('')
      await onCreated().catch(() => undefined)
    } catch (requestError) {
      setMessage('')
      const detail = requestError instanceof ApiError ? apiErrorMessage(requestError) : requestError instanceof Error ? requestError.message : 'Неожиданная ошибка приложения.'
      setError(createdTrapId ? `Ловушка создана на временном порту, но общий порт или запуск не подтверждён: ${detail} Откройте «Ловушки» и проверьте её состояние.` : detail)
      if (createdTrapId) await onCreated().catch(() => undefined)
    }
    finally { setBusy(false) }
  }

  return <section className="space-y-6 p-6"><div className="mx-auto max-w-4xl"><div className="mb-6 text-center"><p className="text-sm text-white/45">КОНФИГУРАЦИЯ</p><div className="mt-3 flex justify-center"><FuzzyText fontSize={28} fontWeight={600} color="#f1a36b" baseIntensity={0.2} hoverIntensity={0.5} fuzzRange={8} fps={30} enableHover className="block">Добавить ловушку</FuzzyText></div><p className="mt-3 text-sm text-white/45">Задайте имя, сервер, профиль и публичный порт SSH.</p></div>
    <form onSubmit={submit} className="w-full space-y-6 rounded-xl border border-white/10 bg-[#160e0c]/80 p-6 backdrop-blur-xl">
      <label className="block text-sm text-white/70">Название ловушки<input required disabled={readOnly} value={name} onChange={(e) => setName(e.target.value)} placeholder="Например, SSH-ловушка 01" className="mt-2 w-full rounded-lg border border-white/10 bg-black/20 px-4 py-3 outline-none focus:border-orange-500/50" /></label>
      <div className="grid gap-4 sm:grid-cols-2"><label className="text-sm text-white/70">Сервер<select required disabled={readOnly || busy || availableServers.length === 0} value={serverId} onChange={(e) => setServerId(e.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-[#100a09] px-4 py-3"><option value="">{availableServers.length ? 'Выберите подключённый сервер' : 'Нет подключённых серверов'}</option>{availableServers.map((server) => <option key={server.server_id} value={server.server_id}>{server.name} — {server.host}</option>)}</select>{availableServers.length === 0 && <span className="mt-1 block text-xs text-white/40">Сервер появится здесь после успешного подключения агента.</span>}</label><label className="text-sm text-white/70">Профиль<select required disabled={readOnly || busy} value={profileId} onChange={(e) => { const next = supported.find((item) => item.id === e.target.value); setProfileId(e.target.value); if (next) setResources(next.resources) }} className="mt-2 w-full rounded-lg border border-white/10 bg-[#100a09] px-4 py-3"><option value="">Выберите профиль нижнего или среднего уровня</option>{supported.map((item) => <option key={item.id} value={item.id}>{profileNameLabel(item.name, item.level)}</option>)}</select></label></div>
      {profile && <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">{[['Уровень', statusLabel(profile.level)], ['Служба', profile.service_type.toUpperCase()], ['По умолчанию', `${profile.resources.cpu_cores} CPU · ${profile.resources.memory_mb} МБ · ${profile.resources.pids} PID`]].map(([label, value]) => <div key={label} className="rounded-lg border border-white/10 bg-black/20 p-3"><p className="text-[10px] uppercase text-white/35">{label}</p><p className="mt-1 text-sm capitalize">{value}</p></div>)}</div>}
      {profile && <section className="rounded-xl border border-white/10 bg-black/10 p-4"><div><h3 className="text-sm font-medium text-white/80">Лимиты этого контейнера</h3><p className="mt-1 text-xs text-white/40">Не выше ограничений уровня ловушки: Нижний — 0,5 CPU / 128 МБ / 64 процесса; Средний — 1 CPU / 512 МБ / 256 процессов.</p></div><div className="mt-4 grid gap-3 sm:grid-cols-3"><ResourceInput label="CPU (ядра)" value={resources.cpu_cores} min={0.05} max={profile.level === 'low' ? 0.5 : 1} step={0.05} disabled={readOnly || busy} onChange={(value) => updateResource('cpu_cores', value)}/><ResourceInput label="RAM (МБ)" value={resources.memory_mb} min={32} max={profile.level === 'low' ? 128 : 512} step={16} disabled={readOnly || busy} onChange={(value) => updateResource('memory_mb', value)}/><ResourceInput label="Процессы" value={resources.pids} min={16} max={profile.level === 'low' ? 64 : 256} step={1} disabled={readOnly || busy} onChange={(value) => updateResource('pids', value)}/></div></section>}
      <div className="rounded-lg border border-white/10 bg-black/15 p-4"><p className="text-xs uppercase tracking-wider text-white/40">Публичный адрес доступа</p>
        <label className="mt-3 block text-sm text-white/70">Режим порта<select disabled={readOnly || busy || !serverId} value={sharedPort === null ? 'direct' : String(sharedPort)} onChange={(event) => setSharedPort(event.target.value === 'direct' ? null : Number(event.target.value))} className="mt-2 w-full rounded-lg border border-white/10 bg-[#100a09] px-4 py-3"><option value="direct">Отдельный порт</option>{shareablePorts.map((port) => <option key={port} value={port}>Общий порт {port} через Dispatcher</option>)}</select></label>
        {sharedPort !== null && <label className="mt-3 block max-w-xs text-sm text-white/70">Доля новой ловушки, %<input type="number" min={1} max={maxNewWeight} step={1} disabled={readOnly || busy} value={newWeight} onChange={(event) => setNewWeight(Number(event.target.value))} className="mt-2 w-full rounded-lg border border-white/10 bg-black/20 px-4 py-3 outline-none focus:border-orange-500/50"/></label>}
        <p className="mt-3 font-mono text-lg text-orange-100/85">{selectedServer?.host ?? 'Выберите сервер'}:{sharedPort ?? hostPort ?? '…'}</p><p className="mt-1 text-xs text-white/40">{sharedPort === null ? 'Для отдельной ловушки порт назначается автоматически.' : `Новая ловушка получит ${newWeight}% подключений. Остальные ${100 - newWeight}% делятся между существующими ловушками; один IP попадает в одну и ту же ловушку.`}</p>{portError && <p role="alert" className="mt-2 text-xs text-red-300">Не удалось проверить порты: {portError}</p>}</div>
      {error && <p role="alert" className="text-sm text-red-400">{error}</p>}{message && <p role="status" className="text-sm text-emerald-300">{message}</p>}
      {!readOnly && <button disabled={busy || !availableServers.length || !supported.length || !hostPort || Boolean(portError) || (sharedPort !== null && (newWeight < 1 || newWeight > maxNewWeight || !Number.isInteger(newWeight)))} className="rounded-lg border border-orange-500/30 bg-orange-500/10 px-5 py-3 text-sm font-medium text-[#f1a36b] disabled:opacity-40">{busy ? 'Устанавливаю ловушку…' : 'Создать ловушку'}</button>}
    </form></div></section>
}

function ResourceInput({ label, value, min, max, step, disabled, onChange }: { label: string; value: number; min: number; max: number; step: number; disabled: boolean; onChange: (value: number) => void }) {
  return <label className="text-xs text-white/55">{label}<input type="number" min={min} max={max} step={step} required disabled={disabled} value={value} onChange={(event) => onChange(Number(event.target.value))} className="mt-2 w-full rounded-lg border border-white/10 bg-black/20 px-3 py-3 text-sm"/></label>
}
