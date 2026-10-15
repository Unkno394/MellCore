import { profileNameLabel } from '../i18n/labels'
import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react'
import FuzzyText from '../components/FuzzyText'
import SshAuthSettings, { chooseDefaultSshCredentials, validateSshCredentials, withFixedSshUsername } from '../components/SshAuthSettings'
import type { ToastNotify } from '../components/ToastNotifications'
import { ApiError, apiErrorMessage } from '../api/client'
import type { MellCoreApi } from '../api/services'
import type { ContainerResourceLimits, MiddleSshAuthMode, Profile, Server, SshCredential, Trap, TrapActionProgress, TrapLevel } from '../api/types'

type Props = { api: MellCoreApi; profiles: Profile[]; servers: Server[]; traps: Trap[]; readOnly: boolean; onCreated: () => Promise<void>; notify: ToastNotify; dismissToast: (id: number) => void }

class ConfirmedTrapActionFailure extends Error {}

export default function CreateHoneypot({ api, profiles, servers, traps, readOnly, onCreated, notify, dismissToast }: Props) {
  const availableServers = servers
  const supported = useMemo(() => {
    const levelOrder: Record<string, number> = { low: 0, medium: 1, high: 2 }
    return profiles
      .filter((profile) => profile.level in levelOrder)
      .sort((a, b) => levelOrder[a.level] - levelOrder[b.level]
        || profileNameLabel(a.name, a.level).localeCompare(profileNameLabel(b.name, b.level), 'ru'))
  }, [profiles])
  const highVmProfiles = supported.filter((item) => item.level === 'high' && item.honeypot_type === 'high_vm'
    && ['ubuntu_ssh', 'debian_ssh', 'arch_linux_ssh', 'windows_rdp'].includes(String(item.config.os_profile)))
  const highOsChoices = [
    { value: 'ubuntu_ssh', label: 'Ubuntu Server 24.04' },
    { value: 'debian_ssh', label: 'Debian 12' },
    { value: 'arch_linux_ssh', label: 'Arch Linux' },
    { value: 'windows_rdp', label: 'Windows Server 2022' },
  ].filter((choice) => highVmProfiles.some((item) => item.config.os_profile === choice.value))
  const [name, setName] = useState('')
  const [middleHostname, setMiddleHostname] = useState('srv-app-01')
  const [middleDistribution, setMiddleDistribution] = useState<'ubuntu' | 'debian' | 'arch' | 'windows'>('ubuntu')
  const [middleUsername, setMiddleUsername] = useState('admin')
  const [middleSshAuthMode, setMiddleSshAuthMode] = useState<MiddleSshAuthMode>('realistic')
  const [middleSshCredentials, setMiddleSshCredentials] = useState<SshCredential[]>(chooseDefaultSshCredentials)
  const [lowAuthMode, setLowAuthMode] = useState<'capture_credentials' | 'configured' | 'any_password' | 'passwordless'>('capture_credentials')
  const [lowUsername, setLowUsername] = useState('admin')
  const [lowPassword, setLowPassword] = useState('admin123')
  const [serverId, setServerId] = useState('')
  const [selectedLevel, setSelectedLevel] = useState<TrapLevel | ''>('')
  const [highOsProfile, setHighOsProfile] = useState('ubuntu_ssh')
  const [highRuntimeMode, setHighRuntimeMode] = useState<'public_kvm' | 'private_tcg_test'>('public_kvm')
  const [hostPort, setHostPort] = useState<number | null>(null)
  const manualPort = useRef(false)
  const [sharedPort, setSharedPort] = useState<number | null>(null)
  const [newWeight, setNewWeight] = useState(50)
  const [portError, setPortError] = useState('')
  const [resources, setResources] = useState<ContainerResourceLimits>({ cpu_cores: 0.5, memory_mb: 128, pids: 64 })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const legacyHighProfile = supported.find((item) => item.level === 'high' && item.honeypot_type === 'high_ubuntu_ssh')
  const profile = selectedLevel === 'high'
    ? highVmProfiles.find((item) => item.config.os_profile === highOsProfile) ?? highVmProfiles[0] ?? legacyHighProfile
    : supported.find((item) => item.level === selectedLevel
      && item.honeypot_type === (selectedLevel === 'low' ? 'kozyavka' : 'pritvoryashka'))
  const selectedServer = availableServers.find((server) => server.server_id === serverId)
  const privateTcgTest = profile?.honeypot_type === 'high_vm' && highRuntimeMode === 'private_tcg_test'
  const isHigh = profile?.level === 'high'
  const windowsHigh = profile?.honeypot_type === 'high_vm' && profile.config.os_profile === 'windows_rdp'
  const highServiceLabel = profile?.service_type === 'rdp' ? 'RDP' : 'SSH'
  const shareablePorts = useMemo(() => {
    if (profile?.level === 'high' || profile?.service_type !== 'ssh') return []
    const candidates = traps.filter((trap) => trap.server_id === serverId && trap.actual_state === 'running'
      && trap.profile_snapshot.service_type === 'ssh'
      && (trap.profile_snapshot.honeypot_type === 'kozyavka' || trap.profile_snapshot.honeypot_type === 'pritvoryashka')
      && trap.ports.some((port) => port.transport === 'tcp' && (port.target_port === 2222 || port.route_mode === 'dispatcher_backend')))
    const ports = new Set(candidates.flatMap((trap) => trap.ports
      .filter((port) => port.transport === 'tcp' && (port.target_port === 2222 || port.route_mode === 'dispatcher_backend'))
      .filter((port) => selectedServer?.dispatcher_port == null || port.host_port === selectedServer.dispatcher_port)
      .map((port) => port.host_port)))
    return [...ports].filter((port) => !traps.some((trap) => trap.server_id === serverId && trap.actual_state !== 'running'
      && trap.ports.some((binding) => binding.host_port === port && binding.route_mode === 'dispatcher_backend'))).sort((a, b) => a - b)
  }, [traps, serverId, selectedServer, profile])
  const sharedMemberCount = sharedPort === null ? 0 : traps.filter((trap) => trap.server_id === serverId && trap.actual_state === 'running'
    && trap.ports.some((port) => port.transport === 'tcp' && port.host_port === sharedPort)).length
  const maxNewWeight = 100 - sharedMemberCount

  async function awaitAction(trapId: string, queued: TrapActionProgress, phase: 'start' | 'share'): Promise<void> {
    let progress = queued
    const waitSeconds = phase === 'start' && profile?.level === 'high' ? 1200 : 120
    const deadline = Date.now() + waitSeconds * 1000
    while (progress.status === 'queued' && Date.now() < deadline) {
      await new Promise<void>((resolve) => window.setTimeout(resolve, 2000))
      progress = await api.traps.actionStatus(trapId, queued.action_id)
    }
    if (progress.status === 'failed') throw new ConfirmedTrapActionFailure(progress.detail || 'Агент не смог выполнить команду.')
    if (progress.status === 'queued') throw new Error(phase === 'start'
      ? `Агент не подтвердил запуск за ${waitSeconds === 1200 ? '20 минут' : '120 секунд'} (операция ${queued.action_id}). Настройка общего порта ещё не отправлялась.`
      : `Агент не подтвердил настройку общего порта за 120 секунд (операция ${queued.action_id}).`)
  }

  function groupWeights(existing: Trap[], freshId: string, listenerPort: number) {
    const remaining = 100 - newWeight
    if (newWeight < 1 || remaining < existing.length) throw new Error('Сумма весов должна быть 100%, каждому участнику нужен минимум 1%.')
    const shares = existing.map((trap) => trap.ports.find((port) => port.host_port === listenerPort)?.weight || 1)
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
    manualPort.current = false
    if (!serverId) { setHostPort(null); setSharedPort(null); setPortError(''); return }
    if (privateTcgTest) {
      setHostPort(null); setSharedPort(null); setPortError('')
      return
    }
    let active = true
    setHostPort(null); setSharedPort(null); setPortError('')
    void api.servers.ports(serverId).then((reservations) => {
      if (!active) return
      const free = nextFreePort(reservations)
      if (!manualPort.current) {
        if (free) setHostPort(free)
        else setPortError('Свободный публичный TCP-порт не найден.')
      }
    }).catch((reason: unknown) => { if (active && !manualPort.current) setPortError(apiErrorMessage(reason)) })
    return () => { active = false }
  }, [api, serverId, profile?.level, privateTcgTest])

  const updateResource = (key: keyof ContainerResourceLimits, value: number) => setResources((current) => ({ ...current, [key]: value }))

  function selectLevel(level: TrapLevel | '') {
    setSelectedLevel(level)
    setSharedPort(null)
    if (!level) return
    let next: Profile | undefined
    if (level === 'high') {
      next = highVmProfiles.find((item) => item.config.os_profile === highOsProfile)
        ?? highVmProfiles.find((item) => item.config.os_profile === 'ubuntu_ssh')
        ?? highVmProfiles[0]
        ?? legacyHighProfile
      if (next?.honeypot_type === 'high_vm') setHighOsProfile(String(next.config.os_profile))
    } else {
      next = supported.find((item) => item.level === level
        && item.honeypot_type === (level === 'low' ? 'kozyavka' : 'pritvoryashka'))
    }
    if (next) setResources(next.resources)
  }

  async function submit(event: FormEvent) {
    event.preventDefault(); setError('')
    if (!serverId || !availableServers.some((server) => server.server_id === serverId) || !profile) return setError('Выберите подключённый сервер и поддерживаемый профиль.')
    if (profile.honeypot_type === 'pritvoryashka' && middleUsername.trim() === 'root') return setError('Для Middle выберите обычного пользователя; root нельзя использовать как имя SSH-пользователя.')
    if (profile.honeypot_type === 'pritvoryashka' && middleSshAuthMode === 'realistic') {
      const credentialError = validateSshCredentials(middleSshCredentials, middleUsername.trim())
      if (credentialError) {
        setError(credentialError)
        notify('error', 'Проверьте пары SSH', credentialError)
        return
      }
    }
    if (profile.honeypot_type === 'kozyavka' && lowAuthMode === 'configured' && (!lowUsername.trim() || !lowPassword)) return setError('Для Low укажите логин и пароль, которые ловушка будет принимать.')
    const isHigh = profile.level === 'high'
    const isPrivateTcgTest = privateTcgTest
    setBusy(true)
    let createdTrapId: string | null = null
    let started = false
    let progressToastId: number | null = null
    let effectiveSharedPort = sharedPort
    try {
      const freshReservations = isPrivateTcgTest ? [] : await api.servers.ports(serverId)
      if (effectiveSharedPort === null && hostPort !== null && shareablePorts.includes(hostPort)
        && freshReservations.some((reservation) => reservation.transport === 'tcp' && reservation.host_port === hostPort)) {
        effectiveSharedPort = hostPort
        setSharedPort(hostPort)
      }
      let deploymentPort = 0
      if (isPrivateTcgTest) {
        if (effectiveSharedPort !== null) return setError('Приватная TCG-ловушка не использует общий публичный порт.')
      } else if (effectiveSharedPort === null) {
        if (!hostPort || !Number.isInteger(hostPort) || hostPort < 1 || hostPort > 65535) return setError('Введите TCP-порт от 1 до 65535.')
          if (freshReservations.some((reservation) => reservation.transport === 'tcp' && reservation.host_port === hostPort)) {
          return setError(`TCP-порт ${hostPort} занят. Для High ${highServiceLabel} нужна отдельная свободная прямая публикация; проверьте порт или выберите другой.`)
        }
        deploymentPort = hostPort
      } else {
        // Shared listener ports are already reserved by design. A new trap
        // starts on a temporary free port, then joins the shared listener.
        const presence = await api.servers.presence(serverId)
        if (!presence.connected) return setError('Агент сейчас не отвечает Центру; общий порт не изменён.')
        if (!presence.can_share_tcp_ports) return setError('Агент не подтвердил поддержку Dispatcher. Обновите на нём hf-agent и hf-dispatcher, затем повторите попытку.')
        const memberCount = traps.filter((trap) => trap.server_id === serverId && trap.actual_state === 'running'
          && trap.ports.some((port) => port.transport === 'tcp' && port.host_port === effectiveSharedPort)).length
        if (newWeight < 1 || newWeight > 100 - memberCount || !Number.isInteger(newWeight)) {
          return setError('Доля новой ловушки должна оставлять не менее 1% каждой существующей ловушке.')
        }
        const temporaryPort = nextFreePort(freshReservations, [effectiveSharedPort])
        if (temporaryPort === null) return setError('Не найден свободный временный TCP-порт для запуска ловушки перед подключением к общему порту.')
        deploymentPort = temporaryPort
      }
      const isMiddle = profile.honeypot_type === 'pritvoryashka'
      const serviceLabel = profile.service_type.toUpperCase()
      const config = isMiddle ? {
        hostname: middleHostname.trim(),
        username: middleUsername.trim(),
        distribution: middleDistribution,
        vulnerability_profiles: [],
        ssh_auth_mode: middleSshAuthMode,
        ssh_credentials: middleSshAuthMode === 'realistic' ? withFixedSshUsername(middleSshCredentials, middleUsername.trim()) : [],
      } : profile.honeypot_type === 'kozyavka' ? {
        auth_mode: lowAuthMode,
        credentials: lowAuthMode === 'configured' ? [{ username: lowUsername.trim(), password: lowPassword }] : [],
      } : isPrivateTcgTest ? { high_runtime_mode: 'private_tcg_test' } : {}
      const ports = isPrivateTcgTest ? [] : [{ transport: 'tcp' as const, host_port: deploymentPort, target_port: isHigh ? (profile.service_type === 'rdp' ? 3389 : 22) : 2222, route_mode: 'direct' as const }]
      const input = { name, profile_id: profile.id, config, resources, desired_state: 'stopped' as const, ports }
      try {
        const created = await api.traps.create(serverId, input)
        createdTrapId = created.trap_id
      } catch (createError) {
        if (createError instanceof ApiError && createError.status === 409 && createError.message === 'Public port is already reserved on this server') {
          throw new Error(`TCP-порт ${deploymentPort} только что заняли. Повторите попытку с обновлённой проверкой порта.`)
        }
        throw createError
      }
      if (!createdTrapId) throw new Error('Не удалось определить созданную ловушку.')
      progressToastId = notify(
        'info',
        'Ловушка устанавливается',
        isPrivateTcgTest
          ? `Поднимаю «${name}» в приватном TCG-режиме на ${selectedServer?.host ?? 'выбранном сервере'}. Публичный порт не открывается; события будут поступать в Центр.`
          : effectiveSharedPort === null
          ? `Устанавливаю «${name}» на ${selectedServer?.host ?? 'выбранном сервере'}:${deploymentPort}. Подождите — сообщу, когда она будет готова.`
          : `Устанавливаю «${name}» на временный порт и подключаю к общему порту ${effectiveSharedPort}. Подождите — сообщу по завершении.`,
        { persistent: true },
      )
      const queued = await api.traps.action(createdTrapId, 'start')
      await awaitAction(createdTrapId, queued, 'start')
      started = true
      if (effectiveSharedPort !== null) {
        const existing = traps.filter((trap) => trap.server_id === serverId && trap.actual_state === 'running'
          && trap.ports.some((port) => port.host_port === effectiveSharedPort && port.transport === 'tcp'))
        if (!existing.length) throw new Error('На выбранном общем порту больше нет работающих ловушек.')
        await awaitAction(createdTrapId, await api.traps.sharePort(createdTrapId, effectiveSharedPort, groupWeights(existing, createdTrapId, effectiveSharedPort)), 'share')
      }
      const serviceSuffix = ''
      if (progressToastId !== null) dismissToast(progressToastId)
      notify(
        'success',
        isPrivateTcgTest ? 'Лабораторная ловушка установлена' : effectiveSharedPort === null ? 'Ловушка установлена' : 'Общий порт настроен',
        isPrivateTcgTest
          ? `«${name}» запущена в закрытой TCG-сети на ${selectedServer?.host ?? 'сервере'}. Публичного SSH-порта нет; телеметрия передаётся в Центр.`
          : effectiveSharedPort === null
          ? `«${name}» доступна по ${serviceLabel} на ${selectedServer?.host ?? 'выбранном сервере'}:${hostPort}.${serviceSuffix}`
          : `«${name}» доступна по ${serviceLabel} через общий порт ${effectiveSharedPort}.${serviceSuffix}`,
      )
      setName('')
      setMiddleSshAuthMode('realistic')
      setMiddleSshCredentials(chooseDefaultSshCredentials(middleUsername.trim()))
      await onCreated().catch(() => undefined)
    } catch (requestError) {
      const detail = requestError instanceof ApiError ? apiErrorMessage(requestError) : requestError instanceof Error ? requestError.message : 'Неожиданная ошибка приложения.'
      // This error is emitted before Middle starts a container. The agent has
      // rejected the command, so its provisional database registration is safe
      // to remove. Timeouts and ambiguous failures must remain reviewable.
      let removedFailedRegistration = false
      if (createdTrapId && !started && requestError instanceof ConfirmedTrapActionFailure
        && detail.includes('does not accept the current bait/process configuration')) {
        try {
          await api.traps.delete(createdTrapId)
          removedFailedRegistration = true
        } catch {
          // Keep the original deployment error visible and expose manual cleanup.
        }
      }
      const failure = createdTrapId
        ? removedFailedRegistration
          ? `Ловушка «${name}» не запущена: ${detail} Неудачная запись удалена из панели.`
          : effectiveSharedPort !== null && started
          ? `Ловушка «${name}» запущена на временном порту, но подключение к общему порту ${effectiveSharedPort} не подтверждено: ${detail} Проверьте состояние операции и порты ловушки во вкладке «Ловушки».`
          : effectiveSharedPort === null
          ? `Ловушка «${name}» создана, но запуск не подтверждён: ${detail} Проверьте её состояние во вкладке «Ловушки».`
          : `Ловушка «${name}» создана на временном порту, но запуск не подтверждён: ${detail} Проверьте состояние во вкладке «Ловушки».`
        : detail
      if (progressToastId !== null) dismissToast(progressToastId)
      notify('error', createdTrapId && !removedFailedRegistration ? 'Ловушка создана не полностью' : 'Не удалось создать ловушку', failure)
      if (createdTrapId) await onCreated().catch(() => undefined)
    }
    finally { setBusy(false) }
  }

  return <section className="space-y-6 p-6"><div className="mx-auto max-w-4xl"><div className="mb-6 text-center"><p className="text-sm text-white/45">КОНФИГУРАЦИЯ</p><div className="mt-3 flex justify-center"><FuzzyText fontSize={28} fontWeight={600} color="#f1a36b" baseIntensity={0.2} hoverIntensity={0.5} fuzzRange={8} fps={30} enableHover className="block">Добавить ловушку</FuzzyText></div><p className="mt-3 text-sm text-white/45">Выберите профиль ловушки. ОС и способ развёртывания задаются отдельно ниже.</p></div>
    <form onSubmit={submit} className="w-full space-y-6 rounded-xl border border-white/10 bg-[#160e0c]/80 p-6 backdrop-blur-xl">
      <label className="block text-sm text-white/70">Название ловушки<input required disabled={readOnly} value={name} onChange={(e) => setName(e.target.value)} placeholder="Например, SSH-ловушка 01" className="mt-2 w-full rounded-lg border border-white/10 bg-black/20 px-4 py-3 outline-none focus:border-orange-500/50" /></label>
      <div className="grid gap-4 sm:grid-cols-2">
        <label className="text-sm text-white/70">Сервер<select required disabled={readOnly || busy || availableServers.length === 0} value={serverId} onChange={(event) => setServerId(event.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-[#100a09] px-4 py-3"><option value="">{availableServers.length ? 'Выберите подключённый сервер' : 'Нет подключённых серверов'}</option>{availableServers.map((server) => <option key={server.server_id} value={server.server_id}>{server.name} — {server.host}</option>)}</select>{availableServers.length === 0 && <span className="mt-1 block text-xs text-white/40">Сервер появится здесь после успешного подключения агента.</span>}</label>
        <label className="text-sm text-white/70">Профиль ловушки<select required disabled={readOnly || busy} value={selectedLevel} onChange={(event) => selectLevel(event.target.value as TrapLevel | '')} className="mt-2 w-full rounded-lg border border-white/10 bg-[#100a09] px-4 py-3">
          <option value="">Выберите профиль</option>
          <option value="low" disabled={!supported.some((item) => item.level === 'low' && item.honeypot_type === 'kozyavka')}>Нижний</option>
          <option value="medium" disabled={!supported.some((item) => item.level === 'medium' && item.honeypot_type === 'pritvoryashka')}>Средний</option>
          <option value="high" disabled={!highVmProfiles.length && !legacyHighProfile}>Верхний</option>
        </select></label>
      </div>
      {profile && <div className="grid grid-cols-2 gap-3 sm:grid-cols-2">{[['Служба', profile.service_type.toUpperCase()], ...(profile.level === 'high' ? [] : [['Лимит по умолчанию', `${profile.resources.cpu_cores} CPU · ${profile.resources.memory_mb} МБ · ${profile.resources.pids} PID`]])].map(([label, value]) => <div key={label} className="rounded-lg border border-white/10 bg-black/20 p-3"><p className="text-[10px] uppercase text-white/35">{label}</p><p className="mt-1 text-sm capitalize">{value}</p></div>)}</div>}
      {profile && <section className="rounded-xl border border-white/10 bg-black/10 p-4">
        <h3 className="text-sm font-medium text-white/80">ОС и развёртывание</h3>
        {profile.honeypot_type === 'kozyavka' && <p className="mt-2 text-xs leading-5 text-white/45">Low запускается как Docker-контейнер. Образ и системная среда выбираются профилем ловушки.</p>}
        {profile.honeypot_type === 'pritvoryashka' && <label className="mt-3 block text-sm text-white/70">Операционная система<select disabled={readOnly || busy} value={middleDistribution} onChange={(event) => setMiddleDistribution(event.target.value as 'ubuntu' | 'debian' | 'arch' | 'windows')} className="mt-2 w-full rounded-lg border border-white/10 bg-[#100a09] px-4 py-3"><option value="ubuntu">Ubuntu 22.04</option><option value="debian">Debian 13</option><option value="arch">Arch Linux</option><option value="windows">Windows Server 2022 · PowerShell по SSH</option></select><span className="mt-1 block text-xs text-white/40">Выбранная система будет эмулироваться в SSH-ловушке.</span></label>}
        {profile.honeypot_type === 'pritvoryashka' && <p className="mt-2 text-xs leading-5 text-white/45">Средний запускается в Docker-контейнере; выбранная ОС эмулируется виртуальной файловой системой и shell.</p>}
        {profile.honeypot_type === 'high_vm' && <div className="mt-3 grid gap-4 sm:grid-cols-2">
          <label className="text-sm text-white/70">Операционная система<select disabled={readOnly || busy} value={highOsProfile} onChange={(event) => { const next = highVmProfiles.find((item) => item.config.os_profile === event.target.value); if (next) { setHighOsProfile(event.target.value); setResources(next.resources); setSharedPort(null); if (event.target.value === 'windows_rdp') { setHighRuntimeMode('public_kvm'); manualPort.current = false } } }} className="mt-2 w-full rounded-lg border border-white/10 bg-[#100a09] px-4 py-3">{highOsChoices.map((choice) => <option key={choice.value} value={choice.value}>{choice.label}</option>)}</select></label>
          <label className="text-sm text-white/70">Способ запуска<select disabled={readOnly || busy} value={highRuntimeMode} onChange={(event) => { manualPort.current = false; setHighRuntimeMode(event.target.value as typeof highRuntimeMode); if (event.target.value === 'private_tcg_test') { setHostPort(null); setSharedPort(null) } }} className="mt-2 w-full rounded-lg border border-white/10 bg-[#100a09] px-4 py-3"><option value="public_kvm">Публичная VM · KVM</option><option value="private_tcg_test" disabled={windowsHigh}>Лабораторная VM · QEMU TCG</option></select></label>
        </div>}
        {profile.honeypot_type === 'high_vm' && <p className="mt-3 text-xs leading-5 text-white/45">High разворачивается отдельной VM из подготовленного образа. {windowsHigh ? 'Windows публикует RDP на отдельном порту 3389 через изолированную сеть агента. Нужен сервер с KVM и готовый одобренный образ; для его первой сборки нужны Packer и заранее одобренные администратором Windows media и контрольные суммы.' : 'Linux-профиль использует SSH: публичный KVM открывает собственный порт, приватный TCG не открывает порт; события передаются в Центр через агент.'}</p>}
        {profile.honeypot_type === 'high_ubuntu_ssh' && <p className="mt-3 text-xs leading-5 text-white/45">Старый профиль фиксирован на Ubuntu Server и публичном запуске через KVM.</p>}
      </section>}
      {profile?.honeypot_type === 'pritvoryashka' && <section className="rounded-xl border border-white/10 bg-black/10 p-4"><h3 className="text-sm font-medium text-white/80">Виртуальная SSH-система Middle</h3><p className="mt-1 text-xs text-white/40">Имя ловушки используется в панели. Эти значения увидит посетитель SSH-сессии.</p><div className="mt-4 grid gap-3 sm:grid-cols-2"><label className="text-sm text-white/70">Hostname<input required disabled={readOnly || busy} maxLength={64} pattern="[A-Za-z0-9][A-Za-z0-9.-]*" value={middleHostname} onChange={(event) => setMiddleHostname(event.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-black/20 px-4 py-3 outline-none focus:border-orange-500/50" /></label><label className="text-sm text-white/70">Пользователь SSH и shell<input required disabled={readOnly || busy} maxLength={32} pattern="[a-z_][a-z0-9_-]*" value={middleUsername} onChange={(event) => setMiddleUsername(event.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-black/20 px-4 py-3 outline-none focus:border-orange-500/50" /></label></div><p className="mt-3 font-mono text-xs text-orange-100/75">{middleDistribution === 'windows' ? `PS C:\\Users\\${middleUsername || 'admin'}>` : `${middleUsername || 'admin'}@${middleHostname || 'srv-app-01'}:~$`}</p>{middleDistribution === 'windows' ? <p className="mt-2 text-xs text-white/45">Виртуальный PowerShell по SSH. RDP, WinRM и настоящие программы Windows здесь не запускаются. Linux-профили уязвимостей недоступны.</p> : <p className="mt-2 text-xs text-white/45">После создания сценарии можно выбрать на отдельной странице «Сценарии уязвимостей».</p>}</section>}
      {profile?.honeypot_type === 'pritvoryashka' && <SshAuthSettings mode={middleSshAuthMode} credentials={middleSshCredentials} fixedUsername={middleUsername.trim()} disabled={readOnly || busy} onModeChange={setMiddleSshAuthMode} onCredentialsChange={setMiddleSshCredentials}/>}
      {profile?.honeypot_type === 'kozyavka' && <section className="rounded-xl border border-white/10 bg-black/10 p-4"><h3 className="text-sm font-medium text-white/80">Авторизация SSH Low</h3><label className="mt-3 block text-sm text-white/70">Режим<select disabled={readOnly || busy} value={lowAuthMode} onChange={(event) => setLowAuthMode(event.target.value as typeof lowAuthMode)} className="mt-2 w-full rounded-lg border border-white/10 bg-[#100a09] px-4 py-3"><option value="capture_credentials">Сбор попыток: отклонять все входы</option><option value="configured">Имитация входа: принимать указанную пару</option><option value="any_password">Имитация входа: принимать любой пароль</option><option value="passwordless">Имитация входа: без пароля</option></select></label>{lowAuthMode === 'configured' && <div className="mt-3 grid gap-3 sm:grid-cols-2"><label className="text-sm text-white/70">Логин<input disabled={readOnly || busy} maxLength={32} value={lowUsername} onChange={(event) => setLowUsername(event.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-black/20 px-4 py-3"/></label><label className="text-sm text-white/70">Пароль<input disabled={readOnly || busy} maxLength={128} value={lowPassword} onChange={(event) => setLowPassword(event.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-black/20 px-4 py-3"/></label></div>}<p className="mt-3 text-xs text-white/45">При успешном входе открывается простая виртуальная оболочка. Настоящие команды сервера не выполняются.</p></section>}
      {profile && profile.level !== 'high' && <section className="rounded-xl border border-white/10 bg-black/10 p-4"><div><h3 className="text-sm font-medium text-white/80">Лимиты этого контейнера</h3><p className="mt-1 text-xs text-white/40">Не выше ограничений уровня ловушки: Нижний — 0,5 CPU / 128 МБ / 64 процесса; Средний — 1 CPU / 512 МБ / 256 процессов.</p></div><div className="mt-4 grid gap-3 sm:grid-cols-3"><ResourceInput label="CPU (ядра)" value={resources.cpu_cores} min={0.05} max={profile.level === 'low' ? 0.5 : 1} step={0.05} disabled={readOnly || busy} onChange={(value) => updateResource('cpu_cores', value)}/><ResourceInput label="RAM (МБ)" value={resources.memory_mb} min={32} max={profile.level === 'low' ? 128 : 512} step={16} disabled={readOnly || busy} onChange={(value) => updateResource('memory_mb', value)}/><ResourceInput label="Процессы" value={resources.pids} min={16} max={profile.level === 'low' ? 64 : 256} step={1} disabled={readOnly || busy} onChange={(value) => updateResource('pids', value)}/></div></section>}
      <div className="rounded-lg border border-white/10 bg-black/15 p-4"><p className="text-xs uppercase tracking-wider text-white/40">{privateTcgTest ? 'Лабораторный режим без публичного порта' : 'Адреса доступа'}</p>
        {!privateTcgTest && <>
        <label className="mt-3 block text-sm text-white/70">Режим порта<select disabled={readOnly || busy || !serverId || profile?.level === 'high'} value={sharedPort === null ? 'direct' : String(sharedPort)} onChange={(event) => setSharedPort(event.target.value === 'direct' ? null : Number(event.target.value))} className="mt-2 w-full rounded-lg border border-white/10 bg-[#100a09] px-4 py-3"><option value="direct">Отдельный порт</option>{shareablePorts.map((port) => <option key={port} value={port}>Общий порт {port} через Dispatcher</option>)}</select></label>
        {sharedPort === null && <label className="mt-3 block max-w-xs text-sm text-white/70">Публичный {isHigh ? highServiceLabel : 'SSH'}-порт<input type="number" min={1} max={65535} step={1} required disabled={readOnly || busy || !serverId} value={hostPort ?? ''} onChange={(event) => { manualPort.current = true; setHostPort(event.target.value === '' ? null : Number(event.target.value)); setPortError('') }} placeholder={`Например, ${windowsHigh ? '3389' : '2222'}`} className="mt-2 w-full rounded-lg border border-white/10 bg-black/20 px-4 py-3 outline-none focus:border-orange-500/50"/><span className="mt-1 block text-xs text-white/40">{isHigh ? `Для High нужен свободный отдельный TCP-порт; ${highServiceLabel} гостя работает на ${windowsHigh ? 3389 : 22}.` : 'Порт подставляется автоматически. Если он уже используется запущенной SSH-ловушкой Low или Middle, новая ловушка подключится к нему через Dispatcher. Сценарии и их порты настраиваются после создания на странице «Сценарии уязвимостей».'}</span></label>}
        {sharedPort !== null && <label className="mt-3 block max-w-xs text-sm text-white/70">Доля новой ловушки, %<input type="number" min={1} max={maxNewWeight} step={1} disabled={readOnly || busy} value={newWeight} onChange={(event) => setNewWeight(Number(event.target.value))} className="mt-2 w-full rounded-lg border border-white/10 bg-black/20 px-4 py-3 outline-none focus:border-orange-500/50"/></label>}
        <p className="mt-3 font-mono text-lg text-orange-100/85">{selectedServer?.host ?? 'Выберите сервер'}:{sharedPort ?? hostPort ?? '…'}</p><p className="mt-1 text-xs text-white/40">{profile?.level === 'high' ? `High ${highServiceLabel} работает в отдельной виртуальной машине и использует собственный TCP-порт.` : sharedPort === null ? 'Указанный публичный порт используется для этой ловушки.' : `Новая ловушка получит ${newWeight}% подключений. Остальные ${100 - newWeight}% делятся между существующими ловушками; один IP попадает в одну и ту же ловушку. У ловушек разных ОС за общим портом будут одинаковые SSH-баннер и ключ.`}</p>{portError && <p role="alert" className="mt-2 text-xs text-amber-200/80">{portError} Можно указать порт вручную; Центр проверит, свободен ли он.</p>}
        </>}
        {privateTcgTest && <div className="mt-4 rounded-lg border border-sky-400/15 bg-sky-400/[0.04] p-3 text-xs leading-5 text-white/60"><p>VM будет доступна только внутри закрытой сети сервера. HoneyForge не резервирует и не открывает входящий порт. События High передаются в Центр через агент.</p><p className="mt-2">Для проверки используйте гостевой IP из `virsh domifaddr` на сервере и порт {profile?.service_type === 'rdp' ? '3389' : '22'}. Удаление ловушки из панели удалит и VM.</p></div>}
      </div>
      {error && <p role="alert" className="text-sm text-red-400">{error}</p>}
      {!readOnly && <button disabled={busy || !availableServers.length || !profile || (!privateTcgTest && !hostPort) || (sharedPort !== null && (newWeight < 1 || newWeight > maxNewWeight || !Number.isInteger(newWeight)))} className="rounded-lg border border-orange-500/30 bg-orange-500/10 px-5 py-3 text-sm font-medium text-[#f1a36b] disabled:opacity-40">{busy ? 'Устанавливаю ловушку…' : 'Создать ловушку'}</button>}
    </form></div></section>
}

function ResourceInput({ label, value, min, max, step, disabled, onChange }: { label: string; value: number; min: number; max: number; step: number; disabled: boolean; onChange: (value: number) => void }) {
  return <label className="text-xs text-white/55">{label}<input type="number" min={min} max={max} step={step} required disabled={disabled} value={value} onChange={(event) => onChange(Number(event.target.value))} className="mt-2 w-full rounded-lg border border-white/10 bg-black/20 px-3 py-3 text-sm"/></label>
}
