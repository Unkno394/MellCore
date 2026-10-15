import { useEffect, useMemo, useState } from 'react'
import { apiErrorMessage } from '../api/client'
import SshAuthSettings, { fallbackSshCredentials, orderFixedSshUsernameFirst, validateSshCredentials, withFixedSshUsername } from '../components/SshAuthSettings'
import type { MellCoreApi } from '../api/services'
import type { MiddleSshAuthMode, PortBinding, SshCredential, Trap, TrapInput } from '../api/types'
import { endpointsForScenarios, linuxScenarioOptions, windowsScenarioOptions } from '../vulnerabilities/scenarioCatalog'

type Props = {
  api: MellCoreApi
  traps: Trap[]
  readOnly: boolean
  onChanged: () => Promise<void>
}

function enabledProfiles(trap: Trap | undefined): string[] {
  const value = trap?.effective_config.vulnerability_profiles
  return Array.isArray(value) ? value.filter((id): id is string => typeof id === 'string') : []
}

function sshAuthMode(trap: Trap | undefined): MiddleSshAuthMode {
  return trap?.effective_config.ssh_auth_mode === 'adaptive' ? 'adaptive' : 'realistic'
}

function sshCredentials(trap: Trap | undefined): SshCredential[] {
  const value = trap?.effective_config.ssh_credentials
  if (!Array.isArray(value)) return fallbackSshCredentials.map((credential) => ({ ...credential }))
  const credentials = value.filter((item): item is SshCredential => !!item && typeof item === 'object'
    && typeof (item as SshCredential).username === 'string' && typeof (item as SshCredential).password === 'string')
  return credentials.length ? credentials : fallbackSshCredentials.map((credential) => ({ ...credential }))
}

export default function TrapScenarioEditor({ api, traps, readOnly, onChanged }: Props) {
  const middleTraps = useMemo(() => traps.filter((trap) =>
    trap.profile_snapshot.honeypot_type === 'pritvoryashka'), [traps])
  const [selectedId, setSelectedId] = useState('')
  const selected = middleTraps.find((trap) => trap.trap_id === selectedId) ?? middleTraps[0]
  const currentProfiles = enabledProfiles(selected)
  const [draft, setDraft] = useState<string[]>([])
  const [authMode, setAuthMode] = useState<MiddleSshAuthMode>('realistic')
  const [credentials, setCredentials] = useState<SshCredential[]>(() => fallbackSshCredentials.map((credential) => ({ ...credential })))
  const [ports, setPorts] = useState<Record<number, string>>({})
  const [advanced, setAdvanced] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const isLinux = selected?.effective_config.distribution !== 'windows'
  const endpoints = useMemo(() => isLinux ? endpointsForScenarios(draft) : [], [draft, isLinux])
  const selectedAuthMode = sshAuthMode(selected)
  const selectedCredentials = sshCredentials(selected)
  const fixedUsername = typeof selected?.effective_config.username === 'string'
    ? selected.effective_config.username
    : typeof selected?.config.username === 'string' ? selected.config.username : undefined
  const scenariosChanged = JSON.stringify([...draft].sort()) !== JSON.stringify([...currentProfiles].sort())
  const portsChanged = endpoints.some((endpoint) => Number(ports[endpoint.targetPort]) !== selected?.ports.find((port) => port.target_port === endpoint.targetPort)?.host_port)
  const authChanged = authMode !== selectedAuthMode || JSON.stringify(credentials) !== JSON.stringify(selectedCredentials)

  useEffect(() => {
    if (selected && selected.trap_id !== selectedId) setSelectedId(selected.trap_id)
  }, [selected, selectedId])

  useEffect(() => {
    setDraft(currentProfiles)
    setAuthMode(sshAuthMode(selected))
    setCredentials(orderFixedSshUsernameFirst(sshCredentials(selected), fixedUsername))
    const existing = Object.fromEntries(selected?.ports.map((port) => [port.target_port, String(port.host_port)]) ?? [])
    setPorts(existing)
    setError('')
    setMessage('')
  }, [selected?.trap_id, selected?.version])

  useEffect(() => {
    if (!selected || endpoints.length === 0) return
    let active = true
    void api.servers.ports(selected.server_id).then((reservations) => {
      if (!active) return
      const occupied = new Set(reservations
        .filter((reservation) => reservation.transport === 'tcp' && reservation.trap_id !== selected.trap_id)
        .map((reservation) => reservation.host_port))
      selected.ports.forEach((port) => occupied.add(port.host_port))
      setPorts((current) => {
        const next = { ...current }
        for (const endpoint of endpoints) {
          const value = Number(next[endpoint.targetPort])
          const retainedBinding = selected.ports.find((port) => port.target_port === endpoint.targetPort)
          if (retainedBinding && (value === retainedBinding.host_port || !occupied.has(value))) {
            occupied.add(value)
            continue
          }
          if (Number.isInteger(value) && value >= 1 && value <= 65535 && !occupied.has(value)) {
            occupied.add(value)
            continue
          }
          const preferred = endpoint.defaultPublicPort
          const assigned = !occupied.has(preferred)
            ? preferred
            : Array.from({ length: 1000 }, (_, index) => 30000 + index).find((port) => !occupied.has(port))
          if (assigned) {
            next[endpoint.targetPort] = String(assigned)
            occupied.add(assigned)
          }
        }
        return next
      })
    }).catch(() => undefined)
    return () => { active = false }
  }, [api, selected, endpoints])

  async function save() {
    if (!selected || busy) return
    if (authMode === 'realistic') {
      const credentialError = validateSshCredentials(credentials, fixedUsername)
      if (credentialError) {
        setError(credentialError)
        return
      }
    }
    setBusy(true)
    setError('')
    setMessage('')
    let saved = false
    try {
      const reservations = await api.servers.ports(selected.server_id)
      const occupied = new Set(reservations
        .filter((reservation) => reservation.transport === 'tcp' && reservation.trap_id !== selected.trap_id)
        .map((reservation) => reservation.host_port))
      const sshBindings = selected.ports.filter((port) => port.target_port === 2222 || port.route_mode === 'dispatcher_backend')
      sshBindings.forEach((port) => occupied.add(port.host_port))
      const serviceBindings: PortBinding[] = endpoints.map((endpoint) => {
        const hostPort = Number(ports[endpoint.targetPort])
        if (!Number.isInteger(hostPort) || hostPort < 1 || hostPort > 65535) {
          throw new Error(`Укажи публичный TCP-порт от 1 до 65535 для ${endpoint.service}.`)
        }
        if (occupied.has(hostPort)) throw new Error(`TCP-порт ${hostPort} для ${endpoint.service} занят или уже используется этой ловушкой.`)
        occupied.add(hostPort)
        return { transport: 'tcp', host_port: hostPort, target_port: endpoint.targetPort, route_mode: 'direct' }
      })
      const input: TrapInput = {
        name: selected.name,
        profile_id: selected.profile_id,
        config: {
          ...selected.config,
          vulnerability_profiles: draft,
          ssh_auth_mode: authMode,
          ssh_credentials: authMode === 'realistic' ? withFixedSshUsername(credentials, fixedUsername) : [],
        },
        resources: selected.resources,
        desired_state: selected.desired_state,
        ports: [...sshBindings, ...serviceBindings],
      }
      await api.traps.update(selected, input)
      saved = true
      await onChanged()
      if (selected.desired_state === 'running') {
        setMessage('Настройки сохранены. Перезапускаю ловушку…')
        const action = await api.traps.action(selected.trap_id, 'restart')
        let progress = action
        for (let attempt = 0; progress.status === 'queued' && attempt < 30; attempt += 1) {
          await new Promise((resolve) => window.setTimeout(resolve, 2000))
          progress = await api.traps.actionStatus(selected.trap_id, action.action_id)
        }
        if (progress.status === 'failed') throw new Error(progress.detail || 'Агент не смог применить сценарии.')
        setMessage(progress.status === 'succeeded' ? 'Настройки сохранены и применены.' : 'Настройки сохранены; проверь состояние ловушки.')
        await onChanged()
      } else setMessage('Настройки сохранены. Они применятся при запуске ловушки.')
    } catch (cause) {
      setError(`${saved ? 'Настройки сохранены, но применение не завершилось: ' : ''}${apiErrorMessage(cause)}`)
    } finally { setBusy(false) }
  }

  return <section className="space-y-5 rounded-xl border border-white/10 bg-[#160e0c]/75 p-4 sm:p-5">
    <header><h3 className="font-semibold">Настройки Middle-ловушки</h3><p className="mt-1 text-xs leading-5 text-white/45">Выбери сценарии для операционной системы ловушки. Порты нужны только сценариям с сетевым listener.</p></header>
    <label className="block max-w-lg text-sm text-white/75">Middle<select value={selected?.trap_id ?? ''} onChange={(event) => setSelectedId(event.target.value)} disabled={!middleTraps.length || busy} className="mt-2 w-full rounded-lg border border-white/10 bg-[#100a09] px-3 py-2.5 text-sm text-white outline-none focus:border-orange-400/40">
      {!middleTraps.length && <option value="">Нет Middle-ловушек</option>}{middleTraps.map((trap) => <option key={trap.trap_id} value={trap.trap_id}>{trap.name}</option>)}
    </select></label>
    {!middleTraps.length ? <p className="text-xs text-white/45">Создай Middle в разделе «Инфраструктура».</p> : <>
      <SshAuthSettings mode={authMode} credentials={credentials} fixedUsername={fixedUsername} disabled={readOnly || busy} onModeChange={setAuthMode} onCredentialsChange={setCredentials}/>
      {<><div className="grid gap-2 sm:grid-cols-2">{(isLinux ? linuxScenarioOptions : windowsScenarioOptions).map((scenario) => <label key={scenario.id} className={`flex items-start gap-3 rounded-lg border p-3 ${draft.includes(scenario.id) ? 'border-orange-400/30 bg-orange-400/[0.06]' : 'border-white/10 bg-black/10'} ${readOnly ? 'opacity-60' : 'cursor-pointer'}`}><input type="checkbox" checked={draft.includes(scenario.id)} disabled={readOnly || busy} onChange={(event) => setDraft((current) => event.target.checked ? [...current, scenario.id] : current.filter((id) => id !== scenario.id))} className="mt-0.5 accent-orange-400"/><span><span className="block text-sm text-white/80">{scenario.name}</span><span className="mt-1 block text-xs leading-5 text-white/40">{scenario.protocol} · {scenario.description}</span></span></label>)}</div>
      <div className="flex flex-wrap items-center justify-between gap-3"><p className="text-xs text-white/40">Выбрано: {draft.length} · сетевых endpoints: {endpoints.length}</p><button type="button" onClick={() => setAdvanced((value) => !value)} className="rounded-lg border border-white/10 px-3 py-2 text-xs text-orange-100/80">{advanced ? 'Скрыть порты' : 'Настроить порты'}</button></div>
      {advanced && endpoints.length > 0 && <div className="grid gap-3 rounded-lg border border-white/10 bg-black/15 p-3 sm:grid-cols-2">{endpoints.map((endpoint) => <label key={endpoint.targetPort} className="text-xs text-white/65">Публичный порт · {endpoint.service}<input type="number" min="1" max="65535" value={ports[endpoint.targetPort] ?? ''} disabled={readOnly || busy} onChange={(event) => setPorts((current) => ({ ...current, [endpoint.targetPort]: event.target.value }))} className="mt-1.5 w-full rounded-lg border border-white/10 bg-black/20 px-3 py-2.5 text-sm"/><span className="mt-1 block text-[10px] text-white/35">Порт внутри контейнера: {endpoint.targetPort}</span></label>)}</div>}
      </>}
      {error && <p role="alert" className="text-sm text-red-200">{error}</p>}{message && <p role="status" className="text-sm text-emerald-200">{message}</p>}
      {!readOnly && <button type="button" disabled={busy || !(scenariosChanged || portsChanged || authChanged)} onClick={() => void save()} className="rounded-lg bg-orange-400 px-4 py-2.5 text-sm font-medium text-black transition hover:bg-orange-300 disabled:cursor-not-allowed disabled:opacity-40">{busy ? 'Применяем…' : 'Сохранить настройки'}</button>}
    </>}
  </section>
}
