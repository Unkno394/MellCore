import { useEffect, useMemo, useState } from 'react'
import { apiErrorMessage } from '../api/client'
import type { MellCoreApi } from '../api/services'
import type { PortBinding, Trap, TrapInput } from '../api/types'
import { endpointsForScenarios, type ScenarioOption } from '../vulnerabilities/scenarioCatalog'

type Props = {
  api: MellCoreApi
  traps: Trap[]
  options: ScenarioOption[]
  windows: boolean
  readOnly: boolean
  onChanged: () => Promise<void>
}

function profilesFor(trap: Trap | undefined): string[] {
  const profiles = trap?.effective_config.vulnerability_profiles
  return Array.isArray(profiles) ? profiles.filter((id): id is string => typeof id === 'string') : []
}

function isWindowsMiddle(trap: Trap): boolean {
  return trap.effective_config.distribution === 'windows' || trap.config.distribution === 'windows'
}

async function updateScenarioProfiles(api: MellCoreApi, trap: Trap, profiles: string[]): Promise<void> {
  const reservations = await api.servers.ports(trap.server_id)
  const occupied = new Set(reservations
    .filter((reservation) => reservation.transport === 'tcp' && reservation.trap_id !== trap.trap_id)
    .map((reservation) => reservation.host_port))
  const sshBindings = trap.ports.filter((port) => port.target_port === 2222 || port.route_mode === 'dispatcher_backend')
  sshBindings.forEach((port) => occupied.add(port.host_port))

  const endpoints = isWindowsMiddle(trap) ? [] : endpointsForScenarios(profiles)
  const serviceBindings: PortBinding[] = endpoints.map((endpoint) => {
    const current = trap.ports.find((port) => port.target_port === endpoint.targetPort)
    let hostPort = current?.host_port
    if (!hostPort || occupied.has(hostPort)) {
      hostPort = !occupied.has(endpoint.defaultPublicPort)
        ? endpoint.defaultPublicPort
        : Array.from({ length: 1000 }, (_, index) => 30000 + index).find((port) => !occupied.has(port))
    }
    if (!hostPort) throw new Error(`Не удалось подобрать свободный порт для ${endpoint.service}.`)
    occupied.add(hostPort)
    return { transport: 'tcp', host_port: hostPort, target_port: endpoint.targetPort, route_mode: 'direct' }
  })

  const input: TrapInput = {
    name: trap.name,
    profile_id: trap.profile_id,
    config: { ...trap.config, vulnerability_profiles: profiles },
    resources: trap.resources,
    desired_state: trap.desired_state,
    ports: [...sshBindings, ...serviceBindings],
  }
  await api.traps.update(trap, input)
}

export default function ScenarioAssignmentPanel({ api, traps, options, windows, readOnly, onChanged }: Props) {
  const middleTraps = useMemo(() => traps.filter((trap) =>
    trap.profile_snapshot.honeypot_type === 'pritvoryashka' && isWindowsMiddle(trap) === windows), [traps, windows])
  const [selectedId, setSelectedId] = useState('')
  const selected = middleTraps.find((trap) => trap.trap_id === selectedId) ?? middleTraps[0]
  const enabledProfiles = profilesFor(selected)
  const [busyScenario, setBusyScenario] = useState<string | null>(null)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    if (selected && selected.trap_id !== selectedId) setSelectedId(selected.trap_id)
  }, [selected, selectedId])

  async function setEnabled(scenarioId: string, enabled: boolean) {
    if (!selected || busyScenario) return
    const nextProfiles = enabled
      ? [...new Set([...enabledProfiles, scenarioId])]
      : enabledProfiles.filter((id) => id !== scenarioId)
    setBusyScenario(scenarioId)
    setError('')
    setMessage('')
    let saved = false
    try {
      await updateScenarioProfiles(api, selected, nextProfiles)
      saved = true
      await onChanged()
      if (selected.desired_state === 'running') {
        const action = await api.traps.action(selected.trap_id, 'restart')
        let progress = action
        for (let attempt = 0; progress.status === 'queued' && attempt < 30; attempt += 1) {
          await new Promise((resolve) => window.setTimeout(resolve, 2000))
          progress = await api.traps.actionStatus(selected.trap_id, action.action_id)
        }
        if (progress.status === 'failed') throw new Error(progress.detail || 'Не удалось применить сценарий.')
        setMessage(progress.status === 'succeeded'
          ? `Сценарий ${enabled ? 'включён' : 'выключен'} и применён.`
          : 'Изменение сохранено; проверь состояние ловушки.')
        await onChanged()
      } else {
        setMessage(`Сценарий ${enabled ? 'включён' : 'выключен'}; он применится при запуске ловушки.`)
      }
    } catch (cause) {
      setError(`${saved ? 'Изменение сохранено, но применение не завершилось: ' : ''}${apiErrorMessage(cause)}`)
      if (saved) await onChanged()
    } finally {
      setBusyScenario(null)
    }
  }

  return <section className="space-y-4 rounded-xl border border-orange-300/20 bg-orange-300/[0.035] p-4 sm:p-5">
    <header>
      <h3 className="font-semibold">Назначить сценарии конкретной ловушке</h3>
      <p className="mt-1 text-xs leading-5 text-white/50">Выбери Middle-ловушку. Переключатель сразу сохранит сценарий и перезапустит работающую ловушку.</p>
    </header>
    <label className="block max-w-lg text-sm text-white/75">Ловушка<select value={selected?.trap_id ?? ''} onChange={(event) => { setSelectedId(event.target.value); setMessage(''); setError('') }} disabled={!middleTraps.length || !!busyScenario} className="mt-2 w-full rounded-lg border border-white/10 bg-[#100a09] px-3 py-2.5 text-sm text-white outline-none focus:border-orange-400/40">
      {!middleTraps.length && <option value="">Нет Middle-ловушек для этой ОС</option>}
      {middleTraps.map((trap) => <option key={trap.trap_id} value={trap.trap_id}>{trap.name}</option>)}
    </select></label>
    {!middleTraps.length ? <p className="text-xs text-white/45">Создай {windows ? 'Windows' : 'Linux'} Middle в разделе «Инфраструктура».</p> : <div className="grid gap-2 sm:grid-cols-2">
      {options.map((scenario) => {
        const enabled = enabledProfiles.includes(scenario.id)
        const busy = busyScenario === scenario.id
        return <label key={scenario.id} className={`flex items-start gap-3 rounded-lg border p-3 ${enabled ? 'border-orange-400/30 bg-orange-400/[0.06]' : 'border-white/10 bg-black/10'} ${readOnly || busyScenario ? 'opacity-60' : 'cursor-pointer'}`}>
          <input type="checkbox" checked={enabled} disabled={readOnly || !!busyScenario} onChange={(event) => void setEnabled(scenario.id, event.target.checked)} className="mt-0.5 accent-orange-400"/>
          <span className="min-w-0"><span className="block text-sm text-white/85">{scenario.name}{busy && <span className="ml-2 text-xs text-orange-200">Применяем…</span>}</span><span className="mt-1 block text-xs leading-5 text-white/45">{scenario.protocol} · {scenario.description}</span></span>
        </label>
      })}
    </div>}
    {error && <p role="alert" className="text-sm text-red-200">{error}</p>}
    {message && <p role="status" className="text-sm text-emerald-200">{message}</p>}
  </section>
}
