import { useState } from 'react'
import type { MellCoreApi } from '../api/services'
import type { Trap } from '../api/types'
import { linuxScenarioOptions, windowsScenarioOptions } from '../vulnerabilities/scenarioCatalog'
import ScenarioAssignmentPanel from './ScenarioAssignmentPanel'
import HighGuestSettings from './HighGuestSettings'

type Props = { api: MellCoreApi; traps: Trap[]; readOnly: boolean; onChanged: () => Promise<void> }

export default function Vulnerabilities({ api, traps, readOnly, onChanged }: Props) {
  const [windows, setWindows] = useState(false)

  return <section className="space-y-5 p-6">
    <header>
      <h2 className="text-2xl font-semibold">Настроить уязвимости ловушки</h2>
      <p className="mt-2 max-w-2xl text-sm leading-6 text-white/55">Настрой сценарии для Middle или SSH-уязвимости внутри Linux High.</p>
    </header>

    <div role="tablist" aria-label="Операционная система ловушки" className="inline-flex rounded-lg border border-white/10 bg-black/20 p-1">
      {([false, true] as const).map((isWindows) => <button
        key={String(isWindows)}
        type="button"
        role="tab"
        aria-selected={windows === isWindows}
        onClick={() => setWindows(isWindows)}
        className={`rounded-md px-4 py-2 text-sm transition ${windows === isWindows ? 'bg-orange-400/15 text-orange-100' : 'text-white/50 hover:text-white/80'}`}
      >{isWindows ? 'Windows' : 'Linux'}</button>)}
    </div>

    <ScenarioAssignmentPanel
      api={api}
      traps={traps}
      options={windows ? windowsScenarioOptions : linuxScenarioOptions}
      windows={windows}
      readOnly={readOnly}
      onChanged={onChanged}
    />
    <HighGuestSettings api={api} traps={traps} readOnly={readOnly} onChanged={onChanged} mode="vulnerabilities" />
  </section>
}
