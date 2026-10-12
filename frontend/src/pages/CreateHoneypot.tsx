import { statusLabel } from '../i18n/labels'
import { useMemo, useState, type FormEvent } from 'react'
import FuzzyText from '../components/FuzzyText'
import { apiErrorMessage } from '../api/client'
import type { MellCoreApi } from '../api/services'
import type { Profile, Server } from '../api/types'

type Props = { api: MellCoreApi; profiles: Profile[]; servers: Server[]; readOnly: boolean; onCreated: () => Promise<void> }

export default function CreateHoneypot({ api, profiles, servers, readOnly, onCreated }: Props) {
  const supported = useMemo(() => profiles.filter((profile) => profile.level === 'low' || profile.level === 'medium'), [profiles])
  const [name, setName] = useState('')
  const [serverId, setServerId] = useState('')
  const [profileId, setProfileId] = useState('')
  const [hostPort, setHostPort] = useState('2222')
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const profile = supported.find((item) => item.id === profileId)

  async function submit(event: FormEvent) {
    event.preventDefault(); setError(''); setMessage('')
    if (!serverId || !profile) return setError('Выберите зарегистрированный сервер и поддерживаемый профиль.')
    setBusy(true)
    try {
      await api.traps.create(serverId, { name, profile_id: profile.id, config: {}, desired_state: 'stopped', ports: [{ transport: 'tcp', host_port: Number(hostPort), target_port: 2222, route_mode: 'direct' }] })
      setMessage('Конфигурация ловушки создана.')
      setName('')
      await onCreated()
    } catch (requestError) { setError(apiErrorMessage(requestError)) }
    finally { setBusy(false) }
  }

  return <section className="space-y-6 p-6"><div className="mx-auto max-w-4xl"><div className="mb-6 text-center"><p className="text-sm text-white/45">КОНФИГУРАЦИЯ</p><div className="mt-3 flex justify-center"><FuzzyText fontSize={28} fontWeight={600} color="#f1a36b" baseIntensity={0.2} hoverIntensity={0.5} fuzzRange={8} fps={30} enableHover className="block">Создать ловушку</FuzzyText></div><p className="mt-3 text-sm text-white/45">Задайте имя, сервер, профиль и публичный порт SSH.</p></div>
    <form onSubmit={submit} className="w-full space-y-6 rounded-xl border border-white/10 bg-[#160e0c]/80 p-6 backdrop-blur-xl">
      <label className="block text-sm text-white/70">Название ловушки<input required disabled={readOnly} value={name} onChange={(e) => setName(e.target.value)} placeholder="Например, SSH-ловушка 01" className="mt-2 w-full rounded-lg border border-white/10 bg-black/20 px-4 py-3 outline-none focus:border-orange-500/50" /></label>
      <div className="grid gap-4 sm:grid-cols-2"><label className="text-sm text-white/70">Сервер<select required disabled={readOnly} value={serverId} onChange={(e) => setServerId(e.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-[#100a09] px-4 py-3"><option value="">Выберите сервер</option>{servers.map((server) => <option key={server.server_id} value={server.server_id}>{server.name} — {server.host}</option>)}</select></label><label className="text-sm text-white/70">Профиль<select required disabled={readOnly} value={profileId} onChange={(e) => setProfileId(e.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-[#100a09] px-4 py-3"><option value="">Выберите профиль низкого или среднего уровня</option>{supported.map((item) => <option key={item.id} value={item.id}>{item.name} ({statusLabel(item.level)})</option>)}</select></label></div>
      {profile && <div className="grid grid-cols-3 gap-3">{[['Уровень', statusLabel(profile.level)], ['Тип', profile.honeypot_type], ['Служба', profile.service_type]].map(([label, value]) => <div key={label} className="rounded-lg border border-white/10 bg-black/20 p-3"><p className="text-[10px] uppercase text-white/35">{label}</p><p className="mt-1 text-sm capitalize">{value}</p></div>)}</div>}
      <label className="block text-sm text-white/70">Порт ловушки
        <input required disabled={readOnly} type="number" min="1" max="65535" value={hostPort} onChange={(e) => setHostPort(e.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-black/20 px-4 py-3" />
        <span className="mt-1 block text-xs text-white/40">Внешний TCP-порт для SSH-подключений к ловушке. Внутри контейнера SSH слушает 2222.</span>
      </label>
      {error && <p role="alert" className="text-sm text-red-400">{error}</p>}{message && <p role="status" className="text-sm text-emerald-300">{message}</p>}
      {!readOnly && <button disabled={busy || !servers.length || !supported.length} className="rounded-lg border border-orange-500/30 bg-orange-500/10 px-5 py-3 text-sm font-medium text-[#f1a36b] disabled:opacity-40">{busy ? 'Сохранение…' : 'Сохранить конфигурацию'}</button>}
    </form></div></section>
}
