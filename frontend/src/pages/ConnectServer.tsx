import { useEffect, useState, type FormEvent } from 'react'
import { ApiError, apiErrorMessage } from '../api/client'
import type { MellCoreApi } from '../api/services'
import type { BootstrapProgress, ServerInput } from '../api/types'
import type { ToastKind } from '../components/ToastNotifications'

type Props = {
  api: MellCoreApi
  readOnly: boolean
  onChanged: () => Promise<void>
  notify: (kind: ToastKind, title: string, message: string) => void
}

const emptyServer: ServerInput = {
  name: '', host: '', ssh_port: 22, ssh_user: 'root',
  credential_ref: null, dispatcher_port: null, settings: {},
}

type BootstrapOutcome = { status: 'succeeded' | 'failed'; message: string }
const outcomeKey = 'mellcore-last-bootstrap-outcome'

function savedOutcome(): BootstrapOutcome | null {
  try {
    const value = JSON.parse(window.sessionStorage.getItem(outcomeKey) || 'null') as BootstrapOutcome | null
    return value && (value.status === 'succeeded' || value.status === 'failed') && typeof value.message === 'string'
      ? value : null
  } catch {
    return null
  }
}

export default function ConnectServer({ api, readOnly, onChanged, notify }: Props) {
  const [form, setForm] = useState<ServerInput>(emptyServer)
  const [busy, setBusy] = useState(false)
  const [authKind, setAuthKind] = useState<'password' | 'key'>('password')
  const [sshSecret, setSshSecret] = useState('')
  const [keyPassphrase, setKeyPassphrase] = useState('')
  const [pendingServerId, setPendingServerId] = useState<string | null>(
    () => window.localStorage.getItem('mellcore-pending-bootstrap'),
  )
  const [progress, setProgress] = useState<BootstrapProgress | null>(null)
  const [outcome, setOutcome] = useState<BootstrapOutcome | null>(savedOutcome)
  const [checkError, setCheckError] = useState('')

  const finish = (next: BootstrapOutcome) => {
    window.localStorage.removeItem('mellcore-pending-bootstrap')
    window.sessionStorage.setItem(outcomeKey, JSON.stringify(next))
    setPendingServerId(null)
    setProgress(null)
    setCheckError('')
    setOutcome(next)
  }

  useEffect(() => {
    if (!pendingServerId) return
    let cancelled = false
    let finished = false
    let pollErrorShown = false
    let timer = 0
    async function poll() {
      try {
        const result = await api.servers.bootstrapStatus(pendingServerId!)
        if (cancelled) return
        pollErrorShown = false
        setCheckError('')
        setProgress(result)
        if (result.status !== 'running') {
          finished = true
          if (result.status === 'succeeded') {
            finish({ status: 'succeeded', message: 'Агент установлен и зарегистрирован. Сервер готов к работе.' })
            notify('success', 'Сервер подключён', 'Агент установлен и зарегистрирован. Сервер готов к работе.')
            await onChanged()
          } else {
            const message = result.message || 'Центр не подтвердил установку. Если данные SSH верны, проверьте /tmp/hf-agent-bootstrap.log на целевом сервере и журнал hf-center на сервере MellCore.'
            finish({ status: 'failed', message })
            notify('error', 'Не удалось установить агента', message)
          }
        }
      } catch (requestError) {
        if (!cancelled && requestError instanceof ApiError && requestError.status === 404) {
          finished = true
          const message = 'Задание установки не найдено. Центр мог перезапуститься во время подключения.'
          finish({ status: 'failed', message })
          notify('error', 'Задание установки не найдено', message)
        } else if (!cancelled && !pollErrorShown) {
          pollErrorShown = true
          const message = `Не удалось проверить статус установки. Проверка продолжится автоматически. ${apiErrorMessage(requestError)}`
          setCheckError(message)
          notify('error', 'Не удалось проверить установку', message)
        }
      } finally {
        if (!cancelled && !finished) timer = window.setTimeout(() => { void poll() }, 3000)
      }
    }
    void poll()
    return () => { cancelled = true; window.clearTimeout(timer) }
  }, [api, onChanged, notify, pendingServerId])

  const update = <K extends keyof ServerInput>(key: K, value: ServerInput[K]) =>
    setForm((current) => ({ ...current, [key]: value }))

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setBusy(true)
    const serverName = form.name.trim()
    try {
      const result = await api.servers.bootstrap({
        server: { ...form, name: form.name.trim(), host: form.host.trim(), ssh_user: form.ssh_user.trim() },
        ssh_password: authKind === 'password' ? sshSecret : null,
        ssh_private_key: authKind === 'key' ? sshSecret : null,
        ssh_key_passphrase: authKind === 'key' && keyPassphrase ? keyPassphrase : null,
      })
      setForm({ ...emptyServer })
      setSshSecret('')
      setKeyPassphrase('')
      window.localStorage.setItem('mellcore-pending-bootstrap', result.server_id)
      window.sessionStorage.removeItem(outcomeKey)
      setOutcome(null)
      setProgress(result)
      setCheckError('')
      notify('info', 'Установка началась', `Подключаю «${serverName}» и ожидаю регистрации агента.`)
      setPendingServerId(result.server_id)
      await onChanged().catch(() => undefined)
    } catch (requestError) {
      notify('error', 'Не удалось подключить сервер', apiErrorMessage(requestError))
    } finally {
      setBusy(false)
    }
  }

  return <section className="flex min-h-[calc(100vh-72px)] items-center justify-center p-4 sm:p-8">
    <div className="w-full max-w-xl space-y-5">
      <div className="text-center">
        <p className="text-xs uppercase tracking-[0.18em] text-orange-300/70">Инфраструктура</p>
        <h1 className="mt-3 text-2xl font-semibold">Добавить сервер</h1>
        <p className="mt-2 text-sm text-white/50">Укажите понятное название и адрес сервера.</p>
      </div>

      {pendingServerId && <div role="status" className="rounded-xl border border-orange-400/40 bg-orange-500/10 p-4 text-sm text-orange-100">
        <p className="font-semibold">Установка агента продолжается</p>
        <p className="mt-1 text-orange-100/75">{checkError || progress?.message || (progress?.registered
          ? 'Агент зарегистрирован. Ожидаю завершения установки.'
          : 'Ожидаю подтверждения от Центра.')}</p>
      </div>}
      {!pendingServerId && outcome && <div role={outcome.status === 'failed' ? 'alert' : 'status'} className={`rounded-xl border p-4 text-sm ${outcome.status === 'succeeded' ? 'border-emerald-400/40 bg-emerald-500/10 text-emerald-100' : 'border-red-400/40 bg-red-500/10 text-red-100'}`}>
        <p className="font-semibold">{outcome.status === 'succeeded' ? 'Сервер подключён' : 'Установка не завершилась'}</p>
        <p className="mt-1 opacity-75">{outcome.message}</p>
      </div>}

      <form onSubmit={save} className="space-y-5 rounded-xl border border-white/10 bg-[#160e0c]/85 p-5 backdrop-blur-xl sm:p-8">
        <label className="block text-sm text-white/70">Название сервера
          <input required disabled={readOnly || busy} value={form.name} onChange={(event) => update('name', event.target.value)} placeholder="Например, VPS Москва" className="mt-2 w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 outline-none focus:border-orange-500/60" />
        </label>
        <label className="block text-sm text-white/70">IP-адрес или домен
          <input required disabled={readOnly || busy} value={form.host} onChange={(event) => update('host', event.target.value)} placeholder="192.0.2.10" className="mt-2 w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 outline-none focus:border-orange-500/60" />
        </label>
        <div className="grid gap-4 sm:grid-cols-[1fr_8rem]">
          <label className="block text-sm text-white/70">Пользователь SSH
            <input required disabled={readOnly || busy} value={form.ssh_user} onChange={(event) => update('ssh_user', event.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 outline-none focus:border-orange-500/60" />
          </label>
          <label className="block text-sm text-white/70">Порт SSH
            <input required disabled={readOnly || busy} type="number" min="1" max="65535" value={form.ssh_port} onChange={(event) => update('ssh_port', Number(event.target.value))} className="mt-2 w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 outline-none focus:border-orange-500/60" />
          </label>
        </div>
        <label className="block text-sm text-white/70">Авторизация SSH
          <select disabled={readOnly || busy} value={authKind} onChange={(event) => { setAuthKind(event.target.value as 'password' | 'key'); setSshSecret('') }} className="mt-2 w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3">
            <option value="password">Пароль</option><option value="key">Приватный ключ</option>
          </select>
        </label>
        <label className="block text-sm text-white/70">{authKind === 'password' ? 'Пароль SSH' : 'Приватный ключ SSH'}
          {authKind === 'password'
            ? <input required type="password" autoComplete="off" disabled={readOnly || busy} value={sshSecret} onChange={(event) => setSshSecret(event.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3" />
            : <textarea required disabled={readOnly || busy} value={sshSecret} onChange={(event) => setSshSecret(event.target.value)} rows={5} className="mt-2 w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3" />}
        </label>
        {authKind === 'key' && <label className="block text-sm text-white/70">Пароль ключа (если есть)
          <input type="password" autoComplete="off" disabled={readOnly || busy} value={keyPassphrase} onChange={(event) => setKeyPassphrase(event.target.value)} className="mt-2 w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3" />
        </label>}
        {readOnly ? <p className="text-sm text-white/50">Роль наблюдателя допускает только просмотр.</p> : <button type="submit" disabled={busy || Boolean(pendingServerId)} className="w-full rounded-lg bg-orange-600 px-5 py-3 text-sm font-semibold disabled:opacity-50">{busy ? 'Подключение…' : 'Подключить сервер и установить агента'}</button>}
      </form>
    </div>
  </section>
}
