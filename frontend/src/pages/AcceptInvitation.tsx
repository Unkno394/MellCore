import { useMemo, useState, type FormEvent } from 'react'
import { apiErrorMessage } from '../api/client'
import type { MellCoreApi } from '../api/services'

export default function AcceptInvitation({ api }: { api: MellCoreApi }) {
  const token = useMemo(() => new URLSearchParams(window.location.hash.slice(1)).get('token') ?? '', [])
  const [name, setName] = useState('')
  const [password, setPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [accepted, setAccepted] = useState(false)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    if (!token) return setError('В ссылке отсутствует токен приглашения.')
    if (password.length < 12) return setError('Пароль должен содержать не менее 12 символов.')
    if (password !== confirmation) return setError('Пароли не совпадают.')
    setBusy(true)
    try {
      await api.auth.acceptInvitation(token, name, password)
      setAccepted(true)
    } catch (requestError) {
      setError(apiErrorMessage(requestError))
    } finally {
      setBusy(false)
    }
  }

  return <section className="flex min-h-screen items-center justify-center p-5"><div className="w-full max-w-md rounded-2xl border border-orange-500/20 bg-[#160e0c]/90 p-6 shadow-2xl shadow-black/40 sm:p-9"><div className="mb-7 text-center"><div className="text-3xl font-bold tracking-[0.18em] text-[#f1a36b]">MellCore</div><h1 className="mt-5 text-xl font-semibold">Приглашение в команду</h1><p className="mt-2 text-sm text-white/45">Создайте аккаунт — назначенные администратором роли применятся автоматически.</p></div>{accepted ? <div className="space-y-5 text-center"><p className="rounded-lg border border-emerald-400/20 bg-emerald-400/5 p-4 text-sm text-emerald-200">Аккаунт создан. Приглашение больше нельзя использовать.</p><a href="/" className="inline-block rounded-lg bg-orange-600 px-5 py-3 text-sm font-semibold">Перейти ко входу</a></div> : <form onSubmit={submit} className="space-y-5"><label className="block text-sm text-white/65">Ваше имя<input required maxLength={128} value={name} onChange={(event) => setName(event.target.value)} autoComplete="name" className="mt-2 w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 outline-none focus:border-orange-500/60"/></label><label className="block text-sm text-white/65">Пароль<input required type="password" minLength={12} maxLength={256} value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password" className="mt-2 w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 outline-none focus:border-orange-500/60"/></label><label className="block text-sm text-white/65">Повторите пароль<input required type="password" minLength={12} maxLength={256} value={confirmation} onChange={(event) => setConfirmation(event.target.value)} autoComplete="new-password" className="mt-2 w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 outline-none focus:border-orange-500/60"/></label>{error && <p role="alert" className="text-sm text-red-400">{error}</p>}<button disabled={busy || !token} className="w-full rounded-lg bg-orange-600 px-5 py-3 text-sm font-semibold disabled:opacity-40">{busy ? 'Создаём аккаунт…' : 'Принять приглашение'}</button>{!token && <p className="text-center text-xs text-white/35">Откройте полную ссылку, которую прислал администратор.</p>}</form>}</div></section>
}
