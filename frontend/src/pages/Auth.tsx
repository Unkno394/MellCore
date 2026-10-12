import { useState, type FormEvent } from 'react'
import { apiErrorMessage } from '../api/client'
import type { MellCoreApi } from '../api/services'
import type { AuthSession } from '../auth/session'
import { createSession, saveSession } from '../auth/session'

type AuthMode = 'login' | 'register' | 'forgot' | 'resend'

type AuthProps = {
  api: MellCoreApi
  onAuthenticated: (session: AuthSession) => void
  notice?: string
}

export default function Auth({ api, onAuthenticated, notice }: AuthProps) {
  const [mode, setMode] = useState<AuthMode>('login')
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState(notice ?? '')
  const [submitting, setSubmitting] = useState(false)

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    setMessage('')
    if (mode === 'register' && password.length < 12) {
      setError('Пароль должен содержать не менее 12 символов.')
      return
    }
    if (mode === 'register' && password !== confirmPassword) {
      setError('Пароли не совпадают.')
      return
    }

    setSubmitting(true)
    try {
      if (mode === 'login') {
        const response = await api.auth.login(email, password)
        const session = createSession(response)
        saveSession(session)
        onAuthenticated(session)
      } else if (mode === 'register') {
        await api.auth.register(name, email, password)
        setPassword('')
        setConfirmPassword('')
        setMode('login')
        setMessage('Аккаунт создан. Войдите по электронной почте. Возможно, потребуется подтвердить адрес.')
      } else if (mode === 'forgot') {
        await api.auth.forgotPassword(email)
        setMessage('Если адрес зарегистрирован, на него отправлена инструкция по восстановлению пароля.')
      } else {
        await api.auth.resendVerification(email)
        setMessage('Если адрес зарегистрирован, на него отправлена новая ссылка для подтверждения.')
      }
    } catch (requestError) {
      setError(apiErrorMessage(requestError))
    } finally {
      setSubmitting(false)
    }
  }

  const title = mode === 'forgot' ? 'Восстановление пароля' : mode === 'resend' ? 'Подтверждение почты' : null

  return (
    <section className="flex min-h-screen items-center justify-center p-5">
      <div className="w-full max-w-md rounded-2xl border border-orange-500/20 bg-[#160e0c]/90 p-6 shadow-2xl shadow-black/40 backdrop-blur-xl sm:p-9">
        <div className="mb-8 text-center">
          <div className="mb-3 text-3xl font-bold tracking-[0.18em] text-[#f1a36b]">MellCore</div>
          <p className="text-xs uppercase tracking-[0.2em] text-white/40">Платформа мониторинга угроз</p>
        </div>

        {title ? (
          <div className="mb-7 border-b border-white/10 pb-4 text-center"><h2 className="text-lg font-semibold">{title}</h2></div>
        ) : (
          <div className="mb-7 grid grid-cols-2 border-b border-white/10">
            {(['login', 'register'] as const).map((item) => (
              <button key={item} type="button" onClick={() => { setMode(item); setError(''); setMessage('') }} className={`border-b-2 py-3 text-sm capitalize transition ${mode === item ? 'border-orange-400 text-[#f1a36b]' : 'border-transparent text-white/45 hover:text-white'}`}>{item === 'login' ? 'Вход' : 'Регистрация'}</button>
            ))}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-5">
          {mode === 'register' && (
            <label className="block text-sm text-white/65">Имя<input required value={name} onChange={(event) => setName(event.target.value)} placeholder="Ваше имя" autoComplete="name" className="mt-2 w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 outline-none transition placeholder:text-white/25 focus:border-orange-500/60" /></label>
          )}

          <label className="block text-sm text-white/65">Электронная почта<input required type="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@example.com" autoComplete="email" className="mt-2 w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 outline-none transition placeholder:text-white/25 focus:border-orange-500/60" /></label>

          {(mode === 'login' || mode === 'register') && (
            <div>
              <label className="block text-sm text-white/65">Пароль<input required type={showPassword ? 'text' : 'password'} minLength={mode === 'register' ? 12 : undefined} maxLength={256} value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Введите пароль" autoComplete={mode === 'login' ? 'current-password' : 'new-password'} className="mt-2 w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 outline-none transition placeholder:text-white/25 focus:border-orange-500/60" /></label>
              <label className="mt-2 flex items-center gap-2 text-xs text-white/45"><input type="checkbox" checked={showPassword} onChange={(event) => setShowPassword(event.target.checked)} className="accent-orange-500" />Показать пароль</label>
            </div>
          )}

          {mode === 'register' && (
            <label className="block text-sm text-white/65">Подтвердите пароль<input required type="password" minLength={12} maxLength={256} value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} placeholder="Повторите пароль" autoComplete="new-password" className="mt-2 w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 outline-none transition placeholder:text-white/25 focus:border-orange-500/60" /></label>
          )}

          {error && <p role="alert" className="text-sm text-red-400">{error}</p>}
          {message && <p role="status" className="text-sm text-emerald-300">{message}</p>}

          <button type="submit" disabled={submitting} className="w-full rounded-lg border border-orange-400/40 bg-gradient-to-r from-orange-700/80 to-orange-500/80 px-4 py-3 text-sm font-semibold text-white transition hover:brightness-110 disabled:cursor-wait disabled:opacity-60">
            {submitting ? 'Подождите…' : mode === 'login' ? 'Войти →' : mode === 'register' ? 'Создать аккаунт →' : mode === 'forgot' ? 'Отправить инструкцию →' : 'Отправить письмо повторно →'}
          </button>
        </form>

        <div className="mt-6 flex flex-wrap justify-center gap-x-4 gap-y-2 text-xs">
          {mode === 'login' ? <><button type="button" onClick={() => setMode('forgot')} className="text-white/45 hover:text-orange-300">Забыли пароль?</button><button type="button" onClick={() => setMode('resend')} className="text-white/45 hover:text-orange-300">Повторить подтверждение</button></> : <button type="button" onClick={() => setMode('login')} className="text-[#f1a36b] hover:text-orange-300">Вернуться ко входу</button>}
        </div>
        <p className="mt-6 text-center text-[10px] text-white/25">СЕАНС ПРОДЛЕВАЕТСЯ АВТОМАТИЧЕСКИ</p>
      </div>
    </section>
  )
}
