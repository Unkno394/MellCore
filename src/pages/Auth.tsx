
import { useState, type FormEvent } from 'react'

type AuthProps = {
  onAuthenticated: () => void
}

export default function Auth({ onAuthenticated }: AuthProps) {
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [identifier, setIdentifier] = useState('')
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')

    if (mode === 'register') {
      if (password.length < 8) {
        setError('Пароль должен содержать минимум 8 символов.')
        return
      }

      if (password !== confirmPassword) {
        setError('Пароли не совпадают.')
        return
      }
    }

    // Демо-режим: настоящая авторизация появится после подключения backend.
    onAuthenticated()
  }

  return (
    <section className="flex min-h-screen items-center justify-center p-5">
      <div className="w-full max-w-md rounded-2xl border border-orange-500/20 bg-[#160e0c]/90 p-6 shadow-2xl shadow-black/40 backdrop-blur-xl sm:p-9">
        <div className="mb-8 text-center">
          <div className="mb-3 text-3xl font-bold tracking-[0.18em] text-[#f1a36b]">
            MellCore
          </div>
          <p className="text-xs uppercase tracking-[0.2em] text-white/40">
            Threat monitoring platform
          </p>
        </div>

        <div className="mb-7 grid grid-cols-2 border-b border-white/10">
          <button
            type="button"
            onClick={() => {
              setMode('login')
              setError('')
            }}
            className={`border-b-2 py-3 text-sm transition ${
              mode === 'login'
                ? 'border-orange-400 text-[#f1a36b]'
                : 'border-transparent text-white/45 hover:text-white'
            }`}
          >
            Login
          </button>

          <button
            type="button"
            onClick={() => {
              setMode('register')
              setError('')
            }}
            className={`border-b-2 py-3 text-sm transition ${
              mode === 'register'
                ? 'border-orange-400 text-[#f1a36b]'
                : 'border-transparent text-white/45 hover:text-white'
            }`}
          >
            Register
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-5">
          {mode === 'register' && (
            <>
              <div>
                <label className="mb-2 block text-sm text-white/65">
                  Username
                </label>
                <input
                  required
                  minLength={3}
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  placeholder="Enter your username"
                  autoComplete="username"
                  className="w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 text-sm outline-none transition placeholder:text-white/25 focus:border-orange-500/60"
                />
              </div>

              <div>
                <label className="mb-2 block text-sm text-white/65">
                  Email
                </label>
                <input
                  required
                  type="email"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  placeholder="you@example.com"
                  autoComplete="email"
                  className="w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 text-sm outline-none transition placeholder:text-white/25 focus:border-orange-500/60"
                />
              </div>
            </>
          )}

          {mode === 'login' && (
            <div>
              <label className="mb-2 block text-sm text-white/65">
                Email or username
              </label>
              <input
                required
                value={identifier}
                onChange={(event) => setIdentifier(event.target.value)}
                placeholder="Email or username"
                autoComplete="username"
                className="w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 text-sm outline-none transition placeholder:text-white/25 focus:border-orange-500/60"
              />
            </div>
          )}

          <div>
            <label className="mb-2 block text-sm text-white/65">
              Password
            </label>
            <input
              required
              type={showPassword ? 'text' : 'password'}
              minLength={mode === 'register' ? 8 : undefined}
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="Enter your password"
              autoComplete={
                mode === 'login' ? 'current-password' : 'new-password'
              }
              className="w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 text-sm outline-none transition placeholder:text-white/25 focus:border-orange-500/60"
            />
            <label className="mt-2 flex items-center gap-2 text-xs text-white/45">
              <input
                type="checkbox"
                checked={showPassword}
                onChange={(event) => setShowPassword(event.target.checked)}
                className="accent-orange-500"
              />
              Show password
            </label>
          </div>

          {mode === 'register' && (
            <div>
              <label className="mb-2 block text-sm text-white/65">
                Confirm password
              </label>
              <input
                required
                type="password"
                value={confirmPassword}
                onChange={(event) => setConfirmPassword(event.target.value)}
                placeholder="Repeat your password"
                autoComplete="new-password"
                className="w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 text-sm outline-none transition placeholder:text-white/25 focus:border-orange-500/60"
              />
            </div>
          )}

          {error && (
            <p role="alert" className="text-sm text-red-400">
              {error}
            </p>
          )}

          <button
            type="submit"
            className="w-full rounded-lg border border-orange-400/40 bg-gradient-to-r from-orange-700/80 to-orange-500/80 px-4 py-3 text-sm font-semibold text-white transition hover:brightness-110"
          >
            {mode === 'login' ? 'Sign in →' : 'Create account →'}
          </button>
        </form>

        <p className="mt-6 text-center text-sm text-white/45">
          {mode === 'login'
            ? "Don't have an account?"
            : 'Already have an account?'}
          {' '}
          <button
            type="button"
            onClick={() => {
              setMode(mode === 'login' ? 'register' : 'login')
              setError('')
            }}
            className="font-medium text-[#f1a36b] hover:text-orange-300"
          >
            {mode === 'login' ? 'Register' : 'Login'}
          </button>
        </p>

        <p className="mt-6 text-center text-[10px] text-white/25">
          DEMO MODE · AUTHENTICATION NOT CONNECTED
        </p>
      </div>
    </section>
  )
}