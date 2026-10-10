
import { useState, type FormEvent } from 'react'

type AuthMethod = 'password' | 'key'

export default function ConnectServer() {
  const [host, setHost] = useState('')
  const [port, setPort] = useState('22')
  const [username, setUsername] = useState('')
  const [authMethod, setAuthMethod] = useState<AuthMethod>('password')
  const [password, setPassword] = useState('')
  const [privateKey, setPrivateKey] = useState('')
  const [status, setStatus] = useState<'idle' | 'testing' | 'demo'>('idle')

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setStatus('demo')
  }

  return (
    <section className="space-y-6 p-6">
      <div>
        <p className="text-sm text-white/40">INFRASTRUCTURE</p>
        <h1 className="mt-2 text-2xl font-semibold">Connect server</h1>
        <p className="mt-2 text-sm text-white/45">
          Connect your VPS to deploy and manage honeypots.
        </p>
      </div>

      <div className="grid gap-6 xl:grid-cols-[1.4fr_1fr]">
        <form
          onSubmit={handleSubmit}
          className="space-y-5 rounded-xl border border-white/10 bg-[#160e0c]/85 p-6 backdrop-blur-xl"
        >
          <div>
            <h2 className="font-semibold">SSH connection</h2>
            <p className="mt-1 text-xs text-white/40">
              Enter your server connection details.
            </p>
          </div>

          <div>
            <label className="mb-2 block text-sm text-white/60">
              Server IP or hostname
            </label>
            <input
              required
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder="192.0.2.10"
              className="w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 text-sm outline-none focus:border-orange-500/60"
            />
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label className="mb-2 block text-sm text-white/60">
                SSH username
              </label>
              <input
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="root"
                autoComplete="username"
                className="w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 text-sm outline-none focus:border-orange-500/60"
              />
            </div>

            <div>
              <label className="mb-2 block text-sm text-white/60">
                SSH port
              </label>
              <input
                required
                type="number"
                min="1"
                max="65535"
                value={port}
                onChange={(e) => setPort(e.target.value)}
                className="w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 text-sm outline-none focus:border-orange-500/60"
              />
            </div>
          </div>

          <div>
            <label className="mb-2 block text-sm text-white/60">
              Authentication method
            </label>
            <div className="grid grid-cols-2 gap-3">
              <button
                type="button"
                onClick={() => setAuthMethod('password')}
                className={`rounded-lg border p-3 text-sm transition ${
                  authMethod === 'password'
                    ? 'border-orange-500/50 bg-orange-500/10 text-[#f1a36b]'
                    : 'border-white/10 text-white/50 hover:bg-white/5'
                }`}
              >
                SSH password
              </button>
              <button
                type="button"
                onClick={() => setAuthMethod('key')}
                className={`rounded-lg border p-3 text-sm transition ${
                  authMethod === 'key'
                    ? 'border-orange-500/50 bg-orange-500/10 text-[#f1a36b]'
                    : 'border-white/10 text-white/50 hover:bg-white/5'
                }`}
              >
                SSH private key
              </button>
            </div>
          </div>

          {authMethod === 'password' ? (
            <div>
              <label className="mb-2 block text-sm text-white/60">
                SSH password
              </label>
              <input
                required
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="off"
                placeholder="Enter SSH password"
                className="w-full rounded-lg border border-white/10 bg-black/30 px-4 py-3 text-sm outline-none focus:border-orange-500/60"
              />
            </div>
          ) : (
            <div>
              <label className="mb-2 block text-sm text-white/60">
                Private key
              </label>
              <textarea
                required
                rows={5}
                value={privateKey}
                onChange={(e) => setPrivateKey(e.target.value)}
                placeholder="Paste your private key"
                autoComplete="off"
                className="w-full resize-y rounded-lg border border-white/10 bg-black/30 px-4 py-3 font-mono text-xs outline-none focus:border-orange-500/60"
              />
              <p className="mt-2 text-xs text-white/35">
                Demo form only. Do not paste a real private key here.
              </p>
            </div>
          )}

          <button
            type="submit"
            className="w-full rounded-lg border border-orange-400/40 bg-orange-600/80 px-4 py-3 text-sm font-semibold transition hover:bg-orange-500"
          >
            Test connection →
          </button>

          {status === 'demo' && (
            <div
              role="status"
              className="rounded-lg border border-orange-500/20 bg-orange-500/5 p-4 text-sm text-orange-200"
            >
              Demo mode: no SSH connection was made. Backend integration is
              required to verify this server.
            </div>
          )}
        </form>

        <aside className="space-y-4">
          <div className="rounded-xl border border-white/10 bg-[#160e0c]/85 p-5">
            <h2 className="font-semibold">Connection status</h2>
            <div className="mt-5 flex items-center gap-3">
              <span className="h-2.5 w-2.5 rounded-full bg-white/25" />
              <span className="text-sm text-white/55">
                {status === 'demo'
                  ? 'Not verified'
                  : 'Waiting for connection'}
              </span>
            </div>
            <p className="mt-3 text-xs leading-5 text-white/35">
              The server will be verified when the MellCore backend is
              connected.
            </p>
          </div>

          <div className="rounded-xl border border-white/10 bg-[#160e0c]/85 p-5">
            <h2 className="font-semibold">Before connecting</h2>
            <ul className="mt-4 space-y-3 text-sm text-white/50">
              <li>• Make sure SSH access is enabled.</li>
              <li>• Confirm that the SSH port is reachable.</li>
              <li>• Use a dedicated account with appropriate permissions.</li>
            </ul>
          </div>
        </aside>
      </div>
    </section>
  )
}