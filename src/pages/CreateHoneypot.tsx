import FuzzyText from '../components/FuzzyText'
import { useState } from 'react'
import type { Honeypot } from '../data/honeypots'

type Level = 'Low' | 'Medium' | 'High'

type CreateHoneypotProps = {
  onCreateHoneypot: (honeypot: Honeypot, level: Level) => void
}
  
  export default function CreateHoneypot({
    onCreateHoneypot,
  }: CreateHoneypotProps) {
  const [level, setLevel] = useState<Level>('Low')
  const [name, setName] = useState('')
  const [service, setService] = useState('SSH')
  const [port, setPort] = useState('22')
  const [profile, setProfile] = useState('Linux server')
  const [operatingSystem, setOperatingSystem] = useState('Ubuntu 22.04')
  const [created, setCreated] = useState(false)

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
  
    const newHoneypot: Honeypot = {
      id: `HP-${Date.now()}`,
      name,
      ip: 'Not assigned',
      type: service,
      profile:
        level === 'Low'
          ? 'Basic'
          : level === 'Medium'
            ? profile
            : operatingSystem,
      status: 'Inactive',
      lastActivity: 'Never',
      sessions: 0,
      location: 'Not assigned',
      description: `${service} honeypot. Security level: ${level}. Port: ${port}.`,
    }
  
    onCreateHoneypot(newHoneypot, level)
    setCreated(true)
  }

  const levels: { value: Level; title: string; description: string }[] = [
    {
      value: 'Low',
      title: 'Low',
      description: 'Basic port and service simulation.',
    },
    {
      value: 'Medium',
      title: 'Medium',
      description: 'Simulated service with a behavior profile.',
    },
    {
      value: 'High',
      title: 'High',
      description: 'Advanced isolated environment simulation.',
    },
  ]

  
  return (
    <section className="space-y-6 p-6">
      <div className="mx-auto max-w-4xl">
        <div className="mb-6 text-center">
          <p className="text-sm text-white/45">Configuration</p>

          <div className="mt-3 flex justify-center">
            <FuzzyText
              fontSize={28}
              fontWeight={600}
              color="#f1a36b"
              baseIntensity={0.2}
              hoverIntensity={0.5}
              fuzzRange={8}
              fps={30}
              enableHover
              className="block"
            >
              Create Honeypot
            </FuzzyText>
          </div>

          <p className="mt-3 text-sm text-white/45">
            Configure a new honeypot for your monitoring environment.
          </p>
        </div>

        
        <form
          onSubmit={handleSubmit}
          className="w-full space-y-6 rounded-xl border border-white/10 bg-[#160e0c]/80 p-6 backdrop-blur-xl"
        >
        <div>
          <label className="mb-2 block text-sm text-white/70">
            Honeypot name
          </label>
          <input
            required
            value={name}
            onChange={(event) => {
              setName(event.target.value)
              setCreated(false)
            }}
            placeholder="e.g. SSH Honeypot 01"
            className="w-full rounded-lg border border-white/10 bg-black/20 px-4 py-3 text-sm outline-none transition focus:border-orange-500/50"
          />
        </div>

        <div>
          <h3 className="mb-3 text-sm font-medium">Security level</h3>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
            {levels.map((item) => (
              <button
                key={item.value}
                type="button"
                onClick={() => {
                  setLevel(item.value)
                  setCreated(false)
                }}
                className={`rounded-xl border p-4 text-left transition ${
                  level === item.value
                    ? 'border-orange-500/50 bg-orange-500/10'
                    : 'border-white/10 bg-black/10 hover:border-white/20'
                }`}
              >
                <div className="font-semibold text-[#f1a36b]">
                  {item.title}
                </div>
                <p className="mt-2 text-xs leading-5 text-white/45">
                  {item.description}
                </p>
                {level === item.value && (
                  <p className="mt-3 text-xs text-orange-300">Selected</p>
                )}
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div>
            <label className="mb-2 block text-sm text-white/70">
              Service type
            </label>
            <select
              value={service}
              onChange={(event) => {
                setService(event.target.value)
                setPort(
                  event.target.value === 'SSH'
                    ? '22'
                    : event.target.value === 'HTTP'
                      ? '80'
                      : '21',
                )
                setCreated(false)
              }}
              className="w-full rounded-lg border border-white/10 bg-[#100a09] px-4 py-3 text-sm outline-none focus:border-orange-500/50"
            >
              <option value="SSH">SSH</option>
              <option value="HTTP">HTTP</option>
              <option value="FTP">FTP</option>
            </select>
          </div>

          <div>
            <label className="mb-2 block text-sm text-white/70">
              Port
            </label>
            <input
              required
              type="number"
              min="1"
              max="65535"
              value={port}
              onChange={(event) => {
                setPort(event.target.value)
                setCreated(false)
              }}
              className="w-full rounded-lg border border-white/10 bg-black/20 px-4 py-3 text-sm outline-none focus:border-orange-500/50"
            />
          </div>

          {level === 'Medium' && (
            <div>
              <label className="mb-2 block text-sm text-white/70">
                Behavior profile
              </label>
              <select
                value={profile}
                onChange={(event) => {
                  setProfile(event.target.value)
                  setCreated(false)
                }}
                className="w-full rounded-lg border border-white/10 bg-[#100a09] px-4 py-3 text-sm outline-none focus:border-orange-500/50"
              >
                <option>Linux server</option>
                <option>Web server</option>
                <option>Database server</option>
              </select>
            </div>
          )}

          {level === 'High' && (
            <div>
              <label className="mb-2 block text-sm text-white/70">
                Operating system
              </label>
              <select
                value={operatingSystem}
                onChange={(event) => {
                  setOperatingSystem(event.target.value)
                  setCreated(false)
                }}
                className="w-full rounded-lg border border-white/10 bg-[#100a09] px-4 py-3 text-sm outline-none focus:border-orange-500/50"
              >
                <option>Ubuntu 22.04</option>
                <option>Debian 12</option>
                <option>Windows</option>
              </select>
            </div>
          )}
        </div>

        <div className="rounded-lg border border-orange-500/15 bg-orange-500/5 p-4">
          <p className="text-sm font-medium text-[#f1a36b]">
            Configuration summary
          </p>
          <p className="mt-2 text-xs leading-5 text-white/50">
            Level: {level} · Service: {service} · Port: {port}
            {level === 'Medium' && ` · Profile: ${profile}`}
            {level === 'High' && ` · OS: ${operatingSystem}`}
          </p>
        </div>

        <button
          type="submit"
          className="rounded-lg border border-orange-500/30 bg-orange-500/10 px-5 py-3 text-sm font-medium text-[#f1a36b] transition hover:bg-orange-500/20"
        >
          Create Honeypot
        </button>

        {created && (
          <p className="text-sm text-emerald-300">
            Demo configuration created. No server was deployed.
          </p>
        )}
        </form>
      </div>
    </section>
  )
}