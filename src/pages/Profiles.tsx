import type { Honeypot } from '../data/honeypots'
import { useState } from 'react'

type InteractionLevel = 'Low' | 'Medium' | 'High'
type ProfileStatus = 'Active' | 'Draft'

type Profile = {
  id: string
  name: string
  description: string
  interactionLevel: InteractionLevel
  operatingSystem: string
  assignedHoneypot: string
  status: ProfileStatus
  services: string[]
  updatedAt: string
}

const availableServices = ['SSH', 'HTTP', 'FTP', 'Telnet']

const initialProfiles: Profile[] = [
  {
    id: 'PR-001',
    name: 'Linux SSH Decoy',
    description: 'A Linux-style environment designed to observe suspicious login attempts.',
    interactionLevel: 'High',
    operatingSystem: 'Ubuntu Linux',
    assignedHoneypot: 'SSH Honeypot 01',
    status: 'Active',
    services: ['SSH', 'FTP'],
    updatedAt: 'Today, 14:32',
  },
  {
    id: 'PR-002',
    name: 'Web Frontline',
    description: 'A lightweight web environment for detecting scans and suspicious requests.',
    interactionLevel: 'Medium',
    operatingSystem: 'Debian Linux',
    assignedHoneypot: 'Web Honeypot 02',
    status: 'Active',
    services: ['HTTP', 'SSH'],
    updatedAt: 'Today, 12:08',
  },
  {
    id: 'PR-003',
    name: 'Legacy Service',
    description: 'A simulated legacy environment for observing automated service probes.',
    interactionLevel: 'Low',
    operatingSystem: 'Windows Server',
    assignedHoneypot: 'Network Sensor 03',
    status: 'Draft',
    services: ['FTP', 'Telnet'],
    updatedAt: 'Yesterday',
  },
]

const levelDescriptions: Record<InteractionLevel, string> = {
  Low: 'Basic responses · minimal interaction',
  Medium: 'Simulated services · extended responses',
  High: 'Deep interaction · richer activity logs',
}

const levelStyles: Record<InteractionLevel, string> = {
  Low: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300',
  Medium: 'border-orange-500/30 bg-orange-500/10 text-orange-300',
  High: 'border-red-500/30 bg-red-500/10 text-red-300',
}


type ProfilesProps = {
    honeypots: Honeypot[]
    onUpdateHoneypot: (honeypotId: string, profileName: string) => void
  }
  
  
export default function Profiles({
    honeypots,
    onUpdateHoneypot,
  }: ProfilesProps) {
    const [profiles, setProfiles] = useState<Profile[]>(initialProfiles)
    const [selectedId, setSelectedId] = useState('PR-001')
    const [saved, setSaved] = useState(false)

  const selectedProfile =
    profiles.find((profile) => profile.id === selectedId) ?? profiles[0]

  const activeCount = profiles.filter(
    (profile) => profile.status === 'Active',
  ).length

  const highInteractionCount = profiles.filter(
    (profile) => profile.interactionLevel === 'High',
  ).length

  function updateSelected<K extends keyof Profile>(
    key: K,
    value: Profile[K],
  ) {
    setProfiles((current) =>
      current.map((profile) =>
        profile.id === selectedId ? { ...profile, [key]: value } : profile,
      ),
    )
    setSaved(false)
  }

  function createProfile() {
    const newId = `PR-${String(profiles.length + 1).padStart(3, '0')}`

    const newProfile: Profile = {
      id: newId,
      name: 'New interaction profile',
      description: 'Describe what this profile is designed to observe.',
      interactionLevel: 'Medium',
      operatingSystem: 'Ubuntu Linux',
      assignedHoneypot: 'Unassigned',
      status: 'Draft',
      services: ['SSH'],
      updatedAt: 'Just created',
    }

    setProfiles((current) => [...current, newProfile])
    setSelectedId(newId)
    setSaved(false)
  }

  
function saveProfile() {
    setProfiles((current) =>
      current.map((profile) =>
        profile.id === selectedId
          ? { ...profile, updatedAt: 'Just now' }
          : profile,
      ),
    )
  
    if (selectedProfile.assignedHoneypot !== 'Unassigned') {
      const assignedHoneypot = honeypots.find(
        (honeypot) => honeypot.name === selectedProfile.assignedHoneypot,
      )
  
      if (assignedHoneypot) {
        onUpdateHoneypot(assignedHoneypot.id, selectedProfile.name)
      }
    }
  
    setSaved(true)
  }
  

  if (!selectedProfile) return null

  return (
    <section className="space-y-6 p-6">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.25em] text-orange-400/70">
            Configuration / 03
          </p>
          <h2 className="mt-2 text-2xl font-semibold tracking-tight">
            Interaction Profiles
          </h2>
          <p className="mt-2 max-w-xl text-sm leading-6 text-white/45">
            Configure how your decoys respond, what services they expose, and
            which honeypots use each profile.
          </p>
        </div>

        <button
          type="button"
          onClick={createProfile}
          className="flex shrink-0 items-center justify-center gap-2 rounded-lg border border-orange-400/30 bg-orange-500/10 px-4 py-3 text-sm font-medium text-orange-200 transition hover:border-orange-400/60 hover:bg-orange-500/20"
        >
          <span className="text-lg">+</span>
          Create profile
        </button>
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <article className="rounded-xl border border-white/10 bg-[#160e0c]/75 p-4 backdrop-blur-xl">
          <p className="text-xs uppercase tracking-wider text-white/40">
            Total profiles
          </p>
          <div className="mt-3 flex items-end justify-between">
            <span className="text-3xl font-semibold">{String(profiles.length).padStart(2, '0')}</span>
            <span className="text-xs text-white/35">Configurations</span>
          </div>
        </article>

        <article className="rounded-xl border border-white/10 bg-[#160e0c]/75 p-4 backdrop-blur-xl">
          <p className="text-xs uppercase tracking-wider text-white/40">
            Active profiles
          </p>
          <div className="mt-3 flex items-end justify-between">
            <span className="text-3xl font-semibold text-emerald-300">
              {String(activeCount).padStart(2, '0')}
            </span>
            <span className="text-xs text-white/35">Enabled</span>
          </div>
        </article>

        <article className="rounded-xl border border-white/10 bg-[#160e0c]/75 p-4 backdrop-blur-xl">
          <p className="text-xs uppercase tracking-wider text-white/40">
            High interaction
          </p>
          <div className="mt-3 flex items-end justify-between">
            <span className="text-3xl font-semibold text-orange-300">
              {String(highInteractionCount).padStart(2, '0')}
            </span>
            <span className="text-xs text-white/35">Deep simulation</span>
          </div>
        </article>
      </div>

      <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-[0.85fr_1.5fr]">
        <section className="min-w-0 rounded-xl border border-white/10 bg-[#160e0c]/75 p-4 backdrop-blur-xl">
          <div className="flex items-center justify-between gap-3 px-1 pb-4">
            <div>
              <h3 className="font-semibold">Profile library</h3>
              <p className="mt-1 text-xs text-white/40">
                Select a profile to configure
              </p>
            </div>
            <span className="rounded-md border border-white/10 px-2 py-1 text-xs text-white/40">
              {profiles.length} items
            </span>
          </div>

          <div className="space-y-2">
            {profiles.map((profile) => {
              const isSelected = profile.id === selectedId

              return (
                <button
                  key={profile.id}
                  type="button"
                  onClick={() => {
                    setSelectedId(profile.id)
                    setSaved(false)
                  }}
                  className={`w-full rounded-lg border p-4 text-left transition ${
                    isSelected
                      ? 'border-orange-400/40 bg-orange-500/[0.08]'
                      : 'border-white/[0.07] bg-black/10 hover:border-white/20 hover:bg-white/[0.03]'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex min-w-0 items-start gap-3">
                      <div className={`mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border text-sm ${
                        isSelected
                          ? 'border-orange-400/30 bg-orange-500/10 text-orange-300'
                          : 'border-white/10 bg-white/[0.03] text-white/50'
                      }`}>
                        ◈
                      </div>
                      <div className="min-w-0">
                        <p className={`truncate text-sm font-medium ${
                          isSelected ? 'text-orange-100' : 'text-white/85'
                        }`}>
                          {profile.name}
                        </p>
                        <p className="mt-1 text-[10px] tracking-wider text-white/35">
                          {profile.id}
                        </p>
                      </div>
                    </div>

                    <span className={`shrink-0 rounded-full border px-2 py-1 text-[9px] ${
                      profile.status === 'Active'
                        ? 'border-emerald-500/20 bg-emerald-500/10 text-emerald-300'
                        : 'border-white/10 bg-white/[0.04] text-white/40'
                    }`}>
                      {profile.status}
                    </span>
                  </div>

                  <div className="mt-4 flex flex-wrap items-center gap-2">
                    <span className={`rounded-md border px-2 py-1 text-[10px] ${levelStyles[profile.interactionLevel]}`}>
                      {profile.interactionLevel} interaction
                    </span>
                    <span className="text-[10px] text-white/35">
                      {profile.services.length} services
                    </span>
                  </div>

                  <div className="mt-3 truncate text-xs text-white/40">
                    ↳ {profile.assignedHoneypot}
                  </div>
                </button>
              )
            })}
          </div>

          <div className="mt-4 rounded-lg border border-dashed border-white/10 p-3">
            <p className="text-xs font-medium text-white/60">
              Configuration tip
            </p>
            <p className="mt-1 text-xs leading-5 text-white/35">
              Higher interaction can reveal richer activity, but requires more
              careful isolation and monitoring.
            </p>
          </div>
        </section>

        <section className="min-w-0 rounded-xl border border-white/10 bg-[#160e0c]/75 p-5 backdrop-blur-xl">
          <div className="flex flex-col justify-between gap-3 border-b border-white/[0.08] pb-5 sm:flex-row sm:items-start">
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[10px] uppercase tracking-[0.2em] text-orange-300/70">
                  Editing profile
                </span>
                <span className="text-[10px] text-white/25">
                  / {selectedProfile.id}
                </span>
              </div>
              <h3 className="mt-2 text-lg font-semibold">
                {selectedProfile.name || 'Untitled profile'}
              </h3>
              <p className="mt-1 text-xs text-white/40">
                Last modified: {selectedProfile.updatedAt}
              </p>
            </div>

            <span className={`w-fit rounded-full border px-3 py-1 text-xs ${levelStyles[selectedProfile.interactionLevel]}`}>
              {selectedProfile.interactionLevel} interaction
            </span>
          </div>

          <div className="mt-5 space-y-5">
            <div>
              <label className="mb-2 block text-xs font-medium text-white/55">
                Profile name
              </label>
              <input
                value={selectedProfile.name}
                onChange={(event) => updateSelected('name', event.target.value)}
                className="w-full rounded-lg border border-white/10 bg-black/20 px-3 py-3 text-sm text-white outline-none transition placeholder:text-white/25 focus:border-orange-400/50"
                placeholder="Enter profile name"
              />
            </div>

            <div>
              <label className="mb-2 block text-xs font-medium text-white/55">
                Description
              </label>
              <textarea
                value={selectedProfile.description}
                onChange={(event) => updateSelected('description', event.target.value)}
                rows={3}
                className="w-full resize-y rounded-lg border border-white/10 bg-black/20 px-3 py-3 text-sm leading-6 text-white/80 outline-none transition placeholder:text-white/25 focus:border-orange-400/50"
                placeholder="What should this profile simulate?"
              />
            </div>

            <div>
              <div className="mb-3 flex items-center justify-between gap-3">
                <label className="text-xs font-medium text-white/55">
                  Interaction level
                </label>
                <span className="text-[10px] text-white/35">
                  Response complexity
                </span>
              </div>

              <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                {(['Low', 'Medium', 'High'] as const).map((level) => {
                  const isSelected = selectedProfile.interactionLevel === level

                  return (
                    <button
                      key={level}
                      type="button"
                      onClick={() => updateSelected('interactionLevel', level)}
                      className={`rounded-lg border p-3 text-left transition ${
                        isSelected
                          ? levelStyles[level]
                          : 'border-white/10 bg-black/10 text-white/45 hover:border-white/20 hover:text-white/70'
                      }`}
                    >
                      <span className="block text-sm font-medium">{level}</span>
                      <span className="mt-2 block text-[10px] leading-4 opacity-70">
                        {level === 'Low'
                          ? 'Basic replies'
                          : level === 'Medium'
                            ? 'Simulated services'
                            : 'Deep interaction'}
                      </span>
                    </button>
                  )
                })}
              </div>

              <p className="mt-2 text-xs text-white/35">
                {levelDescriptions[selectedProfile.interactionLevel]}
              </p>
            </div>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <label className="mb-2 block text-xs font-medium text-white/55">
                  Environment
                </label>
                <select
                  value={selectedProfile.operatingSystem}
                  onChange={(event) => updateSelected('operatingSystem', event.target.value)}
                  className="w-full rounded-lg border border-white/10 bg-[#100a09] px-3 py-3 text-sm text-white/80 outline-none focus:border-orange-400/50"
                >
                  <option>Ubuntu Linux</option>
                  <option>Debian Linux</option>
                  <option>Windows Server</option>
                  <option>Generic Unix</option>
                </select>
              </div>

              <div>
                <label className="mb-2 block text-xs font-medium text-white/55">
                  Assign to honeypot
                </label>
                <select
                  value={selectedProfile.assignedHoneypot}
                  onChange={(event) => updateSelected('assignedHoneypot', event.target.value)}
                  className="w-full rounded-lg border border-white/10 bg-[#100a09] px-3 py-3 text-sm text-white/80 outline-none focus:border-orange-400/50"
                >
                  <option value="Unassigned">Unassigned</option>

{honeypots.map((honeypot) => (
  <option key={honeypot.id} value={honeypot.name}>
    {honeypot.name}
  </option>
))}
                </select>
              </div>
            </div>

            <div>
              <div className="mb-3 flex items-center justify-between gap-3">
                <label className="text-xs font-medium text-white/55">
                  Exposed services
                </label>
                <span className="text-xs text-white/35">
                  {selectedProfile.services.length} selected
                </span>
              </div>

              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                {availableServices.map((service) => {
                  const checked = selectedProfile.services.includes(service)

                  return (
                    <label
                      key={service}
                      className={`flex cursor-pointer items-center gap-2 rounded-lg border px-3 py-3 text-sm transition ${
                        checked
                          ? 'border-orange-400/30 bg-orange-500/[0.08] text-orange-100'
                          : 'border-white/10 bg-black/10 text-white/45 hover:border-white/20'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={() => {
                          const nextServices = checked
                            ? selectedProfile.services.filter((item) => item !== service)
                            : [...selectedProfile.services, service]

                          updateSelected('services', nextServices)
                        }}
                        className="accent-orange-500"
                      />
                      {service}
                    </label>
                  )
                })}
              </div>
            </div>

            <div className="flex flex-col justify-between gap-4 border-t border-white/[0.08] pt-5 sm:flex-row sm:items-center">
              <label className="flex cursor-pointer items-center gap-3">
                <input
                  type="checkbox"
                  checked={selectedProfile.status === 'Active'}
                  onChange={(event) =>
                    updateSelected('status', event.target.checked ? 'Active' : 'Draft')
                  }
                  className="h-4 w-4 accent-orange-500"
                />
                <span>
                  <span className="block text-sm text-white/80">
                    Enable profile
                  </span>
                  <span className="mt-1 block text-xs text-white/35">
                    Mark this configuration as active
                  </span>
                </span>
              </label>

              <button
                type="button"
                onClick={saveProfile}
                className="rounded-lg bg-orange-500 px-5 py-3 text-sm font-semibold text-[#1a0d08] transition hover:bg-orange-400"
              >
                {saved ? '✓ Changes saved' : 'Save changes'}
              </button>
            </div>

            {saved && (
              <p className="text-xs text-emerald-300/80">
                Profile changes saved in this demo session.
              </p>
            )}
          </div>
        </section>
      </div>

      <p className="text-xs leading-5 text-white/25">
        DEMO MODE — profile settings and assignments are stored only in the
        current frontend session. They are not connected to a backend yet.
      </p>
    </section>
  )
}