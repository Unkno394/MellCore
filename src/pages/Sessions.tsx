import { useState } from 'react'
import { sessions, type Session } from '../data/sessions'

export default function Sessions() {
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState('All')
  const [selectedSession, setSelectedSession] =
    useState<Session | null>(null)

  const filteredSessions = sessions.filter((session) => {
    const matchesSearch =
      `${session.id} ${session.honeypot} ${session.ip}`
        .toLowerCase()
        .includes(search.toLowerCase())

    const matchesFilter =
      filter === 'All' || session.status === filter

    return matchesSearch && matchesFilter
  })

  return (
    <section className="space-y-6 p-6">
      <div>
        <p className="text-sm text-white/45">
          SECURITY / SESSIONS
        </p>

        <h2 className="mt-1 text-2xl font-semibold">
          Sessions
        </h2>

        <p className="mt-2 text-sm text-white/45">
          Investigate attacker interactions and session activity.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        {[
          {
            label: 'Total Sessions',
            value: sessions.length,
          },
          {
            label: 'Active Sessions',
            value: sessions.filter(
              (session) => session.status === 'Active'
            ).length,
          },
          {
            label: 'Completed Sessions',
            value: sessions.filter(
              (session) => session.status === 'Completed'
            ).length,
          },
        ].map((stat) => (
          <div
            key={stat.label}
            className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-5 backdrop-blur-xl"
          >
            <p className="text-sm text-white/50">
              {stat.label}
            </p>

            <p className="mt-4 text-3xl font-semibold">
              {stat.value}
            </p>
          </div>
        ))}
      </div>

      <div className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-5 backdrop-blur-xl">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h3 className="font-semibold">
              Session history
            </h3>

            <p className="mt-1 text-xs text-white/40">
              Recorded attacker interactions
            </p>
          </div>

          <div className="flex flex-wrap gap-3">
            <input
              type="text"
              placeholder="Search sessions..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="rounded-lg border border-white/10 bg-black/30 px-4 py-2 text-sm text-white outline-none focus:border-orange-500/50"
            />

            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="rounded-lg border border-white/10 bg-[#160e0c] px-4 py-2 text-sm text-white outline-none"
            >
              <option value="All">All sessions</option>
              <option value="Active">Active</option>
              <option value="Completed">Completed</option>
            </select>
          </div>
        </div>

        <div className="mt-6 overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-white/10 text-xs text-white/40">
              <tr>
                <th className="px-4 py-3">Session ID</th>
                <th className="px-4 py-3">Honeypot</th>
                <th className="px-4 py-3">Source IP</th>
                <th className="px-4 py-3">Started</th>
                <th className="px-4 py-3">Duration</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Action</th>
              </tr>
            </thead>

            <tbody>
              {filteredSessions.map((session) => (
                <tr
                  key={session.id}
                  className="border-b border-white/5 transition hover:bg-white/5"
                >
                  <td className="px-4 py-4 font-mono text-orange-300">
                    {session.id}
                  </td>

                  <td className="px-4 py-4">
                    {session.honeypot}
                  </td>

                  <td className="px-4 py-4 font-mono text-white/50">
                    {session.ip}
                  </td>

                  <td className="px-4 py-4 text-white/50">
                    {session.started}
                  </td>

                  <td className="px-4 py-4 text-white/60">
                    {session.duration}
                  </td>

                  <td className="px-4 py-4">
                    <span
                      className={`rounded-md px-3 py-1 text-xs ${
                        session.status === 'Active'
                          ? 'bg-emerald-500/15 text-emerald-400'
                          : 'bg-white/10 text-white/50'
                      }`}
                    >
                      {session.status}
                    </span>
                  </td>

                  <td className="px-4 py-4">
                    <button
                      type="button"
                      onClick={() => setSelectedSession(session)}
                      className="rounded-lg border border-orange-500/30 px-3 py-2 text-xs text-orange-300 transition hover:bg-orange-500/10"
                    >
                      View details
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {filteredSessions.length === 0 && (
            <p className="py-8 text-center text-sm text-white/40">
              No sessions found
            </p>
          )}
        </div>

        <div className="mt-4 text-xs text-white/40">
          Showing {filteredSessions.length} of {sessions.length} sessions
          <span className="ml-3 text-orange-400/70">
            Demo data
          </span>
        </div>
      </div>

      {selectedSession && (
        <div className="rounded-xl border border-orange-500/20 bg-[#160e0c]/90 p-6 backdrop-blur-xl">
          <div className="flex items-center justify-between gap-4">
            <div>
              <p className="text-xs text-orange-400">
                SESSION DETAILS
              </p>

              <h3 className="mt-2 text-xl font-semibold">
                {selectedSession.id}
              </h3>
            </div>

            <button
              type="button"
              onClick={() => setSelectedSession(null)}
              className="rounded-lg border border-white/10 px-4 py-2 text-sm text-white/60 hover:bg-white/5"
            >
              Close
            </button>
          </div>

          <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
            <div>
              <p className="text-xs text-white/40">
                Honeypot
              </p>
              <p className="mt-2 text-sm">
                {selectedSession.honeypot}
              </p>
            </div>

            <div>
              <p className="text-xs text-white/40">
                Source IP
              </p>
              <p className="mt-2 font-mono text-sm">
                {selectedSession.ip}
              </p>
            </div>

            <div>
              <p className="text-xs text-white/40">
                Duration
              </p>
              <p className="mt-2 text-sm">
                {selectedSession.duration}
              </p>
            </div>
          </div>

          <div className="mt-8">
            <h4 className="font-semibold">
              Event timeline
            </h4>

            <p className="mt-1 text-xs text-white/40">
              Chronological sequence of recorded activity
            </p>

            <div className="mt-6 space-y-0">
              {selectedSession.events.map((event, index) => (
                <div
                  key={`${event.time}-${index}`}
                  className="flex gap-4"
                >
                  <div className="flex flex-col items-center">
                    <span className="h-3 w-3 shrink-0 rounded-full border-2 border-orange-400 bg-[#160e0c]" />

                    {index < selectedSession.events.length - 1 && (
                      <div className="min-h-14 w-px flex-1 bg-orange-500/20" />
                    )}
                  </div>

                  <div className="pb-6">
                    <p className="font-mono text-xs text-orange-300">
                      {event.time}
                    </p>

                    <p className="mt-2 text-sm font-medium">
                      {event.action}
                    </p>

                    <p className="mt-1 text-xs text-white/45">
                      {event.detail}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </section>
  )
}
