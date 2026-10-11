
import { useState } from 'react'

// Демонстрационные события безопасности
const events = [
  { id: 1, time: '14:32:08', type: 'SSH login attempt', honeypot: 'SSH Honeypot 01', ip: '192.0.2.15', level: 'High' },
  { id: 2, time: '14:28:41', type: 'Port scan detected', honeypot: 'Network Sensor 03', ip: '198.51.100.22', level: 'Medium' },
  { id: 3, time: '14:24:15', type: 'New session opened', honeypot: 'Web Honeypot 02', ip: '203.0.113.10', level: 'Low' },
  { id: 4, time: '14:19:32', type: 'Authentication failed', honeypot: 'SSH Honeypot 01', ip: '192.0.2.44', level: 'High' },
  { id: 5, time: '14:15:06', type: 'HTTP request detected', honeypot: 'Web Honeypot 02', ip: '198.51.100.35', level: 'Low' },
  { id: 6, time: '14:08:51', type: 'Suspicious command', honeypot: 'SSH Honeypot 01', ip: '203.0.113.81', level: 'High' },
]

export default function LiveFeed() {
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState('All')

  const filteredEvents = events.filter((event) => {
    const matchesSearch =
      `${event.type} ${event.honeypot} ${event.ip}`
        .toLowerCase()
        .includes(search.toLowerCase())

    const matchesFilter =
      filter === 'All' || event.level === filter

    return matchesSearch && matchesFilter
  })

  return (
    <section className="space-y-6 p-6">
      <div>
        <p className="text-sm text-white/45">
          SECURITY / MONITORING
        </p>
        <h2 className="mt-1 text-2xl font-semibold">
          Live Feed
        </h2>
        <p className="mt-2 text-sm text-white/45">
          Monitor incoming activity across all honeypots.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        {[
          { label: 'Total Events', value: events.length },
          { label: 'High Threats', value: events.filter(e => e.level === 'High').length },
          { label: 'Active Sensors', value: new Set(events.map(e => e.honeypot)).size },
        ].map((stat) => (
          <div
            key={stat.label}
            className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-5 backdrop-blur-xl"
          >
            <p className="text-sm text-white/50">{stat.label}</p>
            <p className="mt-4 text-3xl font-semibold">{stat.value}</p>
          </div>
        ))}
      </div>

      <div className="rounded-xl border border-white/10 bg-[#160e0c]/80 p-5 backdrop-blur-xl">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h3 className="font-semibold">Event stream</h3>
            <p className="mt-1 text-xs text-white/40">
              Latest detected security events
            </p>
          </div>

          <div className="flex flex-wrap gap-3">
            <input
              type="text"
              placeholder="Search events..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="rounded-lg border border-white/10 bg-black/30 px-4 py-2 text-sm text-white outline-none focus:border-orange-500/50"
            />

            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="rounded-lg border border-white/10 bg-[#160e0c] px-4 py-2 text-sm text-white outline-none"
            >
              <option value="All">All levels</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>
        </div>

        <div className="mt-6 overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-white/10 text-xs text-white/40">
              <tr>
                <th className="px-4 py-3">Time</th>
                <th className="px-4 py-3">Event</th>
                <th className="px-4 py-3">Honeypot</th>
                <th className="px-4 py-3">Source IP</th>
                <th className="px-4 py-3">Threat Level</th>
              </tr>
            </thead>

            <tbody>
              {filteredEvents.map((event) => (
                <tr
                  key={event.id}
                  className="border-b border-white/5 transition hover:bg-white/5"
                >
                  <td className="px-4 py-4 text-white/50">
                    {event.time}
                  </td>
                  <td className="px-4 py-4">{event.type}</td>
                  <td className="px-4 py-4 text-white/60">
                    {event.honeypot}
                  </td>
                  <td className="px-4 py-4 font-mono text-white/50">
                    {event.ip}
                  </td>
                  <td className="px-4 py-4">
                    <span className={`rounded-md px-3 py-1 text-xs ${
                      event.level === 'High'
                        ? 'bg-red-500/15 text-red-400'
                        : event.level === 'Medium'
                          ? 'bg-orange-500/15 text-orange-400'
                          : 'bg-emerald-500/15 text-emerald-400'
                    }`}>
                      {event.level}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {filteredEvents.length === 0 && (
            <p className="py-8 text-center text-sm text-white/40">
              No events found
            </p>
          )}
        </div>

        <div className="mt-4 text-xs text-white/40">
          Showing {filteredEvents.length} of {events.length} events
          <span className="ml-3 text-orange-400/70">
            Demo data
          </span>
        </div>
      </div>
    </section>
  )
}
