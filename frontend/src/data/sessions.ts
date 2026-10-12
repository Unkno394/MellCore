export type SessionStatus = 'Active' | 'Completed'

export type SessionEvent = {
  time: string
  action: string
  detail: string
}

export type Session = {
  id: string
  honeypot: string
  ip: string
  started: string
  duration: string
  status: SessionStatus
  events: SessionEvent[]
}

export const sessions: Session[] = [
  {
    id: 'SES-001',
    honeypot: 'SSH Honeypot 01',
    ip: '192.0.2.15',
    started: '14:32:08',
    duration: '12m 34s',
    status: 'Active',
    events: [
      { time: '14:32:08', action: 'Connection established', detail: 'Incoming SSH connection detected' },
      { time: '14:32:15', action: 'Login attempt', detail: 'Username: root' },
      { time: '14:32:19', action: 'Authentication failed', detail: 'Invalid credentials' },
      { time: '14:33:02', action: 'Command executed', detail: 'Command: whoami' },
    ],
  },
  {
    id: 'SES-002',
    honeypot: 'Web Honeypot 02',
    ip: '203.0.113.10',
    started: '14:24:15',
    duration: '8m 12s',
    status: 'Completed',
    events: [
      { time: '14:24:15', action: 'Session opened', detail: 'HTTP connection established' },
      { time: '14:24:22', action: 'HTTP request', detail: 'GET /admin' },
      { time: '14:25:03', action: 'Authentication attempt', detail: 'Login form submitted' },
      { time: '14:32:27', action: 'Session closed', detail: 'Connection terminated' },
    ],
  },
  {
    id: 'SES-003',
    honeypot: 'Network Sensor 03',
    ip: '198.51.100.22',
    started: '14:18:41',
    duration: '3m 45s',
    status: 'Completed',
    events: [
      { time: '14:18:41', action: 'Connection detected', detail: 'Incoming TCP connection' },
      { time: '14:19:05', action: 'Port scan', detail: 'Multiple ports scanned' },
      { time: '14:22:26', action: 'Session closed', detail: 'Connection terminated' },
    ],
  },
  {
    id: 'SES-004',
    honeypot: 'SSH Honeypot 01',
    ip: '192.0.2.44',
    started: '13:56:20',
    duration: '24m 18s',
    status: 'Completed',
    events: [
      { time: '13:56:20', action: 'Connection established', detail: 'Incoming SSH connection detected' },
      { time: '13:57:02', action: 'Login attempt', detail: 'Username: admin' },
      { time: '13:57:06', action: 'Authentication failed', detail: 'Invalid password' },
      { time: '14:20:38', action: 'Session closed', detail: 'Connection terminated' },
    ],
  },
]
