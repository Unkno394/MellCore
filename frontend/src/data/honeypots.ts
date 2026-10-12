export type Status = 'Active' | 'Inactive' | 'Warning'

export type Honeypot = {
  id: string
  name: string
  ip: string
  type: string
  profile: string
  status: Status
  lastActivity: string
  sessions: number
  location: string
  description: string

}

export const initialHoneypots: Honeypot[] = [
  {
    id: 'HP-001',
    name: 'SSH Honeypot 01',
    ip: '192.0.2.10',
    type: 'SSH',
    profile: 'Linux Server',
    status: 'Active',
    lastActivity: '2 min ago',
    sessions: 12,
    location: 'DMZ / Zone A',
    description: 'Emulates a Linux server and records SSH login attempts.',
  },

  {
    id: 'HP-002',
    name: 'Web Honeypot 02',
    ip: '192.0.2.20',
    type: 'Web',
    profile: 'Web Application',
    status: 'Active',
    lastActivity: '5 min ago',
    sessions: 8,
    location: 'DMZ / Zone A',
    description: 'Simulates a web application to observe suspicious requests.',
  },

  {
    id: 'HP-003',
    name: 'Network Sensor 03',
    ip: '192.0.2.30',
    type: 'Network',
    profile: 'Network Monitor',
    status: 'Warning',
    lastActivity: '1 min ago',
    sessions: 4,
    location: 'DMZ / Zone B',
    description: 'Monitors simulated network scans and connection attempts.',
  },

  {
    id: 'HP-004',
    name: 'Database Trap 04',
    ip: '192.0.2.40',
    type: 'Database',
    profile: 'SQL Server',
    status: 'Inactive',
    lastActivity: '3 hours ago',
    sessions: 0,
    location: 'DMZ / Zone B',
    description: 'Emulates a database endpoint for observing access attempts.',
  },

  {
    id: 'HP-005',
    name: 'SSH Honeypot 05',
    ip: '192.0.2.50',
    type: 'SSH',
    profile: 'Linux Server',
    status: 'Active',
    lastActivity: '12 min ago',
    sessions: 6,
    location: 'DMZ / Zone C',
    description: 'Collects simulated authentication attempts and session activity.',
  },

  {
    id: 'HP-006',
    name: 'Web Honeypot 06',
    ip: '192.0.2.60',
    type: 'Web',
    profile: 'Admin Panel',
    status: 'Active',
    lastActivity: '18 min ago',
    sessions: 3,
    location: 'DMZ / Zone C',
    description: 'Simulates an administration panel for testing detection workflows.',
  },

]