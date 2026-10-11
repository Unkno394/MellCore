
import { sessions } from './sessions'

export type SecurityEvent = {
  id: string
  time: string
  type: string
  honeypot: string
  ip: string
  level: 'High' | 'Medium' | 'Low'
}

export const events: SecurityEvent[] = sessions.flatMap((session) =>
  session.events.map((event, index) => {
    const action = event.action.toLowerCase()

    let level: SecurityEvent['level'] = 'Low'

    if (
      action.includes('authentication failed') ||
      action.includes('login attempt') ||
      action.includes('command executed')
    ) {
      level = 'High'
    } else if (
      action.includes('port scan') ||
      action.includes('authentication attempt')
    ) {
      level = 'Medium'
    }

    return {
      id: `${session.id}-${index}`,
      time: event.time,
      type: event.action,
      honeypot: session.honeypot,
      ip: session.ip,
      level,
    }
  }),
)
