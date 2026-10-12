import type { ErrorResponse } from './types'

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly requestId: string | null

  constructor(
    message: string,
    options: { status: number; code: string; requestId?: string | null },
  ) {
    super(message)
    this.name = 'ApiError'
    this.status = options.status
    this.code = options.code
    this.requestId = options.requestId ?? null
  }
}

export type ApiClientOptions = {
  baseUrl?: string
  timeoutMs?: number
  fetchImpl?: typeof fetch
  getToken?: () => string | null
  onUnauthorized?: () => void
}

export type ApiRequestOptions = Omit<RequestInit, 'body'> & {
  body?: unknown
}

const defaultBaseUrl =
  typeof import.meta.env?.VITE_API_BASE_URL === 'string'
    ? import.meta.env.VITE_API_BASE_URL
    : '/api/v1'
const configuredTimeout = Number(import.meta.env?.VITE_API_TIMEOUT_MS)
const defaultTimeoutMs =
  Number.isFinite(configuredTimeout) && configuredTimeout > 0
    ? configuredTimeout
    : 10_000

export class ApiClient {
  private readonly baseUrl: string
  private readonly timeoutMs: number
  private readonly fetchImpl: typeof fetch
  private readonly getToken: () => string | null
  private readonly onUnauthorized: () => void

  constructor(options: ApiClientOptions = {}) {
    this.baseUrl = (options.baseUrl ?? defaultBaseUrl).replace(/\/$/, '')
    this.timeoutMs = options.timeoutMs ?? defaultTimeoutMs
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis)
    this.getToken = options.getToken ?? (() => null)
    this.onUnauthorized = options.onUnauthorized ?? (() => undefined)
  }

  async request<T>(path: string, options: ApiRequestOptions = {}): Promise<T> {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort('timeout'), this.timeoutMs)
    const abortFromCaller = () => controller.abort(options.signal?.reason)
    options.signal?.addEventListener('abort', abortFromCaller, { once: true })

    const headers = new Headers(options.headers)
    headers.set('Accept', 'application/json')
    const token = this.getToken()
    if (token) headers.set('Authorization', `Bearer ${token}`)
    if (options.body !== undefined) headers.set('Content-Type', 'application/json')

    try {
      const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
        ...options,
        credentials: options.credentials ?? 'same-origin',
        headers,
        body: options.body === undefined ? undefined : JSON.stringify(options.body),
        signal: controller.signal,
      })
      const headerRequestId = response.headers.get('x-request-id')
      const text = await response.text()
      const payload = text ? safelyParseJson(text) : undefined

      if (!response.ok) {
        const error = payload as ErrorResponse | undefined
        const requestId = error?.error?.request_id ?? headerRequestId
        if (response.status === 401 && token && path !== '/auth/refresh') this.onUnauthorized()
        throw new ApiError(error?.error?.message ?? `Ошибка запроса (${response.status})`, {
          status: response.status,
          code: error?.error?.code ?? 'http_error',
          requestId,
        })
      }

      return payload as T
    } catch (error) {
      if (error instanceof ApiError) throw error
      if (controller.signal.aborted) {
        throw new ApiError('Время ожидания истекло или запрос отменён.', {
          status: 0,
          code: controller.signal.reason === 'timeout' ? 'request_timeout' : 'request_cancelled',
        })
      }
      throw new ApiError('Не удалось подключиться к API MellCore.', {
        status: 0,
        code: 'network_error',
      })
    } finally {
      clearTimeout(timeout)
      options.signal?.removeEventListener('abort', abortFromCaller)
    }
  }
}

function safelyParseJson(text: string): unknown {
  try {
    return JSON.parse(text)
  } catch {
    return undefined
  }
}

export function apiErrorMessage(error: unknown): string {
  if (!(error instanceof ApiError)) return 'Неожиданная ошибка приложения.'
  const knownMessages: Record<string, string> = {
    unauthorized: 'Неверные учётные данные или срок действия сеанса истёк.',
    forbidden: 'Доступ запрещён.',
    not_found: 'Запрошенные данные не найдены.',
    email_not_verified: 'Подтвердите адрес электронной почты перед входом.',
    mail_unavailable: 'Отправка писем сейчас недоступна.',
    database_unavailable: 'База данных сейчас недоступна.',
    rate_limited: 'Слишком много запросов. Повторите попытку позже.',
    internal_error: 'Внутренняя ошибка сервера.',
  }
  const suffix = error.requestId ? ` ID запроса: ${error.requestId}` : ''
  return `${knownMessages[error.code] ?? error.message}${suffix}`
}
