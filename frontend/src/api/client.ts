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
  const requestId = error.requestId ? ` ID запроса: ${error.requestId}.` : ''
  const logHint = 'Если ошибка повторится, проверьте журналы Центра: journalctl -u honeyforge-backend -u hf-center -n 100 --no-pager.'

  switch (error.code) {
    case 'validation_error':
      return `Введены некорректные данные. Проверьте поля формы: ${error.message}`
    case 'unauthorized':
      return 'Неверные учётные данные или срок действия сеанса истёк.'
    case 'forbidden':
      return 'У вашей учётной записи нет доступа к этому действию.'
    case 'not_found':
      return 'Запрошенные данные не найдены. Обновите страницу и попробуйте снова.'
    case 'email_not_verified':
      return 'Подтвердите адрес электронной почты перед входом.'
    case 'conflict':
      return `Операцию нельзя выполнить в текущем состоянии: ${error.message}`
    case 'mail_unavailable':
      return `Не удалось отправить письмо. Проверьте настройки SMTP. ${logHint}${requestId}`
    case 'database_unavailable':
      return `MellCore не получил ответ от базы данных или Центра. Повторите попытку. ${logHint}${requestId}`
    case 'rate_limited':
      return 'Слишком много запросов. Подождите немного и повторите попытку.'
    case 'internal_error':
      return `Внутренняя ошибка MellCore. ${logHint}${requestId}`
    case 'network_error':
      return `Не удалось подключиться к API MellCore. Проверьте соединение с панелью. ${logHint}`
    case 'request_timeout':
      return `API MellCore не ответил вовремя. Повторите попытку. ${logHint}`
    case 'request_cancelled':
      return 'Запрос отменён.'
    default:
      if (error.status >= 500) return `API MellCore вернул ошибку (${error.status}). ${logHint}${requestId}`
      return `${error.message}${requestId}`
  }
}
