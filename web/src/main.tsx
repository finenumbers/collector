import { FormEvent, useCallback, useEffect, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import {
  Activity, AlertTriangle, CirclePlus, Database, FileClock,
  LogOut, Network, PhoneCall, Radio, Search, Server, Settings, ShieldCheck,
} from 'lucide-react'
import './styles.css'

type User = { id: string; username: string; role: 'admin' | 'analyst' | 'viewer' }
type Device = {
  id: string
  name: string
  model: string
  firmware: string
  timezone: string
  syslogSourceIp: string
  managementIp?: string
  deviceSign: string
  antifraudEnabled: boolean
  antifraudMode: string
  ftpUsername: string
  ftpHome: string
  generatedPassword?: string
  enabled: boolean
}
type EventRow = {
  eventId: string
  receivedAt: string
  category: string
  component: string
  message: string
  rawPayload: string
  parseStatus: string
  attributes: Record<string, string>
}
type TimelineRow = EventRow & { method: string; confidence: number }
type DeviceStats = {
  calls24h: number; failedCalls24h: number; averageTalkMs: number
  alarms24h: number; radius24h: number; unknown24h: number
}
type SyslogBreakdown = {
  category: string; parseStatus: string; parserVersion: string; headerFormat: string
  sourcePort: number; count: number; lastReceivedAt: string
}
type IngestRuntime = {
  acceptedDatagrams: number; rejectedDatagrams: number; spoolWriteErrors: number
  handoffErrors: number; handedOff: number
}
type IngressStatus = {
  updatedAt: string
  runtime: IngestRuntime
  spoolDepth: number
  quarantineDepth: number
}
type SyslogDiagnostics = {
  version: string
  parserVersion: string
  runtime: IngestRuntime
  spoolDepth: number
  quarantineDepth: number
  natsStreamMessages: number
  natsConsumerPending: number
  breakdown: SyslogBreakdown[]
  appliedMigrations: string[]
  ingressAvailable: boolean
  ingress: IngressStatus
}
type CallRow = {
  recordId: string
  setupTime?: string
  durationMs?: number
  releaseCause?: number
  releaseInfo: string
  incomingCgpn: string
  outgoingCgpn: string
  incomingCdpn: string
  outgoingCdpn: string
  incomingDescription: string
  outgoingDescription: string
  radiusSessionId: string
  uniqueTag: string
}
type PageCursor = { before: string; beforeId: string }
type PageResponse = {
  items: Array<EventRow | CallRow>
  hasMore: boolean
  nextCursor?: PageCursor
}
type Dataset = 'calls' | 'syslog_all' | 'antifraud' | 'alarms' | 'call_trace' | 'sip' | 'isup' |
  'q931' | 'ip_connections' | 'ip_modules' | 'radius' | 'config_history' |
  'system_journal' | 'unknown'

let csrfToken = ''
const PAGE_SIZE = 100

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, {
    credentials: 'same-origin',
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
      ...init?.headers,
    },
  })
  if (response.status === 204) return undefined as T
  const body = await response.json().catch(() => ({})) as { error?: string }
  if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`)
  return body as T
}

function App() {
  const [bootstrapped, setBootstrapped] = useState<boolean | null>(null)
  const [user, setUser] = useState<User | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    api<{ bootstrapped: boolean }>('/bootstrap/status')
      .then(({ bootstrapped: value }) => {
        setBootstrapped(value)
        if (value) {
          api<{ user: User; csrfToken: string }>('/auth/me')
            .then((session) => {
              csrfToken = session.csrfToken
              setUser(session.user)
            })
            .catch(() => undefined)
        }
      })
      .catch((reason) => setError(reason.message))
  }, [])

  if (bootstrapped === null) return <Centered><div className="loader" /></Centered>
  if (!bootstrapped || !user) {
    return <AuthScreen
      bootstrap={!bootstrapped}
      externalError={error}
      onSuccess={(session) => {
        csrfToken = session.csrfToken
        setBootstrapped(true)
        setUser(session.user)
      }}
    />
  }
  return <Workspace user={user} onLogout={() => {
    api<void>('/auth/logout', { method: 'POST' }).finally(() => {
      csrfToken = ''
      setUser(null)
    })
  }} />
}

function AuthScreen(props: {
  bootstrap: boolean
  externalError: string
  onSuccess: (session: { user: User; csrfToken: string }) => void
}) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState(props.externalError)
  const [busy, setBusy] = useState(false)
  async function submit(event: FormEvent) {
    event.preventDefault()
    if (props.bootstrap && password !== confirm) {
      setError('Пароли не совпадают')
      return
    }
    setBusy(true)
    setError('')
    try {
      const session = await api<{ user: User; csrfToken: string }>(
        props.bootstrap ? '/bootstrap' : '/auth/login',
        { method: 'POST', body: JSON.stringify({ username, password }) },
      )
      props.onSuccess(session)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Ошибка входа')
    } finally {
      setBusy(false)
    }
  }
  return <Centered>
    <form className="auth-panel" onSubmit={submit}>
      <div className="product-mark"><Radio size={18} /> SMG Collector</div>
      <h1>{props.bootstrap ? 'Первичная настройка' : 'Вход в систему'}</h1>
      <p>{props.bootstrap
        ? 'Создайте первого администратора. Пароль должен содержать не менее 12 символов.'
        : 'Внутренний сервис мониторинга телекоммуникационного оборудования.'}</p>
      <label>Имя пользователя<input autoFocus value={username} minLength={3}
        onChange={(event) => setUsername(event.target.value)} required /></label>
      <label>Пароль<input type="password" value={password} minLength={props.bootstrap ? 12 : 1}
        onChange={(event) => setPassword(event.target.value)} required /></label>
      {props.bootstrap && <label>Повторите пароль<input type="password" value={confirm}
        onChange={(event) => setConfirm(event.target.value)} required /></label>}
      {error && <div className="form-error">{error}</div>}
      <button className="primary" disabled={busy}>{busy ? 'Подождите…' : props.bootstrap ? 'Создать администратора' : 'Войти'}</button>
    </form>
  </Centered>
}

function Workspace({ user, onLogout }: { user: User; onLogout: () => void }) {
  const [devices, setDevices] = useState<Device[]>([])
  const [activeDevice, setActiveDevice] = useState<string>('')
  const [dataset, setDataset] = useState<Dataset>('calls')
  const [showCreate, setShowCreate] = useState(false)
  const [credentials, setCredentials] = useState<Device | null>(null)
  const [error, setError] = useState('')

  const loadDevices = () => api<{ items: Device[] }>('/devices').then(({ items }) => {
    setDevices(items || [])
    setActiveDevice((current) => current || items?.[0]?.id || '')
  }).catch((reason) => setError(reason.message))
  useEffect(() => {
    void loadDevices()
  }, [])
  const selected = devices.find((device) => device.id === activeDevice)

  return <div className="workspace">
    <aside className="sidebar">
      <div className="brand"><Radio size={17} /><span>SMG Collector</span></div>
      <div className="side-section-label">ОБОРУДОВАНИЕ</div>
      <div className="device-list">
        {devices.map((device) => <button key={device.id}
          className={`device-button ${device.id === activeDevice ? 'active' : ''}`}
          onClick={() => { setActiveDevice(device.id); setDataset('calls') }}>
          <span className={`status-dot ${device.enabled ? 'online' : ''}`} />
          <span><strong>{device.name}</strong><small>{device.syslogSourceIp}</small></span>
        </button>)}
        {user.role === 'admin' && <button className="add-device" onClick={() => setShowCreate(true)}>
          <CirclePlus size={15} /> Добавить SMG
        </button>}
      </div>
      {selected && <DeviceNavigation active={dataset} onChange={setDataset} />}
      <div className="sidebar-footer">
        <button><Settings size={15} /> Настройки</button>
        <div className="user-line"><span><strong>{user.username}</strong><small>{user.role}</small></span>
          <button title="Выйти" onClick={onLogout}><LogOut size={15} /></button></div>
      </div>
    </aside>
    <main>
      <header className="topbar">
        <div>
          <h2>{selected?.name || 'Обзор оборудования'}</h2>
          {selected && <span>{selected.model} · {selected.firmware} · {selected.timezone}</span>}
        </div>
        {selected && <div className="header-health">
          <span><i className="status-dot online" /> Приём активен</span>
          <span>{selected.antifraudEnabled ? `АнтиФрод: ${selected.antifraudMode}` : 'Без АнтиФрод'}</span>
        </div>}
      </header>
      {error && <div className="global-error">{error}</div>}
      {!selected ? <EmptyDevices canCreate={user.role === 'admin'} onCreate={() => setShowCreate(true)} /> :
        <DataView key={`${selected.id}:${dataset}`} device={selected} dataset={dataset}
          admin={user.role === 'admin'} />}
    </main>
    {showCreate && <CreateDeviceDialog onClose={() => setShowCreate(false)} onCreated={(device) => {
      setShowCreate(false)
      setCredentials(device)
      loadDevices()
      setActiveDevice(device.id)
    }} />}
    {credentials && <CredentialsDialog device={credentials} onClose={() => setCredentials(null)} />}
  </div>
}

const navigation: { id: Dataset; label: string; icon: typeof Activity }[] = [
  { id: 'calls', label: 'Вызовы и CDR', icon: PhoneCall },
  { id: 'syslog_all', label: 'Все Syslog', icon: FileClock },
  { id: 'antifraud', label: 'АнтиФрод', icon: ShieldCheck },
  { id: 'alarms', label: 'Аварии', icon: AlertTriangle },
  { id: 'call_trace', label: 'Обработка вызовов', icon: Activity },
  { id: 'sip', label: 'SIP', icon: Radio },
  { id: 'isup', label: 'SS7 / ISUP', icon: Network },
  { id: 'q931', label: 'Q.931', icon: Network },
  { id: 'ip_connections', label: 'IP-соединения', icon: Server },
  { id: 'ip_modules', label: 'IP-субмодули', icon: Database },
  { id: 'radius', label: 'RADIUS', icon: ShieldCheck },
  { id: 'config_history', label: 'Изменения', icon: FileClock },
  { id: 'system_journal', label: 'Системный журнал', icon: FileClock },
  { id: 'unknown', label: 'Нераспознанное', icon: AlertTriangle },
]

function DeviceNavigation({ active, onChange }: { active: Dataset; onChange: (value: Dataset) => void }) {
  return <nav className="device-nav">
    {navigation.map((item) => <button key={item.id} className={active === item.id ? 'active' : ''}
      onClick={() => onChange(item.id)}><item.icon size={14} />{item.label}</button>)}
  </nav>
}

function DataView({ device, dataset, admin }: { device: Device; dataset: Dataset; admin: boolean }) {
  const [query, setQuery] = useState('')
  const [rows, setRows] = useState<Array<EventRow | CallRow>>([])
  const [loading, setLoading] = useState(false)
  const [selectedCall, setSelectedCall] = useState<CallRow | null>(null)
  const [selectedEvent, setSelectedEvent] = useState<EventRow | null>(null)
  const [stats, setStats] = useState<DeviceStats | null>(null)
  const [diagnostics, setDiagnostics] = useState<SyslogDiagnostics | null>(null)
  const [cursor, setCursor] = useState<PageCursor | null>(null)
  const [hasMore, setHasMore] = useState(false)
  const tableShellRef = useRef<HTMLDivElement>(null)
  const sentinelRef = useRef<HTMLDivElement>(null)
  const loadingRef = useRef(false)
  const generationRef = useRef(0)
  const title = navigation.find((item) => item.id === dataset)?.label || dataset
  const category = dataset === 'syslog_all' ? 'all' : dataset
  const exportUrl = `/api/devices/${device.id}/export.xlsx?dataset=${dataset === 'calls' ? 'calls' : 'events'}&category=${encodeURIComponent(category)}&q=${encodeURIComponent(query)}`
  const pagePath = useCallback((pageCursor?: PageCursor) => {
    const base = dataset === 'calls'
      ? `/devices/${device.id}/calls?q=${encodeURIComponent(query)}&limit=${PAGE_SIZE}`
      : `/devices/${device.id}/events?category=${encodeURIComponent(category)}&q=${encodeURIComponent(query)}&limit=${PAGE_SIZE}`
    return pageCursor
      ? `${base}&before=${encodeURIComponent(pageCursor.before)}&before_id=${encodeURIComponent(pageCursor.beforeId)}`
      : base
  }, [category, dataset, device.id, query])
  const setBusy = useCallback((value: boolean) => {
    loadingRef.current = value
    setLoading(value)
  }, [])
  useEffect(() => {
    api<DeviceStats>(`/devices/${device.id}/stats`).then(setStats).catch(() => setStats(null))
    if (admin) {
      api<SyslogDiagnostics>(`/devices/${device.id}/syslog-diagnostics`)
        .then(setDiagnostics).catch(() => setDiagnostics(null))
    }
  }, [admin, device.id])
  useEffect(() => {
    const generation = ++generationRef.current
    let active = true
    const timer = window.setTimeout(() => {
      setRows([])
      setCursor(null)
      setHasMore(false)
      if (tableShellRef.current) tableShellRef.current.scrollTop = 0
      setBusy(true)
      api<PageResponse>(pagePath())
        .then(({ items, hasMore: more, nextCursor }) => {
          if (!active || generation !== generationRef.current) return
          setRows(items || [])
          setHasMore(more)
          setCursor(nextCursor || null)
        })
        .finally(() => {
          if (active) setBusy(false)
        })
    }, 250)
    return () => {
      active = false
      window.clearTimeout(timer)
    }
  }, [pagePath, setBusy])
  const loadMore = useCallback(() => {
    if (!cursor || !hasMore || loadingRef.current) return
    const generation = generationRef.current
    setBusy(true)
    api<PageResponse>(pagePath(cursor))
      .then(({ items, hasMore: more, nextCursor }) => {
        if (generation !== generationRef.current) return
        setRows((current) => [...current, ...(items || [])])
        setHasMore(more)
        setCursor(nextCursor || null)
      })
      .finally(() => {
        if (generation === generationRef.current) setBusy(false)
      })
  }, [cursor, hasMore, pagePath, setBusy])
  useEffect(() => {
    const root = tableShellRef.current
    const target = sentinelRef.current
    if (!root || !target || !hasMore) return
    const observer = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting) loadMore()
    }, { root, rootMargin: '240px 0px', threshold: 0 })
    observer.observe(target)
    return () => observer.disconnect()
  }, [hasMore, loadMore])
  const showRadiusEmpty = !loading && rows.length === 0 && (dataset === 'antifraud' || dataset === 'radius')
  return <section className="data-view">
    {stats && <div className="stat-strip">
      <span><small>Вызовов, 24 ч</small><strong>{stats.calls24h.toLocaleString('ru-RU')}</strong></span>
      <span><small>Неуспешных</small><strong>{stats.failedCalls24h.toLocaleString('ru-RU')}</strong></span>
      <span><small>Средняя длительность</small><strong>{(stats.averageTalkMs / 1000).toFixed(1)} с</strong></span>
      <span><small>Аварий, 24 ч</small><strong>{stats.alarms24h.toLocaleString('ru-RU')}</strong></span>
      <span><small>RADIUS, 24 ч</small><strong>{stats.radius24h.toLocaleString('ru-RU')}</strong></span>
      <span><small>Нераспознано, 24 ч</small><strong className={stats.unknown24h ? 'warning-text' : ''}>{stats.unknown24h.toLocaleString('ru-RU')}</strong></span>
    </div>}
    {admin && diagnostics && <SyslogDiagnosticPanel value={diagnostics} />}
    <div className="toolbar">
      <div><h3>{title}</h3><span>{rows.length} записей в текущей выборке</span></div>
      <div className="toolbar-actions">
        <div className="search"><Search size={14} /><input placeholder="Поиск по данным…"
          value={query} onChange={(event) => setQuery(event.target.value)} /></div>
        <button className="secondary" onClick={() => { window.location.href = exportUrl }}>Экспорт XLSX</button>
      </div>
    </div>
    <div className="table-shell" ref={tableShellRef}>
      {loading && <div className="table-loading" />}
      {dataset === 'calls' ? <CallsTable rows={rows as CallRow[]} onSelect={setSelectedCall} /> :
        <EventsTable rows={rows as EventRow[]} onSelect={setSelectedEvent} />}
      {showRadiusEmpty && <RadiusEmptyState />}
      <div className="scroll-sentinel" ref={sentinelRef}>
        {loading && rows.length > 0 ? 'Загрузка следующих 100 записей…' : hasMore ? '' : rows.length > 0 ? 'Все записи загружены' : ''}
      </div>
    </div>
    {selectedCall && <CallDrawer device={device} call={selectedCall} onClose={() => setSelectedCall(null)} />}
    {selectedEvent && <EventDrawer event={selectedEvent} onClose={() => setSelectedEvent(null)} />}
  </section>
}

function SyslogDiagnosticPanel({ value }: { value: SyslogDiagnostics }) {
  const trace = value.breakdown.filter((row) => row.sourcePort === 10003)
    .reduce((sum, row) => sum + row.count, 0)
  return <details className="diagnostic-panel">
    <summary>
      Диагностика Syslog · Collector {value.version} · parser {value.parserVersion} ·
      порт 10003: {trace.toLocaleString('ru-RU')} · ingress:
      {value.ingressAvailable ? value.ingress.runtime.acceptedDatagrams.toLocaleString('ru-RU') : ' недоступен'}
    </summary>
    <div className="diagnostic-facts">
      <span>Ingress принято: <strong>{value.ingressAvailable
        ? value.ingress.runtime.acceptedDatagrams.toLocaleString('ru-RU') : '—'}</strong></span>
      <span>Ingress передано: <strong>{value.ingressAvailable
        ? value.ingress.runtime.handedOff.toLocaleString('ru-RU') : '—'}</strong></span>
      <span>Ingress spool: <strong>{value.ingressAvailable
        ? value.ingress.spoolDepth.toLocaleString('ru-RU') : '—'}</strong></span>
      <span>Ошибок handoff: <strong>{value.ingressAvailable
        ? value.ingress.runtime.handoffErrors.toLocaleString('ru-RU') : '—'}</strong></span>
      <span>App принято: <strong>{value.runtime.acceptedDatagrams.toLocaleString('ru-RU')}</strong></span>
      <span>App отклонено: <strong>{value.runtime.rejectedDatagrams.toLocaleString('ru-RU')}</strong></span>
      <span>App spool: <strong>{value.spoolDepth.toLocaleString('ru-RU')}</strong></span>
      <span>NATS stream: <strong>{value.natsStreamMessages.toLocaleString('ru-RU')}</strong></span>
      <span>NATS pending: <strong>{value.natsConsumerPending.toLocaleString('ru-RU')}</strong></span>
      <span>Quarantine: <strong>{value.quarantineDepth.toLocaleString('ru-RU')}</strong></span>
      <span>Миграции: <strong>{value.appliedMigrations.join(', ') || '—'}</strong></span>
    </div>
    <div className="diagnostic-breakdown">
      {value.breakdown.map((row) => <span key={[
        row.category, row.parseStatus, row.parserVersion, row.headerFormat, row.sourcePort,
      ].join(':')}>
        <strong>{row.category}</strong> · {row.parseStatus} · {row.parserVersion} ·
        {row.headerFormat} · UDP/{row.sourcePort}: {row.count.toLocaleString('ru-RU')}
      </span>)}
    </div>
  </details>
}

function RadiusEmptyState() {
  return <div className="table-empty">
    <strong>RADIUS-сообщения не получены</strong>
    <p>Проверьте наличие тестового вызова, включение «АнтиФрод» в активном RADIUS-профиле SMG,
      группы Access/Accounting серверов и уровень трассировки Syslog. Режим Custom сам по себе
      задаёт формат RADIUS, но не создаёт события без вызовов.</p>
  </div>
}

function CallsTable({ rows, onSelect }: { rows: CallRow[]; onSelect: (row: CallRow) => void }) {
  return <table><thead><tr>
    <th>Установка</th><th>Входящий маршрут</th><th>Исходящий маршрут</th><th>Номер A: вход</th>
    <th>Номер A: выход</th><th>Номер B: вход</th><th>Номер B: выход</th><th>Длит.</th>
    <th>Q.850</th><th>Результат</th><th>Acct-Session-Id</th><th>UniqueTag</th>
  </tr></thead><tbody>{rows.map((row) => <tr key={row.recordId} onClick={() => onSelect(row)}>
    <td className="mono">{formatTime(row.setupTime)}</td>
    <td>{row.incomingDescription || '—'}</td><td>{row.outgoingDescription || '—'}</td>
    <td className="mono">{row.incomingCgpn || '—'}</td><td className="mono">{row.outgoingCgpn || '—'}</td>
    <td className="mono">{row.incomingCdpn || '—'}</td><td className="mono">{row.outgoingCdpn || '—'}</td>
    <td className="right">{row.durationMs == null ? '—' : `${(row.durationMs / 1000).toFixed(3)} c`}</td>
    <td className="right">{row.releaseCause ?? '—'}</td><td>{row.releaseInfo || '—'}</td>
    <td className="mono">{row.radiusSessionId || '—'}</td><td className="mono">{row.uniqueTag || '—'}</td>
  </tr>)}</tbody></table>
}

function CallDrawer({ device, call, onClose }: { device: Device; call: CallRow; onClose: () => void }) {
  const [timeline, setTimeline] = useState<TimelineRow[]>([])
  useEffect(() => {
    api<{ items: TimelineRow[] }>(`/devices/${device.id}/calls/${call.recordId}/timeline`)
      .then(({ items }) => setTimeline(items || []))
  }, [device.id, call.recordId])
  return <div className="drawer">
    <div className="drawer-header"><div><h3>Карточка вызова</h3><span className="mono">{call.recordId}</span></div>
      <button onClick={onClose}>×</button></div>
    <div className="call-facts">
      <span><small>Установка</small><strong>{formatTime(call.setupTime)}</strong></span>
      <span><small>Длительность</small><strong>{call.durationMs == null ? '—' : `${(call.durationMs / 1000).toFixed(3)} c`}</strong></span>
      <span><small>Q.850</small><strong>{call.releaseCause ?? '—'} · {call.releaseInfo || '—'}</strong></span>
      <span><small>Acct-Session-Id</small><strong className="mono">{call.radiusSessionId || '—'}</strong></span>
    </div>
    <h4>Связанные события АнтиФрод и Syslog</h4>
    <div className="timeline">{timeline.length === 0 && <p>Связанные события пока не найдены.</p>}
      {timeline.map((event) => <div className="timeline-item" key={event.eventId}>
        <i /><div><time>{formatTime(event.receivedAt)}</time><strong>{event.category} · {event.component || 'SMG'}</strong>
          <p>{event.message}</p><small>{event.method} · confidence {event.confidence.toFixed(2)}</small></div>
      </div>)}
    </div>
  </div>
}

function EventsTable({ rows, onSelect }: { rows: EventRow[]; onSelect: (row: EventRow) => void }) {
  return <table><thead><tr><th>Получено</th><th>Раздел</th><th>Компонент</th>
    <th>Сообщение</th><th>Статус</th><th>Атрибуты</th></tr></thead>
    <tbody>{rows.map((row) => <tr key={row.eventId} onClick={() => onSelect(row)}>
      <td className="mono">{formatTime(row.receivedAt)}</td><td><span className="tag">{row.category}</span></td>
      <td className="mono">{row.component || '—'}</td><td className="message-cell">{row.message}</td>
      <td><span className={`parse-status ${row.parseStatus}`}>{row.parseStatus}</span></td>
      <td className="mono">{Object.entries(row.attributes || {}).map(([key, value]) => `${key}=${value}`).join(' · ') || '—'}</td>
    </tr>)}</tbody></table>
}

function EventDrawer({ event, onClose }: { event: EventRow; onClose: () => void }) {
  return <div className="drawer">
    <div className="drawer-header"><div><h3>Событие Syslog</h3><span className="mono">{event.eventId}</span></div>
      <button onClick={onClose}>×</button></div>
    <div className="call-facts">
      <span><small>Получено</small><strong>{formatTime(event.receivedAt)}</strong></span>
      <span><small>Раздел</small><strong>{event.category}</strong></span>
      <span><small>Компонент</small><strong>{event.component || '—'}</strong></span>
      <span><small>Разбор</small><strong>{event.parseStatus}</strong></span>
    </div>
    <h4>Сообщение</h4>
    <pre className="raw-payload">{event.message}</pre>
    <h4>Исходный Syslog без изменений</h4>
    <pre className="raw-payload">{event.rawPayload}</pre>
    <h4>Извлечённые атрибуты</h4>
    <pre className="raw-payload">{JSON.stringify(event.attributes || {}, null, 2)}</pre>
  </div>
}

function CreateDeviceDialog({ onClose, onCreated }: { onClose: () => void; onCreated: (device: Device) => void }) {
  const [form, setForm] = useState({
    name: '', model: 'SMG-1016M', firmware: '3.410.0.7443', timezone: 'Asia/Novosibirsk',
    managementIp: '', syslogSourceIp: '', deviceSign: '', antifraudEnabled: true, antifraudMode: 'Custom',
  })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const update = (field: string, value: string | boolean) => setForm((current) => ({ ...current, [field]: value }))
  async function submit(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    try {
      const device = await api<Device>('/devices', {
        method: 'POST', body: JSON.stringify({ ...form, cdrColumns: [] }),
      })
      onCreated(device)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Ошибка добавления')
    } finally {
      setBusy(false)
    }
  }
  return <Modal title="Добавление SMG-1016M" onClose={onClose}>
    <form className="device-form" onSubmit={submit}>
      <div className="form-grid">
        <label>Название<input autoFocus required value={form.name} onChange={(e) => update('name', e.target.value)} /></label>
        <label>Device Sign<input value={form.deviceSign} onChange={(e) => update('deviceSign', e.target.value)} /></label>
        <label>IP управления<input placeholder="10.0.0.10" value={form.managementIp} onChange={(e) => update('managementIp', e.target.value)} /></label>
        <label>IP-источник Syslog<input required placeholder="10.0.0.10" value={form.syslogSourceIp} onChange={(e) => update('syslogSourceIp', e.target.value)} /></label>
        <label>Прошивка<input required value={form.firmware} onChange={(e) => update('firmware', e.target.value)} /></label>
        <label>Часовой пояс<input required value={form.timezone} onChange={(e) => update('timezone', e.target.value)} /></label>
        <label className="checkbox-row"><input type="checkbox" checked={form.antifraudEnabled}
          onChange={(e) => update('antifraudEnabled', e.target.checked)} /> Используется АнтиФрод</label>
        <label>Режим АнтиФрод<select disabled={!form.antifraudEnabled} value={form.antifraudMode}
          onChange={(e) => update('antifraudMode', e.target.value)}>
          <option>Custom</option><option>Astarta</option><option>Intek</option><option>OFF</option>
        </select></label>
      </div>
      {error && <div className="form-error">{error}</div>}
      <div className="dialog-actions"><button type="button" className="secondary" onClick={onClose}>Отмена</button>
        <button className="primary" disabled={busy}>{busy ? 'Создание…' : 'Создать устройство'}</button></div>
    </form>
  </Modal>
}

function CredentialsDialog({ device, onClose }: { device: Device; onClose: () => void }) {
  return <Modal title="Параметры приёма данных" onClose={onClose}>
    <div className="credentials-warning">Пароль FTP отображается один раз. Сохраните его в защищённом хранилище.</div>
    <dl className="credentials">
      <dt>Syslog сервер</dt><dd className="mono">{window.location.hostname}:514 / UDP</dd>
      <dt>FTP сервер</dt><dd className="mono">{window.location.hostname}:21</dd>
      <dt>FTP пользователь</dt><dd className="mono">{device.ftpUsername}</dd>
      <dt>FTP пароль</dt><dd className="mono secret">{device.generatedPassword}</dd>
      <dt>Каталог CDR</dt><dd className="mono">/</dd>
    </dl>
    <div className="dialog-actions"><button className="primary" onClick={onClose}>Готово</button></div>
  </Modal>
}

function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) {
  return <div className="modal-backdrop" onMouseDown={onClose}><div className="modal" onMouseDown={(e) => e.stopPropagation()}>
    <div className="modal-header"><h3>{title}</h3><button onClick={onClose}>×</button></div>{children}
  </div></div>
}

function EmptyDevices({ canCreate, onCreate }: { canCreate: boolean; onCreate: () => void }) {
  return <div className="empty-devices"><Server size={28} /><h3>Нет подключённого оборудования</h3>
    <p>Добавьте SMG-1016M, чтобы получить изолированные параметры Syslog и FTP.</p>
    {canCreate && <button className="primary" onClick={onCreate}>Добавить устройство</button>}</div>
}

function Centered({ children }: { children: React.ReactNode }) {
  return <div className="centered">{children}</div>
}

function formatTime(value?: string) {
  if (!value) return '—'
  return new Intl.DateTimeFormat('ru-RU', {
    year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit',
    minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3,
  }).format(new Date(value))
}

createRoot(document.getElementById('root')!).render(<App />)
