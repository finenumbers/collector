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
  activeTimezone: string
  timezoneRevision: number
  activeTimezoneRevision: number
  cdrSourceTimezone: string
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
  eventTime?: string
  sourceTimezone: string
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
  antifraud24h: number; antifraudRejected24h: number
  antifraudIncomplete24h: number; unlinkedCalls24h: number
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
  rawEvents24h: number
  classified24h: number
  reprocessedCurrent: number
  reprocessRemaining: number
  antifraudComplete: number
  antifraudIncomplete: number
  antifraudOrphan: number
  correlationExact: number
  correlationComposite: number
  correlationAmbiguous: number
  activeRevision: number
  buildingRevision: number
  revisionTimezone: string
  revisionStatus: string
  replayProcessed: number
  replayTotal: number
  cdrReplayProcessed: number
  cdrReplayTotal: number
  missingCdrInterpretations: number
  radiusRawFragments: number
  lifecycleDerived: number
  correlationTotal: number
  correlationOrphan: number
  ingestRevision: number
  revisionAligned: boolean
  latestRawAt: string
  latestFactAt: string
  latestLifecycleAt: string
  latestAssignmentAt: string
  pendingDirtyBuckets: number
  oldestDirtyAt: string
  ingressAvailable: boolean
  ingress: IngressStatus
}
type CallRow = {
  recordId: string
  setupTime?: string
  setupTimeLocal?: string
  sourceTimezone?: string
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
type AntifraudRow = {
  transactionId: string
  firstEventAt: string
  lastEventAt: string
  callContext: string
  acctSessionId: string
  requestType: string
  requestCode: string
  responseCode: string
  decision: string
  decisionReason: string
  serverAddress: string
  retries: number
  latencyMs?: number
  callingStationId: string
  calledStationId: string
  srcNumberIn: string
  dstNumberIn: string
  srcNumberOut: string
  dstNumberOut: string
  inTrunkgroupLabel: string
  outTrunkgroupLabel: string
  accountingStatus: string
  q850Cause?: number
  completeness: string
  attributes: Record<string, string>
  linkedRecordIds: string[]
  legCount: number
  cdrSetupTime?: string
  correlationMethod: string
  correlationConfidence: number
  correlationTimeDeltaMs: number
  ambiguityReason: string
  cdrSessionId: string
  correlationState: 'exact' | 'composite' | 'ambiguous' | 'orphan'
  matchedFields: string[]
  sourceTimezone: string
  firstEventLocal: string
  lastEventLocal: string
  cdrSetupLocal: string
}
type PageCursor = { before: string; beforeId: string }
type PageResponse = {
  items: Array<EventRow | CallRow | AntifraudRow>
  hasMore: boolean
  nextCursor?: PageCursor
}
type Dataset = 'calls' | 'syslog_all' | 'antifraud' | 'alarms' | 'call_trace' | 'sip' | 'isup' |
  'q931' | 'h323' | 'rtp' | 'hardware' | 'ivr' | 'ip_network' | 'ip_connections' |
  'ip_modules' | 'radius' | 'config_history' | 'auth_log' | 'system_journal' | 'unknown'

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
  const [editingDevice, setEditingDevice] = useState<Device | null>(null)
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
          {user.role === 'admin' && <button className="secondary"
            onClick={() => setEditingDevice(selected)}>Настройки SMG</button>}
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
    {editingDevice && <EditDeviceDialog device={editingDevice}
      onClose={() => setEditingDevice(null)} onSaved={(device) => {
        setDevices((current) => current.map((item) => item.id === device.id ? device : item))
        setEditingDevice(null)
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
  { id: 'h323', label: 'H.323', icon: Network },
  { id: 'rtp', label: 'RTP / RTCP', icon: Radio },
  { id: 'hardware', label: 'Аппаратные модули', icon: Database },
  { id: 'ivr', label: 'IVR', icon: PhoneCall },
  { id: 'ip_network', label: 'IP-сеть', icon: Network },
  { id: 'ip_connections', label: 'IP-соединения', icon: Server },
  { id: 'ip_modules', label: 'IP-субмодули', icon: Database },
  { id: 'radius', label: 'RADIUS', icon: ShieldCheck },
  { id: 'config_history', label: 'Изменения', icon: FileClock },
  { id: 'auth_log', label: 'Журнал доступа', icon: ShieldCheck },
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
  const [rows, setRows] = useState<Array<EventRow | CallRow | AntifraudRow>>([])
  const [loading, setLoading] = useState(false)
  const [selectedCall, setSelectedCall] = useState<CallRow | null>(null)
  const [selectedAntifraud, setSelectedAntifraud] = useState<AntifraudRow | null>(null)
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
  const exportDataset = dataset === 'calls' ? 'calls' : dataset === 'antifraud' ? 'antifraud' : 'events'
  const exportUrl = `/api/devices/${device.id}/export.xlsx?dataset=${exportDataset}&category=${encodeURIComponent(category)}&q=${encodeURIComponent(query)}`
  const pagePath = useCallback((pageCursor?: PageCursor) => {
    const base = dataset === 'calls'
      ? `/devices/${device.id}/calls?q=${encodeURIComponent(query)}&limit=${PAGE_SIZE}`
      : dataset === 'antifraud'
        ? `/devices/${device.id}/antifraud?q=${encodeURIComponent(query)}&limit=${PAGE_SIZE}`
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
  const showRadiusEmpty = !loading && rows.length === 0 && dataset === 'radius'
  const showAntifraudEmpty = !loading && rows.length === 0 && dataset === 'antifraud'
  return <section className="data-view">
    {device.timezoneRevision !== device.activeTimezoneRevision && <div className="timezone-rebuild">
      Часовой пояс {device.timezone} пересобирается в фоне. До атомарного переключения
      показана активная ревизия {device.activeTimezoneRevision} ({activeDeviceTimezone(device)}).
    </div>}
    {stats && <div className="stat-strip">
      <span><small>Вызовов, 24 ч</small><strong>{stats.calls24h.toLocaleString('ru-RU')}</strong></span>
      <span><small>Неуспешных</small><strong>{stats.failedCalls24h.toLocaleString('ru-RU')}</strong></span>
      <span><small>Средняя длительность</small><strong>{(stats.averageTalkMs / 1000).toFixed(1)} с</strong></span>
      <span><small>Аварий, 24 ч</small><strong>{stats.alarms24h.toLocaleString('ru-RU')}</strong></span>
      <span><small>RADIUS, 24 ч</small><strong>{stats.radius24h.toLocaleString('ru-RU')}</strong></span>
      <span><small>AntiFraud, 24 ч</small><strong>{stats.antifraud24h.toLocaleString('ru-RU')}</strong></span>
      <span><small>Reject, 24 ч</small><strong className={stats.antifraudRejected24h ? 'warning-text' : ''}>{stats.antifraudRejected24h.toLocaleString('ru-RU')}</strong></span>
      <span><small>Без связи CDR</small><strong className={stats.unlinkedCalls24h ? 'warning-text' : ''}>{stats.unlinkedCalls24h.toLocaleString('ru-RU')}</strong></span>
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
      {dataset === 'calls' ? <CallsTable rows={rows as CallRow[]}
        timezone={activeDeviceTimezone(device)} onSelect={setSelectedCall} /> :
        dataset === 'antifraud'
          ? <AntifraudTable rows={rows as AntifraudRow[]} timezone={activeDeviceTimezone(device)}
            onSelect={setSelectedAntifraud} />
          : <EventsTable rows={rows as EventRow[]} timezone={activeDeviceTimezone(device)}
            onSelect={setSelectedEvent} />}
      {showRadiusEmpty && <RadiusEmptyState />}
      {showAntifraudEmpty && <AntifraudEmptyState />}
      <div className="scroll-sentinel" ref={sentinelRef}>
        {loading && rows.length > 0 ? 'Загрузка следующих 100 записей…' : hasMore ? '' : rows.length > 0 ? 'Все записи загружены' : ''}
      </div>
    </div>
    {selectedCall && <CallDrawer device={device} call={selectedCall} onClose={() => setSelectedCall(null)} />}
    {selectedAntifraud && <AntifraudDrawer device={device} row={selectedAntifraud}
      onClose={() => setSelectedAntifraud(null)} />}
    {selectedEvent && <EventDrawer event={selectedEvent} timezone={activeDeviceTimezone(device)}
      onClose={() => setSelectedEvent(null)} />}
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
      <span>Classified, 24 ч: <strong>{value.classified24h.toLocaleString('ru-RU')} / {value.rawEvents24h.toLocaleString('ru-RU')}</strong></span>
      <span>Reprocess current: <strong>{value.reprocessedCurrent.toLocaleString('ru-RU')}</strong></span>
      <span>Осталось reprocess: <strong>{value.reprocessRemaining.toLocaleString('ru-RU')}</strong></span>
      <span>Active / building revision: <strong>{value.activeRevision || '—'} / {value.buildingRevision || '—'}</strong></span>
      <span>Read / ingest revision: <strong>{value.activeRevision || '—'} / {value.ingestRevision || '—'} · {value.revisionAligned ? 'aligned' : 'SPLIT'}</strong></span>
      <span>Revision timezone / status: <strong>{value.revisionTimezone || '—'} / {value.revisionStatus || '—'}</strong></span>
      <span>Replay Syslog: <strong>{formatCount(value.replayProcessed)} / {formatCount(value.replayTotal)}</strong></span>
      <span>Replay CDR: <strong>{formatCount(value.cdrReplayProcessed)} / {formatCount(value.cdrReplayTotal)}</strong></span>
      <span>CDR без time fact: <strong>{formatCount(value.missingCdrInterpretations)}</strong></span>
      <span>RADIUS raw / lifecycle: <strong>{formatCount(value.radiusRawFragments)} / {formatCount(value.lifecycleDerived)}</strong></span>
      <span>Последний raw / fact: <strong>{formatTime(value.latestRawAt, 'UTC')} / {formatTime(value.latestFactAt, 'UTC')}</strong></span>
      <span>Последний lifecycle / link: <strong>{formatTime(value.latestLifecycleAt, 'UTC')} / {formatTime(value.latestAssignmentAt, 'UTC')}</strong></span>
      <span>Dirty buckets: <strong>{formatCount(value.pendingDirtyBuckets)} · oldest {formatTime(value.oldestDirtyAt, 'UTC')}</strong></span>
      <span>AntiFraud complete: <strong>{value.antifraudComplete.toLocaleString('ru-RU')}</strong></span>
      <span>AntiFraud incomplete: <strong>{value.antifraudIncomplete.toLocaleString('ru-RU')}</strong></span>
      <span>AntiFraud без CDR: <strong>{value.antifraudOrphan.toLocaleString('ru-RU')}</strong></span>
      <span>Exact links: <strong>{value.correlationExact.toLocaleString('ru-RU')}</strong></span>
      <span>Composite links: <strong>{value.correlationComposite.toLocaleString('ru-RU')}</strong></span>
      <span>Ambiguous: <strong>{value.correlationAmbiguous.toLocaleString('ru-RU')}</strong></span>
      <span>Coverage invariant: <strong>{(value.correlationExact || 0) +
        (value.correlationComposite || 0) + (value.correlationAmbiguous || 0) +
        (value.correlationOrphan || 0)} / {value.correlationTotal || 0}</strong></span>
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

function AntifraudEmptyState() {
  return <div className="table-empty">
    <strong>AntiFraud lifecycle пока не собран</strong>
    <p>Технический RADIUS-поток доступен в разделе «RADIUS». В AntiFraud появляются
      только операции number/save_call/check_call, подтверждённые xpgk-атрибутами,
      вместе с ответом, решением и связью с CDR.</p>
  </div>
}

function AntifraudTable({ rows, timezone, onSelect }: {
  rows: AntifraudRow[]
  timezone: string
  onSelect: (row: AntifraudRow) => void
}) {
  return <table><thead><tr>
    <th>Последнее событие</th><th>Операция</th><th>Решение</th><th>Номер A</th>
    <th>Номер B</th><th>Входящий маршрут</th><th>Исходящий маршрут</th>
    <th>RADIUS server</th><th>Latency</th><th>Accounting</th><th>Корреляция</th><th>CDR legs</th>
    <th>Полнота</th><th>Acct-Session-Id</th><th>Call context</th>
  </tr></thead><tbody>{rows.map((row) => <tr key={row.transactionId}
    onClick={() => onSelect(row)}>
    <td className="mono">{formatTime(row.lastEventAt, timezone)}</td>
    <td><span className="tag">{row.requestType || 'не определена'}</span></td>
    <td><span className={`decision ${row.decision || 'pending'}`}>
      {decisionLabel(row.decision)}</span></td>
    <td className="mono">{row.srcNumberIn || row.callingStationId || '—'}</td>
    <td className="mono">{row.dstNumberIn || row.calledStationId || '—'}</td>
    <td>{row.inTrunkgroupLabel || '—'}</td><td>{row.outTrunkgroupLabel || '—'}</td>
    <td className="mono">{row.serverAddress || '—'}</td>
    <td className="right">{row.latencyMs == null ? '—' : `${row.latencyMs} мс`}</td>
    <td>{row.accountingStatus || '—'}</td>
    <td><span className={`parse-status ${row.correlationState || 'orphan'}`}>
      {row.correlationState || 'orphan'}</span> {row.correlationMethod}</td>
    <td className="right">{row.legCount || 'нет CDR'}</td>
    <td><span className={`parse-status ${row.completeness}`}>
      {row.completeness}</span></td>
    <td className="mono">{row.acctSessionId || '—'}</td>
    <td className="mono">{row.callContext || '—'}</td>
  </tr>)}</tbody></table>
}

function AntifraudDrawer({ device, row, onClose }: {
  device: Device
  row: AntifraudRow
  onClose: () => void
}) {
  const [timeline, setTimeline] = useState<TimelineRow[]>([])
  useEffect(() => {
    api<{ items: TimelineRow[] }>(
      `/devices/${device.id}/antifraud/${row.transactionId}/timeline`,
    ).then(({ items }) => setTimeline(items || []))
  }, [device.id, row.transactionId])
  return <div className="drawer">
    <div className="drawer-header"><div><h3>AntiFraud lifecycle</h3>
      <span className="mono">{row.transactionId}</span></div>
      <button onClick={onClose}>×</button></div>
    <div className="call-facts">
      <span><small>Операция</small><strong>{row.requestType || '—'}</strong></span>
      <span><small>Решение</small><strong>{decisionLabel(row.decision)}</strong></span>
      <span><small>Причина</small><strong>{row.decisionReason || '—'}</strong></span>
      <span><small>Q.850</small><strong>{row.q850Cause ?? '—'}</strong></span>
      <span><small>RADIUS server</small><strong className="mono">{row.serverAddress || '—'}</strong></span>
      <span><small>Latency / retries</small><strong>{row.latencyMs == null ? '—' : `${row.latencyMs} мс`} / {row.retries}</strong></span>
      <span><small>Accounting</small><strong>{row.accountingStatus || '—'}</strong></span>
      <span><small>CDR legs</small><strong>{row.legCount}</strong></span>
      <span><small>SMG timezone</small><strong>{row.sourceTimezone || activeDeviceTimezone(device)}</strong></span>
      <span><small>AntiFraud local / UTC</small><strong>{row.firstEventLocal || formatTime(row.firstEventAt, activeDeviceTimezone(device))}
        {' / '}{row.firstEventAt}</strong></span>
      <span><small>CDR setup local / UTC</small><strong>{row.cdrSetupLocal || formatTime(row.cdrSetupTime, activeDeviceTimezone(device))}
        {' / '}{row.cdrSetupTime || '—'}</strong></span>
      <span><small>Состояние корреляции</small><strong>{row.correlationState || 'orphan'}</strong></span>
      <span><small>Метод</small><strong>{row.correlationMethod || '—'}</strong></span>
      <span><small>Confidence / delta</small><strong>
        {row.correlationMethod ? `${row.correlationConfidence.toFixed(2)} / ${row.correlationTimeDeltaMs} мс` : '—'}</strong></span>
      <span><small>Matched fields</small><strong>{row.matchedFields?.join(', ') || '—'}</strong></span>
      <span><small>Причина ambiguity/orphan</small><strong>{row.ambiguityReason || '—'}</strong></span>
      <span><small>Acct-Session-Id</small><strong className="mono">{row.acctSessionId || '—'}</strong></span>
      <span><small>CDR Acct-Session-Id</small><strong className="mono">{row.cdrSessionId || '—'}</strong></span>
      <span><small>Call context</small><strong className="mono">{row.callContext || '—'}</strong></span>
    </div>
    <h4>Номера и маршруты</h4>
    <div className="call-facts">
      <span><small>A: вход / выход</small><strong className="mono">
        {row.srcNumberIn || row.callingStationId || '—'} / {row.srcNumberOut || '—'}</strong></span>
      <span><small>B: вход / выход</small><strong className="mono">
        {row.dstNumberIn || row.calledStationId || '—'} / {row.dstNumberOut || '—'}</strong></span>
      <span><small>Входящий trunk</small><strong>{row.inTrunkgroupLabel || '—'}</strong></span>
      <span><small>Исходящий trunk</small><strong>{row.outTrunkgroupLabel || '—'}</strong></span>
    </div>
    <h4>CDR legs</h4>
    {row.linkedRecordIds.length === 0
      ? <p className="warning-text">CDR не назначен: {row.correlationState || 'orphan'}.
        {row.ambiguityReason ? ` ${row.ambiguityReason}` : ' Сверка повторится после новых фактов.'}</p>
      : <div className="timeline">{row.linkedRecordIds.map((recordId, index) =>
        <div className="timeline-item" key={recordId}><i /><div>
          <strong>Leg {index + 1}</strong><p className="mono">{recordId}</p>
        </div></div>)}</div>}
    <h4>Исходные события RADIUS</h4>
    <div className="timeline">{timeline.length === 0 && <p>События пока не найдены.</p>}
      {timeline.map((event) => <div className="timeline-item" key={event.eventId}>
        <i /><div><time>{formatTime(event.eventTime || event.receivedAt, activeDeviceTimezone(device))}</time>
          <strong>{event.component || 'RADIUS'} · {event.attributes.packet_code || 'fragment'}</strong>
          <p>{event.message}</p></div>
      </div>)}
    </div>
    <h4>Все собранные атрибуты</h4>
    <pre className="raw-payload">{JSON.stringify(row.attributes || {}, null, 2)}</pre>
  </div>
}

function CallsTable({ rows, timezone, onSelect }: {
  rows: CallRow[]
  timezone: string
  onSelect: (row: CallRow) => void
}) {
  return <table><thead><tr>
    <th>Установка</th><th>Входящий маршрут</th><th>Исходящий маршрут</th><th>Номер A: вход</th>
    <th>Номер A: выход</th><th>Номер B: вход</th><th>Номер B: выход</th><th>Длит.</th>
    <th>Q.850</th><th>Результат</th><th>Acct-Session-Id</th><th>UniqueTag</th>
  </tr></thead><tbody>{rows.map((row) => <tr key={row.recordId} onClick={() => onSelect(row)}>
    <td className="mono">{formatTime(row.setupTime, timezone)}</td>
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
  const groups = groupCallTimeline(timeline)
  const timezone = activeDeviceTimezone(device)
  return <div className="drawer">
    <div className="drawer-header"><div><h3>Карточка вызова</h3><span className="mono">{call.recordId}</span></div>
      <button onClick={onClose}>×</button></div>
    <div className="call-facts">
      <span><small>Установка · {timezone}</small><strong>{formatTime(call.setupTime, timezone)}</strong></span>
      <span><small>Длительность</small><strong>{call.durationMs == null ? '—' : `${(call.durationMs / 1000).toFixed(3)} c`}</strong></span>
      <span><small>Q.850</small><strong>{call.releaseCause ?? '—'} · {call.releaseInfo || '—'}</strong></span>
      <span><small>Acct-Session-Id</small><strong className="mono">{call.radiusSessionId || '—'}</strong></span>
    </div>
    <h4>Связанные события АнтиФрод и Syslog</h4>
    {timeline.length === 0 && <div className="timeline"><p>Связанные события пока не найдены.</p></div>}
    <div className="timeline-groups">{groups.map((group) => <section
      className="timeline-group" key={group.id}>
      <h5><span>{group.label}</span><b>{group.items.length}</b></h5>
      <div className="timeline">{group.items.map((event) => <div
        className="timeline-item" key={event.eventId}>
        <i /><div><time>{formatTime(event.eventTime || event.receivedAt, timezone)}</time>
          <strong>{event.component || 'SMG'}</strong>
          <p>{event.message}</p><small>{event.method} · confidence {event.confidence.toFixed(2)}</small>
        </div>
      </div>)}</div>
    </section>)}</div>
  </div>
}

const timelineGroupOrder = [
  ['antifraud', 'АнтиФрод'],
  ['radius', 'RADIUS'],
  ['call_trace', 'Обработка вызова'],
  ['sip', 'SIP'],
  ['isup', 'SS7 / ISUP'],
  ['q931', 'Q.931'],
  ['h323', 'H.323'],
  ['rtp', 'RTP / RTCP'],
  ['alarms', 'Аварии'],
  ['other', 'Прочие Syslog'],
] as const

function groupCallTimeline(items: TimelineRow[]) {
  const groups = new Map<string, TimelineRow[]>()
  for (const item of items) {
    let group = item.category
    if (item.category === 'radius') {
      const requestType = (item.attributes?.xpgk_request_type || '').toLowerCase()
      group = item.attributes?.is_antifraud === 'true' ||
        ['number', 'save_call', 'check_call'].includes(requestType) ? 'antifraud' : 'radius'
    } else if (!timelineGroupOrder.some(([id]) => id === item.category)) {
      group = 'other'
    }
    groups.set(group, [...(groups.get(group) || []), item])
  }
  return timelineGroupOrder
    .map(([id, label]) => ({ id, label, items: groups.get(id) || [] }))
    .filter((group) => group.items.length > 0)
}

function EventsTable({ rows, timezone, onSelect }: {
  rows: EventRow[]
  timezone: string
  onSelect: (row: EventRow) => void
}) {
  return <table><thead><tr><th>Получено</th><th>Раздел</th><th>Компонент</th>
    <th>Сообщение</th><th>Статус</th><th>Атрибуты</th></tr></thead>
    <tbody>{rows.map((row) => <tr key={row.eventId} onClick={() => onSelect(row)}>
      <td className="mono">{formatTime(row.eventTime || row.receivedAt, timezone)}</td><td><span className="tag">{row.category}</span></td>
      <td className="mono">{row.component || '—'}</td><td className="message-cell">{row.message}</td>
      <td><span className={`parse-status ${row.parseStatus}`}>{row.parseStatus}</span></td>
      <td className="mono">{Object.entries(row.attributes || {}).map(([key, value]) => `${key}=${value}`).join(' · ') || '—'}</td>
    </tr>)}</tbody></table>
}

function EventDrawer({ event, timezone, onClose }: {
  event: EventRow
  timezone: string
  onClose: () => void
}) {
  return <div className="drawer">
    <div className="drawer-header"><div><h3>Событие Syslog</h3><span className="mono">{event.eventId}</span></div>
      <button onClick={onClose}>×</button></div>
    <div className="call-facts">
      <span><small>Время события</small><strong>{formatTime(event.eventTime || event.receivedAt, timezone)}</strong></span>
      <span><small>Получено Collector</small><strong>{formatTime(event.receivedAt, timezone)}</strong></span>
      <span><small>Timezone источника</small><strong>{event.sourceTimezone || timezone}</strong></span>
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

function EditDeviceDialog({ device, onClose, onSaved }: {
  device: Device
  onClose: () => void
  onSaved: (device: Device) => void
}) {
  const [form, setForm] = useState({
    name: device.name, firmware: device.firmware, timezone: device.timezone,
    managementIp: device.managementIp || '', syslogSourceIp: device.syslogSourceIp,
    deviceSign: device.deviceSign, antifraudEnabled: device.antifraudEnabled,
    antifraudMode: device.antifraudMode, enabled: device.enabled,
  })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const update = (field: string, value: string | boolean) =>
    setForm((current) => ({ ...current, [field]: value }))
  async function submit(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      onSaved(await api<Device>(`/devices/${device.id}`, {
        method: 'PATCH', body: JSON.stringify(form),
      }))
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Ошибка сохранения')
    } finally {
      setBusy(false)
    }
  }
  return <Modal title={`Настройки ${device.name}`} onClose={onClose}>
    <form className="device-form" onSubmit={submit}>
      <div className="form-grid">
        <label>Название<input autoFocus required value={form.name}
          onChange={(e) => update('name', e.target.value)} /></label>
        <label>Device Sign<input value={form.deviceSign}
          onChange={(e) => update('deviceSign', e.target.value)} /></label>
        <label>IP управления<input value={form.managementIp}
          onChange={(e) => update('managementIp', e.target.value)} /></label>
        <label>IP-источник Syslog<input required value={form.syslogSourceIp}
          onChange={(e) => update('syslogSourceIp', e.target.value)} /></label>
        <label>Прошивка<input required value={form.firmware}
          onChange={(e) => update('firmware', e.target.value)} /></label>
        <label>Часовой пояс IANA<input required placeholder="Asia/Novosibirsk"
          value={form.timezone} onChange={(e) => update('timezone', e.target.value)} /></label>
        <label className="checkbox-row"><input type="checkbox" checked={form.antifraudEnabled}
          onChange={(e) => update('antifraudEnabled', e.target.checked)} /> Используется АнтиФрод</label>
        <label>Режим АнтиФрод<select disabled={!form.antifraudEnabled}
          value={form.antifraudMode} onChange={(e) => update('antifraudMode', e.target.value)}>
          <option>Custom</option><option>Astarta</option><option>Intek</option><option>OFF</option>
        </select></label>
        <label className="checkbox-row"><input type="checkbox" checked={form.enabled}
          onChange={(e) => update('enabled', e.target.checked)} /> Приём данных включён</label>
      </div>
      {error && <div className="form-error">{error}</div>}
      <div className="dialog-actions"><button type="button" className="secondary"
        onClick={onClose}>Отмена</button>
        <button className="primary" disabled={busy}>{busy ? 'Сохранение…' : 'Сохранить'}</button></div>
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

function activeDeviceTimezone(device: Device) {
  return device.activeTimezone || device.timezone
}

function formatCount(value?: number) {
  return Number.isFinite(value) ? Number(value).toLocaleString('ru-RU') : '0'
}

function formatTime(value?: string, timezone = 'UTC') {
  if (!value) return '—'
  return new Intl.DateTimeFormat('ru-RU', {
    year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit',
    minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3,
    timeZone: timezone,
  }).format(new Date(value))
}

function decisionLabel(value: string) {
  switch (value) {
    case 'accept': return 'Пропущен'
    case 'reject': return 'Заблокирован'
    case 'timeout_fail_open': return 'Пропущен по timeout'
    case 'informational': return 'Информационный'
    default: return 'Ожидается / неизвестно'
  }
}

createRoot(document.getElementById('root')!).render(<App />)
