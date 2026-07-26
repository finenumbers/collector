import { FormEvent, useCallback, useEffect, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import {
  Activity, AlertTriangle, CirclePlus, Database, FileClock,
  LogOut, Network, PhoneCall, Radio, Search, Server, Settings, ShieldCheck,
} from 'lucide-react'
import './styles.css'
import {
  canManageUsers, normalizeFirmwareScheme, purgeConfirmationReady, purgeRetryLabel,
  retentionDescription, retentionLabel,
} from './settings'
import { antifraudOutcome, cdrOutcome, outcomeLabel } from './outcomes'
import { readModelNotice } from './readModelNotice'
import {
  defaultSourceDataset, EquipmentTemplate, fallbackTemplates, normalizeTemplate, sourceCapabilities,
  sourceCategory, SourceCapabilities, SourceCategory, sourceDatasets, templatesFor,
} from './equipment'
import {
  createExportRequest, ExportJob, exportDownloadURL, exportJobsURL, exportJobURL,
  ExportNavigationDataset, isExportActive, localDateInTimezone, pollDelay,
} from './export'
import fineNumbersLogoUrl from './assets/fine-numbers-logo-transparent-v3.png'

type User = { id: string; username: string; role: 'admin' | 'analyst' | 'viewer' }
type ManagedUser = User & {
  active: boolean
  createdAt: string
  lastSeenAt?: string
  lockedUntil?: string
  failedAttempts?: number
}
type SystemInfo = { version: string; status: string; user: User; services: Record<string, boolean> }
type RetentionPolicy = {
  policyClass: 'syslog' | 'cdr' | 'softswitch_cdr' | 'derived' | 'raw_cdr_archive'
  activeDays: number
  pendingDays?: number
  effectiveAt?: string
  lastAppliedAt?: string
  lastError?: string
}
type DashboardDevice = {
  id: string
  name: string
  model: string
  firmware: string
  timezone: string
  activeTimezone: string
  enabled: boolean
  metrics: {
    calls: number
    failedCalls: number
    averageTalkMs: number
    alarms: number
    unknown: number
    antifraud: number
    antifraudRejected: number
  }
  freshness: { latestSyslogAt?: string; latestCdrAt?: string }
  revision: {
    configured: number
    active: number
    building: number
    aligned: boolean
    status: string
    reason?: 'initial_build' | 'timezone_change' | string
  }
  sourceCategory?: SourceCategory
  templateKey?: string
  capabilities?: SourceCapabilities
  fileMetrics?: { files: number; bytes: number; latestAt?: string }
}
type DashboardSnapshot = {
  window: string
  totals: {
    activeDevices: number
    calls: number
    failed: number
    averageTalkMs: number
    alarms: number
    unknown: number
    antifraud: number
    rejects: number
    incomplete: number
    equipment?: DashboardCategoryTotals
    softswitch?: DashboardCategoryTotals
  }
  categoryTotals?: Partial<Record<SourceCategory, DashboardCategoryTotals>>
  devices: DashboardDevice[]
  system: {
    version: string
    services: Record<string, boolean>
    spoolDepth: number
    natsStreamMessages: number
    runtime?: IngestRuntime
  }
  diagnostics: string[]
}
type DashboardCategoryTotals = {
  activeSources?: number
  totalSources?: number
  calls?: number
  failed?: number
  averageTalkMs?: number
  alarms?: number
  unknown?: number
  antifraud?: number
  rejects?: number
  files?: number
  bytes?: number
}
type ReplayProgress = {
  pending: number
  processing: number
  complete: number
  quarantined: number
}
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
  syslogSourceIp?: string
  managementIp?: string
  deviceSign: string
  antifraudEnabled: boolean
  antifraudMode: string
  ftpUsername: string
  ftpHome: string
  generatedPassword?: string
  enabled: boolean
  purgeState?: 'active' | 'deleting' | 'purge_failed'
  purgeError?: string
  sourceCategory?: SourceCategory
  templateKey?: string
  capabilities?: SourceCapabilities
  replay?: ReplayProgress
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
  activeRevisionTimezone: string
  buildingRevision: number
  revisionTimezone: string
  revisionStatus: string
  revisionReason?: 'initial_build' | 'timezone_change' | string
  replayProcessed: number
  replayTotal: number
  cdrReplayProcessed: number
  cdrReplayTotal: number
  missingCdrInterpretations: number
  radiusRawFragments: number
  lifecycleDerived: number
  syslogConstructs: number
  constructMembers: number
  constructOrphans: number
  heuristicConstructs: number
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
  cdrIngestFiles?: CdrIngestFile[]
}
type CdrIngestFile = {
  id: string
  originalName: string
  sha256?: string
  sizeBytes?: number
  objectKey?: string
  status: string
  rowsTotal: number
  rowsValid: number
  error?: string
  receivedAt: string
  processedAt?: string
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
type SatelCdrRow = {
  recordId: string
  externalCdrId?: string
  cdrId?: string
  setupTime?: string
  connectTime?: string
  disconnectTime?: string
  durationMs?: number
  outcome?: string
  inAni?: string
  inDnis?: string
  outAni?: string
  outDnis?: string
  billAni?: string
  billDnis?: string
  srcName?: string
  dstName?: string
  dpName?: string
  protocols?: string[] | string
  sigNodeName?: string
  signalNodeName?: string
  inLegProto?: string
  outLegProto?: string
  inLegTransportProto?: string
  outLegTransportProto?: string
  confId?: string
  callId?: string
  srcCallId?: string
  dstCallId?: string
  inLegCallId?: string
  outLegCallId?: string
  disconnectCode?: string | number
  disconnectText?: string
  disconnectSuccess?: boolean
  disconnectInitiator?: string
  endpoints?: unknown
  codecs?: unknown
  timing?: unknown
  media?: unknown
  pddMs?: number
  scdMs?: number
  pdd?: number
  scd?: number
  termElapsedTime?: number
  termSetupTime?: string
  termConnectTime?: string
  termDisconnectTime?: string
  termPdd?: number
  termScd?: number
  srcGatekeeperAddress?: string
  remoteSrcSigAddress?: string
  remoteDstSigAddress?: string
  remoteSrcMediaAddress?: string
  remoteDstMediaAddress?: string
  localSrcSigAddress?: string
  localDstSigAddress?: string
  localSrcMediaAddress?: string
  localDstMediaAddress?: string
  inLegCodecs?: string
  outLegCodecs?: string
  srcMediaBytesIn?: number
  srcMediaBytesOut?: number
  dstMediaBytesIn?: number
  dstMediaBytesOut?: number
  srcMediaPackets?: number
  dstMediaPackets?: number
  srcMediaPacketsLate?: number
  dstMediaPacketsLate?: number
  srcMediaPacketsLost?: number
  dstMediaPacketsLost?: number
  srcMinJitter?: number
  srcMaxJitter?: number
  dstMinJitter?: number
  dstMaxJitter?: number
  rawFields?: Record<string, unknown>
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
type PageResponse<T> = {
  items: T[]
  hasMore: boolean
  nextCursor?: PageCursor
}
type DataRow = EventRow | CallRow | SatelCdrRow | AntifraudRow
type Dataset = ExportNavigationDataset

let csrfToken = ''
const PAGE_SIZE = 100

async function api<T>(path: string, init?: RequestInit & { timeoutMs?: number }): Promise<T> {
  const { timeoutMs, ...requestInit } = init || {}
  const controller = timeoutMs ? new AbortController() : undefined
  const timer = timeoutMs
    ? window.setTimeout(() => controller?.abort(), timeoutMs)
    : undefined
  try {
    const response = await fetch(`/api${path}`, {
      credentials: 'same-origin',
      ...requestInit,
      signal: controller?.signal ?? requestInit.signal,
      headers: {
        'Content-Type': 'application/json',
        ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
        ...requestInit.headers,
      },
    })
    if (response.status === 204) return undefined as T
    const body = await response.json().catch(() => ({})) as { error?: string }
    if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`)
    return body as T
  } finally {
    if (timer !== undefined) window.clearTimeout(timer)
  }
}

const purgePhases = [
  'Блокировка приёма Syslog/CDR…',
  'Очистка ingress и FTP…',
  'Очистка spool и NATS…',
  'Удаление ClickHouse…',
  'Удаление MinIO и CDR volume…',
  'Финальная проверка PostgreSQL…',
]

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
      <div className="product-mark"><img src={fineNumbersLogoUrl} alt="Fine Numbers" /></div>
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
  const [templates, setTemplates] = useState<EquipmentTemplate[]>(fallbackTemplates)
  const [activeDevice, setActiveDevice] = useState<string>('')
  const [activeCategory, setActiveCategory] = useState<SourceCategory>('equipment')
  const [activeView, setActiveView] = useState<'dashboard' | 'device' | 'settings'>('dashboard')
  const [dataset, setDataset] = useState<Dataset>('calls')
  const [showCreate, setShowCreate] = useState<SourceCategory | null>(null)
  const [editingDevice, setEditingDevice] = useState<Device | null>(null)
  const [credentials, setCredentials] = useState<Device | null>(null)
  const [error, setError] = useState('')

  const loadDevices = useCallback(() => api<{ items: Device[] }>('/devices').then(({ items }) => {
    setDevices(items || [])
    setActiveDevice((current) => current || items?.[0]?.id || '')
  }).catch((reason) => setError(reason.message)), [])
  useEffect(() => {
    void loadDevices()
    api<{ items: EquipmentTemplate[] }>('/equipment-templates')
      .then(({ items }) => setTemplates((items || []).map(normalizeTemplate)))
      .catch(() => setTemplates(fallbackTemplates))
  }, [loadDevices])
  const hasTimezoneRebuild = devices.some((device) =>
    device.timezoneRevision !== device.activeTimezoneRevision)
  const hasReplay = devices.some((device) =>
    Boolean(device.replay?.pending || device.replay?.processing))
  useEffect(() => {
    if (!hasTimezoneRebuild && !hasReplay) return
    const timer = window.setInterval(() => void loadDevices(), 5000)
    return () => window.clearInterval(timer)
  }, [hasReplay, hasTimezoneRebuild, loadDevices])
  const selected = devices.find((device) => device.id === activeDevice)
  const equipment = devices.filter((device) => sourceCategory(device) === 'equipment')
  const softswitches = devices.filter((device) => sourceCategory(device) === 'softswitch')
  const selectSource = (device: Device) => {
    const category = sourceCategory(device)
    setActiveDevice(device.id)
    setActiveCategory(category)
    setDataset(defaultSourceDataset(device))
    setActiveView('device')
  }
  const sourceList = (items: Device[], category: SourceCategory) => <>
    <div className="device-list">
      {items.map((device) => <button key={device.id}
        className={`device-button ${device.id === activeDevice ? 'active' : ''}`}
        onClick={() => selectSource(device)}>
        <span className={`status-dot ${device.enabled && device.purgeState !== 'purge_failed' ? 'online' : ''}`} />
        <span>
          <strong>{device.name}</strong>
          <small>{device.purgeState === 'purge_failed' ? 'Ошибка удаления' :
            device.purgeState === 'deleting' ? 'Удаление…' :
              category === 'softswitch' ? device.ftpUsername : device.syslogSourceIp}</small>
        </span>
      </button>)}
      {user.role === 'admin' && <button className="add-device" onClick={() => {
        setActiveCategory(category)
        setShowCreate(category)
      }}>
        <CirclePlus size={15} /> {category === 'equipment' ? 'Добавить оборудование' : 'Добавить софтсвитч'}
      </button>}
    </div>
    {selected && activeView === 'device' && sourceCategory(selected) === category &&
      <DeviceNavigation device={selected} active={dataset} onChange={setDataset} />}
  </>

  return <div className="workspace">
    <aside className="sidebar">
      <button className="brand" title="Открыть Dashboard" aria-label="Открыть Dashboard"
        onClick={() => setActiveView('dashboard')}>
        <img src={fineNumbersLogoUrl} alt="Fine Numbers" />
      </button>
      <div className="sidebar-scroll">
        <div className="side-section-label">ОБОРУДОВАНИЕ</div>
        {sourceList(equipment, 'equipment')}
        <div className="side-section-label">СОФТСВИТЧИ</div>
        {sourceList(softswitches, 'softswitch')}
      </div>
      <div className="sidebar-footer">
        <button className={activeView === 'settings' ? 'active' : ''}
          onClick={() => setActiveView('settings')}><Settings size={15} /> Настройки</button>
        <div className="user-line"><span><strong>{user.username}</strong><small>{user.role}</small></span>
          <button title="Выйти" onClick={onLogout}><LogOut size={15} /></button></div>
      </div>
    </aside>
    <main>
      <header className="topbar">
        <div>
          <h2>{activeView === 'dashboard' ? 'Dashboard' :
            activeView === 'settings' ? 'Настройки системы' :
              selected?.name || 'Оборудование'}</h2>
          {activeView === 'dashboard' && <span>Состояние Collector и оборудования</span>}
          {activeView === 'settings' && <span>Пользователи, сервисы и хранение данных</span>}
          {activeView === 'device' && selected &&
            <span>{selected.model || (sourceCategory(selected) === 'softswitch' ? 'Софтсвитч' : 'Оборудование')}
              {selected.firmware ? ` · ${selected.firmware}` : ''} · {selected.timezone}</span>}
        </div>
        {activeView === 'device' && selected && <div className="header-health">
          <span><i className={`status-dot ${selected.enabled && selected.purgeState !== 'purge_failed' ? 'online' : ''}`} />
            {selected.purgeState === 'purge_failed' ? 'Удаление не завершено' :
              selected.purgeState === 'deleting' ? 'Идёт удаление' :
                selected.enabled ? 'Приём активен' : 'Приём выключен'}
          </span>
          {sourceCapabilities(selected).antifraud &&
            <span>{selected.antifraudEnabled ? `АнтиФрод: ${selected.antifraudMode}` : 'Без АнтиФрод'}</span>}
          {user.role === 'admin' && selected.purgeState === 'purge_failed' &&
            <button className="danger" onClick={() => setEditingDevice(selected)}>
              Повторить удаление
            </button>}
          {user.role === 'admin' && <button className="secondary"
            onClick={() => setEditingDevice(selected)}>Настройки</button>}
        </div>}
      </header>
      {error && <div className="global-error">{error}</div>}
      {activeView === 'dashboard' && <DashboardPage devices={devices}
        onSelectDevice={(deviceID) => {
          const device = devices.find((item) => item.id === deviceID)
          if (device) selectSource(device)
        }} />}
      {activeView === 'settings' && <SystemSettingsPage user={user} />}
      {activeView === 'device' && (!selected
        ? <EmptyDevices category={activeCategory} canCreate={user.role === 'admin'}
          onCreate={() => setShowCreate(activeCategory)} />
        : <DataView key={`${selected.id}:${dataset}:${activeDeviceTimezone(selected)}`}
          device={selected} dataset={dataset}
          admin={user.role === 'admin'} />)}
    </main>
    {showCreate && <CreateDeviceDialog category={showCreate} templates={templates}
      onClose={() => setShowCreate(null)} onCreated={(device) => {
      setShowCreate(null)
      setCredentials(device)
      loadDevices()
      setActiveDevice(device.id)
      const category = sourceCategory(device)
      setActiveCategory(category)
      setDataset(defaultSourceDataset(device))
      setActiveView('device')
    }} />}
    {editingDevice && <EditDeviceDialog device={editingDevice} templates={templates}
      initialDeleting={editingDevice.purgeState === 'purge_failed'}
      onClose={() => setEditingDevice(null)} onSaved={(device) => {
        setDevices((current) => current.map((item) => item.id === device.id ? device : item))
        setEditingDevice(null)
      }} onDeleted={() => {
        setEditingDevice(null)
        setActiveDevice('')
        void loadDevices()
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
function DashboardPage({ devices, onSelectDevice }: {
  devices: Device[]
  onSelectDevice: (deviceID: string) => void
}) {
  const [snapshot, setSnapshot] = useState<DashboardSnapshot | null>(null)
  const [windowValue, setWindowValue] = useState('24h')
  const [error, setError] = useState('')
  useEffect(() => {
    let active = true
    api<DashboardSnapshot>(`/dashboard?window=${windowValue}`)
      .then((value) => { if (active) setSnapshot(value) })
      .catch((reason) => {
        if (active) setError(reason instanceof Error ? reason.message : 'Dashboard недоступен')
      })
    return () => { active = false }
  }, [windowValue])
  const equipmentRows = dashboardRows(snapshot, devices, 'equipment')
  const softswitchRows = dashboardRows(snapshot, devices, 'softswitch')
  const equipmentTotals = dashboardCategoryTotals(snapshot, devices, equipmentRows, 'equipment')
  const softswitchTotals = dashboardCategoryTotals(snapshot, devices, softswitchRows, 'softswitch')
  return <section className="dashboard-page">
    <div className="page-heading">
      <div><h3>Обзор системы</h3><p>Ключевые показатели Collector и всех источников данных.</p></div>
      <select value={windowValue} onChange={(event) => setWindowValue(event.target.value)}
        aria-label="Интервал Dashboard">
        <option value="1h">Последний час</option>
        <option value="24h">24 часа</option>
        <option value="7d">7 дней</option>
      </select>
    </div>
    {error && <div className="form-error">{error}</div>}
    <div className="dashboard-category-heading"><h4>Оборудование</h4><span>Eltex · Syslog, CDR и AntiFraud</span></div>
    <div className="dashboard-kpis">
      <DashboardKPI label="Оборудование"
        value={`${equipmentTotals.activeSources} / ${equipmentTotals.totalSources}`}
        detail="активно / всего" />
      <DashboardKPI label="Вызовы" value={formatCount(equipmentTotals.calls)}
        detail={`неуспешных ${formatCount(equipmentTotals.failed)}`}
        tone={equipmentTotals.failed ? 'bad' : 'good'} />
      <DashboardKPI label="ASR" value={formatPercent(equipmentTotals.calls, equipmentTotals.failed)}
        detail="доля успешных вызовов" />
      <DashboardKPI label="Средний разговор"
        value={formatDurationAverage(equipmentTotals.averageTalkMs)} />
      <DashboardKPI label="Аварии" value={formatCount(equipmentTotals.alarms)}
        tone={equipmentTotals.alarms ? 'bad' : 'good'} />
      <DashboardKPI label="Нераспознано" value={formatCount(equipmentTotals.unknown)}
        tone={equipmentTotals.unknown ? 'warn' : 'good'} />
      <DashboardKPI label="AntiFraud" value={formatCount(equipmentTotals.antifraud)}
        detail={`reject ${formatCount(equipmentTotals.rejects)}`} />
      <DashboardKPI label="Очередь"
        value={formatCount(snapshot?.system?.natsStreamMessages)}
        detail={`spool ${formatCount(snapshot?.system?.spoolDepth)}`}
        tone={(snapshot?.system?.natsStreamMessages || snapshot?.system?.spoolDepth) ? 'warn' : 'good'} />
    </div>
    <section className="dashboard-panel fleet-panel">
      <div className="panel-heading"><div><h4>Оборудование</h4><span>Метрики Eltex за выбранный интервал</span></div></div>
      <table><thead><tr><th>Оборудование</th><th>Шаблон / timezone</th><th>Статус</th>
        <th>Вызовы</th><th>Неуспешные</th><th>AntiFraud / reject</th><th>Аварии</th>
        <th>Unknown</th><th>Последний приём Syslog</th><th>Revision</th></tr></thead>
        <tbody>{equipmentRows.map((row) => <tr key={row.id} onClick={() => onSelectDevice(row.id)}>
          <td><strong>{row.name}</strong><small>{row.model}</small></td>
          <td>{row.templateKey || row.firmware || '—'} / {row.timezone || 'UTC'}
            <small>Активный: {row.activeTimezone || row.timezone || 'UTC'}</small></td>
          <td><span className={row.enabled ? 'healthy' : 'service-error'}>
            {row.enabled ? 'Приём активен' : 'Выключен'}</span></td>
          <td className="right">{formatCount(row.metrics.calls)}</td>
          <td className="right">{formatCount(row.metrics.failedCalls)}</td>
          <td className="right">{`${formatCount(row.metrics.antifraud)} / ${formatCount(row.metrics.antifraudRejected)}`}</td>
          <td className="right">{formatCount(row.metrics.alarms)}</td>
          <td className="right">{formatCount(row.metrics.unknown)}</td>
          <td className="mono">
            {formatTime(row.freshness.latestSyslogAt, row.activeTimezone || row.timezone || 'UTC')}
            <small>{row.activeTimezone || row.timezone || 'UTC'}</small>
          </td>
          <td>{row.revision.aligned ? 'aligned' : 'rebuild'}</td>
        </tr>)}</tbody></table>
      {equipmentRows.length === 0 && <div className="table-empty">
        <strong>Оборудование ещё не добавлено</strong>
      </div>}
    </section>
    <div className="dashboard-category-heading"><h4>Софтсвитчи</h4><span>Типизированные и исходные CDR</span></div>
    <div className="dashboard-kpis">
      <DashboardKPI label="Софтсвитчи"
        value={`${softswitchTotals.activeSources} / ${softswitchTotals.totalSources}`}
        detail="активно / всего" />
      <DashboardKPI label="Вызовы" value={formatCount(softswitchTotals.calls)}
        detail={`неуспешных ${formatCount(softswitchTotals.failed)}`}
        tone={softswitchTotals.failed ? 'bad' : 'good'} />
      <DashboardKPI label="ASR" value={formatPercent(softswitchTotals.calls, softswitchTotals.failed)}
        detail="для типизированных CDR" />
      <DashboardKPI label="Средний разговор"
        value={formatDurationAverage(softswitchTotals.averageTalkMs)} />
      <DashboardKPI label="CDR-файлы" value={formatCount(softswitchTotals.files)}
        detail={formatBytes(softswitchTotals.bytes)} />
    </div>
    <section className="dashboard-panel fleet-panel">
      <div className="panel-heading"><div><h4>Софтсвитчи</h4><span>Метрики за выбранный интервал</span></div></div>
      <table><thead><tr><th>Софтсвитч</th><th>Шаблон / timezone</th><th>Статус</th>
        <th>Вызовы</th><th>Успешные</th><th>Неуспешные</th><th>ASR</th>
        <th>Средний разговор</th><th>CDR-файлы</th><th>Объём файлов</th>
        <th>Последний CDR</th></tr></thead>
        <tbody>{softswitchRows.map((row) => {
          const typed = sourceCapabilities(row).typedCdr
          return <tr key={row.id} onClick={() => onSelectDevice(row.id)}>
            <td><strong>{row.name}</strong><small>{row.model || 'Софтсвитч'}</small></td>
            <td>{row.templateKey || '—'} / {row.timezone || 'UTC'}</td>
            <td><span className={row.enabled ? 'healthy' : 'service-error'}>
              {row.enabled ? 'Приём активен' : 'Выключен'}</span></td>
            <td className="right">{typed ? formatCount(row.metrics.calls) : '—'}</td>
            <td className="right">{typed
              ? formatCount(Math.max(0, row.metrics.calls - row.metrics.failedCalls)) : '—'}</td>
            <td className="right">{typed ? formatCount(row.metrics.failedCalls) : '—'}</td>
            <td className="right">{typed
              ? formatPercent(row.metrics.calls, row.metrics.failedCalls) : '—'}</td>
            <td className="right">{typed ? formatDurationAverage(row.metrics.averageTalkMs) : '—'}</td>
            <td className="right">{formatCount(row.fileMetrics?.files)}</td>
            <td className="right">{formatBytes(row.fileMetrics?.bytes)}</td>
            <td className="mono">{formatTime(row.fileMetrics?.latestAt || row.freshness.latestCdrAt, 'UTC')}</td>
          </tr>
        })}</tbody></table>
      {softswitchRows.length === 0 && <div className="table-empty">
        <strong>Софтсвитчи ещё не добавлены</strong>
      </div>}
    </section>
    <section className="dashboard-panel">
      <div className="panel-heading"><div><h4>Сервисы</h4>
        <span>{snapshot?.system?.version || 'Collector'}</span></div>
        <span>{snapshot?.diagnostics?.length ? `${snapshot.diagnostics.length} предупреждений` : 'Без ошибок'}</span></div>
      <div className="service-grid">
        {Object.entries(snapshot?.system?.services || {}).map(([name, healthy]) =>
          <span key={name} className={healthy ? 'healthy' : 'service-error'}>
            <i className={`status-dot ${healthy ? 'online' : ''}`} /> {name}
          </span>)}
      </div>
    </section>
  </section>
}

function DashboardKPI({ label, value, detail, tone }: {
  label: string
  value: string
  detail?: string
  tone?: 'good' | 'warn' | 'bad'
}) {
  return <div className={`dashboard-kpi ${tone || ''}`}>
    <small>{label}</small><strong>{value}</strong>{detail && <span>{detail}</span>}
  </div>
}

function dashboardRows(
  snapshot: DashboardSnapshot | null,
  devices: Device[],
  category: SourceCategory,
) {
  return (snapshot?.devices || []).map((row) => {
    const source = devices.find((device) => device.id === row.id)
    return {
      ...row,
      sourceCategory: row.sourceCategory || source?.sourceCategory,
      templateKey: row.templateKey || source?.templateKey,
      capabilities: row.capabilities || source?.capabilities,
      metrics: row.metrics || {
        calls: 0, failedCalls: 0, alarms: 0, unknown: 0, antifraud: 0, antifraudRejected: 0,
      },
      revision: row.revision || {
        configured: 0, active: 0, building: 0, aligned: true, status: '',
      },
    }
  }).filter((row) => sourceCategory(row) === category)
}

function dashboardCategoryTotals(
  snapshot: DashboardSnapshot | null,
  devices: Device[],
  rows: DashboardDevice[],
  category: SourceCategory,
): Required<DashboardCategoryTotals> {
  const apiTotals = snapshot?.categoryTotals?.[category] || snapshot?.totals?.[category] || {}
  const sources = devices.filter((device) => sourceCategory(device) === category)
  const fallback = rows.reduce((totals, row) => ({
    calls: totals.calls + (sourceCapabilities(row).typedCdr ? row.metrics.calls || 0 : 0),
    failed: totals.failed + (sourceCapabilities(row).typedCdr ? row.metrics.failedCalls || 0 : 0),
    alarms: totals.alarms + (row.metrics.alarms || 0),
    unknown: totals.unknown + (row.metrics.unknown || 0),
    antifraud: totals.antifraud + (row.metrics.antifraud || 0),
    rejects: totals.rejects + (row.metrics.antifraudRejected || 0),
    files: totals.files + (row.fileMetrics?.files || 0),
    bytes: totals.bytes + (row.fileMetrics?.bytes || 0),
  }), { calls: 0, failed: 0, alarms: 0, unknown: 0, antifraud: 0, rejects: 0, files: 0, bytes: 0 })
  return {
    activeSources: apiTotals.activeSources ?? sources.filter((source) => source.enabled).length,
    totalSources: apiTotals.totalSources ?? sources.length,
    calls: apiTotals.calls ?? fallback.calls,
    failed: apiTotals.failed ?? fallback.failed,
    averageTalkMs: apiTotals.averageTalkMs ?? 0,
    alarms: apiTotals.alarms ?? fallback.alarms,
    unknown: apiTotals.unknown ?? fallback.unknown,
    antifraud: apiTotals.antifraud ?? fallback.antifraud,
    rejects: apiTotals.rejects ?? fallback.rejects,
    files: apiTotals.files ?? fallback.files,
    bytes: apiTotals.bytes ?? fallback.bytes,
  }
}

function formatDurationAverage(value?: number) {
  return value ? `${(value / 1000).toFixed(1)} с` : '—'
}

function formatPercent(total?: number, failed?: number) {
  if (!total) return '—'
  return `${Math.max(0, ((total - (failed || 0)) / total) * 100).toFixed(1)}%`
}

function DeviceNavigation({ device, active, onChange }: {
  device: Device
  active: Dataset
  onChange: (value: Dataset) => void
}) {
  const capabilities = sourceCapabilities(device)
  const items = sourceCategory(device) === 'softswitch'
    ? sourceDatasets(device).map(() => navigation[0])
    : navigation.filter((item) =>
      (item.id !== 'calls' || capabilities.typedCdr) &&
      (item.id !== 'antifraud' || capabilities.antifraud) &&
      (item.id !== 'radius' || capabilities.radius) &&
      (item.id === 'calls' || item.id === 'antifraud' || item.id === 'radius' || capabilities.syslog))
  return <nav className="device-nav">
    {items.map((item) => <button key={item.id} className={active === item.id ? 'active' : ''}
      onClick={() => onChange(item.id)}><item.icon size={14} />{item.label}</button>)}
  </nav>
}

function SatelPipelineNotice({ templateKey, replay }: {
  templateKey?: string
  replay: ReplayProgress
}) {
  const remaining = replay.pending + replay.processing
  const total = remaining + replay.complete
  if (templateKey !== 'satel-rtu-cdr-v1') return null
  if (remaining > 0) {
    return <div className="pipeline-notice pipeline-pending">
      <strong>Satel RTU: обработано {replay.complete} из {total}</strong>
      <span>В очереди {replay.pending}, обрабатывается {replay.processing}
        {replay.quarantined ? `, архивов с ошибками ${replay.quarantined}` : ''}.</span>
    </div>
  }
  return null
}

function ExportButton({ deviceID, dataset, query, date }: {
  deviceID: string
  dataset: Dataset
  query: string
  date: string
}) {
  const storageKey = `collector:export:${deviceID}:${dataset}:${date}:${query}`
  const [job, setJob] = useState<ExportJob | null>(() => {
    const saved = window.sessionStorage.getItem(storageKey)
    return saved ? ({ id: saved, status: 'queued' } as ExportJob) : null
  })
  const [creating, setCreating] = useState(false)
  const [error, setError] = useState('')
  const jobID = job?.id
  const jobStatus = job?.status

  const download = useCallback((completed: ExportJob, forget: boolean) => {
    const link = document.createElement('a')
    link.href = exportDownloadURL(deviceID, completed.id)
    link.download = completed.filename || ''
    document.body.appendChild(link)
    link.click()
    link.remove()
    if (forget) {
      window.sessionStorage.removeItem(storageKey)
      setJob(null)
    }
  }, [deviceID, storageKey])

  useEffect(() => {
    if (!jobID || !jobStatus || !isExportActive(jobStatus)) return
    let active = true
    let timer: number | undefined
    let failures = 0
    const poll = () => {
      api<{ job: ExportJob }>(exportJobURL(deviceID, jobID))
        .then(({ job: next }) => {
          if (!active) return
          failures = 0
          setError('')
          setJob(next)
          if (next.status === 'completed') {
            download(next, false)
            return
          }
          if (!isExportActive(next.status)) {
            window.sessionStorage.removeItem(storageKey)
            setError(next.error || 'Не удалось подготовить архив')
            return
          }
          timer = window.setTimeout(poll, pollDelay(0, true))
        })
        .catch((reason) => {
          if (!active) return
          failures += 1
          setError(reason instanceof Error ? reason.message : 'Не удалось проверить экспорт')
          timer = window.setTimeout(poll, pollDelay(failures, true))
        })
    }
    poll()
    return () => {
      active = false
      if (timer !== undefined) window.clearTimeout(timer)
    }
  }, [deviceID, download, jobID, jobStatus, storageKey])

  const createJob = () => {
    setCreating(true)
    setError('')
    setJob(null)
    api<{ job: ExportJob }>(exportJobsURL(deviceID), {
      method: 'POST',
      body: JSON.stringify(createExportRequest(dataset, query, date, date)),
    })
      .then(({ job: next }) => {
        window.sessionStorage.setItem(storageKey, next.id)
        setJob(next)
      })
      .catch((reason) => setError(reason instanceof Error ? reason.message : 'Не удалось создать экспорт'))
      .finally(() => setCreating(false))
  }

  const active = creating || (job != null && isExportActive(job.status))
  const label = creating ? 'Запуск…' : job?.status === 'queued' ? 'Архив в очереди…'
    : job?.status === 'running' ? `Архив: ${job.rowsWritten.toLocaleString('ru-RU')} строк…`
      : job?.status === 'completed' ? 'Скачать архив'
        : error ? 'Повторить экспорт' : 'Экспорт CSV.zip'
  return <div className="export-button-wrap">
    <button className="secondary" disabled={active}
      onClick={() => job?.status === 'completed' ? download(job, true) : createJob()}>{label}</button>
    {error && <small className="export-inline-error" title={error}>{error}</small>}
  </div>
}

function DataView({ device, dataset, admin }: { device: Device; dataset: Dataset; admin: boolean }) {
  const [query, setQuery] = useState('')
  const timezone = activeDeviceTimezone(device)
  const dateStorageKey = `collector:date:${device.id}`
  const [date, setDate] = useState(() =>
    window.sessionStorage.getItem(dateStorageKey) || localDateInTimezone(timezone))
  const [rows, setRows] = useState<DataRow[]>([])
  const [loading, setLoading] = useState(false)
  const [selectedCall, setSelectedCall] = useState<CallRow | null>(null)
  const [selectedSatelCall, setSelectedSatelCall] = useState<SatelCdrRow | null>(null)
  const [selectedAntifraud, setSelectedAntifraud] = useState<AntifraudRow | null>(null)
  const [selectedEvent, setSelectedEvent] = useState<EventRow | null>(null)
  const [statsResult, setStatsResult] = useState<{
    date: string
    value: DeviceStats | null
  }>({ date: '', value: null })
  const stats = statsResult.date === date ? statsResult.value : null
  const [diagnostics, setDiagnostics] = useState<SyslogDiagnostics | null>(null)
  const [cursor, setCursor] = useState<PageCursor | null>(null)
  const [hasMore, setHasMore] = useState(false)
  const tableShellRef = useRef<HTMLDivElement>(null)
  const sentinelRef = useRef<HTMLDivElement>(null)
  const loadingRef = useRef(false)
  const generationRef = useRef(0)
  const isSatel = device.templateKey === 'satel-rtu-cdr-v1'
  const hasSyslog = sourceCapabilities(device).syslog
  const title = navigation.find((item) => item.id === dataset)?.label || dataset
  const category = dataset === 'syslog_all' ? 'all' : dataset
  const pagePath = useCallback((pageCursor?: PageCursor) => {
    const base = dataset === 'calls'
      ? `/devices/${device.id}/calls?q=${encodeURIComponent(query)}&date=${date}&limit=${PAGE_SIZE}`
      : dataset === 'antifraud'
        ? `/devices/${device.id}/antifraud?q=${encodeURIComponent(query)}&date=${date}&limit=${PAGE_SIZE}`
        : `/devices/${device.id}/events?category=${encodeURIComponent(category)}&q=${encodeURIComponent(query)}&date=${date}&limit=${PAGE_SIZE}`
    return pageCursor
      ? `${base}&before=${encodeURIComponent(pageCursor.before)}&before_id=${encodeURIComponent(pageCursor.beforeId)}`
      : base
  }, [category, dataset, date, device.id, query])
  const setBusy = useCallback((value: boolean) => {
    loadingRef.current = value
    setLoading(value)
  }, [])
  useEffect(() => {
    let active = true
    api<DeviceStats>(`/devices/${device.id}/stats?date=${date}`)
      .then((value) => { if (active) setStatsResult({ date, value }) })
      .catch(() => { if (active) setStatsResult({ date, value: null }) })
    if (admin && hasSyslog) {
      api<SyslogDiagnostics>(`/devices/${device.id}/syslog-diagnostics`)
        .then(setDiagnostics).catch(() => setDiagnostics(null))
    }
    return () => { active = false }
  }, [admin, date, device.id, hasSyslog])
  useEffect(() => {
    const generation = ++generationRef.current
    let active = true
    const timer = window.setTimeout(() => {
      setRows([])
      setCursor(null)
      setHasMore(false)
      setSelectedEvent(null)
      if (tableShellRef.current) tableShellRef.current.scrollTop = 0
      setBusy(true)
      api<PageResponse<DataRow>>(pagePath())
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
    api<PageResponse<DataRow>>(pagePath(cursor))
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
  const revisionNotice = readModelNotice(device, diagnostics)
  return <section className="data-view">
    {revisionNotice && <div className="timezone-rebuild">{revisionNotice}</div>}
    {isSatel && dataset === 'calls' && <SatelPipelineNotice
      templateKey={device.templateKey}
      replay={device.replay || { pending: 0, processing: 0, complete: 0, quarantined: 0 }} />}
    {admin && dataset === 'calls' && diagnostics && <CdrIngestBanner files={diagnostics.cdrIngestFiles || []} />}
    <div className="stat-strip">
      <label className="stat-date"><small>Дата · {timezone}</small><input type="date"
        required value={date} onChange={(event) => {
          if (event.target.value) {
            window.sessionStorage.setItem(dateStorageKey, event.target.value)
            setDate(event.target.value)
          }
        }} /></label>
      <span><small>Вызовов</small><strong>{stats ? stats.calls24h.toLocaleString('ru-RU') : '—'}</strong></span>
      <span><small>Неуспешных</small><strong>{stats ? stats.failedCalls24h.toLocaleString('ru-RU') : '—'}</strong></span>
      <span><small>Средняя длительность</small><strong>{stats ? `${(stats.averageTalkMs / 1000).toFixed(1)} с` : '—'}</strong></span>
      {!isSatel && <>
        <span><small>Аварий</small><strong>{stats ? stats.alarms24h.toLocaleString('ru-RU') : '—'}</strong></span>
        <span><small>RADIUS</small><strong>{stats ? stats.radius24h.toLocaleString('ru-RU') : '—'}</strong></span>
        <span><small>AntiFraud</small><strong>{stats ? stats.antifraud24h.toLocaleString('ru-RU') : '—'}</strong></span>
        <span><small>Reject</small><strong className={stats?.antifraudRejected24h ? 'warning-text' : ''}>{stats ? stats.antifraudRejected24h.toLocaleString('ru-RU') : '—'}</strong></span>
        <span><small>Без связи CDR</small><strong className={stats?.unlinkedCalls24h ? 'warning-text' : ''}>{stats ? stats.unlinkedCalls24h.toLocaleString('ru-RU') : '—'}</strong></span>
        <span><small>Нераспознано</small><strong className={stats?.unknown24h ? 'warning-text' : ''}>{stats ? stats.unknown24h.toLocaleString('ru-RU') : '—'}</strong></span>
      </>}
    </div>
    {admin && diagnostics && <SyslogDiagnosticPanel value={diagnostics} />}
    <div className="toolbar">
      <div><h3>{title}</h3><span>Загружено {rows.length} записей за {date}</span></div>
      <div className="toolbar-actions">
        <div className="search"><Search size={14} /><input placeholder="Поиск по данным…"
          value={query} onChange={(event) => setQuery(event.target.value)} /></div>
        <ExportButton key={`${dataset}:${date}:${query}`} deviceID={device.id}
          dataset={dataset} query={query} date={date} />
      </div>
    </div>
    <div className="table-shell" ref={tableShellRef}>
      {loading && <div className="table-loading" />}
      {dataset === 'calls' ? (isSatel
        ? <SatelCallsTable rows={rows as SatelCdrRow[]}
          timezone={activeDeviceTimezone(device)} onSelect={setSelectedSatelCall} />
        : <CallsTable rows={rows as CallRow[]}
          timezone={activeDeviceTimezone(device)} onSelect={setSelectedCall} />) :
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
    {selectedSatelCall && <SatelCallDrawer call={selectedSatelCall}
      timezone={activeDeviceTimezone(device)} onClose={() => setSelectedSatelCall(null)} />}
    {selectedAntifraud && <AntifraudDrawer device={device} row={selectedAntifraud}
      onClose={() => setSelectedAntifraud(null)} />}
    {selectedEvent && <EventDrawer event={selectedEvent} timezone={activeDeviceTimezone(device)}
      onClose={() => setSelectedEvent(null)} />}
  </section>
}

function CdrIngestBanner({ files }: { files: CdrIngestFile[] }) {
  if (files.length === 0) {
    return <div className="timezone-rebuild">
      CDR ingest: файлов в ledger ещё нет. Если оборудование уже отправляет CDR по FTP —
      проверьте, что файлы лежат в корне FTP home (не в подкаталоге).
    </div>
  }
  const problem = files.find((file) => file.status === 'failed' ||
    (file.status === 'quarantined' && file.rowsValid === 0) ||
    file.status === 'received')
  if (!problem) return null
  return <div className="timezone-rebuild">
    CDR ingest: {problem.originalName} → {problem.status}
    {problem.error ? ` · ${problem.error}` : ''}.
    Повторная обработка failed/quarantined файлов выполняется автоматически.
  </div>
}

function SyslogDiagnosticPanel({ value }: { value: SyslogDiagnostics }) {
  const trace = value.breakdown.filter((row) => row.sourcePort === 10003)
    .reduce((sum, row) => sum + row.count, 0)
  const cdrFiles = value.cdrIngestFiles || []
  return <details className="diagnostic-panel">
    <summary>
      Диагностика Syslog · Collector {value.version} · parser {value.parserVersion} ·
      порт 10003: {trace.toLocaleString('ru-RU')} · ingress:
      {value.ingressAvailable ? value.ingress.runtime.acceptedDatagrams.toLocaleString('ru-RU') : ' недоступен'}
      · CDR files: {cdrFiles.length.toLocaleString('ru-RU')}
    </summary>
    <div className="diagnostic-facts">
      <span>Глобально · ingress принято: <strong>{value.ingressAvailable
        ? value.ingress.runtime.acceptedDatagrams.toLocaleString('ru-RU') : '—'}</strong></span>
      <span>Глобально · ingress передано: <strong>{value.ingressAvailable
        ? value.ingress.runtime.handedOff.toLocaleString('ru-RU') : '—'}</strong></span>
      <span>Глобально · ingress spool: <strong>{value.ingressAvailable
        ? value.ingress.spoolDepth.toLocaleString('ru-RU') : '—'}</strong></span>
      <span>Глобально · ошибок handoff: <strong>{value.ingressAvailable
        ? value.ingress.runtime.handoffErrors.toLocaleString('ru-RU') : '—'}</strong></span>
      <span>Глобально · app принято: <strong>{value.runtime.acceptedDatagrams.toLocaleString('ru-RU')}</strong></span>
      <span>Глобально · app отклонено: <strong>{value.runtime.rejectedDatagrams.toLocaleString('ru-RU')}</strong></span>
      <span>Глобально · app spool: <strong>{value.spoolDepth.toLocaleString('ru-RU')}</strong></span>
      <span>Глобально · NATS stream: <strong>{value.natsStreamMessages.toLocaleString('ru-RU')}</strong></span>
      <span>Глобально · NATS pending: <strong>{value.natsConsumerPending.toLocaleString('ru-RU')}</strong></span>
      <span>Глобально · quarantine: <strong>{value.quarantineDepth.toLocaleString('ru-RU')}</strong></span>
      <span>Classified, 24 ч: <strong>{value.classified24h.toLocaleString('ru-RU')} / {value.rawEvents24h.toLocaleString('ru-RU')}</strong></span>
      <span>Reprocess current: <strong>{value.reprocessedCurrent.toLocaleString('ru-RU')}</strong></span>
      <span>Осталось reprocess: <strong>{value.reprocessRemaining.toLocaleString('ru-RU')}</strong></span>
      <span>Active / building revision: <strong>{value.activeRevision || '—'} / {value.buildingRevision || '—'}</strong></span>
      <span>Read / ingest revision: <strong>{value.activeRevision || '—'} / {value.ingestRevision || '—'} · {value.revisionAligned ? 'aligned' : 'SPLIT'}</strong></span>
      <span>Active / building timezone: <strong>{value.activeRevisionTimezone || '—'} / {value.revisionTimezone || '—'}</strong></span>
      <span>Revision status / reason: <strong>{value.revisionStatus || '—'} / {value.revisionReason || '—'}</strong></span>
      <span>Replay Syslog: <strong>{formatCount(value.replayProcessed)} / {formatCount(value.replayTotal)}</strong></span>
      <span>Replay CDR: <strong>{formatCount(value.cdrReplayProcessed)} / {formatCount(value.cdrReplayTotal)}</strong></span>
      <span>CDR без time fact: <strong>{formatCount(value.missingCdrInterpretations)}</strong></span>
      <span>RADIUS raw / lifecycle: <strong>{formatCount(value.radiusRawFragments)} / {formatCount(value.lifecycleDerived)}</strong></span>
      <span>Syslog constructs / members: <strong>{formatCount(value.syslogConstructs)} / {formatCount(value.constructMembers)}</strong></span>
      <span>Construct heuristic / orphan: <strong>{formatCount(value.heuristicConstructs)} / {formatCount(value.constructOrphans)}</strong></span>
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
      <span>CDR ingest files: <strong>{cdrFiles.length.toLocaleString('ru-RU')}</strong></span>
    </div>
    {cdrFiles.length > 0 && <div className="diagnostic-breakdown">
      {cdrFiles.map((file) => <span key={file.id}>
        <strong>{file.originalName}</strong> · {file.status} ·
        rows {file.rowsValid}/{file.rowsTotal}
        {file.error ? ` · ${file.error}` : ''}
      </span>)}
    </div>}
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
    <p>Проверьте наличие тестового вызова, включение «АнтиФрод» в активном RADIUS-профиле оборудования,
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
    className={`outcome-row outcome-${antifraudOutcome(row)}`}
    onClick={() => onSelect(row)}>
    <td className="mono">{formatTime(row.lastEventAt, timezone)}</td>
    <td><span className="tag">{row.requestType || 'не определена'}</span></td>
    <td><span className={`decision ${row.decision || 'pending'}`}>
      {decisionLabel(row.decision)}</span>
      <span className={`outcome-badge ${antifraudOutcome(row)}`}>
        {outcomeLabel(antifraudOutcome(row))}
      </span></td>
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
      <span><small>Timezone источника</small><strong>{row.sourceTimezone || activeDeviceTimezone(device)}</strong></span>
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
  </tr></thead><tbody>{rows.map((row) => <tr key={row.recordId}
    className={`outcome-row outcome-${cdrOutcome(row.releaseCause)}`}
    onClick={() => onSelect(row)}>
    <td className="mono">{formatTime(row.setupTime, timezone)}</td>
    <td>{row.incomingDescription || '—'}</td><td>{row.outgoingDescription || '—'}</td>
    <td className="mono">{row.incomingCgpn || '—'}</td><td className="mono">{row.outgoingCgpn || '—'}</td>
    <td className="mono">{row.incomingCdpn || '—'}</td><td className="mono">{row.outgoingCdpn || '—'}</td>
    <td className="right">{row.durationMs == null ? '—' : `${(row.durationMs / 1000).toFixed(3)} c`}</td>
    <td className="right">{row.releaseCause ?? '—'}</td><td>
      <span className={`outcome-badge ${cdrOutcome(row.releaseCause)}`}>
        {outcomeLabel(cdrOutcome(row.releaseCause))}
      </span> {row.releaseInfo || '—'}</td>
    <td className="mono">{row.radiusSessionId || '—'}</td><td className="mono">{row.uniqueTag || '—'}</td>
  </tr>)}</tbody></table>
}

function satelCallOutcome(row: SatelCdrRow): 'success' | 'failure' | 'warning' {
  if (row.connectTime) return 'success'
  const outcome = (row.outcome || '').toLowerCase()
  if (['answered', 'answer', 'connected', 'success', 'completed'].includes(outcome)) return 'success'
  if (outcome || row.disconnectTime) return 'failure'
  return 'warning'
}

function formatSatelProtocols(row: SatelCdrRow) {
  const configured = Array.isArray(row.protocols) ? row.protocols.join(' / ') : row.protocols
  return configured || [row.inLegProto, row.outLegProto].filter(Boolean).join(' → ') || '—'
}

function SatelCallsTable({ rows, timezone, onSelect }: {
  rows: SatelCdrRow[]
  timezone: string
  onSelect: (row: SatelCdrRow) => void
}) {
  return <table className="satel-cdr-table"><thead><tr>
    <th>Установка</th><th>Соединение</th><th>Завершение</th><th>Результат</th><th>ANI вход</th><th>DNIS вход</th>
    <th>ANI выход</th><th>DNIS выход</th><th>Src маршрут</th><th>Dst маршрут</th>
    <th>DP маршрут</th><th>Длительность</th><th>Протоколы</th>
    <th>Разъединение</th><th>Код</th><th>Узел</th>
  </tr></thead><tbody>{rows.map((row) => {
    const outcome = satelCallOutcome(row)
    return <tr key={row.recordId} className={`outcome-row outcome-${outcome}`}
      onClick={() => onSelect(row)}>
      <td className="mono">{formatTime(row.setupTime, timezone)}</td>
      <td className="mono">{formatTime(row.connectTime, timezone)}</td>
      <td className="mono">{formatTime(row.disconnectTime, timezone)}</td>
      <td><span className={`outcome-badge ${outcome}`}>{row.outcome || (row.connectTime ? 'answered' : 'failed')}</span></td>
      <td className="mono">{row.inAni || '—'}</td><td className="mono">{row.inDnis || '—'}</td>
      <td className="mono">{row.outAni || '—'}</td><td className="mono">{row.outDnis || '—'}</td>
      <td>{row.srcName || '—'}</td><td>{row.dstName || '—'}</td><td>{row.dpName || '—'}</td>
      <td className="right">{row.durationMs == null ? '—' : `${(row.durationMs / 1000).toFixed(3)} c`}</td>
      <td>{formatSatelProtocols(row)}</td><td>{row.disconnectText || '—'}</td>
      <td className="right">{row.disconnectCode ?? '—'}</td><td>{row.signalNodeName || row.sigNodeName || '—'}</td>
    </tr>
  })}</tbody></table>
}

function SatelCallDrawer({ call, timezone, onClose }: {
  call: SatelCdrRow
  timezone: string
  onClose: () => void
}) {
  return <div className="drawer">
    <div className="drawer-header"><div><h3>CDR Satel RTU</h3>
      <span className="mono">{call.recordId}</span></div><button onClick={onClose}>×</button></div>
    <div className="call-facts">
      <span><small>Установка</small><strong>{formatTime(call.setupTime, timezone)}</strong></span>
      <span><small>Соединение</small><strong>{formatTime(call.connectTime, timezone)}</strong></span>
      <span><small>Завершение</small><strong>{formatTime(call.disconnectTime, timezone)}</strong></span>
      <span><small>Результат</small><strong>{call.outcome || (call.connectTime ? 'answered' : 'failed')}</strong></span>
      <span><small>Длительность</small><strong>{call.durationMs == null ? '—' : `${(call.durationMs / 1000).toFixed(3)} c`}</strong></span>
      <span><small>Разъединение</small><strong>{call.disconnectText || '—'} · {call.disconnectCode ?? '—'}</strong></span>
      <span><small>Инициатор</small><strong>{call.disconnectInitiator || '—'}</strong></span>
      <span><small>Сигнальный узел</small><strong>{call.signalNodeName || call.sigNodeName || '—'}</strong></span>
    </div>
    <h4>Идентификаторы вызова</h4>
    <div className="call-facts">
      <span><small>External CDR ID</small><strong className="mono">{call.externalCdrId || call.cdrId || '—'}</strong></span>
      <span><small>Call ID</small><strong className="mono">{call.callId || call.inLegCallId || '—'}</strong></span>
      <span><small>Source Call ID</small><strong className="mono">{call.srcCallId || '—'}</strong></span>
      <span><small>Destination Call ID</small><strong className="mono">{call.dstCallId || call.outLegCallId || '—'}</strong></span>
      <span><small>Conference ID</small><strong className="mono">{call.confId || '—'}</strong></span>
      <span><small>Протоколы</small><strong>{formatSatelProtocols(call)}</strong></span>
    </div>
    <h4>Номера и маршруты</h4>
    <div className="call-facts">
      <span><small>ANI: вход / выход</small><strong className="mono">{call.inAni || '—'} / {call.outAni || '—'}</strong></span>
      <span><small>DNIS: вход / выход</small><strong className="mono">{call.inDnis || '—'} / {call.outDnis || '—'}</strong></span>
      <span><small>Billing ANI / DNIS</small><strong className="mono">{call.billAni || '—'} / {call.billDnis || '—'}</strong></span>
      <span><small>Src / Dst / DP</small><strong>{call.srcName || '—'} / {call.dstName || '—'} / {call.dpName || '—'}</strong></span>
    </div>
    <h4>Endpoints и codecs</h4>
    <pre className="raw-payload">{JSON.stringify({
      endpoints: call.endpoints || {
        srcGatekeeper: call.srcGatekeeperAddress,
        remoteSrcSignal: call.remoteSrcSigAddress,
        remoteDstSignal: call.remoteDstSigAddress,
        localSrcSignal: call.localSrcSigAddress,
        localDstSignal: call.localDstSigAddress,
        remoteSrcMedia: call.remoteSrcMediaAddress,
        remoteDstMedia: call.remoteDstMediaAddress,
        localSrcMedia: call.localSrcMediaAddress,
        localDstMedia: call.localDstMediaAddress,
      },
      codecs: call.codecs || { incoming: call.inLegCodecs, outgoing: call.outLegCodecs },
    }, null, 2)}</pre>
    <h4>PDD / SCD и timing</h4>
    <pre className="raw-payload">{JSON.stringify({
      pdd: call.pdd ?? call.pddMs, scd: call.scd ?? call.scdMs, timing: call.timing || {
        termElapsed: call.termElapsedTime, termSetup: call.termSetupTime,
        termConnect: call.termConnectTime, termDisconnect: call.termDisconnectTime,
        termPdd: call.termPdd, termScd: call.termScd,
      },
    }, null, 2)}</pre>
    <h4>Качество медиа</h4>
    <pre className="raw-payload">{JSON.stringify(call.media || {
      srcBytesIn: call.srcMediaBytesIn, srcBytesOut: call.srcMediaBytesOut,
      dstBytesIn: call.dstMediaBytesIn, dstBytesOut: call.dstMediaBytesOut,
      srcPackets: call.srcMediaPackets, dstPackets: call.dstMediaPackets,
      srcPacketsLate: call.srcMediaPacketsLate, dstPacketsLate: call.dstMediaPacketsLate,
      srcPacketsLost: call.srcMediaPacketsLost, dstPacketsLost: call.dstMediaPacketsLost,
      srcJitter: [call.srcMinJitter, call.srcMaxJitter],
      dstJitter: [call.dstMinJitter, call.dstMaxJitter],
    }, null, 2)}</pre>
    <h4>Исходные поля</h4>
    <pre className="raw-payload">{JSON.stringify(call.rawFields ?? {}, null, 2)}</pre>
  </div>
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
          <strong>{event.component || 'Оборудование'}</strong>
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
    <tbody>{rows.map((row) => <EventTableRow key={row.eventId} row={row}
      timezone={timezone} onSelect={onSelect} />)}</tbody></table>
}

function formatEventAttrs(row: EventRow) {
  return Object.entries(row.attributes || {}).map(([key, value]) => `${key}=${value}`).join(' · ') || '—'
}

function EventTableRow({ row, timezone, onSelect, nested }: {
  row: EventRow
  timezone: string
  onSelect: (row: EventRow) => void
  nested?: boolean
}) {
  return <tr className={nested ? 'thread-child' : undefined} onClick={() => onSelect(row)}>
    <td className="mono">{formatTime(row.eventTime || row.receivedAt, timezone)}</td>
    <td><span className="tag">{row.category}</span></td>
    <td className="mono">{row.component || '—'}</td>
    <td className={`message-cell ${nested ? 'thread-fragment' : ''}`}>{row.message || '—'}</td>
    <td><span className={`parse-status ${row.parseStatus}`}>{row.parseStatus}</span></td>
    <td className="mono">{formatEventAttrs(row)}</td>
  </tr>
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

function CreateDeviceDialog({ category, templates, onClose, onCreated }: {
  category: SourceCategory
  templates: EquipmentTemplate[]
  onClose: () => void
  onCreated: (device: Device) => void
}) {
  const available = templatesFor(templates, category)
  const options = available.length ? available : templatesFor(fallbackTemplates, category)
  const defaultTemplate = options[0]
  const isSoftswitch = category === 'softswitch'
  const [form, setForm] = useState({
    name: '', templateKey: defaultTemplate.key, sourceCategory: category,
    model: isSoftswitch ? '' : 'SMG-1016M',
    firmware: defaultTemplate.key.endsWith('3.410') ? '3.410' : isSoftswitch ? '' : '3.23.2',
    timezone: 'Asia/Novosibirsk', managementIp: '', syslogSourceIp: '', deviceSign: '',
    antifraudEnabled: !isSoftswitch, antifraudMode: isSoftswitch ? 'OFF' : 'Custom',
  })
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const update = (field: string, value: string | boolean) => setForm((current) => ({ ...current, [field]: value }))
  const updateTemplate = (templateKey: string) => setForm((current) => ({
    ...current,
    templateKey,
    firmware: templateKey.endsWith('3.410') ? '3.410' :
      templateKey.endsWith('3.23.2') ? '3.23.2' : '',
  }))
  async function submit(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    try {
      const payload = isSoftswitch
        ? {
          name: form.name, templateKey: form.templateKey,
          sourceCategory: form.sourceCategory, timezone: form.timezone,
        }
        : form
      const device = await api<Device>('/devices', {
        method: 'POST', body: JSON.stringify(payload),
      })
      onCreated(device)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Ошибка добавления')
    } finally {
      setBusy(false)
    }
  }
  return <Modal title={isSoftswitch ? 'Добавление софтсвитча' : 'Добавление оборудования'} onClose={onClose}>
    <form className="device-form" onSubmit={submit}>
      <div className="form-grid">
        <label>Название<input autoFocus required value={form.name} onChange={(e) => update('name', e.target.value)} /></label>
        <label>{isSoftswitch ? 'Софтсвитч' : 'Оборудование'}
          <select required value={form.templateKey}
            onChange={(e) => updateTemplate(e.target.value)}>
            {options.map((item) => <option key={item.key} value={item.key}>{item.displayName}</option>)}
          </select></label>
        <label>Часовой пояс устройства<TimezoneSelect value={form.timezone}
          onChange={(value) => update('timezone', value)} /></label>
        {!isSoftswitch && <>
          <label>Device Sign<input value={form.deviceSign}
            onChange={(e) => update('deviceSign', e.target.value)} /></label>
          <label>IP управления<input placeholder="10.0.0.10" value={form.managementIp}
            onChange={(e) => update('managementIp', e.target.value)} /></label>
          <label>IP-источник Syslog<input required placeholder="10.0.0.10"
            value={form.syslogSourceIp} onChange={(e) => update('syslogSourceIp', e.target.value)} /></label>
          <label className="checkbox-row"><input type="checkbox" checked={form.antifraudEnabled}
            onChange={(e) => update('antifraudEnabled', e.target.checked)} /> Используется АнтиФрод</label>
          <label>Режим АнтиФрод<select disabled={!form.antifraudEnabled} value={form.antifraudMode}
            onChange={(e) => update('antifraudMode', e.target.value)}>
            <option>Custom</option><option>Astarta</option><option>Intek</option><option>OFF</option>
          </select></label>
        </>}
      </div>
      {error && <div className="form-error">{error}</div>}
      <div className="dialog-actions"><button type="button" className="secondary" onClick={onClose}>Отмена</button>
        <button className="primary" disabled={busy}>{busy ? 'Создание…' : 'Создать устройство'}</button></div>
    </form>
  </Modal>
}

function EditDeviceDialog({ device, templates, onClose, onSaved, onDeleted, initialDeleting = false }: {
  device: Device
  templates: EquipmentTemplate[]
  onClose: () => void
  onSaved: (device: Device) => void
  onDeleted: () => void
  initialDeleting?: boolean
}) {
  const isSoftswitch = sourceCategory(device) === 'softswitch'
  const categoryTemplates = templatesFor(templates, sourceCategory(device))
  const templateOptions = categoryTemplates.length
    ? categoryTemplates : templatesFor(fallbackTemplates, sourceCategory(device))
  const [form, setForm] = useState({
    templateKey: device.templateKey || (normalizeFirmwareScheme(device.firmware) === '3.410'
      ? 'eltex-smg-1016m-3.410' : isSoftswitch
        ? 'satel-rtu-cdr-v1' : 'eltex-smg-1016m-3.23.2'),
    sourceCategory: sourceCategory(device),
    name: device.name, firmware: isSoftswitch ? '' : normalizeFirmwareScheme(device.firmware),
    timezone: device.timezone,
    managementIp: device.managementIp || '', syslogSourceIp: device.syslogSourceIp || '',
    deviceSign: device.deviceSign, antifraudEnabled: device.antifraudEnabled,
    antifraudMode: device.antifraudMode, enabled: device.enabled,
  })
  const [error, setError] = useState(device.purgeError || '')
  const [busy, setBusy] = useState(false)
  const [deleting, setDeleting] = useState(initialDeleting || device.purgeState === 'purge_failed')
  const [deleteName, setDeleteName] = useState('')
  const [phaseIndex, setPhaseIndex] = useState(0)
  const update = (field: string, value: string | boolean) =>
    setForm((current) => ({ ...current, [field]: value }))
  const updateTemplate = (templateKey: string) => setForm((current) => ({
    ...current,
    templateKey,
    firmware: templateKey.endsWith('3.410') ? '3.410' : '3.23.2',
  }))
  useEffect(() => {
    if (!busy || !deleting) return
    const timer = window.setInterval(() => {
      setPhaseIndex((current) => Math.min(current + 1, purgePhases.length - 1))
    }, 2500)
    return () => window.clearInterval(timer)
  }, [busy, deleting])
  async function submit(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      const payload = isSoftswitch
        ? {
          name: form.name, templateKey: form.templateKey,
          sourceCategory: form.sourceCategory, timezone: form.timezone, enabled: form.enabled,
        }
        : form
      onSaved(await api<Device>(`/devices/${device.id}`, {
        method: 'PATCH', body: JSON.stringify(payload),
      }))
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Ошибка сохранения')
    } finally {
      setBusy(false)
    }
  }
  async function purgeDevice() {
    if (deleteName !== device.name) return
    setPhaseIndex(0)
    setBusy(true)
    setError('')
    try {
      await api<void>(`/devices/${device.id}`, {
        method: 'DELETE',
        timeoutMs: 16 * 60 * 1000,
      })
      onDeleted()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Ошибка полного удаления')
    } finally {
      setBusy(false)
    }
  }
  if (deleting) {
    return <Modal title={`Полное удаление ${device.name}`} onClose={busy ? () => undefined : onClose}>
      <div className="danger-panel" data-testid="purge-dialog">
        <strong>Операция необратима.</strong>
        <p>{isSoftswitch
          ? 'Будут удалены raw CDR, архив MinIO, FTP-файлы, журнал приёма и аудит источника.'
          : 'Будут удалены Syslog, CDR, RADIUS/АнтиФрод, связи, архив MinIO, FTP-файлы, очереди, ревизии и аудит оборудования.'}</p>
        <label>Введите точное имя источника для подтверждения
          <input autoFocus value={deleteName} onChange={(event) => setDeleteName(event.target.value)}
            disabled={busy} data-testid="purge-confirm-name" />
        </label>
        {busy && <div className="purge-progress" data-testid="purge-phase">
          {purgePhases[phaseIndex]} Не закрывайте окно.
        </div>}
        {error && <div className="form-error">{error}</div>}
        <div className="dialog-actions">
          <button className="secondary" disabled={busy}
            onClick={() => device.purgeState === 'purge_failed' ? onClose() : setDeleting(false)}>
            {device.purgeState === 'purge_failed' ? 'Закрыть' : 'Назад'}
          </button>
          <button className="danger"
            disabled={!purgeConfirmationReady(device.name, deleteName, busy)}
            data-testid="purge-confirm"
            onClick={() => void purgeDevice()}>
            {busy ? 'Полное удаление…' : purgeRetryLabel(device.purgeState)}
          </button>
        </div>
      </div>
    </Modal>
  }
  return <Modal title={`Настройки ${device.name}`} onClose={onClose}>
    <form className="device-form" onSubmit={submit}>
      <div className="form-grid">
        <label>Название<input autoFocus required value={form.name}
          onChange={(e) => update('name', e.target.value)} /></label>
        <label>{isSoftswitch ? 'Софтсвитч' : 'Оборудование'}
          <select required value={form.templateKey}
            onChange={(e) => updateTemplate(e.target.value)}>
            {templateOptions.map((item) =>
              <option key={item.key} value={item.key}>{item.displayName}</option>)}
          </select></label>
        <label>Часовой пояс устройства<TimezoneSelect value={form.timezone}
          onChange={(value) => update('timezone', value)} /></label>
        {!isSoftswitch && <>
          <label>Device Sign<input value={form.deviceSign}
            onChange={(e) => update('deviceSign', e.target.value)} /></label>
          <label>IP управления<input value={form.managementIp}
            onChange={(e) => update('managementIp', e.target.value)} /></label>
          <label>IP-источник Syslog<input required value={form.syslogSourceIp}
            onChange={(e) => update('syslogSourceIp', e.target.value)} /></label>
          <label className="checkbox-row"><input type="checkbox" checked={form.antifraudEnabled}
            onChange={(e) => update('antifraudEnabled', e.target.checked)} /> Используется АнтиФрод</label>
          <label>Режим АнтиФрод<select disabled={!form.antifraudEnabled}
            value={form.antifraudMode} onChange={(e) => update('antifraudMode', e.target.value)}>
            <option>Custom</option><option>Astarta</option><option>Intek</option><option>OFF</option>
          </select></label>
        </>}
        <label className="checkbox-row"><input type="checkbox" checked={form.enabled}
          onChange={(e) => update('enabled', e.target.checked)} /> Приём данных включён</label>
      </div>
      {error && <div className="form-error">{error}</div>}
      <div className="dialog-actions">
        <button type="button" className="danger ghost" disabled={busy}
          onClick={() => setDeleting(true)}>Удалить источник…</button>
        <button type="button" className="secondary"
        onClick={onClose}>Отмена</button>
        <button className="primary" disabled={busy}>{busy ? 'Сохранение…' : 'Сохранить'}</button></div>
    </form>
  </Modal>
}

function SystemSettingsPage({ user }: { user: User }) {
  const [tab, setTab] = useState<'system' | 'users' | 'retention'>('system')
  const [info, setInfo] = useState<SystemInfo | null>(null)
  const [users, setUsers] = useState<ManagedUser[]>([])
  const [retention, setRetention] = useState<RetentionPolicy[]>([])
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [busyUserID, setBusyUserID] = useState('')
  const [userErrors, setUserErrors] = useState<Record<string, string>>({})
  const [resetUser, setResetUser] = useState<ManagedUser | null>(null)
  const [userQuery, setUserQuery] = useState('')
  const [form, setForm] = useState({ username: '', password: '', role: 'viewer' })
  const load = useCallback(async () => {
    try {
      setInfo(await api<SystemInfo>('/system/info'))
      if (user.role === 'admin') {
        const [userResponse, retentionResponse] = await Promise.all([
          api<{ items: ManagedUser[] }>('/system/users'),
          api<{ items: RetentionPolicy[] }>('/system/retention'),
        ])
        setUsers(userResponse.items || [])
        setRetention(retentionResponse.items || [])
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Ошибка загрузки настроек')
    }
  }, [user.role])
  useEffect(() => {
    void api<SystemInfo>('/system/info').then(setInfo)
      .catch((reason) => setError(reason instanceof Error ? reason.message : 'Ошибка загрузки настроек'))
    if (user.role === 'admin') {
      void api<{ items: ManagedUser[] }>('/system/users')
        .then((response) => setUsers(response.items || []))
        .catch((reason) => setError(reason instanceof Error ? reason.message : 'Ошибка загрузки пользователей'))
      void api<{ items: RetentionPolicy[] }>('/system/retention')
        .then((response) => setRetention(response.items || []))
        .catch((reason) => setError(reason instanceof Error ? reason.message : 'Ошибка загрузки retention'))
    }
  }, [user.role])
  async function create(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      await api('/system/users', { method: 'POST', body: JSON.stringify(form) })
      setForm({ username: '', password: '', role: 'viewer' })
      await load()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Ошибка создания пользователя')
    } finally {
      setBusy(false)
    }
  }
  async function update(managed: ManagedUser, patch: Partial<ManagedUser>, password = '') {
    setBusyUserID(managed.id)
    setUserErrors((current) => ({ ...current, [managed.id]: '' }))
    try {
      const updated = await api<ManagedUser>(`/system/users/${managed.id}`, {
        method: 'PATCH',
        body: JSON.stringify({
          role: patch.role ?? managed.role,
          active: patch.active ?? managed.active,
          password,
        }),
      })
      setUsers((current) => current.map((item) => item.id === updated.id ? updated : item))
      return true
    } catch (reason) {
      setUserErrors((current) => ({
        ...current,
        [managed.id]: reason instanceof Error ? reason.message : 'Ошибка изменения пользователя',
      }))
      return false
    } finally {
      setBusyUserID('')
    }
  }
  async function remove(managed: ManagedUser) {
    if (managed.active || managed.id === user.id) return
    if (!window.confirm(`Удалить пользователя ${managed.username}? Это действие нельзя отменить.`)) return
    setBusyUserID(managed.id)
    setUserErrors((current) => ({ ...current, [managed.id]: '' }))
    try {
      await api<void>(`/system/users/${managed.id}`, { method: 'DELETE' })
      setUsers((current) => current.filter((item) => item.id !== managed.id))
    } catch (reason) {
      setUserErrors((current) => ({
        ...current,
        [managed.id]: reason instanceof Error ? reason.message : 'Ошибка удаления пользователя',
      }))
    } finally {
      setBusyUserID('')
    }
  }
  async function changeRetention(policy: RetentionPolicy, days: number) {
    setBusy(true)
    setError('')
    try {
      await api('/system/retention', {
        method: 'PATCH',
        body: JSON.stringify({ policyClass: policy.policyClass, days }),
      })
      await load()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Ошибка изменения retention')
      await load()
    } finally {
      setBusy(false)
    }
  }
  async function cancelRetention(policy: RetentionPolicy) {
    setBusy(true)
    setError('')
    try {
      await api('/system/retention', {
        method: 'PATCH',
        body: JSON.stringify({ policyClass: policy.policyClass, cancel: true }),
      })
      await load()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Ошибка отмены изменения')
    } finally {
      setBusy(false)
    }
  }
  const filteredUsers = users.filter((managed) =>
    managed.username.toLowerCase().includes(userQuery.trim().toLowerCase()))
  return <section className="settings-page">
    <nav className="settings-tabs" aria-label="Разделы настроек">
      <button className={tab === 'system' ? 'active' : ''} onClick={() => setTab('system')}>
        Система
      </button>
      {canManageUsers(user.role) && <button className={tab === 'users' ? 'active' : ''}
        onClick={() => setTab('users')}>Пользователи</button>}
      {canManageUsers(user.role) && <button className={tab === 'retention' ? 'active' : ''}
        onClick={() => setTab('retention')}>Хранение</button>}
    </nav>
    <div className="settings-content">
      {tab === 'system' && <>
        <div className="page-heading"><div><h3>Состояние системы</h3>
          <p>Версия Collector и доступность зависимых сервисов.</p></div></div>
      <section className="settings-summary">
        <div><small>Collector</small><strong>{info?.version || '…'}</strong></div>
        <div><small>Состояние API</small><strong className="healthy">{info?.status || 'проверка'}</strong></div>
        <div><small>Пользователь</small><strong>{user.username} · {user.role}</strong></div>
      </section>
      {info && <div className="service-health">
        {Object.entries(info.services).map(([name, healthy]) =>
          <span key={name} className={healthy ? 'healthy' : 'service-error'}>
            <i className={`status-dot ${healthy ? 'online' : ''}`} /> {name}
          </span>)}
      </div>}
      </>}
      {tab === 'users' && canManageUsers(user.role) && <section data-testid="user-admin">
        <div className="page-heading"><div><h3>Пользователи</h3>
          <p>Роли, доступ и безопасность учётных записей.</p></div>
          <input placeholder="Поиск пользователя" value={userQuery}
            onChange={(event) => setUserQuery(event.target.value)} /></div>
        <div className="user-admin-list">
          {filteredUsers.map((managed) => {
            const rowBusy = busyUserID === managed.id
            return <div className="user-admin-row" key={managed.id}>
            <span><strong>{managed.username}</strong><small>
              {managed.active ? 'Активен' : 'Отключён'} · создан {formatTime(managed.createdAt, 'UTC')}
            </small><small>Последний вход: {formatTime(managed.lastSeenAt, 'UTC')}</small></span>
            <select value={managed.role} disabled={rowBusy}
              onChange={(event) => void update(managed, {
                role: event.target.value as ManagedUser['role'],
              })}>
              <option value="admin">Администратор</option>
              <option value="analyst">Аналитик</option>
              <option value="viewer">Наблюдатель</option>
            </select>
            <button className="secondary" disabled={rowBusy || managed.id === user.id}
              onClick={() => {
                if (managed.active && !window.confirm(
                  `Отключить пользователя ${managed.username} и завершить его активные сессии?`,
                )) return
                void update(managed, { active: !managed.active })
              }}>
              {managed.active ? 'Отключить' : 'Включить'}
            </button>
            <button className="secondary" disabled={rowBusy}
              onClick={() => setResetUser(managed)}>Сбросить пароль</button>
            <button className="danger ghost" disabled={rowBusy || managed.active || managed.id === user.id}
              title={managed.active ? 'Сначала отключите пользователя' : 'Удалить пользователя'}
              onClick={() => void remove(managed)}>Удалить</button>
            {userErrors[managed.id] && <span className="form-error row-error">
              {userErrors[managed.id]}
            </span>}
          </div>})}
        </div>
        <form className="new-user-form" onSubmit={create}>
          <input required placeholder="Логин" value={form.username}
            onChange={(event) => setForm({ ...form, username: event.target.value })} />
          <input required minLength={12} type="password" placeholder="Пароль (не менее 12 символов)"
            value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} />
          <select value={form.role} onChange={(event) => setForm({ ...form, role: event.target.value })}>
            <option value="viewer">Наблюдатель</option><option value="analyst">Аналитик</option>
            <option value="admin">Администратор</option>
          </select>
          <button className="primary" disabled={busy}>Добавить</button>
        </form>
      </section>}
      {tab === 'retention' && canManageUsers(user.role) && <section>
        <div className="page-heading"><div><h3>Хранение данных</h3>
          <p>Новый срок применяется сразу ко всем ресурсам выбранного класса.</p></div></div>
        <div className="retention-list">{retention.map((policy) =>
          <RetentionPolicyEditor key={`${policy.policyClass}:${policy.activeDays}:${policy.pendingDays}`}
            policy={policy} busy={busy}
            onChange={(days) => changeRetention(policy, days)}
            onCancel={() => cancelRetention(policy)} />)}</div>
      </section>}
      {error && <div className="form-error">{error}</div>}
    </div>
    {resetUser && <UserPasswordReset user={resetUser}
      disabled={busyUserID === resetUser.id} onClose={() => setResetUser(null)}
      onReset={(password) => update(resetUser, {}, password)} />}
  </section>
}

function RetentionPolicyEditor({ policy, busy, onChange, onCancel }: {
  policy: RetentionPolicy
  busy: boolean
  onChange: (days: number) => Promise<void>
  onCancel: () => Promise<void>
}) {
  const [days, setDays] = useState(policy.pendingDays || policy.activeDays)
  const [referenceNow] = useState(() => Date.now())
  return <article className="retention-row">
    <div><strong>{retentionLabel(policy.policyClass)}</strong>
      <p>{retentionDescription(policy.policyClass)}</p></div>
    <label>Текущий срок<strong>{policy.activeDays} дней</strong>
      <small>Граница удаления: {new Date(referenceNow - policy.activeDays * 86_400_000)
        .toLocaleDateString('ru-RU')}</small>
    </label>
    <label>Новый срок<input type="number" min={7} max={1095} value={days}
      onChange={(event) => setDays(Number(event.target.value))} /></label>
    <div className="retention-actions">
      <button className="secondary" disabled={busy || days < 7 || days > 1095 ||
        days === (policy.pendingDays || policy.activeDays)}
      onClick={() => void onChange(days)}>Сохранить</button>
      {policy.pendingDays != null && policy.lastError && <button className="danger ghost"
        disabled={busy} onClick={() => void onCancel()}>Отменить ожидающее</button>}
    </div>
    {policy.pendingDays != null && <div className="retention-pending">
      {policy.lastError ? 'Не применено' : 'Применяется'}: {policy.pendingDays} дней
    </div>}
    {policy.lastError && <div className="form-error">{policy.lastError}</div>}
  </article>
}

function UserPasswordReset({ user, disabled, onReset, onClose }: {
  user: ManagedUser
  disabled: boolean
  onReset: (password: string) => Promise<boolean>
  onClose: () => void
}) {
  const [password, setPassword] = useState('')
  return <Modal title={`Сбросить пароль · ${user.username}`} onClose={onClose}>
    <form className="device-form" onSubmit={(event) => {
      event.preventDefault()
      void onReset(password).then((changed) => {
        if (changed) onClose()
      })
    }}>
      <p>Новый пароль завершит все активные сессии пользователя.</p>
      <label>Новый пароль<input type="password" minLength={12} autoFocus
        placeholder="Не менее 12 символов" value={password}
        disabled={disabled} onChange={(event) => setPassword(event.target.value)} /></label>
      <div className="dialog-actions">
        <button type="button" className="secondary" onClick={onClose}>Отмена</button>
        <button className="primary" disabled={disabled || password.length < 12}>
          Сбросить пароль
        </button>
      </div>
    </form>
  </Modal>
}

function CredentialsDialog({ device, onClose }: { device: Device; onClose: () => void }) {
  const capabilities = sourceCapabilities(device)
  return <Modal title="Параметры приёма данных" onClose={onClose}>
    <div className="credentials-warning">Пароль FTP отображается один раз. Сохраните его в защищённом хранилище.</div>
    <dl className="credentials">
      {capabilities.syslog && <>
        <dt>Syslog сервер</dt><dd className="mono">{window.location.hostname}:514 / UDP</dd>
      </>}
      <dt>FTP сервер</dt><dd className="mono">{window.location.hostname}:21</dd>
      <dt>FTP пользователь</dt><dd className="mono">{device.ftpUsername}</dd>
      <dt>FTP пароль</dt><dd className="mono secret">{device.generatedPassword}</dd>
      <dt>Каталог CDR</dt><dd className="mono">/</dd>
    </dl>
    <div className="dialog-actions"><button className="primary" onClick={onClose}>Готово</button></div>
  </Modal>
}

const primaryTimezones = [
  'UTC',
  'Europe/Kaliningrad',
  'Europe/Moscow',
  'Europe/Samara',
  'Europe/Saratov',
  'Europe/Ulyanovsk',
  'Europe/Astrakhan',
  'Asia/Yekaterinburg',
  'Asia/Omsk',
  'Asia/Novosibirsk',
  'Asia/Barnaul',
  'Asia/Tomsk',
  'Asia/Novokuznetsk',
  'Asia/Krasnoyarsk',
  'Asia/Irkutsk',
  'Asia/Chita',
  'Asia/Yakutsk',
  'Asia/Vladivostok',
  'Asia/Magadan',
  'Asia/Sakhalin',
  'Asia/Kamchatka',
  'Asia/Anadyr',
]

const availableTimezones = (() => {
  try {
    const intl = Intl as typeof Intl & {
      supportedValuesOf?: (key: 'timeZone') => string[]
    }
    return intl.supportedValuesOf?.('timeZone') || primaryTimezones
  } catch {
    return primaryTimezones
  }
})()

function TimezoneSelect({ value, onChange }: {
  value: string
  onChange: (value: string) => void
}) {
  const primary = Array.from(new Set([value, ...primaryTimezones]))
  const remaining = availableTimezones.filter((timezone) => !primary.includes(timezone))
  return <select required value={value} onChange={(event) => onChange(event.target.value)}>
    <optgroup label="Основные часовые пояса">
      {primary.map((timezone) => <option key={timezone} value={timezone}>{timezone}</option>)}
    </optgroup>
    {remaining.length > 0 && <optgroup label="Все часовые пояса IANA">
      {remaining.map((timezone) => <option key={timezone} value={timezone}>{timezone}</option>)}
    </optgroup>}
  </select>
}

function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) {
  return <div className="modal-backdrop" onMouseDown={onClose}><div className="modal" onMouseDown={(e) => e.stopPropagation()}>
    <div className="modal-header"><h3>{title}</h3><button onClick={onClose}>×</button></div>{children}
  </div></div>
}

function EmptyDevices({ category, canCreate, onCreate }: {
  category: SourceCategory
  canCreate: boolean
  onCreate: () => void
}) {
  const softswitch = category === 'softswitch'
  return <div className="empty-devices"><Server size={28} />
    <h3>{softswitch ? 'Нет подключённых софтсвитчей' : 'Нет подключённого оборудования'}</h3>
    <p>{softswitch
      ? 'Добавьте софтсвитч, чтобы получить изолированный FTP для исходных CDR-файлов.'
      : 'Добавьте оборудование и выберите шаблон обработки его данных.'}</p>
    {canCreate && <button className="primary" onClick={onCreate}>
      {softswitch ? 'Добавить софтсвитч' : 'Добавить оборудование'}</button>}</div>
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

function formatBytes(value?: number) {
  if (!Number.isFinite(value)) return '—'
  const bytes = Number(value)
  if (bytes < 1024) return `${bytes} Б`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} КБ`
  return `${(bytes / (1024 * 1024)).toFixed(1)} МБ`
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
