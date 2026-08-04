import { FormEvent, ReactNode, useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { createRoot } from 'react-dom/client'
import {
  Check, ChevronDown, ChevronUp, ChevronsUpDown, CirclePlus, FileClock,
  LogOut, PhoneCall, Search, Server, Settings, ShieldCheck, X,
} from 'lucide-react'
import './styles.css'
import {
  canManageUsers, normalizeFirmwareScheme, purgeConfirmationReady, purgeRetryLabel,
  retentionDescription, retentionLabel,
} from './settings'
import {
  cdrOutcome, outcomeLabel,
} from './outcomes'
import { readModelNotice } from './readModelNotice'
import { redactDisplayText, redactDisplayValue } from './redaction'
import {
  defaultSourceDataset, deviceSurfaces, DeviceSurface, EquipmentTemplate, fallbackTemplates,
  normalizeTemplate, sourceCapabilities, sourceCategory, SourceCapabilities, SourceCategory, templatesFor,
} from './equipment'
import {
  createExportRequest, ExportJob, exportDownloadURL, exportJobsURL, exportJobDisposition,
  exportJobURL, ExportNavigationDataset, exportStorageKey, isExportActive,
  localDateInTimezone, pollDelay, restoreExportTracking, serializeExportTracking,
} from './export'
import { formatAntifraudTranscript } from './antifraudTranscript'
import {
  CdrColumnDef, cdrPresetStorageKey, cdrPresetsForVendor, defaultCdrPresetId,
  eltexPresetFlexShare, resolvePresetColumns, satelPresetFillWidth, satelPresetFlexShare,
} from './cdrColumns'
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
  policyClass: 'syslog' | 'cdr' | 'softswitch_cdr' | 'raw_cdr_archive'
  activeDays: number
  pendingDays?: number
  effectiveAt?: string
  lastAppliedAt?: string
  lastError?: string
}
type RuntimeSettings = {
  projection: {
    enabled: boolean
    lookback: string
    batchSize: number
    maxEvents: number
    threads: number
    maxMemoryBytes: number
    sleep: string
    lease: string
    responseTimeout: string
    pairingHorizon: string
    retryHorizon: string
    assemblyIdle: string
  }
  coverage: {
    expectedGrace: string
    lateThreshold: string
    missingTerminal: string
    retryHorizon: string
    workerSleep: string
  }
  voipmonitor: {
    enabled: boolean
    apiUrl: string
    user: string
    password?: string
    passwordSet?: boolean
    guiUrl: string
    cardUrlTemplate: string
    callIdWindow: string
    fallbackWindow: string
    fallbackWindowMax: string
    workerSleep: string
    lease: string
    minScore: number
    disambiguityMargin: number
    numberSuffixLen: number
    rateLimitPerSec: number
    useShareUrl: boolean
  }
  enrichment?: {
    pstn: { enabled: boolean; apiUrl: string; token?: string; tokenSet?: boolean }
    geoip: { enabled: boolean; apiUrl: string; token?: string; tokenSet?: boolean }
    workers?: number
    catchUp?: { enabled: boolean; pageSize: number; sleep: string }
  }
  platform: {
    clickhouseAdmissionCapacity: number
    exportPageSize: number
  }
  containers: {
    apiCpus: string
    apiMemory: string
    exportCpus: string
    exportMemory: string
    maintenanceCpus: string
    maintenanceMemory: string
    appCpus: string
    appMemory: string
  }
}
type DashboardDevice = {
  id: string
  name: string
  model: string
  firmware: string
  timezone: string
  activeTimezone: string
  enabled: boolean
  antifraudEnabled: boolean
  metrics: {
    calls: number
    failedCalls: number
    averageTalkMs: number
    pstnEnrichedCalls?: number
    geoipEnrichedCalls?: number
    antifraud: number
    antifraudRejected: number
    voipmonitorMatchedExact?: number
    voipmonitorMatchedFallback?: number
    voipmonitorAmbiguous?: number
    voipmonitorUnmatched?: number
  }
  freshness: { latestSyslogAt?: string; latestCdrAt?: string; latestAntifraudAt?: string }
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
  pstnEnrichedCalls?: number
  geoipEnrichedCalls?: number
  antifraud?: number
  rejects?: number
  files?: number
  bytes?: number
  storageBytes?: number
  voipmonitorMatchedExact?: number
  voipmonitorMatchedFallback?: number
  voipmonitorAmbiguous?: number
  voipmonitorUnmatched?: number
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
  voipmonitorEnabled: boolean
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
  deviceId: string
  receivedAt: string
  sourceIp: string
  sourcePort: number
  transport: string
  payload: string
  payloadSha256: string
  truncated?: boolean
}
type DeviceStats = {
  calls24h: number
  failedCalls24h: number
  averageTalkMs: number
  syslogMessages24h: number
}
type IngestRuntime = {
  acceptedDatagrams: number; rejectedDatagrams: number; spoolWriteErrors: number
  handoffErrors: number; handedOff: number
}
type CdrIngestFile = {
  id: string
  originalName: string
  sha256?: string
  sizeBytes?: number
  status: string
  rowsTotal: number
  rowsValid: number
  error?: string
  receivedAt: string
  processedAt?: string
}
type ProjectionDeviceDiagnostics = {
  deviceId: string
  name: string
  depth: number
  bucketDepth?: number
  failed: number
  backfilling: number
  oldestAge: number
  oldestBucketAge?: number
  watermarkState: string
  watermarkLagSeconds: number
  lastError?: string
  syslogLagSeconds: number
  afCallLagSeconds: number
  afSyslogLagSeconds?: number
  hasAFSyslogTip?: boolean
  activatedLagSeconds: number
  afAuthHeaders6h: number
  xpgkHeaders6h: number
  classificationGap: boolean
  healthLagSeconds?: number
  contentLagSeconds?: number
  eventTipLagSeconds?: number
  projectionLagSeconds: number
  projectionSloMet: boolean
  openHourStatus?: string
  openHourAgeSeconds?: number
}
type OperationalDiagnostics = {
  generatedAt: string
  customProjectionEnabled: boolean
  projectionQueue: {
    depth: number
    oldestAge: number
    oldestBucketAge?: number
    discoverAge?: number
    failed: number
    backfilling: number
    lagSeconds: number
    maxDeviceLagSeconds?: number
    maxEventTipLagSeconds?: number
    anyDeviceFailed?: boolean
    anyClassificationGap?: boolean
  }
  projectionDevices?: ProjectionDeviceDiagnostics[]
  reconciliationQueue: {
    depth: number
    oldestAge: number
    failed: number
  }
  derived: {
    projectionLagSeconds: number
    maxDeviceProjectionLagSeconds?: number
    calls: number
    packets: number
    orphans: number
    ambiguity: number
    coverage: Record<string, number>
    coverageSloMet: boolean
    projectionSloMet: boolean
    anyDeviceFailed?: boolean
    anyClassificationGap?: boolean
  }
  exports: {
    queued: number
    running: number
    oldestAge: number
  }
  enrichmentApis?: {
    pstn?: EnrichmentAPIDiagnostics
    geoip?: EnrichmentAPIDiagnostics
  }
  enrichmentCoverage?: {
    windowSeconds: number
    calls: number
    pstnEligible: number
    pstnEnriched: number
    pstnCoverage: number
    geoipEligible: number
    geoipEnriched: number
    geoipCoverage: number
    backlog: number
  }
  enrichmentWorkers?: number
  enrichmentCatchUp?: boolean
}
type EnrichmentAPIDiagnostics = {
  enabled: boolean
  configured: boolean
  lookups: number
  cacheHits: number
  errors: number
  errorRate: number
  p95LatencyMs: number
  lastError?: string
  lastSuccessAt?: string
  healthy: boolean
}
type CallRow = {
  recordId: string
  setupTime?: string
  connectTime?: string
  disconnectTime?: string
  setupTimeLocal?: string
  sourceTimezone?: string
  sourceUtcOffsetMinutes?: number
  durationMs?: number
  releaseCause?: number
  releaseInfo: string
  releaseSide?: string
  incomingIp?: string
  outgoingIp?: string
  incomingType?: string
  outgoingType?: string
  incomingCgpn: string
  outgoingCgpn: string
  incomingCdpn: string
  outgoingCdpn: string
  incomingRedirectingNumber?: string
  outgoingRedirectingNumber?: string
  incomingNumplan?: string
  outgoingNumplan?: string
  callingNai?: string
  calledNai?: string
  incomingE1Stream?: string
  incomingE1Channel?: string
  outgoingE1Stream?: string
  outgoingE1Channel?: string
  incomingSipCallId?: string
  outgoingSipCallId?: string
  incomingSs7Cic?: number
  outgoingSs7Cic?: number
  incomingDescription: string
  outgoingDescription: string
  radiusSessionId: string
  radiusSessionIdNormalized?: string
  globalCallref?: string
  uniqueTag: string
  transferMark?: string
  rejectingRadiusServer?: string
  sequenceNumber?: string
  bootEpoch?: string
  sequence?: number
  voipmonitorCdrId?: string
  voipmonitorCallId?: string
  voipmonitorCardUrl?: string
  voipmonitorMatchStatus?: string
  voipmonitorMatchMethod?: string
  voipmonitorMatchScore?: number
}
type SatelCdrRow = {
  recordId: string
  externalCdrId?: string
  cdrId?: string
  cdrDate?: string
  setupTime?: string
  connectTime?: string
  disconnectTime?: string
  durationMs?: number
  elapsedTime?: number
  outcome?: string
  inAni?: string
  inDnis?: string
  outAni?: string
  outDnis?: string
  billAni?: string
  billDnis?: string
  billAniOperator?: string
  billDnisOperator?: string
  billAniRegion?: string
  billDnisRegion?: string
  srcUser?: string
  dstUser?: string
  radiusUser?: string
  srcName?: string
  dstName?: string
  dpName?: string
  inCpc?: string
  outCpc?: string
  inZone?: string
  outZone?: string
  inOrigDnis?: string
  outOrigDnis?: string
  inAniTypeOfNumber?: string
  inDnisTypeOfNumber?: string
  outAniTypeOfNumber?: string
  outDnisTypeOfNumber?: string
  inOrigDnisTypeOfNumber?: string
  outOrigDnisTypeOfNumber?: string
  extAniTypeOfNumber?: string
  extDnisTypeOfNumber?: string
  extOrigDnisTypeOfNumber?: string
  inAniScreening?: string
  inAniPresentation?: string
  outAniScreening?: string
  outAniPresentation?: string
  inLrn?: string
  retrievedLrn?: string
  lrn?: string
  extLrn?: string
  outLrn?: string
  lnpServer?: string
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
  srcInLegConfId?: string
  srcInLegCallId?: string
  srcOutLegCallId?: string
  disconnectCode?: string | number
  disconnectText?: string
  disconnectSuccess?: boolean
  disconnectInitiator?: string
  srcDisconnectCodes?: string
  dstDisconnectCodes?: string
  srcDisconnectText?: string
  dstDisconnectText?: string
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
  remoteSrcGeoipIso?: string
  remoteSrcGeoipCity?: string
  remoteSrcAsnOrg?: string
  remoteDstGeoipIso?: string
  remoteDstGeoipCity?: string
  remoteDstAsnOrg?: string
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
  routeRetries?: number
  outgoingPulses?: number
  incomingPulses?: number
  loopingCycles?: number
  proxyMode?: string
  larFaultReason?: string
  mediaGroup?: string
  externalRouter?: string
  radiusGroup?: string
  sipRoutingGroup?: string
  authDnis?: string
  extAni?: string
  extDnis?: string
  extSigAddress?: string
  inPartnerId?: string
  outPartnerId?: string
  inEncryption?: string
  outEncryption?: string
  recordType?: string
  lastCdr?: boolean
  parserVersion?: string
  sourceTimezone?: string
  sourceUtcOffsetMinutes?: number
  setupTimeLocal?: string
  rawFields?: Record<string, unknown>
  voipmonitorCdrId?: string
  voipmonitorCallId?: string
  voipmonitorCardUrl?: string
  voipmonitorMatchStatus?: string
  voipmonitorMatchMethod?: string
  voipmonitorMatchScore?: number
}
type CoverageSummary = {
  state: 'matched' | 'expected' | 'late' | 'missing' | 'ambiguous' | 'not_applicable' |
    'unmatched' | 'awaiting_cdr'
  method?: string
  reason?: string
  deltaMs?: number
  ambiguous: boolean
  ambiguityReason?: string
  evidence?: Record<string, unknown>
  linkedCdrIds: string[]
}
type ChainCompleteness = {
  state: string
  missingStages?: string[]
  missingResponses?: string[]
  notes?: string[]
}
type TimelineEvent = {
  ts: string
  phase: string
  radiusType: string
  xpgkRequestType?: string
  acctStatusType?: string
  decision?: string
  summary: string
  packetId: string
}
type AntifraudRow = {
  callId: string
  firstSeenAt: string
  lastSeenAt: string
  acctSessionId: string
  acctSessionIds?: string[]
  h323ConfId: string
  calling: string
  called: string
  status: string
  radiusOutcome?: string
  phases: string[]
  packetCount: number
  explanationCodes: string[]
  coverage: CoverageSummary
  chainCompleteness?: ChainCompleteness
}
type OrderedAttribute = { name: string; value: unknown }
type AntifraudPacket = {
  packetId: string
  firstSeenAt: string
  lastSeenAt: string
  family: string
  radiusType: string
  direction: string
  phase: string
  decision: string
  confidence: string
  status: string
  requestId?: string
  responseId?: string
  attemptIds: string[]
  attributes: OrderedAttribute[]
  explanationCodes: string[]
  warnings?: unknown
  orphanReason?: string
  ambiguityReason?: string
  members: { eventId: string; receivedAt: string; sourceIp: string; sourcePort: number }[]
}
type AntifraudCallDetail = AntifraudRow & {
  participants?: { callingNumber?: string; calledNumber?: string }
  requestTypes?: string[]
  indicationAcked?: boolean
  verificationResult?: string
  accountingAcked?: boolean
  finalDecision?: string
  durationSec?: number
  disconnectCauseQ850?: number
  timeline?: TimelineEvent[]
  accounting?: {
    setupTime?: string
    connectTime?: string
    disconnectTime?: string
    eventTimestamp?: string
    disconnectCause?: string
    disconnectCauseQ850?: number
    sessionTimeSec?: number
    delayTimeSec?: number
  }
  routing?: Record<string, string>
  accountingStart?: string
  accountingStop?: string
  sessionDurationSeconds?: number
  attributes: OrderedAttribute[]
  unmatched?: unknown
  orphanPacketIds: string[]
  packets: AntifraudPacket[]
  rawPackets?: AntifraudPacket[]
  exchanges: {
    exchangeId: string
    requestId: string
    responseId?: string
    attemptIds: string[]
    status: string
    decision: string
    explanationCodes: string[]
    occurredAt: string
  }[]
  linkedCdrs: CallRow[]
  truncated: boolean
  warnings: string[]
}
type CallCardDTO = {
  cdr: CallRow
  coverage: CoverageSummary
  antifraud?: AntifraudCallDetail
}
type PageCursor = { before: string; beforeId: string }
type PageResponse<T> = {
  items: T[]
  hasMore: boolean
  hasNewer?: boolean
  nextCursor?: PageCursor
}
type DataRow = EventRow | CallRow | SatelCdrRow | AntifraudRow
type Dataset = ExportNavigationDataset
type SyslogViewMode = 'table' | 'raw'

const SYSLOG_VIEW_STORAGE_KEY = 'collector:syslog-view'
const SYSLOG_HIDE_STREAM_STORAGE_KEY = 'collector:syslog-hide-stream'

function readSyslogViewMode(): SyslogViewMode {
  return window.sessionStorage.getItem(SYSLOG_VIEW_STORAGE_KEY) === 'table' ? 'table' : 'raw'
}

function readSyslogHideStream(): boolean {
  return window.sessionStorage.getItem(SYSLOG_HIDE_STREAM_STORAGE_KEY) === '1'
}

/** Case-insensitive find highlight for Syslog find-in-list (not API filter). */
function highlightFind(text: string, find: string, active: boolean): ReactNode {
  const source = text || '—'
  const needle = find.trim()
  if (!needle) return source
  const lower = source.toLowerCase()
  const needleLower = needle.toLowerCase()
  const parts: ReactNode[] = []
  let start = 0
  let key = 0
  while (start < source.length) {
    const index = lower.indexOf(needleLower, start)
    if (index < 0) {
      parts.push(source.slice(start))
      break
    }
    if (index > start) parts.push(source.slice(start, index))
    parts.push(<mark key={key++}
      className={active ? 'syslog-find-hit syslog-find-hit-active' : 'syslog-find-hit'}>
      {source.slice(index, index + needle.length)}</mark>)
    start = index + needle.length
  }
  return parts.length ? <>{parts}</> : source
}

let csrfToken = ''
const PAGE_SIZE = 100
const SYSLOG_FIND_LOCATE_ERROR = 'Не удалось открыть совпадение в ленте. Повторите поиск или включите «Скрывать поток».'

async function restoreCSRF(): Promise<boolean> {
  try {
    const response = await fetch('/api/auth/me', { credentials: 'same-origin' })
    if (!response.ok) return false
    const body = await response.json().catch(() => ({})) as { csrfToken?: string }
    if (!body.csrfToken) return false
    csrfToken = body.csrfToken
    return true
  } catch {
    return false
  }
}

async function api<T>(path: string, init?: RequestInit & { timeoutMs?: number; retryOnCSRF?: boolean }): Promise<T> {
  const { timeoutMs, retryOnCSRF = true, ...requestInit } = init || {}
  const controller = timeoutMs ? new AbortController() : undefined
  const timer = timeoutMs
    ? window.setTimeout(() => controller?.abort(), timeoutMs)
    : undefined
  try {
    const method = (requestInit.method || 'GET').toUpperCase()
    const mutating = method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS'
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
    const body = await response.json().catch(() => ({})) as { error?: string; detail?: string }
    if (!response.ok) {
      if (response.status === 401 && body.error === 'session expired' &&
        mutating && retryOnCSRF && await restoreCSRF()) {
        return api<T>(path, { ...init, retryOnCSRF: false })
      }
      const message = body.detail
        ? `${body.error || `HTTP ${response.status}`}: ${body.detail}`
        : (body.error || `HTTP ${response.status}`)
      throw new Error(message)
    }
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
    const next = items || []
    setDevices((current) =>
      devicesPollFingerprint(current) === devicesPollFingerprint(next) ? current : next)
    setActiveDevice((current) => current || next[0]?.id || '')
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
        className={`device-button ${activeView === 'device' && device.id === activeDevice ? 'active' : ''}`}
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
            <span>{selected.antifraudEnabled ? 'АнтиФрод включён' : 'Без АнтиФрод'}</span>}
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
        if (device.id === activeDevice && !deviceSurfaces(device).includes(dataset as DeviceSurface)) {
          setDataset(defaultSourceDataset(device))
        }
        setEditingDevice(null)
      }} onDeleted={() => {
        setEditingDevice(null)
        setActiveDevice('')
        void loadDevices()
      }} />}
    {credentials && <CredentialsDialog device={credentials} onClose={() => setCredentials(null)} />}
  </div>
}

const navigation: { id: Dataset; label: string; icon: typeof PhoneCall }[] = [
  { id: 'calls', label: 'Вызовы и CDR', icon: PhoneCall },
  { id: 'syslog', label: 'Сообщения Syslog', icon: FileClock },
  { id: 'antifraud', label: 'АнтиФрод', icon: ShieldCheck },
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
    <div className="dashboard-category-heading"><h4>Софтсвитчи</h4><span>Типизированные и исходные CDR</span></div>
    <div className="dashboard-kpis">
      <DashboardKPI label="Вызовы" value={formatCount(softswitchTotals.calls)}
        detail={`неуспешных ${formatCount(softswitchTotals.failed)}`}
        tone={softswitchTotals.failed ? 'bad' : 'good'} />
      <DashboardKPI label="VoIPmonitor"
        value={formatCount(voipmonitorMatched(softswitchTotals))}
        tone={voipmonitorTone(softswitchTotals)} />
      <DashboardKPI label="Неразобранное"
        value={formatCount(softswitchUnresolved(softswitchTotals))}
        tone={softswitchUnresolved(softswitchTotals) > 0 ? 'warn' : 'good'} />
      <DashboardKPI label="Операторы"
        value={formatCount(softswitchTotals.pstnEnrichedCalls)}
        detail="все поля PSTN" />
      <DashboardKPI label="GeoIP"
        value={formatCount(softswitchTotals.geoipEnrichedCalls)}
        detail="все поля GeoIP" />
      <DashboardKPI label="CDR-файлы" value={formatCount(softswitchTotals.files)}
        detail={formatBytes(softswitchTotals.bytes)} />
    </div>
    <section className="dashboard-panel fleet-panel">
      <div className="panel-heading"><div><h4>Софтсвитчи</h4></div></div>
      <table className="table-fit"><thead><tr>
        <th title="Софтсвитч">Софтсвитч</th><th title="Шаблон / timezone">Шаблон / timezone</th>
        <th title="Статус">Статус</th>
        <th title="Вызовы">Вызовы</th><th title="Успешные">Успешные</th>
        <th title="Неуспешные">Неуспешные</th><th title="ASR">ASR</th>
        <th title="Средний разговор">Средний разговор</th><th title="CDR-файлы">CDR-файлы</th>
        <th title="Объём файлов">Объём файлов</th>
        <th className="col-flex" title="Последний CDR">Последний CDR</th></tr></thead>
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
            <td className="mono col-flex">
              {formatTime(
                row.fileMetrics?.latestAt || row.freshness.latestCdrAt,
                row.activeTimezone || row.timezone || 'UTC',
              )}</td>
          </tr>
        })}</tbody></table>
      {softswitchRows.length === 0 && <div className="table-empty">
        <strong>Софтсвитчи ещё не добавлены</strong>
      </div>}
    </section>
    <div className="dashboard-category-heading"><h4>Оборудование</h4><span>Eltex · Syslog, CDR и AntiFraud</span></div>
    <div className="dashboard-kpis">
      <DashboardKPI label="Вызовы" value={formatCount(equipmentTotals.calls)}
        detail={`неуспешных ${formatCount(equipmentTotals.failed)}`}
        tone={equipmentTotals.failed ? 'bad' : 'good'} />
      <DashboardKPI label="VoIPmonitor"
        value={formatCount(voipmonitorMatched(equipmentTotals))}
        tone={voipmonitorTone(equipmentTotals)} />
      <DashboardKPI label="AntiFraud" value={formatCount(equipmentTotals.antifraud)}
        detail={`reject ${formatCount(equipmentTotals.rejects)}`} />
      <DashboardKPI label="ASR" value={formatPercent(equipmentTotals.calls, equipmentTotals.failed)}
        detail="доля успешных вызовов" />
      <DashboardKPI label="Средний разговор"
        value={formatDurationAverage(equipmentTotals.averageTalkMs)} />
      <DashboardKPI label="Объем данных"
        value={formatStorageMB(equipmentTotals.storageBytes)} />
    </div>
    <section className="dashboard-panel fleet-panel">
      <div className="panel-heading"><div><h4>Оборудование</h4></div></div>
      <table className="table-fit"><thead><tr>
        <th title="Оборудование">Оборудование</th>
        <th title="Шаблон / timezone">Шаблон / timezone</th><th title="Статус">Статус</th>
        <th title="Вызовы">Вызовы</th><th title="Неуспешные">Неуспешные</th>
        <th title="AntiFraud / reject">AntiFraud / reject</th>
        <th title="Revision">Revision</th>
        <th className="col-flex" title="Последний CDR">Последний CDR</th>
        <th className="col-flex" title="Последний приём Syslog">Последний приём Syslog</th>
        <th className="col-flex" title="Последнее значение АнтиФрода">Последнее значение АнтиФрода</th>
      </tr></thead>
        <tbody>{equipmentRows.map((row) => <tr key={row.id} onClick={() => onSelectDevice(row.id)}>
          <td><strong>{row.name}</strong><small>{row.model}</small></td>
          <td>{row.templateKey || row.firmware || '—'} / {row.timezone || 'UTC'}
            <small>Активный: {row.activeTimezone || row.timezone || 'UTC'}</small></td>
          <td><span className={row.enabled ? 'healthy' : 'service-error'}>
            {row.enabled ? 'Приём активен' : 'Выключен'}</span></td>
          <td className="right">{formatCount(row.metrics.calls)}</td>
          <td className="right">{formatCount(row.metrics.failedCalls)}</td>
          <td className="right">{row.antifraudEnabled
            ? `${formatCount(row.metrics.antifraud)} / ${formatCount(row.metrics.antifraudRejected)}` : '—'}</td>
          <td>{row.revision.aligned ? 'aligned' : 'rebuild'}</td>
          <td className="mono col-flex">
            {formatTime(row.freshness.latestCdrAt, row.activeTimezone || row.timezone || 'UTC')}
            <small>{row.activeTimezone || row.timezone || 'UTC'}</small>
          </td>
          <td className="mono col-flex">
            {formatTime(row.freshness.latestSyslogAt, row.activeTimezone || row.timezone || 'UTC')}
            <small>{row.activeTimezone || row.timezone || 'UTC'}</small>
          </td>
          <td className="mono col-flex">
            {formatTime(row.freshness.latestAntifraudAt, row.activeTimezone || row.timezone || 'UTC')}
            <small>{row.activeTimezone || row.timezone || 'UTC'}</small>
          </td>
        </tr>)}</tbody></table>
      {equipmentRows.length === 0 && <div className="table-empty">
        <strong>Оборудование ещё не добавлено</strong>
      </div>}
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
      antifraudEnabled: row.antifraudEnabled ?? source?.antifraudEnabled ?? false,
      metrics: row.metrics || {
        calls: 0, failedCalls: 0, averageTalkMs: 0, antifraud: 0, antifraudRejected: 0,
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
    pstnEnrichedCalls: totals.pstnEnrichedCalls +
      (sourceCapabilities(row).typedCdr ? row.metrics.pstnEnrichedCalls || 0 : 0),
    geoipEnrichedCalls: totals.geoipEnrichedCalls +
      (sourceCapabilities(row).typedCdr ? row.metrics.geoipEnrichedCalls || 0 : 0),
    antifraud: totals.antifraud + (row.antifraudEnabled ? row.metrics.antifraud || 0 : 0),
    rejects: totals.rejects + (row.antifraudEnabled ? row.metrics.antifraudRejected || 0 : 0),
    files: totals.files + (row.fileMetrics?.files || 0),
    bytes: totals.bytes + (row.fileMetrics?.bytes || 0),
    voipmonitorMatchedExact: totals.voipmonitorMatchedExact + (row.metrics.voipmonitorMatchedExact || 0),
    voipmonitorMatchedFallback: totals.voipmonitorMatchedFallback + (row.metrics.voipmonitorMatchedFallback || 0),
    voipmonitorAmbiguous: totals.voipmonitorAmbiguous + (row.metrics.voipmonitorAmbiguous || 0),
    voipmonitorUnmatched: totals.voipmonitorUnmatched + (row.metrics.voipmonitorUnmatched || 0),
    storageBytes: totals.storageBytes,
  }), {
    calls: 0, failed: 0, pstnEnrichedCalls: 0, geoipEnrichedCalls: 0,
    antifraud: 0, rejects: 0, files: 0, bytes: 0, storageBytes: 0,
    voipmonitorMatchedExact: 0, voipmonitorMatchedFallback: 0,
    voipmonitorAmbiguous: 0, voipmonitorUnmatched: 0,
  })
  return {
    activeSources: apiTotals.activeSources ?? sources.filter((source) => source.enabled).length,
    totalSources: apiTotals.totalSources ?? sources.length,
    calls: apiTotals.calls ?? fallback.calls,
    failed: apiTotals.failed ?? fallback.failed,
    averageTalkMs: apiTotals.averageTalkMs ?? 0,
    pstnEnrichedCalls: apiTotals.pstnEnrichedCalls ?? fallback.pstnEnrichedCalls,
    geoipEnrichedCalls: apiTotals.geoipEnrichedCalls ?? fallback.geoipEnrichedCalls,
    antifraud: apiTotals.antifraud ?? fallback.antifraud,
    rejects: apiTotals.rejects ?? fallback.rejects,
    files: apiTotals.files ?? fallback.files,
    bytes: apiTotals.bytes ?? fallback.bytes,
    storageBytes: apiTotals.storageBytes ?? fallback.storageBytes,
    voipmonitorMatchedExact: apiTotals.voipmonitorMatchedExact ?? fallback.voipmonitorMatchedExact,
    voipmonitorMatchedFallback: apiTotals.voipmonitorMatchedFallback ?? fallback.voipmonitorMatchedFallback,
    voipmonitorAmbiguous: apiTotals.voipmonitorAmbiguous ?? fallback.voipmonitorAmbiguous,
    voipmonitorUnmatched: apiTotals.voipmonitorUnmatched ?? fallback.voipmonitorUnmatched,
  }
}

function voipmonitorMatched(totals: {
  voipmonitorMatchedExact?: number
  voipmonitorMatchedFallback?: number
}) {
  return (totals.voipmonitorMatchedExact || 0) + (totals.voipmonitorMatchedFallback || 0)
}

/** Softswitch-only: calls not matched by VoIPmonitor within the softswitch totals. */
function softswitchUnresolved(totals: {
  calls?: number
  voipmonitorMatchedExact?: number
  voipmonitorMatchedFallback?: number
}) {
  return Math.max(0, (totals.calls || 0) - voipmonitorMatched(totals))
}

function voipmonitorTone(totals: {
  voipmonitorMatchedExact?: number
  voipmonitorMatchedFallback?: number
  voipmonitorAmbiguous?: number
  voipmonitorUnmatched?: number
}): 'good' | 'warn' | 'bad' | undefined {
  const matched = voipmonitorMatched(totals)
  const open = (totals.voipmonitorAmbiguous || 0) + (totals.voipmonitorUnmatched || 0)
  if (matched + open === 0) return undefined
  if (matched === 0) return 'bad'
  if (open > matched) return 'warn'
  return 'good'
}

function formatDurationAverage(value?: number) {
  return value ? `${Math.round(value / 1000)} с` : '—'
}

function formatDurationSeconds(value?: number) {
  return value == null ? '—' : `${Math.round(value / 1000)} с`
}

function formatPercent(total?: number, failed?: number) {
  if (!total) return '—'
  return `${Math.max(0, ((total - (failed || 0)) / total) * 100).toFixed(1)}%`
}

function formatPercentRatio(ratio?: number) {
  if (ratio == null || Number.isNaN(ratio)) return '—'
  return `${Math.max(0, ratio * 100).toFixed(1)}%`
}

function DeviceNavigation({ device, active, onChange }: {
  device: Device
  active: Dataset
  onChange: (value: Dataset) => void
}) {
  const surfaces = deviceSurfaces(device)
  const items = navigation.filter((item) => surfaces.includes(item.id as typeof surfaces[number]))
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

function ExportButton({ deviceID, dataset, query, date, filters }: {
  deviceID: string
  dataset: Dataset
  query: string
  date: string
  filters?: Record<string, string>
}) {
  const filtersKey = filters && Object.keys(filters).length > 0
    ? Object.keys(filters).sort().map((key) => `${key}=${filters[key]}`).join('&')
    : ''
  const storageKey = exportStorageKey(deviceID, dataset, date, query, filtersKey)
  const [restored] = useState(() =>
    restoreExportTracking(window.sessionStorage.getItem(storageKey)))
  const [job, setJob] = useState<ExportJob | null>(restored.job)
  const [restoringJobID, setRestoringJobID] = useState<string | null>(
    restored.job?.id || restored.legacyJobID,
  )
  const [creating, setCreating] = useState(false)
  const [error, setError] = useState('')
  const jobID = job?.id
  const jobStatus = job?.status

  const acceptJob = useCallback((next: ExportJob) => {
    const disposition = exportJobDisposition(next)
    if (disposition === 'clear') {
      window.sessionStorage.removeItem(storageKey)
      setJob(null)
      setError(next.error || (next.status === 'completed'
        ? 'Срок хранения архива истёк'
        : 'Не удалось подготовить архив'))
      return disposition
    }
    window.sessionStorage.setItem(storageKey, serializeExportTracking(next))
    setJob(next)
    setError('')
    return disposition
  }, [storageKey])

  const forgetDownloaded = useCallback(() => {
    window.sessionStorage.removeItem(storageKey)
  }, [storageKey])

  useEffect(() => {
    if (!restoringJobID) return
    let active = true
    api<{ job: ExportJob }>(exportJobURL(deviceID, restoringJobID))
      .then(({ job: next }) => {
        if (active) acceptJob(next)
      })
      .catch((reason) => {
        if (!active) return
        window.sessionStorage.removeItem(storageKey)
        setJob(null)
        setError(reason instanceof Error ? reason.message : 'Не удалось восстановить экспорт')
      })
      .finally(() => {
        if (active) setRestoringJobID(null)
      })
    return () => {
      active = false
    }
  }, [acceptJob, deviceID, restoringJobID, storageKey])

  useEffect(() => {
    if (restoringJobID || !jobID || !jobStatus || !isExportActive(jobStatus)) return
    let active = true
    let timer: number | undefined
    let failures = 0
    const poll = () => {
      api<{ job: ExportJob }>(exportJobURL(deviceID, jobID))
        .then(({ job: next }) => {
          if (!active) return
          failures = 0
          const disposition = acceptJob(next)
          if (disposition === 'poll') {
            timer = window.setTimeout(poll, pollDelay(0, true))
          }
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
  }, [acceptJob, deviceID, jobID, jobStatus, restoringJobID])

  useEffect(() => {
    if (job?.status !== 'completed' || !job.expiresAt) return
    const remaining = new Date(job.expiresAt).getTime() - Date.now()
    const timer = window.setTimeout(() => acceptJob(job), Math.max(0, remaining + 50))
    return () => window.clearTimeout(timer)
  }, [acceptJob, job])

  const createJob = () => {
    setCreating(true)
    setError('')
    setJob(null)
    api<{ job: ExportJob }>(exportJobsURL(deviceID), {
      method: 'POST',
      body: JSON.stringify(createExportRequest(dataset, query, date, date, filters)),
    })
      .then(({ job: next }) => {
        acceptJob(next)
      })
      .catch((reason) => setError(reason instanceof Error ? reason.message : 'Не удалось создать экспорт'))
      .finally(() => setCreating(false))
  }

  const downloadReady = restoringJobID == null && job != null &&
    exportJobDisposition(job) === 'offer_download'
  const active = creating || restoringJobID != null ||
    (job != null && (isExportActive(job.status) || (job.status === 'completed' && !downloadReady)))
  const label = creating ? 'Запуск…' : restoringJobID ? 'Проверка архива…'
    : job?.status === 'queued' ? 'Архив в очереди…'
    : job?.status === 'running' ? `Архив: ${job.rowsWritten.toLocaleString('ru-RU')} строк…`
      : job?.status === 'completed' ? 'Скачать архив'
        : error ? 'Повторить экспорт' : 'Экспорт CSV.zip'
  return <div className="export-button-wrap">
    {downloadReady && job
      ? <a className="secondary" href={exportDownloadURL(deviceID, job.id)}
        download={job.filename || ''} onClick={forgetDownloaded}>{label}</a>
      : <button className="secondary" disabled={active} onClick={createJob}>{label}</button>}
    {error && <small className="export-inline-error" title={error}>{error}</small>}
  </div>
}

function DataView({ device, dataset, admin }: { device: Device; dataset: Dataset; admin: boolean }) {
  const [query, setQuery] = useState('')
  const [syslogFind, setSyslogFind] = useState('')
  /** Committed Find needle (Submit only). Drives hide-stream q= and active search session. */
  const [syslogCommittedFind, setSyslogCommittedFind] = useState('')
  /** Bumps on each Найти so the same needle can re-run. */
  const [syslogSearchToken, setSyslogSearchToken] = useState(0)
  const [syslogFindHit, setSyslogFindHit] = useState<{
    eventId: string
    receivedAt: string
  } | null>(null)
  const [syslogFindIndex, setSyslogFindIndex] = useState(0)
  const [syslogFindTotal, setSyslogFindTotal] = useState(0)
  const [syslogFindBusy, setSyslogFindBusy] = useState(false)
  const [syslogFindError, setSyslogFindError] = useState('')
  const [columnFilters, setColumnFilters] = useState<SummaryColumnFilters>({})
  const [eltexColumnFilters, setEltexColumnFilters] = useState<EltexColumnFilters>({})
  const [antifraudColumnFilters, setAntifraudColumnFilters] = useState<AntifraudColumnFilters>({})
  const timezone = activeDeviceTimezone(device)
  const dateStorageKey = `collector:date:${device.id}`
  const [date, setDate] = useState(() =>
    window.sessionStorage.getItem(dateStorageKey) || localDateInTimezone(timezone))
  const [rows, setRows] = useState<DataRow[]>([])
  const [loading, setLoading] = useState(false)
  const [loadError, setLoadError] = useState('')
  const [reload, setReload] = useState(0)
  const [selectedCall, setSelectedCall] = useState<CallRow | null>(null)
  const [selectedSatelCall, setSelectedSatelCall] = useState<SatelCdrRow | null>(null)
  const [selectedAntifraud, setSelectedAntifraud] = useState<AntifraudRow | null>(null)
  const [selectedEvent, setSelectedEvent] = useState<EventRow | null>(null)
  const [statsResult, setStatsResult] = useState<{
    date: string
    value: DeviceStats | null
  }>({ date: '', value: null })
  const stats = statsResult.date === date ? statsResult.value : null
  const [hasMore, setHasMore] = useState(false)
  const [hasNewer, setHasNewer] = useState(false)
  const tableShellRef = useRef<HTMLDivElement>(null)
  const sentinelRef = useRef<HTMLDivElement>(null)
  const topSentinelRef = useRef<HTMLDivElement>(null)
  const loadingRef = useRef(false)
  const generationRef = useRef(0)
  const feedRef = useRef<{
    rows: DataRow[]
    cursor: PageCursor | null
    hasMore: boolean
    hasNewer: boolean
  }>({ rows: [], cursor: null, hasMore: false, hasNewer: false })
  const feedEpochRef = useRef(0)
  const syslogFindGenerationRef = useRef(0)
  const syslogFindBusyRef = useRef(false)
  const syslogFindHitRef = useRef<{ eventId: string; receivedAt: string } | null>(null)
  const syslogFindIndexRef = useRef(0)
  const syslogFindTotalRef = useRef(0)
  const syslogFindNeedleRef = useRef('')
  const syslogMatchItemsRef = useRef<{ eventId: string; receivedAt: string }[]>([])
  const syslogMatchHasMoreRef = useRef(false)
  const syslogMatchCursorRef = useRef<PageCursor | null>(null)
  const isSatel = device.templateKey === 'satel-rtu-cdr-v1'
  const cdrVendor = isSatel ? 'satel' as const : 'eltex' as const
  const presetStorageKey = cdrPresetStorageKey(device.id)
  const [columnPresetId, setColumnPresetId] = useState(() =>
    window.sessionStorage.getItem(presetStorageKey) || defaultCdrPresetId())
  const [syslogViewMode, setSyslogViewMode] = useState<SyslogViewMode>(readSyslogViewMode)
  const [syslogHideStream, setSyslogHideStream] = useState(readSyslogHideStream)
  const vendorPresets = cdrPresetsForVendor(cdrVendor)
  const activePresetId = vendorPresets.some((preset) => preset.id === columnPresetId)
    ? columnPresetId
    : defaultCdrPresetId()
  const satelColumnFiltersActive = isSatel && dataset === 'calls'
  const eltexColumnFiltersActive = !isSatel && dataset === 'calls'
  const antifraudFiltersActive = !isSatel && dataset === 'antifraud'
  const columnFiltersActive = satelColumnFiltersActive || eltexColumnFiltersActive || antifraudFiltersActive
  const hasActiveColumnFilters = satelColumnFiltersActive
    ? Object.values(columnFilters).some((value) => value.trim() !== '')
    : eltexColumnFiltersActive
      ? Object.values(eltexColumnFilters).some((value) => Boolean(value?.trim()))
      : antifraudFiltersActive
        ? Object.values(antifraudColumnFilters).some((value) => Boolean(value?.trim()))
        : false
  const exportColumnFilters = satelColumnFiltersActive
    ? satelFiltersToQuery(columnFilters)
    : eltexColumnFiltersActive
      ? eltexFiltersToQuery(eltexColumnFilters)
      : antifraudFiltersActive
        ? antifraudFiltersToQuery(antifraudColumnFilters)
        : undefined
  const title = navigation.find((item) => item.id === dataset)?.label || dataset
  // Only hide-stream + committed find puts q= on the list path (typing alone must not reload).
  const syslogListQ = dataset === 'syslog' && syslogHideStream ? syslogCommittedFind.trim() : ''
  const pagePath = useCallback((pageCursor?: PageCursor) => {
    if (dataset === 'calls') {
      const params = new URLSearchParams()
      params.set('date', date)
      params.set('limit', String(PAGE_SIZE))
      if (isSatel) {
        for (const [key, value] of Object.entries(satelFiltersToQuery(columnFilters))) {
          params.set(`f.${key}`, value)
        }
      } else {
        for (const [key, value] of Object.entries(eltexFiltersToQuery(eltexColumnFilters))) {
          params.set(`f.${key}`, value)
        }
      }
      const base = `/devices/${device.id}/calls?${params.toString()}`
      return pageCursor
        ? `${base}&before=${encodeURIComponent(pageCursor.before)}&before_id=${encodeURIComponent(pageCursor.beforeId)}`
        : base
    }
    if (dataset === 'antifraud') {
      const params = new URLSearchParams()
      params.set('date', date)
      params.set('limit', String(PAGE_SIZE))
      for (const [key, value] of Object.entries(antifraudFiltersToQuery(antifraudColumnFilters))) {
        params.set(`f.${key}`, value)
      }
      const base = `/devices/${device.id}/antifraud-calls?${params.toString()}`
      return pageCursor
        ? `${base}&before=${encodeURIComponent(pageCursor.before)}&before_id=${encodeURIComponent(pageCursor.beforeId)}`
        : base
    }
    // Full day feed by default; hide-stream + find uses list q= (matches only).
    // Find navigation uses /syslog-messages/find + jump (from/from_id) when stream is shown.
    const base = `/devices/${device.id}/syslog-messages?date=${date}&limit=${PAGE_SIZE}`
      + (syslogListQ ? `&q=${encodeURIComponent(syslogListQ)}` : '')
    return pageCursor
      ? `${base}&before=${encodeURIComponent(pageCursor.before)}&before_id=${encodeURIComponent(pageCursor.beforeId)}`
      : base
  }, [
    antifraudColumnFilters, columnFilters, dataset, date, device.id, eltexColumnFilters, isSatel,
    syslogListQ,
  ])
  const setBusy = useCallback((value: boolean) => {
    loadingRef.current = value
    setLoading(value)
  }, [])
  useEffect(() => {
    let active = true
    api<DeviceStats>(`/devices/${device.id}/stats?date=${date}`)
      .then((value) => { if (active) setStatsResult({ date, value }) })
      .catch(() => { if (active) setStatsResult({ date, value: null }) })
    return () => { active = false }
  }, [date, device.id])
  const cursorGenerationRef = useRef(0)
  const setSyslogFindBusyState = useCallback((value: boolean) => {
    syslogFindBusyRef.current = value
    setSyslogFindBusy(value)
  }, [])
  const setSyslogFindHitState = useCallback((
    hit: { eventId: string; receivedAt: string } | null,
  ) => {
    syslogFindHitRef.current = hit
    setSyslogFindHit(hit)
  }, [])
  const setSyslogFindIndexState = useCallback((index: number) => {
    syslogFindIndexRef.current = index
    setSyslogFindIndex(index)
  }, [])
  const setSyslogFindTotalState = useCallback((total: number) => {
    syslogFindTotalRef.current = total
    setSyslogFindTotal(total)
  }, [])
  useEffect(() => {
    const generation = ++generationRef.current
    // Invalidate any in-flight pagination cursor for the previous filter set.
    cursorGenerationRef.current = 0
    feedEpochRef.current += 1
    let active = true
    const timer = window.setTimeout(() => {
      const epoch = ++feedEpochRef.current
      feedRef.current = { rows: [], cursor: null, hasMore: false, hasNewer: false }
      setRows([])
      setHasMore(false)
      setHasNewer(false)
      setSelectedEvent(null)
      setSelectedCall(null)
      setSelectedSatelCall(null)
      setSelectedAntifraud(null)
      setLoadError('')
      if (tableShellRef.current) tableShellRef.current.scrollTop = 0
      setBusy(true)
      api<PageResponse<DataRow>>(pagePath())
        .then(({ items, hasMore: more, nextCursor }) => {
          // Honor feedEpoch so a Find jump cannot be overwritten by a stale day page.
          if (!active || generation !== generationRef.current || epoch !== feedEpochRef.current) {
            return
          }
          const nextRows = items || []
          feedRef.current = {
            rows: nextRows, cursor: nextCursor || null, hasMore: more, hasNewer: false,
          }
          setRows(nextRows)
          setHasMore(more)
          setHasNewer(false)
          cursorGenerationRef.current = generation
        })
        .catch((reason) => {
          if (
            active && generation === generationRef.current && epoch === feedEpochRef.current
          ) {
            setLoadError(reason instanceof Error ? reason.message : 'Не удалось загрузить данные')
          }
        })
        .finally(() => {
          if (
            active && generation === generationRef.current && epoch === feedEpochRef.current
          ) {
            setBusy(false)
          }
        })
    }, 250)
    return () => {
      active = false
      window.clearTimeout(timer)
    }
  }, [pagePath, reload, setBusy])
  const loadMore = useCallback(async (): Promise<boolean> => {
    const feed = feedRef.current
    if (!feed.cursor || !feed.hasMore || loadingRef.current) return false
    const generation = cursorGenerationRef.current
    if (!generation || generation !== generationRef.current) return false
    const epoch = feedEpochRef.current
    const cursorBefore = feed.cursor.before
    const cursorBeforeId = feed.cursor.beforeId
    setBusy(true)
    try {
      const { items, hasMore: more, nextCursor } = await api<PageResponse<DataRow>>(
        pagePath(feed.cursor),
      )
      if (generation !== generationRef.current || epoch !== feedEpochRef.current) return false
      const live = feedRef.current
      if (!live.cursor
        || live.cursor.before !== cursorBefore
        || live.cursor.beforeId !== cursorBeforeId) {
        return false
      }
      const nextRows = [...live.rows, ...(items || [])]
      feedRef.current = {
        rows: nextRows, cursor: nextCursor || null, hasMore: more, hasNewer: live.hasNewer,
      }
      setRows(nextRows)
      setHasMore(more)
      cursorGenerationRef.current = generation
      return Boolean(items?.length)
    } catch (reason) {
      if (generation === generationRef.current && epoch === feedEpochRef.current) {
        setLoadError(reason instanceof Error ? reason.message : 'Не удалось загрузить данные')
      }
      return false
    } finally {
      if (generation === generationRef.current) setBusy(false)
    }
  }, [pagePath, setBusy])
  const loadNewer = useCallback(async (): Promise<boolean> => {
    if (dataset !== 'syslog') return false
    const feed = feedRef.current
    const top = (feed.rows as EventRow[])[0]
    if (!top || !feed.hasNewer || loadingRef.current) return false
    const generation = cursorGenerationRef.current
    if (!generation || generation !== generationRef.current) return false
    const epoch = feedEpochRef.current
    const topEventId = top.eventId
    const topReceivedAt = top.receivedAt
    const shell = tableShellRef.current
    const prevHeight = shell?.scrollHeight || 0
    const prevTop = shell?.scrollTop || 0
    setBusy(true)
    try {
      const path = `/devices/${device.id}/syslog-messages?date=${encodeURIComponent(date)}`
        + `&limit=${PAGE_SIZE}&after=${encodeURIComponent(topReceivedAt)}`
        + `&after_id=${encodeURIComponent(topEventId)}`
        + (syslogListQ ? `&q=${encodeURIComponent(syslogListQ)}` : '')
      const { items, hasNewer: moreNewer } = await api<PageResponse<DataRow>>(path)
      if (generation !== generationRef.current || epoch !== feedEpochRef.current) return false
      const live = feedRef.current
      const liveTop = (live.rows as EventRow[])[0]
      if (!liveTop || liveTop.eventId !== topEventId) return false
      const prepend = items || []
      if (!prepend.length) {
        feedRef.current = { ...live, hasNewer: false }
        setHasNewer(false)
        return false
      }
      const nextRows = [...prepend, ...live.rows]
      feedRef.current = {
        rows: nextRows, cursor: live.cursor, hasMore: live.hasMore,
        hasNewer: Boolean(moreNewer),
      }
      setRows(nextRows)
      setHasNewer(Boolean(moreNewer))
      cursorGenerationRef.current = generation
      requestAnimationFrame(() => {
        if (syslogFindBusyRef.current) return
        const el = tableShellRef.current
        if (!el) return
        el.scrollTop = prevTop + (el.scrollHeight - prevHeight)
      })
      return true
    } catch (reason) {
      if (generation === generationRef.current && epoch === feedEpochRef.current) {
        setLoadError(reason instanceof Error ? reason.message : 'Не удалось загрузить данные')
      }
      return false
    } finally {
      if (generation === generationRef.current) setBusy(false)
    }
  }, [dataset, date, device.id, setBusy, syslogListQ])
  useEffect(() => {
    const root = tableShellRef.current
    const target = sentinelRef.current
    if (!root || !target || !hasMore) return
    const observer = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting && !syslogFindBusyRef.current) void loadMore()
    }, { root, rootMargin: '240px 0px', threshold: 0 })
    observer.observe(target)
    return () => observer.disconnect()
  }, [hasMore, loadMore])
  useEffect(() => {
    const root = tableShellRef.current
    const target = topSentinelRef.current
    if (!root || !target || !hasNewer || dataset !== 'syslog') return
    const observer = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting && !syslogFindBusyRef.current) void loadNewer()
    }, { root, rootMargin: '120px 0px', threshold: 0 })
    observer.observe(target)
    return () => observer.disconnect()
  }, [dataset, hasNewer, loadNewer])
  const syslogFindTrim = syslogFind.trim()
  const syslogCommittedTrim = syslogCommittedFind.trim()
  const syslogHideFind = syslogHideStream && Boolean(syslogCommittedTrim)
  const syslogActiveEventId = syslogFindHit?.eventId || ''
  type SyslogMatchCursor = { eventId: string; receivedAt: string }
  type SyslogFindMatchesResponse = {
    items?: SyslogMatchCursor[]
    hasMore?: boolean
    nextCursor?: PageCursor | null
  }
  type SyslogFindResponse = {
    eventId?: string | null
    receivedAt?: string | null
    hasMore?: boolean
  }
  const resetSyslogMatchIndex = useCallback(() => {
    syslogMatchItemsRef.current = []
    syslogMatchHasMoreRef.current = false
    syslogMatchCursorRef.current = null
  }, [])
  const centerSyslogHit = useCallback(async (
    eventId: string,
    findGeneration: number,
  ): Promise<boolean> => {
    const root = tableShellRef.current
    if (!root) return false
    for (let i = 0; i < 45; i++) {
      if (findGeneration !== syslogFindGenerationRef.current) return false
      const target = root.querySelector(`[data-event-id="${CSS.escape(eventId)}"]`)
      if (target instanceof HTMLElement) {
        const rootRect = root.getBoundingClientRect()
        const targetRect = target.getBoundingClientRect()
        root.scrollTop += (targetRect.top + targetRect.height / 2)
          - (rootRect.top + rootRect.height / 2)
        const rootRect2 = root.getBoundingClientRect()
        const targetRect2 = target.getBoundingClientRect()
        root.scrollTop += (targetRect2.top + targetRect2.height / 2)
          - (rootRect2.top + rootRect2.height / 2)
        return true
      }
      await new Promise<void>((resolve) => {
        window.requestAnimationFrame(() => resolve())
      })
    }
    return false
  }, [])
  const jumpSyslogToHit = useCallback(async (
    hit: SyslogMatchCursor,
    findGeneration: number,
    needle = '',
  ) => {
    if (findGeneration !== syslogFindGenerationRef.current) return false
    if ((feedRef.current.rows as EventRow[]).some((row) => row.eventId === hit.eventId)) {
      return true
    }
    const epoch = ++feedEpochRef.current
    const generation = cursorGenerationRef.current || generationRef.current
    const tookBusy = !loadingRef.current
    if (tookBusy) setBusy(true)
    const loadFrom = async (withQ: boolean) => {
      const path = `/devices/${device.id}/syslog-messages?date=${encodeURIComponent(date)}`
        + `&limit=${PAGE_SIZE}&from=${encodeURIComponent(hit.receivedAt)}`
        + `&from_id=${encodeURIComponent(hit.eventId)}`
        + (withQ && needle ? `&q=${encodeURIComponent(needle)}` : '')
      return api<PageResponse<DataRow>>(path, { timeoutMs: 35000 })
    }
    try {
      let page = await loadFrom(false)
      if (findGeneration !== syslogFindGenerationRef.current || epoch !== feedEpochRef.current) {
        return false
      }
      let nextRows = page.items || []
      // Fallback: seek within q-matches if the full-day from-window missed the hit
      // (timestamp precision / replica lag) — still opens a scrollable window.
      if (!nextRows.some((row) => (row as EventRow).eventId === hit.eventId) && needle) {
        page = await loadFrom(true)
        if (findGeneration !== syslogFindGenerationRef.current || epoch !== feedEpochRef.current) {
          return false
        }
        nextRows = page.items || []
      }
      const more = page.hasMore
      const newer = page.hasNewer
      const nextCursor = page.nextCursor
      feedRef.current = {
        rows: nextRows, cursor: nextCursor || null, hasMore: more, hasNewer: Boolean(newer),
      }
      setRows(nextRows)
      setHasMore(more)
      setHasNewer(Boolean(newer))
      cursorGenerationRef.current = generation || generationRef.current
      return nextRows.some((row) => (row as EventRow).eventId === hit.eventId)
    } catch (reason) {
      if (findGeneration === syslogFindGenerationRef.current) {
        const message = reason instanceof Error ? reason.message : 'Не удалось загрузить данные'
        setLoadError(
          /abort|timeout|timed out/i.test(message)
            ? 'Не удалось открыть совпадение: таймаут загрузки окна ленты.'
            : message,
        )
      }
      return false
    } finally {
      if (tookBusy && findGeneration === syslogFindGenerationRef.current) setBusy(false)
    }
  }, [date, device.id, setBusy])
  const ensureSyslogHitInFilteredFeed = useCallback(async (
    hit: SyslogMatchCursor,
    findGeneration: number,
  ): Promise<boolean> => {
    const sleep = (ms: number) => new Promise((resolve) => window.setTimeout(resolve, ms))
    const hasHit = () => (feedRef.current.rows as EventRow[]).some((row) => row.eventId === hit.eventId)
    for (let wait = 0; wait < 80; wait++) {
      if (findGeneration !== syslogFindGenerationRef.current) return false
      if (hasHit()) return true
      if (loadingRef.current || !cursorGenerationRef.current) {
        await sleep(50)
        continue
      }
      break
    }
    for (let i = 0; i < 40; i++) {
      if (findGeneration !== syslogFindGenerationRef.current) return false
      if (hasHit()) return true
      if (feedRef.current.hasMore) {
        const advanced = await loadMore()
        if (!advanced) {
          await sleep(50)
          if (loadingRef.current) continue
          break
        }
        continue
      }
      break
    }
    return hasHit()
  }, [loadMore])
  const refreshSyslogFindCount = useCallback((needle: string, findGeneration: number) => {
    api<{ total?: number }>(
      `/devices/${device.id}/syslog-messages/find-count?date=${encodeURIComponent(date)}`
        + `&q=${encodeURIComponent(needle)}`,
      { timeoutMs: 35000 },
    ).then((body) => {
      if (findGeneration !== syslogFindGenerationRef.current) return
      setSyslogFindTotalState(Number(body.total) || 0)
    }).catch(() => { /* keep … */ })
  }, [date, device.id, setSyslogFindTotalState])
  const locateSyslogMatch = useCallback(async (
    hit: SyslogMatchCursor,
    index: number,
    findGeneration: number,
    hideMode: boolean,
  ): Promise<boolean> => {
    if (findGeneration !== syslogFindGenerationRef.current) return false
    const needle = syslogFindNeedleRef.current
    let located = hideMode
      ? await ensureSyslogHitInFilteredFeed(hit, findGeneration)
      : await jumpSyslogToHit(hit, findGeneration, needle)
    if (findGeneration !== syslogFindGenerationRef.current) return false
    if (!located) return false
    setSyslogFindHitState(hit)
    setSyslogFindIndexState(index)
    setSyslogFindError('')
    let centered = await centerSyslogHit(hit.eventId, findGeneration)
    if (findGeneration !== syslogFindGenerationRef.current) return false
    // Stale day-page responses used to steal the jump window; re-seek once if the
    // hit vanished from the feed before we could center it.
    if (!centered || !(feedRef.current.rows as EventRow[]).some((row) => row.eventId === hit.eventId)) {
      located = hideMode
        ? await ensureSyslogHitInFilteredFeed(hit, findGeneration)
        : await jumpSyslogToHit(hit, findGeneration, needle)
      if (findGeneration !== syslogFindGenerationRef.current || !located) return false
      centered = await centerSyslogHit(hit.eventId, findGeneration)
    }
    return findGeneration === syslogFindGenerationRef.current && Boolean(centered || located)
  }, [
    centerSyslogHit, ensureSyslogHitInFilteredFeed, jumpSyslogToHit,
    setSyslogFindHitState, setSyslogFindIndexState,
  ])
  const locateSyslogMatchRef = useRef(locateSyslogMatch)
  useEffect(() => {
    locateSyslogMatchRef.current = locateSyslogMatch
  }, [locateSyslogMatch])
  const fetchSyslogMatchPage = useCallback(async (
    needle: string,
    before?: PageCursor | null,
  ): Promise<SyslogFindMatchesResponse> => {
    const params = new URLSearchParams()
    params.set('date', date)
    params.set('q', needle)
    params.set('limit', '50')
    if (before?.before && before.beforeId) {
      params.set('before', before.before)
      params.set('before_id', before.beforeId)
    }
    return api<SyslogFindMatchesResponse>(
      `/devices/${device.id}/syslog-messages/find-matches?${params.toString()}`,
      { timeoutMs: 35000 },
    )
  }, [date, device.id])
  // Hide mode: match index = loaded q-feed rows.
  useEffect(() => {
    if (!syslogHideFind) return
    const items = (rows as EventRow[]).map((row) => ({
      eventId: row.eventId, receivedAt: row.receivedAt,
    }))
    syslogMatchItemsRef.current = items
    syslogMatchHasMoreRef.current = hasMore
    const last = items[items.length - 1]
    syslogMatchCursorRef.current = last
      ? { before: last.receivedAt, beforeId: last.eventId }
      : null
  }, [hasMore, rows, syslogHideFind])
  // Search runs only on committed needle (Найти / Enter), not while typing.
  useEffect(() => {
    if (dataset !== 'syslog') {
      syslogFindGenerationRef.current += 1
      return
    }
    const needle = syslogCommittedTrim
    const hideMode = syslogHideStream && Boolean(needle)
    syslogFindNeedleRef.current = needle
    const findGeneration = ++syslogFindGenerationRef.current
    resetSyslogMatchIndex()
    let cancelled = false
    // Defer setState out of the effect body (eslint react-hooks/set-state-in-effect).
    const resetTimer = window.setTimeout(() => {
      if (cancelled || findGeneration !== syslogFindGenerationRef.current) return
      setSyslogFindHitState(null)
      setSyslogFindIndexState(0)
      setSyslogFindTotalState(0)
      setSyslogFindError('')
      setSyslogFindBusyState(Boolean(needle))
    }, 0)
    if (!needle) {
      return () => {
        cancelled = true
        window.clearTimeout(resetTimer)
      }
    }
    const runTimer = window.setTimeout(() => {
      if (cancelled || findGeneration !== syslogFindGenerationRef.current) return
      const finishCount = () => {
        refreshSyslogFindCount(needle, findGeneration)
      }
      if (hideMode) {
        const waitFeed = async () => {
          for (let i = 0; i < 100; i++) {
            if (cancelled || findGeneration !== syslogFindGenerationRef.current) return
            if (!loadingRef.current && cursorGenerationRef.current) break
            await new Promise((resolve) => window.setTimeout(resolve, 50))
          }
          if (cancelled || findGeneration !== syslogFindGenerationRef.current) return
          const items = (feedRef.current.rows as EventRow[]).map((row) => ({
            eventId: row.eventId, receivedAt: row.receivedAt,
          }))
          syslogMatchItemsRef.current = items
          syslogMatchHasMoreRef.current = feedRef.current.hasMore
          const last = items[items.length - 1]
          syslogMatchCursorRef.current = last
            ? { before: last.receivedAt, beforeId: last.eventId }
            : null
          if (!items[0]) {
            setSyslogFindHitState(null)
            setSyslogFindIndexState(0)
            setSyslogFindTotalState(0)
            setSyslogFindBusyState(false)
            return
          }
          const ok = await locateSyslogMatchRef.current(
            items[0], 1, findGeneration, true,
          )
          if (findGeneration === syslogFindGenerationRef.current) {
            setSyslogFindBusyState(false)
            if (ok) finishCount()
            else setSyslogFindError(SYSLOG_FIND_LOCATE_ERROR)
          }
        }
        void waitFeed()
        return
      }
      fetchSyslogMatchPage(needle).then(async (body) => {
        if (cancelled || findGeneration !== syslogFindGenerationRef.current) return
        const items = body.items || []
        syslogMatchItemsRef.current = items
        syslogMatchHasMoreRef.current = Boolean(body.hasMore)
        syslogMatchCursorRef.current = body.nextCursor || null
        if (!items[0]) {
          setSyslogFindHitState(null)
          setSyslogFindIndexState(0)
          setSyslogFindTotalState(0)
          setSyslogFindError('')
          return
        }
        const ok = await locateSyslogMatchRef.current(
          items[0], 1, findGeneration, false,
        )
        if (findGeneration !== syslogFindGenerationRef.current) return
        if (!ok) {
          setSyslogFindError(SYSLOG_FIND_LOCATE_ERROR)
          return
        }
        finishCount()
      }).catch((reason) => {
        if (cancelled || findGeneration !== syslogFindGenerationRef.current) return
        setSyslogFindHitState(null)
        setSyslogFindIndexState(0)
        setSyslogFindTotalState(0)
        const message = reason instanceof Error ? reason.message : 'Ошибка поиска'
        setSyslogFindError(
          /abort|timeout|timed out/i.test(message)
            ? 'Поиск не уложился во время. Уточните запрос или включите «Скрывать поток».'
            : message,
        )
      }).finally(() => {
        if (findGeneration === syslogFindGenerationRef.current) {
          setSyslogFindBusyState(false)
        }
      })
    }, 0)
    return () => {
      cancelled = true
      window.clearTimeout(resetTimer)
      window.clearTimeout(runTimer)
    }
  }, [
    dataset, date, device.id, fetchSyslogMatchPage, refreshSyslogFindCount,
    resetSyslogMatchIndex, setSyslogFindBusyState, setSyslogFindHitState,
    setSyslogFindIndexState, setSyslogFindTotalState, syslogCommittedTrim,
    syslogHideStream, syslogSearchToken,
  ])
  const goSyslogFindAtIndex = useCallback(async (nextIndex: number) => {
    const findGeneration = syslogFindGenerationRef.current
    const items = syslogMatchItemsRef.current
    const hideMode = syslogHideStream && Boolean(syslogCommittedTrim)
    if (nextIndex < 1) return
    if (nextIndex <= items.length) {
      setSyslogFindBusyState(true)
      try {
        const ok = await locateSyslogMatchRef.current(
          items[nextIndex - 1], nextIndex, findGeneration, hideMode,
        )
        if (!ok && findGeneration === syslogFindGenerationRef.current) {
          setSyslogFindError(SYSLOG_FIND_LOCATE_ERROR)
        }
      } finally {
        if (findGeneration === syslogFindGenerationRef.current) setSyslogFindBusyState(false)
      }
      return
    }
    if (!syslogMatchHasMoreRef.current || hideMode) {
      if (hideMode && feedRef.current.hasMore) {
        setSyslogFindBusyState(true)
        try {
          while (
            syslogMatchItemsRef.current.length < nextIndex
            && feedRef.current.hasMore
            && findGeneration === syslogFindGenerationRef.current
          ) {
            const advanced = await loadMore()
            if (!advanced) break
            // Sync index from feed immediately (rows effect is async after render).
            const synced = (feedRef.current.rows as EventRow[]).map((row) => ({
              eventId: row.eventId, receivedAt: row.receivedAt,
            }))
            syslogMatchItemsRef.current = synced
            syslogMatchHasMoreRef.current = feedRef.current.hasMore
          }
          const updated = syslogMatchItemsRef.current
          if (nextIndex <= updated.length) {
            const ok = await locateSyslogMatchRef.current(
              updated[nextIndex - 1], nextIndex, findGeneration, true,
            )
            if (!ok && findGeneration === syslogFindGenerationRef.current) {
              setSyslogFindError(SYSLOG_FIND_LOCATE_ERROR)
            }
          }
        } finally {
          if (findGeneration === syslogFindGenerationRef.current) setSyslogFindBusyState(false)
        }
      }
      return
    }
    setSyslogFindBusyState(true)
    try {
      while (
        syslogMatchItemsRef.current.length < nextIndex
        && syslogMatchHasMoreRef.current
        && findGeneration === syslogFindGenerationRef.current
      ) {
        const page = await fetchSyslogMatchPage(
          syslogFindNeedleRef.current, syslogMatchCursorRef.current,
        )
        if (findGeneration !== syslogFindGenerationRef.current) return
        const more = page.items || []
        if (!more.length) {
          syslogMatchHasMoreRef.current = false
          break
        }
        syslogMatchItemsRef.current = [...syslogMatchItemsRef.current, ...more]
        syslogMatchHasMoreRef.current = Boolean(page.hasMore)
        syslogMatchCursorRef.current = page.nextCursor || null
      }
      const updated = syslogMatchItemsRef.current
      if (nextIndex <= updated.length) {
        const ok = await locateSyslogMatchRef.current(
          updated[nextIndex - 1], nextIndex, findGeneration, false,
        )
        if (!ok && findGeneration === syslogFindGenerationRef.current) {
          setSyslogFindError(SYSLOG_FIND_LOCATE_ERROR)
        }
      }
    } catch (reason) {
      if (findGeneration === syslogFindGenerationRef.current) {
        const message = reason instanceof Error ? reason.message : 'Ошибка поиска'
        setSyslogFindError(
          /abort|timeout|timed out/i.test(message)
            ? 'Поиск не уложился во время.'
            : message,
        )
      }
    } finally {
      if (findGeneration === syslogFindGenerationRef.current) setSyslogFindBusyState(false)
    }
  }, [
    fetchSyslogMatchPage, loadMore, setSyslogFindBusyState, syslogCommittedTrim,
    syslogHideStream,
  ])
  const submitSyslogFind = useCallback(() => {
    const needle = syslogFind.trim()
    if (!needle || syslogFindBusyRef.current) return
    setSyslogCommittedFind(needle)
    setSyslogSearchToken((value) => value + 1)
  }, [syslogFind])
  const goSyslogFindNext = () => {
    if (!syslogCommittedTrim || syslogFindBusyRef.current) return
    if (syslogFindNeedleRef.current !== syslogCommittedTrim) return
    const index = syslogFindIndexRef.current
    if (!syslogFindHitRef.current) {
      void goSyslogFindAtIndex(1)
      return
    }
    const nextIndex = index + 1
    const total = syslogFindTotalRef.current
    if (total && nextIndex > total) {
      void goSyslogFindAtIndex(1)
      return
    }
    if (
      nextIndex > syslogMatchItemsRef.current.length
      && !syslogMatchHasMoreRef.current
      && !(syslogHideFind && hasMore)
    ) {
      void goSyslogFindAtIndex(1)
      return
    }
    void goSyslogFindAtIndex(nextIndex)
  }
  const goSyslogFindPrev = () => {
    if (!syslogCommittedTrim || syslogFindBusyRef.current || !syslogFindHitRef.current) return
    if (syslogFindNeedleRef.current !== syslogCommittedTrim) return
    const index = syslogFindIndexRef.current
    if (index > 1) {
      void goSyslogFindAtIndex(index - 1)
      return
    }
    // Wrap to oldest match.
    const findGeneration = ++syslogFindGenerationRef.current
    setSyslogFindBusyState(true)
    api<SyslogFindResponse>(
      `/devices/${device.id}/syslog-messages/find?date=${encodeURIComponent(date)}`
        + `&q=${encodeURIComponent(syslogCommittedTrim)}&oldest=1`,
      { timeoutMs: 35000 },
    ).then(async (body) => {
      if (findGeneration !== syslogFindGenerationRef.current) return
      if (!body.eventId || !body.receivedAt) return
      const lastIndex = Math.max(1, syslogFindTotalRef.current || syslogMatchItemsRef.current.length)
      const ok = await locateSyslogMatchRef.current(
        { eventId: body.eventId, receivedAt: body.receivedAt },
        lastIndex,
        findGeneration,
        syslogHideFind,
      )
      if (!ok && findGeneration === syslogFindGenerationRef.current) {
        setSyslogFindError(SYSLOG_FIND_LOCATE_ERROR)
      } else if (ok) setSyslogFindError('')
    }).catch((reason) => {
      if (findGeneration !== syslogFindGenerationRef.current) return
      const message = reason instanceof Error ? reason.message : 'Ошибка поиска'
      setSyslogFindError(message)
    }).finally(() => {
      if (findGeneration === syslogFindGenerationRef.current) setSyslogFindBusyState(false)
    })
  }
  const clearSyslogFind = () => {
    syslogFindGenerationRef.current += 1
    feedEpochRef.current += 1
    syslogFindNeedleRef.current = ''
    resetSyslogMatchIndex()
    setSyslogFind('')
    setSyslogCommittedFind('')
    setSyslogFindHitState(null)
    setSyslogFindIndexState(0)
    setSyslogFindTotalState(0)
    setSyslogFindBusyState(false)
    setSyslogFindError('')
    setReload((value) => value + 1)
  }
  const showAntifraudEmpty = !loading && rows.length === 0 && dataset === 'antifraud'
  const revisionNotice = readModelNotice(device)
  return <section className="data-view">
    {revisionNotice && <div className="timezone-rebuild">{revisionNotice}</div>}
    {isSatel && dataset === 'calls' && <SatelPipelineNotice
      templateKey={device.templateKey}
      replay={device.replay || { pending: 0, processing: 0, complete: 0, quarantined: 0 }} />}
    {admin && dataset === 'calls' && <CdrIngestBannerLoader deviceID={device.id} />}
    <div className="stat-strip">
      <label className="stat-date"><small>Дата · {timezone}</small><input type="date"
        required value={date} onChange={(event) => {
          if (event.target.value) {
            window.sessionStorage.setItem(dateStorageKey, event.target.value)
            setColumnFilters({})
            setEltexColumnFilters({})
            setAntifraudColumnFilters({})
            setSyslogFindHit(null)
            setSyslogFindIndex(0)
            setSyslogFindTotal(0)
            setDate(event.target.value)
          }
        }} /></label>
      <span><small>Вызовов</small><strong>{stats ? stats.calls24h.toLocaleString('ru-RU') : '—'}</strong></span>
      <span><small>Неуспешных</small><strong>{stats ? stats.failedCalls24h.toLocaleString('ru-RU') : '—'}</strong></span>
      <span><small>Средняя длительность</small><strong>{stats ? formatDurationAverage(stats.averageTalkMs) : '—'}</strong></span>
      {!isSatel && <>
        <span><small>Syslog сообщений</small><strong>
          {stats ? stats.syslogMessages24h.toLocaleString('ru-RU') : '—'}
        </strong></span>
      </>}
    </div>
    {admin && <OperationalDiagnosticsPanel />}
    <div className="toolbar">
      <div><h3>{title}</h3><span>Загружено {rows.length} записей за {date}</span></div>
      <div className="toolbar-actions">
        {columnFiltersActive && <button type="button" className="secondary"
          disabled={!hasActiveColumnFilters}
          onClick={() => {
            if (satelColumnFiltersActive) setColumnFilters({})
            else if (eltexColumnFiltersActive) setEltexColumnFilters({})
            else setAntifraudColumnFilters({})
          }}>Сбросить фильтры</button>}
        {dataset === 'calls' && <label className="cdr-preset">
          <select value={activePresetId} onChange={(event) => {
            const next = event.target.value || defaultCdrPresetId()
            window.sessionStorage.setItem(presetStorageKey, next)
            setColumnFilters({})
            setEltexColumnFilters({})
            setColumnPresetId(next)
          }} aria-label="Пресет колонок">
            {vendorPresets.map((preset) =>
              <option key={preset.id} value={preset.id}>{preset.label}</option>)}
          </select>
        </label>}
        {dataset === 'syslog' ? <div className="search syslog-find">
          <Search size={14} />
          <input placeholder="Найти за сутки…" value={syslogFind}
            aria-label="Найти в Syslog"
            onChange={(event) => {
              setSyslogFind(event.target.value)
              setSyslogFindError('')
            }}
            onKeyDown={(event) => {
              if (event.key !== 'Enter') return
              event.preventDefault()
              const draft = syslogFind.trim()
              if (!draft) return
              if (event.shiftKey && syslogCommittedTrim && draft === syslogCommittedTrim
                && syslogFindHit) {
                goSyslogFindPrev()
                return
              }
              if (!event.shiftKey && syslogCommittedTrim && draft === syslogCommittedTrim
                && syslogFindHit) {
                goSyslogFindNext()
                return
              }
              submitSyslogFind()
            }} />
          <button type="button" className="syslog-find-submit"
            disabled={!syslogFindTrim || syslogFindBusy}
            title="Найти" aria-label="Найти"
            onClick={submitSyslogFind}>Найти</button>
          {syslogCommittedTrim ? <span className="syslog-find-count" aria-live="polite"
            title={syslogFindError || undefined}>
            {syslogFindBusy && !syslogFindHit ? '…'
              : syslogFindError && !syslogFindHit ? '!'
                : syslogFindHit
                  ? `${syslogFindIndex} / ${syslogFindTotal || '…'}`
                  : '0 / 0'}
          </span> : null}
          <button type="button" className="syslog-find-prev"
            disabled={!syslogCommittedTrim || syslogFindBusy || !syslogFindHit}
            title="Предыдущее совпадение" aria-label="Предыдущее совпадение"
            onClick={goSyslogFindPrev}><ChevronUp size={14} /></button>
          <button type="button" className="syslog-find-next"
            disabled={!syslogCommittedTrim || syslogFindBusy || !syslogFindHit}
            title="Следующее совпадение" aria-label="Следующее совпадение"
            onClick={goSyslogFindNext}><ChevronDown size={14} /></button>
          <button type="button" className="syslog-find-clear"
            disabled={!syslogFind && !syslogCommittedTrim}
            title="Сбросить поиск" aria-label="Сбросить поиск"
            onClick={clearSyslogFind}><X size={14} /></button>
        </div> : !columnFiltersActive && <div className="search"><Search size={14} />
          <input placeholder="Поиск по данным…" value={query}
            onChange={(event) => setQuery(event.target.value)} /></div>}
        {dataset === 'syslog' && <label className="syslog-hide-stream">
          <input type="checkbox" checked={syslogHideStream}
            onChange={(event) => {
              const next = event.target.checked
              window.sessionStorage.setItem(SYSLOG_HIDE_STREAM_STORAGE_KEY, next ? '1' : '0')
              setSyslogHideStream(next)
            }} />
          Скрывать поток
        </label>}
        {dataset === 'syslog' && <div className="view-toggle" role="group" aria-label="Вид Syslog">
          <button type="button" className={syslogViewMode === 'table' ? 'active' : ''}
            onClick={() => {
              window.sessionStorage.setItem(SYSLOG_VIEW_STORAGE_KEY, 'table')
              setSyslogViewMode('table')
            }}>Table</button>
          <button type="button" className={syslogViewMode === 'raw' ? 'active' : ''}
            onClick={() => {
              window.sessionStorage.setItem(SYSLOG_VIEW_STORAGE_KEY, 'raw')
              setSyslogViewMode('raw')
            }}>Raw</button>
        </div>}
        <ExportButton key={`${dataset}:${date}:${dataset === 'syslog' ? (syslogHideStream ? syslogCommittedFind : '') : query}:${filtersKeyFrom(exportColumnFilters)}`}
          deviceID={device.id} dataset={dataset}
          query={columnFiltersActive ? ''
            : dataset === 'syslog' ? (syslogHideStream ? syslogCommittedFind : '')
              : query}
          date={date}
          filters={exportColumnFilters} />
      </div>
    </div>
    {dataset === 'syslog' && syslogFindError ? <div className="syslog-find-error" role="alert">
      {syslogFindError}</div> : null}
    <div className="table-shell" ref={tableShellRef}>
      {loading && <div className="table-loading" />}
      {loadError && <div className="table-empty" role="alert"><strong>Не удалось загрузить данные</strong>
        <p>{loadError}</p><button className="secondary" onClick={() => setReload((value) => value + 1)}>
          Повторить</button></div>}
      {dataset === 'syslog' && <div className="scroll-sentinel scroll-sentinel-top" ref={topSentinelRef}>
        {loading && hasNewer ? 'Загрузка более свежих…' : ''}
      </div>}
      {dataset === 'calls' ? (isSatel
        ? <SatelCallsTable rows={rows as SatelCdrRow[]}
          columns={resolvePresetColumns('satel', activePresetId)}
          fillWidth={satelPresetFillWidth(activePresetId)}
          flexShare={satelPresetFlexShare(activePresetId)}
          columnFilter={satelColumnFiltersActive ? {
            deviceId: device.id,
            date,
            presetId: activePresetId,
            filters: columnFilters,
            onChange: (key, value) => setColumnFilters((current) => {
              const next = { ...current }
              if (!value.trim()) delete next[key]
              else next[key] = value.trim()
              return next
            }),
          } : undefined}
          timezone={activeDeviceTimezone(device)} onSelect={setSelectedSatelCall} />
        : <CallsTable rows={rows as CallRow[]}
          columns={resolvePresetColumns('eltex', activePresetId)}
          fillWidth={activePresetId === 'summary'}
          flexShare={eltexPresetFlexShare(activePresetId)}
          columnFilter={eltexColumnFiltersActive ? {
            deviceId: device.id,
            date,
            filters: eltexColumnFilters,
            onChange: (key, value) => setEltexColumnFilters((current) => {
              const next = { ...current }
              if (!value.trim()) delete next[key]
              else next[key] = value.trim()
              return next
            }),
          } : undefined}
          timezone={activeDeviceTimezone(device)} onSelect={setSelectedCall} />) :
        dataset === 'antifraud'
          ? <AntifraudTable rows={rows as AntifraudRow[]} timezone={activeDeviceTimezone(device)}
            columnFilter={antifraudFiltersActive ? {
              deviceId: device.id,
              date,
              filters: antifraudColumnFilters,
              onChange: (key, value) => setAntifraudColumnFilters((current) => {
                const next = { ...current }
                if (!value.trim()) delete next[key]
                else next[key] = value.trim()
                return next
              }),
            } : undefined}
            onSelect={setSelectedAntifraud} />
          : syslogViewMode === 'raw'
            ? <EventsRawLog rows={rows as EventRow[]} find={syslogCommittedTrim}
              activeEventId={syslogActiveEventId} onSelect={setSelectedEvent} />
            : <EventsTable rows={rows as EventRow[]} timezone={activeDeviceTimezone(device)}
              find={syslogCommittedTrim} activeEventId={syslogActiveEventId}
              onSelect={setSelectedEvent} />}
      {showAntifraudEmpty && <AntifraudEmptyState />}
      <div className="scroll-sentinel" ref={sentinelRef}>
        {loading && rows.length > 0 ? 'Загрузка следующих 100 записей…' : hasMore ? '' : rows.length > 0 ? 'Все записи загружены' : ''}
      </div>
    </div>
    {selectedCall && <CallDrawer key={selectedCall.recordId} device={device} call={selectedCall}
      onClose={() => setSelectedCall(null)} />}
    {selectedSatelCall && <SatelCallDrawer call={selectedSatelCall}
      timezone={activeDeviceTimezone(device)} onClose={() => setSelectedSatelCall(null)} />}
    {selectedAntifraud && <AntifraudDrawer device={device} row={selectedAntifraud}
      onClose={() => setSelectedAntifraud(null)} />}
    {selectedEvent && <EventDrawer event={selectedEvent} timezone={activeDeviceTimezone(device)}
      onClose={() => setSelectedEvent(null)} />}
  </section>
}

function CdrIngestBannerLoader({ deviceID }: { deviceID: string }) {
  const [files, setFiles] = useState<CdrIngestFile[] | null>(null)
  useEffect(() => {
    let active = true
    api<{ items: CdrIngestFile[] }>(`/devices/${deviceID}/ingest-files?limit=20`)
      .then(({ items }) => { if (active) setFiles(items || []) })
      .catch(() => { if (active) setFiles([]) })
    return () => { active = false }
  }, [deviceID])
  if (!files) return null
  return <CdrIngestBanner files={files} />
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

function OperationalDiagnosticsPanel() {
  const [value, setValue] = useState<OperationalDiagnostics | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [requeueBusy, setRequeueBusy] = useState('')
  const load = () => {
    setLoading(true)
    setError('')
    api<OperationalDiagnostics>('/system/diagnostics')
      .then((next) => setValue(next))
      .catch((reason) => {
        setValue(null)
        setError(reason instanceof Error ? reason.message : 'Диагностика недоступна')
      })
      .finally(() => setLoading(false))
  }
  const requeueFailed = async (deviceId: string) => {
    setRequeueBusy(deviceId)
    setError('')
    try {
      await api(`/devices/${deviceId}/projection/requeue-failed`, { method: 'POST', body: '{}' })
      load()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Не удалось перепоставить failed jobs')
    } finally {
      setRequeueBusy('')
    }
  }
  const queue = value?.projectionQueue
  const derived = value?.derived
  const coverage = derived?.coverage || {}
  const devices = value?.projectionDevices || []
  return <details className="diagnostic-panel" onToggle={(event) => {
    if ((event.currentTarget as HTMLDetailsElement).open) load()
  }}>
    <summary>Диагностика</summary>
    {loading && <div className="diagnostic-facts"><span>Загрузка операционной диагностики…</span></div>}
    {error && <div className="diagnostic-facts"><span className="form-error">{error}</span></div>}
    {value && !loading && <div className="diagnostic-facts">
      <span>Custom projection: <strong>{value.customProjectionEnabled ? 'включена' : 'выключена'}</strong></span>
      <span>Очередь projection · depth / live health lag: <strong>
        {formatCount(queue?.depth)} / {formatCount(queue?.maxDeviceLagSeconds ?? derived?.maxDeviceProjectionLagSeconds)} с
      </strong></span>
      <span>Очередь projection · max event tip lag: <strong>
        {formatCount(queue?.maxEventTipLagSeconds)} с
      </strong></span>
      <span>Очередь projection · global activated lag: <strong>
        {formatCount(queue?.lagSeconds ?? derived?.projectionLagSeconds)} с
      </strong></span>
      <span>Очередь projection · failed / backfill: <strong>
        {formatCount(queue?.failed)} / {formatCount(queue?.backfilling)}
      </strong></span>
      <span>Очередь projection · catch-up oldest bucket / discover: <strong>
        {formatDurationNanos(queue?.oldestBucketAge ?? queue?.oldestAge)} /
        {formatDurationNanos(queue?.discoverAge)}
      </strong></span>
      <span>SLO projection / coverage: <strong>
        {derived?.projectionSloMet ? 'ok' : 'breach'} / {derived?.coverageSloMet ? 'ok' : 'breach'}
      </strong></span>
      <span>Classification gap / device failed: <strong>
        {derived?.anyClassificationGap || queue?.anyClassificationGap ? 'yes' : 'no'} /
        {derived?.anyDeviceFailed || queue?.anyDeviceFailed ? 'yes' : 'no'}
      </strong></span>
      <span>Calls / packets: <strong>{formatCount(derived?.calls)} / {formatCount(derived?.packets)}</strong></span>
      <span>Orphans / ambiguity: <strong>
        {formatCount(derived?.orphans)} / {formatCount(derived?.ambiguity)}
      </strong></span>
      <span>Coverage matched / expected / late / missing: <strong>
        {formatCount(coverage.matched)} / {formatCount(coverage.expected)} /
        {formatCount(coverage.late)} / {formatCount(coverage.missing)}
      </strong></span>
      <span>Coverage ambiguous / n/a: <strong>
        {formatCount(coverage.ambiguous)} / {formatCount(coverage.not_applicable)}
      </strong></span>
      <span>Reconciliation · depth / failed / oldest: <strong>
        {formatCount(value.reconciliationQueue?.depth)} / {formatCount(value.reconciliationQueue?.failed)} /
        {formatDurationNanos(value.reconciliationQueue?.oldestAge)}
      </strong></span>
      <span>Export · queued / running / oldest: <strong>
        {formatCount(value.exports?.queued)} / {formatCount(value.exports?.running)} /
        {formatDurationNanos(value.exports?.oldestAge)}
      </strong></span>
      {(['pstn', 'geoip'] as const).map((name) => {
        const api = value.enrichmentApis?.[name]
        const label = name === 'pstn' ? 'PSTN lookup' : 'GeoIP lookup'
        return <span key={name}>{label}: <strong>
          {api?.enabled ? (api.healthy ? 'ok' : 'breach') : 'off'}
          {api?.configured ? '' : ' · no token'} ·
          lookups {formatCount(api?.lookups)} ·
          cache {formatCount(api?.cacheHits)} ·
          errors {formatCount(api?.errors)} ·
          p95 {formatCount(api?.p95LatencyMs)} мс
          {api?.lastError ? ` · ${api.lastError}` : ''}
        </strong></span>
      })}
      {value.enrichmentCoverage && <span>Enrichment coverage 24h · PSTN / GeoIP: <strong>
        {formatPercentRatio(value.enrichmentCoverage.pstnCoverage)}
        ({formatCount(value.enrichmentCoverage.pstnEnriched)}/
        {formatCount(value.enrichmentCoverage.pstnEligible)}) /
        {formatPercentRatio(value.enrichmentCoverage.geoipCoverage)}
        ({formatCount(value.enrichmentCoverage.geoipEnriched)}/
        {formatCount(value.enrichmentCoverage.geoipEligible)})
      </strong></span>}
      {value.enrichmentCoverage && <span>Enrichment backlog / workers / catch-up: <strong>
        {formatCount(value.enrichmentCoverage.backlog)} /
        {formatCount(value.enrichmentWorkers)} /
        {value.enrichmentCatchUp ? 'on' : 'off'}
      </strong></span>}
      <span>Снимок: <strong>{formatTime(value.generatedAt, 'UTC')}</strong></span>
      {devices.length > 0 && <div className="diagnostic-device-list">
        <strong>Projection по устройствам</strong>
        {devices.map((device) => <span key={device.deviceId}>
          {device.name}: live health {formatCount(device.healthLagSeconds ?? device.projectionLagSeconds)} с ·
          content {formatCount(device.contentLagSeconds)} с ·
          buckets {formatCount(device.bucketDepth ?? 0)}/{formatCount(device.depth)} ·
          AF tip {formatCount(device.afCallLagSeconds)} с ·
          AF syslog {formatCount(device.afSyslogLagSeconds)} с ·
          activated {formatCount(device.activatedLagSeconds)} с ·
          open-hour {device.openHourStatus || 'idle'}
          {device.openHourAgeSeconds ? ` ${formatCount(device.openHourAgeSeconds)} с` : ''} ·
          catch-up {formatDurationNanos(device.oldestBucketAge ?? device.oldestAge)} ·
          failed {formatCount(device.failed)} ·
          SLO {device.projectionSloMet ? 'ok' : 'breach'}
          {device.classificationGap ? ' · classification gap' : ''}
          {device.lastError ? ` · ${device.lastError}` : ''}
          {(device.failed || 0) > 0 && <button type="button" className="secondary"
            disabled={requeueBusy === device.deviceId}
            onClick={(event) => {
              event.preventDefault()
              event.stopPropagation()
              void requeueFailed(device.deviceId)
            }}>
            {requeueBusy === device.deviceId ? 'Requeue…' : 'Requeue failed'}
          </button>}
        </span>)}
      </div>}
    </div>}
  </details>
}

function AntifraudEmptyState() {
  return <div className="table-empty">
    <strong>Вызовы AntiFraud пока не собраны</strong>
    <p>Здесь появится одна строка на вызов Custom AntiFraud после фоновой проекции Syslog.</p>
  </div>
}

function AntifraudTable({ rows, timezone, onSelect, columnFilter }: {
  rows: AntifraudRow[]
  timezone: string
  onSelect: (row: AntifraudRow) => void
  columnFilter?: {
    deviceId: string
    date: string
    filters: AntifraudColumnFilters
    onChange: (key: AntifraudFilterKey, value: string) => void
  }
}) {
  const peerQuery = columnFilter ? antifraudFiltersToQuery(columnFilter.filters) : {}
  const headerFilter = (key: AntifraudFilterKey) => {
    if (!columnFilter) return null
    const filterDef = ANTIFRAUD_FILTER_BY_KEY[key]
    return <SummaryColumnHeaderFilter
      key={`${filterDef.key}:${columnFilter.date}:${columnFilter.filters[filterDef.key] || ''}`}
      deviceId={columnFilter.deviceId}
      date={columnFilter.date}
      column={filterDef.column}
      label={filterDef.header}
      value={columnFilter.filters[filterDef.key] || ''}
      peerFilters={peerQuery}
      valuesPath="antifraud-calls/column-values"
      formatOptionLabel={(value) => antifraudFilterDisplayLabel(filterDef.column, value)}
      onChange={(value) => columnFilter.onChange(filterDef.key, value)} />
  }
  return <table className="antifraud-table table-fit"><thead><tr>
    <th>Начало</th>
    {columnFilter ? headerFilter('calling') : <th>Номер A</th>}
    {columnFilter ? headerFilter('called') : <th>Номер B</th>}
    {columnFilter ? headerFilter('phases') : <th>Фазы</th>}
    {columnFilter ? headerFilter('chain') : <th>Цепочка</th>}
    {columnFilter ? headerFilter('radius_outcome') : <th>Статус</th>}
    <th>Пакеты</th>
    {columnFilter ? headerFilter('coverage') : <th>Покрытие CDR</th>}
    <th className="col-flex-pair">Acct-Session-Id</th>
    <th className="col-flex-pair">H323 Conf ID</th>
  </tr></thead><tbody>{rows.map((row) => <tr key={row.callId}
    onClick={() => onSelect(row)}>
    <td className="mono">{formatTime(row.firstSeenAt, timezone)}</td>
    <td className="mono">{row.calling || '—'}</td>
    <td className="mono">{row.called || '—'}</td>
    <td>{row.phases?.join(' → ') || '—'}</td>
    <td><ChainCompletenessBadge value={row.chainCompleteness} /></td>
    <td><RadiusOutcomeBadge outcome={row.radiusOutcome} lifecycle={row.status} /></td>
    <td className="right">{row.packetCount}</td>
    <td><CoverageBadge coverage={row.coverage} /></td>
    <td className="mono col-flex-pair">{row.acctSessionId || '—'}</td>
    <td className="mono col-flex-pair">{row.h323ConfId || '—'}</td>
  </tr>)}</tbody></table>
}

function AntifraudDrawer({ device, row, onClose }: {
  device: Device
  row: AntifraudRow
  onClose: () => void
}) {
  return <SharedCallCard device={device} callID={row.callId} onClose={onClose} />
}

function emptyCell(value: unknown): string {
  if (value == null || value === '') return '—'
  return String(value)
}

function VoipmonitorLink({ url, label }: { url?: string; label?: string }) {
  if (!url) return '—'
  return <a href={url} target="_blank" rel="noreferrer"
    onClick={(event) => event.stopPropagation()}>{label || 'открыть'}</a>
}

function eltexCallCell(row: CallRow, column: CdrColumnDef, timezone: string): ReactNode {
  switch (column.key) {
    case 'setupTime':
      return formatTime(row.setupTime, timezone)
    case 'connectTime':
      return formatTime(row.connectTime, timezone)
    case 'disconnectTime':
      return formatTime(row.disconnectTime, timezone)
    case 'durationMs':
      return formatDurationSeconds(row.durationMs)
    case 'releaseInfo':
      return <>
        <span className={`outcome-badge ${cdrOutcome(row.releaseCause)}`}>
          {outcomeLabel(cdrOutcome(row.releaseCause))}
        </span>{' '}{row.releaseInfo || '—'}
      </>
    case 'voipmonitorCardUrl':
      return <VoipmonitorLink url={row.voipmonitorCardUrl} label={row.voipmonitorCdrId} />
    default:
      return emptyCell((row as unknown as Record<string, unknown>)[column.key])
  }
}

function CallsTable({ rows, columns, timezone, onSelect, fillWidth, flexShare, columnFilter }: {
  rows: CallRow[]
  columns: CdrColumnDef[]
  timezone: string
  onSelect: (row: CallRow) => void
  fillWidth?: boolean
  flexShare?: { keys: string[]; className: string }
  columnFilter?: {
    deviceId: string
    date: string
    filters: EltexColumnFilters
    onChange: (key: EltexFilterKey, value: string) => void
  }
}) {
  const shareKeys = new Set(fillWidth ? flexShare?.keys || [] : [])
  const shareClass = fillWidth ? flexShare?.className || '' : ''
  const columnClass = (key: string) => shareKeys.has(key) ? shareClass : undefined
  const peerQuery = columnFilter ? eltexFiltersToQuery(columnFilter.filters) : {}
  return <table className={['eltex-cdr-table', fillWidth ? 'table-fit' : ''].filter(Boolean).join(' ')}>
    <thead><tr>
    {columns.map((column) => {
      const filterKey = column.key as EltexFilterKey
      const filterDef = columnFilter && ELTEX_FILTER_KEY_SET.has(filterKey)
        ? ELTEX_FILTER_BY_KEY[filterKey]
        : undefined
      if (columnFilter && filterDef) {
        return <SummaryColumnHeaderFilter
          key={`${filterDef.key}:${columnFilter.date}:${columnFilter.filters[filterDef.key] || ''}`}
          deviceId={columnFilter.deviceId}
          date={columnFilter.date}
          column={filterDef.column}
          label={filterDef.header}
          value={columnFilter.filters[filterDef.key] || ''}
          peerFilters={peerQuery}
          className={columnClass(column.key)}
          onChange={(value) => columnFilter.onChange(filterDef.key, value)} />
      }
      return <th key={column.key} title={column.header}
        className={columnClass(column.key)}>{column.header}</th>
    })}
  </tr></thead><tbody>{rows.map((row) => <tr key={row.recordId}
    className={`outcome-row outcome-${cdrOutcome(row.releaseCause)}`}
    onClick={() => onSelect(row)}>
    {columns.map((column) => <td key={column.key}
      className={[
        column.mono ? 'mono' : '',
        column.align === 'right' ? 'right' : '',
        columnClass(column.key) || '',
      ].filter(Boolean).join(' ') || undefined}>
      {eltexCallCell(row, column, timezone)}
    </td>)}
  </tr>)}</tbody></table>
}

function satelCallOutcome(row: SatelCdrRow): 'success' | 'failure' | 'warning' {
  if (row.connectTime) return 'success'
  const outcome = (row.outcome || '').toLowerCase()
  if (['answered', 'answer', 'connected', 'success', 'completed'].includes(outcome)) return 'success'
  if (outcome || row.disconnectTime) return 'failure'
  return 'warning'
}

const PSTN_NOT_FOUND = 'Не существует'
const PSTN_INELIGIBLE = '-'

function satelPstnRowTint(row: SatelCdrRow): 'pstn-absent' | 'pstn-ineligible' | null {
  const fields = [
    row.billAniOperator, row.billAniRegion, row.billDnisOperator, row.billDnisRegion,
  ]
  if (fields.some((value) => value === PSTN_NOT_FOUND)) return 'pstn-absent'
  if (fields.some((value) => value === PSTN_INELIGIBLE)) return 'pstn-ineligible'
  return null
}

function satelRowClassName(row: SatelCdrRow): string {
  const tint = satelPstnRowTint(row)
  if (tint) return `outcome-row ${tint}`
  return `outcome-row outcome-${satelCallOutcome(row)}`
}

function formatSatelProtocols(row: SatelCdrRow) {
  const configured = Array.isArray(row.protocols) ? row.protocols.join(' / ') : row.protocols
  return configured || [row.inLegProto, row.outLegProto].filter(Boolean).join(' → ') || '—'
}

function satelCallCell(row: SatelCdrRow, column: CdrColumnDef, timezone: string): ReactNode {
  switch (column.key) {
    case 'setupTime':
      return formatTime(row.setupTime, timezone)
    case 'connectTime':
      return formatTime(row.connectTime, timezone)
    case 'disconnectTime':
      return formatTime(row.disconnectTime, timezone)
    case 'termSetupTime':
      return formatTime(row.termSetupTime, timezone)
    case 'termConnectTime':
      return formatTime(row.termConnectTime, timezone)
    case 'termDisconnectTime':
      return formatTime(row.termDisconnectTime, timezone)
    case 'cdrDate':
      return formatTime(row.cdrDate, timezone)
    case 'durationMs':
      return formatDurationSeconds(row.durationMs)
    case 'outcome': {
      const outcome = satelCallOutcome(row)
      return <span className={`outcome-badge ${outcome}`}>
        {row.outcome || (row.connectTime ? 'answered' : 'failed')}
      </span>
    }
    case 'protocols':
      return formatSatelProtocols(row)
    case 'signalNodeName':
      return emptyCell(row.signalNodeName || row.sigNodeName)
    case 'disconnectSuccess':
      return row.disconnectSuccess == null ? '—' : (row.disconnectSuccess ? 'да' : 'нет')
    case 'lastCdr':
      return row.lastCdr == null ? '—' : (row.lastCdr ? 'да' : 'нет')
    case 'voipmonitorCardUrl':
      return <VoipmonitorLink url={row.voipmonitorCardUrl} label={row.voipmonitorCdrId} />
    default:
      return emptyCell((row as unknown as Record<string, unknown>)[column.key])
  }
}

const SATEL_FILTER_COLUMNS = [
  { key: 'billAni', column: 'bill_ani', header: 'Bill ANI' },
  { key: 'billDnis', column: 'bill_dnis', header: 'Bill DNIS' },
  { key: 'outOrigDnis', column: 'out_orig_dnis', header: 'Out orig DNIS' },
  { key: 'srcName', column: 'src_name', header: 'Src маршрут' },
  { key: 'dstName', column: 'dst_name', header: 'Dst маршрут' },
  { key: 'dpName', column: 'dp_name', header: 'DP маршрут' },
  { key: 'disconnectText', column: 'disconnect_text', header: 'Разъединение' },
  { key: 'billAniOperator', column: 'bill_ani_operator', header: 'Оператор A' },
  { key: 'billAniRegion', column: 'bill_ani_region', header: 'Регион A' },
  { key: 'billDnisOperator', column: 'bill_dnis_operator', header: 'Оператор B' },
  { key: 'billDnisRegion', column: 'bill_dnis_region', header: 'Регион B' },
  { key: 'remoteSrcGeoipIso', column: 'remote_src_geoip_iso', header: 'GeoIP ISO A' },
  { key: 'remoteDstGeoipIso', column: 'remote_dst_geoip_iso', header: 'GeoIP ISO B' },
  { key: 'remoteSrcGeoipCity', column: 'remote_src_geoip_city', header: 'GeoIP City A' },
  { key: 'remoteSrcAsnOrg', column: 'remote_src_asn_org', header: 'ASN Org A' },
  { key: 'remoteDstGeoipCity', column: 'remote_dst_geoip_city', header: 'GeoIP City B' },
  { key: 'remoteDstAsnOrg', column: 'remote_dst_asn_org', header: 'ASN Org B' },
] as const

type SatelFilterKey = typeof SATEL_FILTER_COLUMNS[number]['key']
type SummaryColumnFilters = Partial<Record<SatelFilterKey, string>>

const SATEL_FILTER_BY_KEY = Object.fromEntries(
  SATEL_FILTER_COLUMNS.map((item) => [item.key, item]),
) as Record<SatelFilterKey, typeof SATEL_FILTER_COLUMNS[number]>

const SATEL_FILTER_KEYS_BY_PRESET: Record<string, ReadonlySet<SatelFilterKey>> = {
  summary: new Set<SatelFilterKey>([
    'billAni', 'billDnis', 'outOrigDnis', 'srcName', 'dstName', 'dpName', 'disconnectText',
  ]),
  operators: new Set<SatelFilterKey>([
    'billAni', 'billDnis', 'billAniOperator', 'billAniRegion',
    'billDnisOperator', 'billDnisRegion', 'disconnectText',
  ]),
  geoip: new Set<SatelFilterKey>([
    'billAni', 'billDnis', 'remoteSrcGeoipIso', 'remoteDstGeoipIso',
    'remoteSrcGeoipCity', 'remoteSrcAsnOrg', 'remoteDstGeoipCity', 'remoteDstAsnOrg',
    'disconnectText',
  ]),
  all: new Set<SatelFilterKey>([
    'billAni', 'billDnis', 'outOrigDnis', 'srcName', 'dstName', 'dpName',
    'billAniOperator', 'billDnisOperator', 'billAniRegion', 'billDnisRegion',
    'remoteSrcGeoipIso', 'remoteDstGeoipIso', 'remoteSrcGeoipCity', 'remoteDstGeoipCity',
    'remoteSrcAsnOrg', 'remoteDstAsnOrg', 'disconnectText',
  ]),
}

function satelFilterKeysForPreset(presetId: string): ReadonlySet<SatelFilterKey> {
  return SATEL_FILTER_KEYS_BY_PRESET[presetId] || SATEL_FILTER_KEYS_BY_PRESET.summary
}

function satelFiltersToQuery(filters: SummaryColumnFilters): Record<string, string> {
  const out: Record<string, string> = {}
  for (const item of SATEL_FILTER_COLUMNS) {
    const value = filters[item.key]?.trim()
    if (value) out[item.column] = value
  }
  return out
}

const ELTEX_FILTER_COLUMNS = [
  { key: 'outgoingCgpn', column: 'outgoing_cgpn', header: 'Номер A: выход' },
  { key: 'outgoingCdpn', column: 'outgoing_cdpn', header: 'Номер B: выход' },
  { key: 'outgoingRedirectingNumber', column: 'outgoing_redirecting_number', header: 'Redirecting выход' },
  { key: 'incomingDescription', column: 'incoming_description', header: 'Входящий маршрут' },
  { key: 'outgoingDescription', column: 'outgoing_description', header: 'Исходящий маршрут' },
  { key: 'releaseInfo', column: 'release_info', header: 'Результат' },
] as const

type EltexFilterKey = typeof ELTEX_FILTER_COLUMNS[number]['key']
type EltexColumnFilters = Partial<Record<EltexFilterKey, string>>

const ELTEX_FILTER_BY_KEY = Object.fromEntries(
  ELTEX_FILTER_COLUMNS.map((item) => [item.key, item]),
) as Record<EltexFilterKey, typeof ELTEX_FILTER_COLUMNS[number]>

const ELTEX_FILTER_KEY_SET = new Set<EltexFilterKey>(ELTEX_FILTER_COLUMNS.map((item) => item.key))

function eltexFiltersToQuery(filters: EltexColumnFilters): Record<string, string> {
  const out: Record<string, string> = {}
  for (const item of ELTEX_FILTER_COLUMNS) {
    const value = filters[item.key]?.trim()
    if (value) out[item.column] = value
  }
  return out
}

const ANTIFRAUD_FILTER_COLUMNS = [
  { key: 'calling', column: 'calling', header: 'Номер A' },
  { key: 'called', column: 'called', header: 'Номер B' },
  { key: 'phases', column: 'phases', header: 'Фазы' },
  { key: 'chain', column: 'chain', header: 'Цепочка' },
  { key: 'radius_outcome', column: 'radius_outcome', header: 'Статус' },
  { key: 'coverage', column: 'coverage', header: 'Покрытие CDR' },
] as const

type AntifraudFilterKey = typeof ANTIFRAUD_FILTER_COLUMNS[number]['key']
type AntifraudColumnFilters = Partial<Record<AntifraudFilterKey, string>>

const ANTIFRAUD_FILTER_BY_KEY = Object.fromEntries(
  ANTIFRAUD_FILTER_COLUMNS.map((item) => [item.key, item]),
) as Record<AntifraudFilterKey, typeof ANTIFRAUD_FILTER_COLUMNS[number]>

const ANTIFRAUD_FILTER_VALUE_LABELS: Record<string, Record<string, string>> = {
  chain: {
    complete: 'Полная',
    partial: 'Неполная',
    minimal: 'Минимальная',
  },
  radius_outcome: {
    accept: 'Accept',
    reject: 'Reject',
    no_response: 'Нет ответа',
  },
  coverage: {
    matched: 'Связан',
    ambiguous: 'Неоднозначно',
    awaiting_cdr: 'Ожидает CDR',
    expected: 'Ожидается CDR',
    late: 'CDR опаздывает',
    missing: 'CDR отсутствует',
  },
}

function antifraudFiltersToQuery(filters: AntifraudColumnFilters): Record<string, string> {
  const out: Record<string, string> = {}
  for (const item of ANTIFRAUD_FILTER_COLUMNS) {
    const value = filters[item.key]?.trim()
    if (value) out[item.column] = value
  }
  return out
}

function antifraudFilterDisplayLabel(column: string, value: string): string {
  return ANTIFRAUD_FILTER_VALUE_LABELS[column]?.[value] || value
}

function filtersKeyFrom(filters?: Record<string, string>): string {
  if (!filters || Object.keys(filters).length === 0) return ''
  return Object.keys(filters).sort().map((key) => `${key}=${filters[key]}`).join('&')
}

type SummaryColumnFilterProps = {
  deviceId: string
  date: string
  column: string
  label: string
  value: string
  peerFilters: Record<string, string>
  onChange: (value: string) => void
  valuesPath?: string
  formatOptionLabel?: (value: string) => string
  className?: string
}

type ColumnValueItem = { value: string; count: number }

function SummaryColumnHeaderFilter({
  deviceId, date, column, label, value, peerFilters, onChange,
  valuesPath = 'calls/column-values',
  formatOptionLabel,
  className,
}: SummaryColumnFilterProps) {
  const [search, setSearch] = useState('')
  const [open, setOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [suggestions, setSuggestions] = useState<ColumnValueItem[]>([])
  const [menuBox, setMenuBox] = useState({ top: 0, left: 0, width: 0 })
  const thRef = useRef<HTMLTableCellElement>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)
  const searchRef = useRef<HTMLInputElement>(null)
  const seqRef = useRef(0)
  const peerKey = filtersKeyFrom(peerFilters)
  const selected = value.trim()
  const hasSelection = selected !== ''

  const updateMenuBox = useCallback(() => {
    const el = triggerRef.current
    if (!el) return
    const rect = el.getBoundingClientRect()
    setMenuBox({
      top: rect.bottom + 2,
      left: rect.left,
      width: Math.max(rect.width, 200),
    })
  }, [])

  useLayoutEffect(() => {
    if (!open) return
    updateMenuBox()
    searchRef.current?.focus()
  }, [open, updateMenuBox])

  const closeMenu = useCallback(() => {
    setOpen(false)
    setSearch('')
  }, [])

  useEffect(() => {
    if (!open) return
    const onDoc = (event: MouseEvent) => {
      const target = event.target as Node
      if (thRef.current?.contains(target) || menuRef.current?.contains(target)) return
      closeMenu()
    }
    const onResize = () => closeMenu()
    const onScroll = (event: Event) => {
      const target = event.target
      if (target instanceof Node && menuRef.current?.contains(target)) return
      closeMenu()
    }
    document.addEventListener('mousedown', onDoc)
    window.addEventListener('resize', onResize)
    document.addEventListener('scroll', onScroll, true)
    return () => {
      document.removeEventListener('mousedown', onDoc)
      window.removeEventListener('resize', onResize)
      document.removeEventListener('scroll', onScroll, true)
    }
  }, [open, closeMenu])

  useEffect(() => {
    if (!open || !date) return
    const seq = ++seqRef.current
    const timer = window.setTimeout(() => {
      setLoading(true)
      setError('')
      const params = new URLSearchParams()
      params.set('column', column)
      params.set('date', date)
      params.set('q', search.trim())
      params.set('limit', '50')
      for (const [key, filterValue] of Object.entries(peerFilters)) {
        if (key === column || !filterValue) continue
        params.set(`f.${key}`, filterValue)
      }
      const path = `/devices/${deviceId}/${valuesPath}?${params.toString()}`
      api<{ items: ColumnValueItem[] }>(path).then((response) => {
        if (seq !== seqRef.current) return
        const items = Array.isArray(response.items) ? response.items : []
        setSuggestions(items.filter((item) => item && typeof item.value === 'string'))
        setLoading(false)
      }).catch((err: unknown) => {
        if (seq !== seqRef.current) return
        setSuggestions([])
        setError(err instanceof Error ? err.message : 'Не удалось загрузить значения')
        setLoading(false)
      })
    }, 200)
    return () => window.clearTimeout(timer)
  }, [open, deviceId, date, search, column, peerKey, peerFilters, valuesPath])

  const clear = () => {
    onChange('')
    closeMenu()
  }

  const pick = (nextValue: string) => {
    if (nextValue === selected) {
      clear()
      return
    }
    onChange(nextValue)
    closeMenu()
  }

  const menu = open ? createPortal(
    <div ref={menuRef} className="col-filter-menu" role="listbox"
      style={{ top: menuBox.top, left: menuBox.left, width: menuBox.width }}>
      <div className="col-filter-search">
        <input ref={searchRef} value={search}
          placeholder={`Поиск ${label}…`}
          aria-label={`Поиск ${label}`}
          autoComplete="off"
          onChange={(event) => setSearch(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Escape') closeMenu()
          }} />
      </div>
      <ul className="col-filter-list">
        {loading && <li className="col-filter-status">Загрузка…</li>}
        {!loading && error && <li className="col-filter-status">{error}</li>}
        {!loading && !error && suggestions.length === 0 &&
          <li className="col-filter-status">Нет значений за день</li>}
        {!loading && !error && suggestions.map((item) => {
          const isSelected = item.value === selected
          return <li key={item.value} role="option" aria-selected={isSelected}
            className={isSelected ? 'selected' : undefined}
            onMouseDown={(event) => {
              event.preventDefault()
              pick(item.value)
            }}>
            <span className="col-filter-check">{isSelected ? <Check size={11} /> : null}</span>
            <span className="col-filter-value mono"
              title={formatOptionLabel ? formatOptionLabel(item.value) : item.value}>
              {formatOptionLabel ? formatOptionLabel(item.value) : item.value}
            </span>
            <span className="col-filter-count">
              ({Number(item.count || 0).toLocaleString('ru-RU')})
            </span>
          </li>
        })}
      </ul>
      <button type="button" className="col-filter-clear" disabled={!hasSelection}
        onMouseDown={(event) => {
          event.preventDefault()
          clear()
        }}>
        Очистить «{label}»
      </button>
    </div>,
    document.body,
  ) : null

  return <th ref={thRef}
    className={['bill-ani-filter', 'col-filter-cell', className].filter(Boolean).join(' ')}
    title={label}
    onClick={(event) => event.stopPropagation()}>
    <div className={['col-filter-trigger-wrap', hasSelection ? 'has-value' : ''].filter(Boolean).join(' ')}>
      <button ref={triggerRef} type="button"
        className={['col-filter-trigger', hasSelection ? 'active' : ''].filter(Boolean).join(' ')}
        aria-label={`Фильтр ${label}`} aria-expanded={open}
        onClick={() => {
          if (open) closeMenu()
          else {
            setSearch('')
            setOpen(true)
          }
        }}>
        <span className="col-filter-trigger-label">
          {hasSelection ? '1 выбрано' : label}
        </span>
        <ChevronsUpDown size={11} aria-hidden="true" />
      </button>
      {hasSelection && <button type="button" className="col-filter-trigger-x"
        aria-label={`Очистить ${label}`}
        onClick={(event) => {
          event.stopPropagation()
          clear()
        }}>
        <X size={11} aria-hidden="true" />
      </button>}
    </div>
    {menu}
  </th>
}

function SatelCallsTable({ rows, columns, timezone, onSelect, fillWidth, flexShare, columnFilter }: {
  rows: SatelCdrRow[]
  columns: CdrColumnDef[]
  timezone: string
  onSelect: (row: SatelCdrRow) => void
  fillWidth?: boolean
  flexShare?: { keys: string[]; className: string }
  columnFilter?: {
    deviceId: string
    date: string
    presetId: string
    filters: SummaryColumnFilters
    onChange: (key: SatelFilterKey, value: string) => void
  }
}) {
  const shareKeys = new Set(fillWidth ? flexShare?.keys || [] : [])
  const shareClass = fillWidth ? flexShare?.className || '' : ''
  const columnClass = (key: string) => shareKeys.has(key) ? shareClass : undefined
  const presetKeys = columnFilter
    ? satelFilterKeysForPreset(columnFilter.presetId)
    : null
  const peerQuery = columnFilter ? satelFiltersToQuery(columnFilter.filters) : {}
  return <table className={['satel-cdr-table', fillWidth ? 'table-fit' : ''].filter(Boolean).join(' ')}>
    <thead><tr>
    {columns.map((column) => {
      const filterKey = column.key as SatelFilterKey
      const filterDef = columnFilter && presetKeys?.has(filterKey)
        ? SATEL_FILTER_BY_KEY[filterKey]
        : undefined
      if (columnFilter && filterDef) {
        return <SummaryColumnHeaderFilter
          key={`${filterDef.key}:${columnFilter.date}:${columnFilter.filters[filterDef.key] || ''}`}
          deviceId={columnFilter.deviceId}
          date={columnFilter.date}
          column={filterDef.column}
          label={filterDef.header}
          value={columnFilter.filters[filterDef.key] || ''}
          peerFilters={peerQuery}
          className={columnClass(column.key)}
          onChange={(value) => columnFilter.onChange(filterDef.key, value)} />
      }
      return <th key={column.key} title={column.header}
        className={columnClass(column.key)}>{column.header}</th>
    })}
  </tr></thead><tbody>{rows.map((row) => {
    return <tr key={row.recordId} className={satelRowClassName(row)}
      onClick={() => onSelect(row)}>
      {columns.map((column) => <td key={column.key}
        className={[
          column.mono ? 'mono' : '',
          column.align === 'right' ? 'right' : '',
          columnClass(column.key) || '',
        ].filter(Boolean).join(' ') || undefined}>
        {satelCallCell(row, column, timezone)}
      </td>)}
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
      <span><small>Длительность</small><strong>{formatDurationSeconds(call.durationMs)}</strong></span>
      <span><small>Разъединение</small><strong>{call.disconnectText || '—'} · {call.disconnectCode ?? '—'}</strong></span>
      <span><small>Инициатор</small><strong>{call.disconnectInitiator || '—'}</strong></span>
      <span><small>Сигнальный узел</small><strong>{call.signalNodeName || call.sigNodeName || '—'}</strong></span>
      <span><small>VoIPmonitor</small><strong>
        <VoipmonitorLink url={call.voipmonitorCardUrl} label={call.voipmonitorCdrId} />
      </strong></span>
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
  return <SharedCallCard device={device} recordID={call.recordId} fallbackCDR={call} onClose={onClose} />
}

function CoverageBadge({ coverage, perspective = 'antifraud' }: {
  coverage: CoverageSummary
  perspective?: 'antifraud' | 'cdr'
}) {
  const state = coverage.ambiguous ? 'ambiguous' : coverage.state
  const antifraudLabels: Record<string, string> = {
    matched: 'Связан', awaiting_cdr: 'Ожидает CDR', expected: 'Ожидается CDR',
    late: 'CDR опаздывает', missing: 'CDR отсутствует',
    ambiguous: 'Неоднозначно', not_applicable: 'Не применяется', unmatched: 'CDR не найден',
  }
  const cdrLabels: Record<string, string> = {
    matched: 'Связан', awaiting_cdr: 'Ожидается AntiFraud', expected: 'Ожидается AntiFraud',
    late: 'AntiFraud не найден', missing: 'AntiFraud отсутствует',
    ambiguous: 'Неоднозначно', not_applicable: 'Не применяется', unmatched: 'AntiFraud не найден',
  }
  const labels = perspective === 'cdr' ? cdrLabels : antifraudLabels
  return <span className={`parse-status ${state}`} title={coverage.reason || coverage.ambiguityReason}>
    {labels[state] || state}
  </span>
}

function ChainCompletenessBadge({ value }: { value?: ChainCompleteness }) {
  const state = value?.state || 'minimal'
  const labels: Record<string, string> = {
    complete: 'Полная', partial: 'Неполная', minimal: 'Минимальная',
  }
  const title = [
    ...(value?.missingStages || []).map((stage) => `нет: ${stage}`),
    ...(value?.notes || []),
  ].join('; ')
  return <span className={`parse-status ${state}`} title={title || undefined}>
    {labels[state] || state}
  </span>
}

function RadiusOutcomeBadge({ outcome, lifecycle }: { outcome?: string; lifecycle?: string }) {
  const state = outcome || 'no_response'
  const labels: Record<string, string> = {
    accept: 'Accept', reject: 'Reject', no_response: 'Нет ответа',
  }
  const title = [lifecycle ? `lifecycle: ${lifecycle}` : '', outcome ? `radius: ${outcome}` : '']
    .filter(Boolean).join('; ')
  return <span className={`parse-status radius-${state}`} title={title || undefined}>
    {labels[state] || state}
  </span>
}

function SharedCallCard({ device, recordID, callID, fallbackCDR, onClose }: {
  device: Device
  recordID?: string
  callID?: string
  fallbackCDR?: CallRow
  onClose: () => void
}) {
  const [detail, setDetail] = useState<CallCardDTO | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [retry, setRetry] = useState(0)
  useEffect(() => {
    const controller = new AbortController()
    const path = callID
      ? `/devices/${device.id}/antifraud-calls/${callID}`
      : `/devices/${device.id}/calls/${recordID}/card`
    api<CallCardDTO | AntifraudCallDetail>(path, { signal: controller.signal })
      .then((value) => {
        if (callID) {
          const antifraud = value as AntifraudCallDetail
          setDetail({
            cdr: antifraud.linkedCdrs?.[0] || ({} as CallRow),
            coverage: antifraud.coverage,
            antifraud,
          })
        } else {
          setDetail(value as CallCardDTO)
        }
      })
      .catch((reason) => {
        if (!controller.signal.aborted) {
          setError(reason instanceof Error ? reason.message : 'Не удалось загрузить карточку')
        }
      })
      .finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [callID, device.id, recordID, retry])
  const cdr = detail?.cdr?.recordId ? detail.cdr : fallbackCDR
  const antifraud = detail?.antifraud
  const coverage = detail?.coverage
  const timezone = activeDeviceTimezone(device)
  return <div className="drawer">
    <div className="drawer-header"><div><h3>Карточка вызова</h3>
      <span className="mono">{recordID || callID}</span></div>
      <button aria-label="Закрыть карточку" onClick={onClose}>×</button></div>
    {loading && <div className="table-empty" role="status">Загрузка карточки…</div>}
    {error && <div className="table-empty" role="alert"><strong>Карточка недоступна</strong>
      <p>{error}</p><button className="secondary" onClick={() => {
        setLoading(true)
        setError('')
        setRetry((value) => value + 1)
      }}>
        Повторить</button></div>}
    {!loading && !error && <>
      {cdr && <><h4>CDR</h4><div className="call-facts">
        <span><small>Установка · {timezone}</small><strong>{formatTime(cdr.setupTime, timezone)}</strong></span>
        <span><small>Длительность</small><strong>{formatDurationSeconds(cdr.durationMs)}</strong></span>
        <span><small>Q.850</small><strong>{cdr.releaseCause ?? '—'} · {cdr.releaseInfo || '—'}</strong></span>
        <span><small>Acct-Session-Id</small><strong className="mono">{cdr.radiusSessionId || '—'}</strong></span>
        <span><small>Номер A</small><strong className="mono">{cdr.incomingCgpn || cdr.outgoingCgpn || '—'}</strong></span>
        <span><small>Номер B</small><strong className="mono">{cdr.incomingCdpn || cdr.outgoingCdpn || '—'}</strong></span>
        <span><small>VoIPmonitor</small><strong>
          <VoipmonitorLink url={cdr.voipmonitorCardUrl} label={cdr.voipmonitorCdrId} />
        </strong></span>
      </div></>}
      {coverage && <div className="call-facts">
        <span><small>Покрытие AntiFraud</small><strong>
          <CoverageBadge coverage={coverage} perspective={recordID ? 'cdr' : 'antifraud'} />
        </strong></span>
      </div>}
      {antifraud ? <AntiFraudCallBody value={antifraud} cdr={cdr} /> :
        coverage?.state === 'matched'
          ? <p className="warning-text">Связанная цепочка AntiFraud временно недоступна
            {coverage.reason?.includes('antifraud_detail_unavailable') ? ' (детали вызова не загрузились)' : ''}.
            Повторите открытие карточки.</p>
          : coverage?.state !== 'not_applicable' &&
            <p className="warning-text">Пакеты не синтезируются: связанная цепочка AntiFraud отсутствует.</p>}
    </>}
  </div>
}

function attributeDisplay(attributes: OrderedAttribute[] | undefined, name: string): string | undefined {
  const found = attributes?.find((item) => item.name.toLowerCase() === name.toLowerCase())
  if (found == null || found.value == null) return undefined
  return typeof found.value === 'string' ? found.value : String(found.value)
}

function linkedCDRForTranscript(value: AntifraudCallDetail, cdr?: CallRow): CallRow | undefined {
  if (cdr?.recordId) return cdr
  return value.linkedCdrs?.find((item) => item.recordId)
}

function transcriptDuration(value: AntifraudCallDetail, cdr?: CallRow): {
  durationSec?: number
  source?: 'af' | 'cdr'
} {
  const fromAF = value.durationSec ?? value.accounting?.sessionTimeSec ?? value.sessionDurationSeconds
  if (fromAF != null) return { durationSec: fromAF, source: 'af' }
  const linked = linkedCDRForTranscript(value, cdr)
  if (linked?.durationMs == null) return {}
  return { durationSec: Math.round(linked.durationMs / 1000), source: 'cdr' }
}

function transcriptQ850(value: AntifraudCallDetail, cdr?: CallRow): {
  cause?: number | string
  source?: 'af' | 'cdr'
} {
  const fromAF = value.disconnectCauseQ850 ?? value.accounting?.disconnectCauseQ850
  if (fromAF != null) return { cause: fromAF, source: 'af' }
  const linked = linkedCDRForTranscript(value, cdr)
  if (linked?.releaseCause == null) return {}
  return { cause: linked.releaseCause, source: 'cdr' }
}

function omitEmptyRouting(routing?: Record<string, string>) {
  if (!routing) return undefined
  const result: Record<string, string> = {}
  Object.entries(routing).forEach(([key, value]) => {
    if (value) result[key] = value
  })
  return Object.keys(result).length ? result : undefined
}

function antifraudTranscript(value: AntifraudCallDetail, cdr?: CallRow): string {
  const { durationSec } = transcriptDuration(value, cdr)
  const { cause } = transcriptQ850(value, cdr)
  const causeNumber = typeof cause === 'number' ? cause : Number(cause)
  return formatAntifraudTranscript({
    callId: value.callId,
    acctSessionId: value.acctSessionId,
    h323ConfId: value.h323ConfId,
    calling: value.calling,
    called: value.called,
    participants: value.participants,
    finalDecision: value.finalDecision,
    durationSec,
    disconnectCauseQ850: Number.isFinite(causeNumber) ? causeNumber : undefined,
    timeline: value.timeline,
  })
}

function antifraudSlimJSON(value: AntifraudCallDetail, cdr?: CallRow) {
  const packets = value.rawPackets?.length ? value.rawPackets : value.packets
  const { durationSec, source: durationSource } = transcriptDuration(value, cdr)
  const { cause, source: causeSource } = transcriptQ850(value, cdr)
  return {
    callId: value.callId,
    acctSessionId: value.acctSessionId,
    acctSessionIds: value.acctSessionIds?.length
      ? value.acctSessionIds
      : (value.acctSessionId ? [value.acctSessionId] : []),
    h323ConfId: value.h323ConfId,
    participants: {
      callingNumber: value.participants?.callingNumber || value.calling || '',
      calledNumber: value.participants?.calledNumber || value.called || '',
    },
    requestTypes: value.requestTypes || [],
    indicationAcked: Boolean(value.indicationAcked),
    verificationResult: value.verificationResult || 'absent',
    accountingAcked: Boolean(value.accountingAcked),
    status: value.status,
    finalDecision: value.finalDecision || 'not_applicable',
    durationSec: durationSec ?? null,
    ...(durationSource ? { durationSource } : {}),
    disconnectCauseQ850: cause ?? null,
    ...(causeSource ? { causeSource } : {}),
    accounting: {
      setupTime: value.accounting?.setupTime || value.accountingStart,
      connectTime: value.accounting?.connectTime,
      disconnectTime: value.accounting?.disconnectTime || value.accountingStop,
      eventTimestamp: value.accounting?.eventTimestamp,
      sessionTimeSec: value.accounting?.sessionTimeSec ?? value.sessionDurationSeconds ?? durationSec,
      delayTimeSec: value.accounting?.delayTimeSec,
      disconnectCauseQ850: value.accounting?.disconnectCauseQ850 ?? value.disconnectCauseQ850 ?? cause,
    },
    ...(omitEmptyRouting(value.routing) ? { routing: omitEmptyRouting(value.routing) } : {}),
    timeline: (value.timeline || []).map((event) => ({
      ts: event.ts,
      phase: event.phase,
      ...(event.xpgkRequestType ? { requestType: event.xpgkRequestType } : {}),
      ...(event.acctStatusType ? { acctStatusType: event.acctStatusType } : {}),
      summary: event.summary,
    })),
    rawPackets: (packets || []).map((packet) => ({
      packetId: packet.packetId,
      radiusType: packet.radiusType,
      family: packet.family,
      ...(attributeDisplay(packet.attributes, 'xpgk-request-type')
        ? { xpgkRequestType: attributeDisplay(packet.attributes, 'xpgk-request-type') }
        : {}),
      ...(attributeDisplay(packet.attributes, 'Acct-Session-Id')
        ? { acctSessionId: attributeDisplay(packet.attributes, 'Acct-Session-Id') }
        : {}),
      attributes: redactDisplayValue(packet.attributes || []),
    })),
  }
}

function AntiFraudCallBody({ value, cdr }: { value: AntifraudCallDetail; cdr?: CallRow }) {
  const linked = linkedCDRForTranscript(value, cdr)
  const vmURL = cdr?.voipmonitorCardUrl || linked?.voipmonitorCardUrl || value.linkedCdrs?.[0]?.voipmonitorCardUrl
  const vmLabel = cdr?.voipmonitorCdrId || linked?.voipmonitorCdrId || value.linkedCdrs?.[0]?.voipmonitorCdrId
  return <section aria-label="Полный цикл AntiFraud">
    <h4>Цепочка AntiFraud</h4>
    <pre className="raw-payload">{antifraudTranscript(value, cdr)}</pre>
    {(vmURL || vmLabel) && <div className="call-facts">
      <span><small>VoIPmonitor</small><strong>
        <VoipmonitorLink url={vmURL} label={vmLabel} />
      </strong></span>
    </div>}
    <h4>AntiFraud JSON</h4>
    <pre className="raw-payload">{JSON.stringify(antifraudSlimJSON(value, cdr), null, 2)}</pre>
  </section>
}

function EventsTable({ rows, timezone, find, activeEventId, onSelect }: {
  rows: EventRow[]
  timezone: string
  find?: string
  activeEventId?: string
  onSelect: (row: EventRow) => void
}) {
  return <table className="syslog-table"><thead><tr>
    <th>Получено</th><th>Источник</th><th>Transport</th>
    <th className="col-flex">Payload</th><th>SHA-256</th></tr></thead>
    <tbody>{rows.map((row) => <EventTableRow key={row.eventId} row={row}
      timezone={timezone} find={find} active={row.eventId === activeEventId}
      onSelect={onSelect} />)}</tbody></table>
}

function EventsRawLog({ rows, find, activeEventId, onSelect }: {
  rows: EventRow[]
  find?: string
  activeEventId?: string
  onSelect: (row: EventRow) => void
}) {
  return <div className="syslog-raw-log" role="list">
    {rows.map((row) => {
      const active = row.eventId === activeEventId
      return <button type="button" key={row.eventId} className={
        active ? 'syslog-raw-line syslog-find-row-active' : 'syslog-raw-line'}
        data-event-id={row.eventId} role="listitem" onClick={() => onSelect(row)}>
        <span className="syslog-raw-payload">
          {highlightFind(redactDisplayText(row.payload), find || '', active)}</span>
      </button>
    })}
  </div>
}

function EventTableRow({ row, timezone, find, active, onSelect }: {
  row: EventRow
  timezone: string
  find?: string
  active?: boolean
  onSelect: (row: EventRow) => void
}) {
  return <tr data-event-id={row.eventId}
    className={active ? 'syslog-find-row-active' : undefined}
    onClick={() => onSelect(row)}>
    <td className="mono">{formatTime(row.receivedAt, timezone)}</td>
    <td className="mono">{row.sourceIp}:{row.sourcePort}</td>
    <td><span className="tag">{row.transport}</span></td>
    <td className="message-cell col-flex">
      {highlightFind(redactDisplayText(row.payload), find || '', Boolean(active))}</td>
    <td className="mono">{row.payloadSha256}</td>
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
      <span><small>Получено Collector</small><strong>{formatTime(event.receivedAt, timezone)}</strong></span>
      <span><small>Источник</small><strong>{event.sourceIp}:{event.sourcePort}</strong></span>
      <span><small>Transport</small><strong>{event.transport}</strong></span>
      <span><small>Device ID</small><strong>{event.deviceId}</strong></span>
    </div>
    {event.truncated && <p className="warning-text" role="alert">
      Payload был усечён при приёме UDP datagram.</p>}
    <h4>Syslog (секреты скрыты)</h4>
    <pre className="raw-payload">{redactDisplayText(event.payload)}</pre>
    <h4>Payload SHA-256</h4>
    <pre className="raw-payload">{event.payloadSha256}</pre>
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
    antifraudEnabled: !isSoftswitch, voipmonitorEnabled: false,
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
          voipmonitorEnabled: form.voipmonitorEnabled,
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
          <label className="checkbox-row"><input type="checkbox" checked={form.voipmonitorEnabled}
            onChange={(e) => update('voipmonitorEnabled', e.target.checked)} /> Корреляция VoIPmonitor</label>
        </>}
        {isSoftswitch && <label className="checkbox-row"><input type="checkbox"
          checked={form.voipmonitorEnabled}
          onChange={(e) => update('voipmonitorEnabled', e.target.checked)} /> Корреляция VoIPmonitor</label>}
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
    voipmonitorEnabled: device.voipmonitorEnabled, enabled: device.enabled,
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
          sourceCategory: form.sourceCategory, timezone: form.timezone,
          voipmonitorEnabled: form.voipmonitorEnabled, enabled: form.enabled,
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
          : 'Будут удалены Syslog, CDR, архив MinIO, FTP-файлы, очереди и аудит оборудования.'}</p>
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
          <label className="checkbox-row"><input type="checkbox" checked={form.voipmonitorEnabled}
            onChange={(e) => update('voipmonitorEnabled', e.target.checked)} /> Корреляция VoIPmonitor</label>
        </>}
        {isSoftswitch && <label className="checkbox-row"><input type="checkbox"
          checked={form.voipmonitorEnabled}
          onChange={(e) => update('voipmonitorEnabled', e.target.checked)} /> Корреляция VoIPmonitor</label>}
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
  const [tab, setTab] = useState<'system' | 'users' | 'retention' | 'runtime' | 'logs'>('system')
  const [info, setInfo] = useState<SystemInfo | null>(null)
  const [users, setUsers] = useState<ManagedUser[]>([])
  const [retention, setRetention] = useState<RetentionPolicy[]>([])
  const [runtime, setRuntime] = useState<RuntimeSettings | null>(null)
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
        const [userResponse, retentionResponse, runtimeResponse] = await Promise.all([
          api<{ items: ManagedUser[] }>('/system/users'),
          api<{ items: RetentionPolicy[] }>('/system/retention'),
          api<{ settings: RuntimeSettings }>('/system/runtime-settings'),
        ])
        setUsers(userResponse.items || [])
        setRetention(retentionResponse.items || [])
        setRuntime(runtimeResponse.settings)
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
      void api<{ settings: RuntimeSettings }>('/system/runtime-settings')
        .then((response) => setRuntime(response.settings))
        .catch((reason) => setError(reason instanceof Error ? reason.message : 'Ошибка загрузки параметров'))
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
      {canManageUsers(user.role) && <button className={tab === 'runtime' ? 'active' : ''}
        onClick={() => setTab('runtime')}>Параметры</button>}
      {canManageUsers(user.role) && <button className={tab === 'logs' ? 'active' : ''}
        onClick={() => setTab('logs')}>Логи</button>}
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
      {tab === 'runtime' && canManageUsers(user.role) && runtime && (
        <RuntimeSettingsEditor
          key={JSON.stringify(runtime)}
          value={runtime}
          busy={busy}
          onSave={async (next) => {
            setBusy(true)
            setError('')
            try {
              const response = await api<{ settings: RuntimeSettings }>('/system/runtime-settings', {
                method: 'PATCH',
                body: JSON.stringify(next),
              })
              setRuntime(response.settings)
            } catch (reason) {
              setError(reason instanceof Error ? reason.message : 'Ошибка сохранения параметров')
              throw reason
            } finally {
              setBusy(false)
            }
          }}
        />
      )}
      {tab === 'logs' && canManageUsers(user.role) && <SystemAuditLogsPanel />}
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

function normalizeRuntimeSettings(value: RuntimeSettings): RuntimeSettings {
  const enrichment = value.enrichment || {
    pstn: {
      enabled: true,
      apiUrl: 'https://pstn.finenumbers.com/api/v1/lookup',
      tokenSet: false,
    },
    geoip: {
      enabled: true,
      apiUrl: 'https://geoip.finenumbers.com/api/v1/lookup',
      tokenSet: false,
    },
  }
  return {
    ...value,
    enrichment: {
      ...enrichment,
      workers: enrichment.workers ?? 24,
      catchUp: enrichment.catchUp || { enabled: true, pageSize: 1000, sleep: '2s' },
    },
    containers: value.containers || {
      apiCpus: '2', apiMemory: '2G', exportCpus: '2', exportMemory: '2G',
      maintenanceCpus: '2', maintenanceMemory: '2G', appCpus: '4', appMemory: '4G',
    },
  }
}

function SystemAuditLogsPanel() {
  const [query, setQuery] = useState('')
  const [items, setItems] = useState<AuditLogEntry[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const load = useCallback(async (search: string) => {
    await Promise.resolve()
    setLoading(true)
    setError('')
    try {
      const response = await api<{ items: AuditLogEntry[] }>(
        `/system/audit-logs?limit=300&q=${encodeURIComponent(search.trim())}`,
      )
      setItems(response.items || [])
    } catch (reason) {
      setItems([])
      setError(reason instanceof Error ? reason.message : 'Не удалось загрузить логи')
    } finally {
      setLoading(false)
    }
  }, [])
  useEffect(() => {
    const timer = window.setTimeout(() => {
      void load('')
    }, 0)
    return () => window.clearTimeout(timer)
  }, [load])
  const grouped = AUDIT_CATEGORY_ORDER
    .map((category) => ({
      category,
      label: AUDIT_CATEGORY_LABELS[category] || category,
      rows: items.filter((item) => item.category === category),
    }))
    .filter((group) => group.rows.length > 0)
  const other = items.filter((item) => !AUDIT_CATEGORY_ORDER.includes(item.category))
  if (other.length > 0) {
    grouped.push({ category: 'other', label: AUDIT_CATEGORY_LABELS.other, rows: other })
  }
  return <section className="audit-logs-panel">
    <div className="page-heading"><div><h3>Логи системы</h3>
      <p>Журнал действий Collector с поиском по действию, ресурсу и пользователю.</p></div>
      <form className="audit-search" onSubmit={(event) => {
        event.preventDefault()
        void load(query)
      }}>
        <input placeholder="Поиск по логам…" value={query}
          onChange={(event) => setQuery(event.target.value)} />
        <button className="secondary" type="submit" disabled={loading}>Найти</button>
        <button className="secondary" type="button" disabled={loading}
          onClick={() => { setQuery(''); void load('') }}>Сброс</button>
      </form>
    </div>
    {error && <div className="form-error">{error}</div>}
    {loading && <div className="diagnostic-facts"><span>Загрузка журнала…</span></div>}
    {!loading && items.length === 0 && <div className="table-empty">
      <strong>Записей не найдено</strong>
      <p>Измените поисковый запрос или дождитесь новых действий в системе.</p>
    </div>}
    {!loading && grouped.map((group) => <article key={group.category} className="audit-group">
      <h4>{group.label} <small>{formatCount(group.rows.length)}</small></h4>
      <table className="audit-table"><thead><tr>
        <th>Время</th><th>Действие</th><th>Ресурс</th><th>Пользователь</th><th>IP</th><th>Детали</th>
      </tr></thead>
        <tbody>{group.rows.map((row) => <tr key={row.id}>
          <td className="mono">{formatTime(row.occurredAt, 'UTC')}</td>
          <td>{row.action}</td>
          <td>{row.resourceType}{row.resourceId ? ` · ${row.resourceId}` : ''}</td>
          <td>{row.actorName || '—'}</td>
          <td className="mono">{row.remoteIp || '—'}</td>
          <td className="mono audit-details">{formatAuditDetails(row.details)}</td>
        </tr>)}</tbody></table>
    </article>)}
  </section>
}

const AUDIT_CATEGORY_ORDER = ['auth', 'users', 'devices', 'exports', 'retention', 'system', 'other']
const AUDIT_CATEGORY_LABELS: Record<string, string> = {
  auth: 'Аутентификация',
  users: 'Пользователи',
  devices: 'Устройства',
  exports: 'Экспорт',
  retention: 'Хранение',
  system: 'Система',
  other: 'Прочее',
}

type AuditLogEntry = {
  id: number
  occurredAt: string
  actorName?: string
  action: string
  resourceType: string
  resourceId?: string
  remoteIp?: string
  details?: unknown
  category: string
}

function formatAuditDetails(value: unknown) {
  if (value == null || value === '') return '—'
  try {
    const text = typeof value === 'string' ? value : JSON.stringify(value)
    return text.length > 160 ? `${text.slice(0, 157)}…` : text
  } catch {
    return '—'
  }
}

function RuntimeSettingsEditor({ value, busy, onSave }: {
  value: RuntimeSettings
  busy: boolean
  onSave: (next: RuntimeSettings) => Promise<void>
}) {
  const [form, setForm] = useState(() => normalizeRuntimeSettings(value))
  const [password, setPassword] = useState('')
  const [pstnToken, setPstnToken] = useState('')
  const [geoipToken, setGeoipToken] = useState('')
  const updateProjection = (patch: Partial<RuntimeSettings['projection']>) =>
    setForm((current) => ({ ...current, projection: { ...current.projection, ...patch } }))
  const updateCoverage = (patch: Partial<RuntimeSettings['coverage']>) =>
    setForm((current) => ({ ...current, coverage: { ...current.coverage, ...patch } }))
  const updateVoip = (patch: Partial<RuntimeSettings['voipmonitor']>) =>
    setForm((current) => ({ ...current, voipmonitor: { ...current.voipmonitor, ...patch } }))
  const updateEnrichment = (key: 'pstn' | 'geoip', patch: Partial<NonNullable<RuntimeSettings['enrichment']>['pstn']>) =>
    setForm((current) => {
      const enrichment = normalizeRuntimeSettings(current).enrichment!
      return {
        ...current,
        enrichment: {
          ...enrichment,
          [key]: { ...enrichment[key], ...patch },
        },
      }
    })
  const updatePlatform = (patch: Partial<RuntimeSettings['platform']>) =>
    setForm((current) => ({ ...current, platform: { ...current.platform, ...patch } }))
  const updateContainers = (patch: Partial<RuntimeSettings['containers']>) =>
    setForm((current) => ({ ...current, containers: { ...current.containers, ...patch } }))
  const enrichment = form.enrichment || normalizeRuntimeSettings(form).enrichment!
  return <section className="runtime-settings">
    <div className="page-heading"><div><h3>Операционные параметры</h3>
      <p>AntiFraud projection, coverage, VoIPmonitor, обогащение CDR и export. Значения хранятся в БД и
        применяются без правки .env (инфраструктурные секреты остаются в .env).</p></div></div>

    <article className="runtime-card">
      <h4>Custom AntiFraud projection</h4>
      <label className="checkbox-row"><input type="checkbox" checked={form.projection.enabled}
        onChange={(e) => updateProjection({ enabled: e.target.checked })} /> Включена</label>
      <div className="runtime-grid">
        <label>Lookback<input value={form.projection.lookback}
          onChange={(e) => updateProjection({ lookback: e.target.value })} /></label>
        <label>Batch size<input type="number" value={form.projection.batchSize}
          onChange={(e) => updateProjection({ batchSize: Number(e.target.value) })} /></label>
        <label>Max events / hour<input type="number" value={form.projection.maxEvents}
          onChange={(e) => updateProjection({ maxEvents: Number(e.target.value) })} /></label>
        <label>Threads<input type="number" min={1} max={16} value={form.projection.threads}
          onChange={(e) => updateProjection({ threads: Number(e.target.value) })} /></label>
        <label>Max memory (bytes)
          <span className="field-hint">Go payload/hour + ClickHouse CustomReplay/Reconcile</span>
          <input type="number" value={form.projection.maxMemoryBytes}
          onChange={(e) => updateProjection({ maxMemoryBytes: Number(e.target.value) })} /></label>
        <label>Sleep<input value={form.projection.sleep}
          onChange={(e) => updateProjection({ sleep: e.target.value })} /></label>
        <label>Lease<input value={form.projection.lease}
          onChange={(e) => updateProjection({ lease: e.target.value })} /></label>
        <label>Response timeout<input value={form.projection.responseTimeout}
          onChange={(e) => updateProjection({ responseTimeout: e.target.value })} /></label>
        <label>Pairing horizon<input value={form.projection.pairingHorizon}
          onChange={(e) => updateProjection({ pairingHorizon: e.target.value })} /></label>
        <label>Retry horizon<input value={form.projection.retryHorizon}
          onChange={(e) => updateProjection({ retryHorizon: e.target.value })} /></label>
        <label>Assembly idle<input value={form.projection.assemblyIdle}
          onChange={(e) => updateProjection({ assemblyIdle: e.target.value })} /></label>
      </div>
    </article>

    <article className="runtime-card">
      <h4>CDR ↔ AntiFraud coverage</h4>
      <div className="runtime-grid">
        <label>Expected grace<input value={form.coverage.expectedGrace}
          onChange={(e) => updateCoverage({ expectedGrace: e.target.value })} /></label>
        <label>Late threshold<input value={form.coverage.lateThreshold}
          onChange={(e) => updateCoverage({ lateThreshold: e.target.value })} /></label>
        <label>Missing terminal<input value={form.coverage.missingTerminal}
          onChange={(e) => updateCoverage({ missingTerminal: e.target.value })} /></label>
        <label>Retry horizon<input value={form.coverage.retryHorizon}
          onChange={(e) => updateCoverage({ retryHorizon: e.target.value })} /></label>
        <label>Worker sleep<input value={form.coverage.workerSleep}
          onChange={(e) => updateCoverage({ workerSleep: e.target.value })} /></label>
      </div>
    </article>

    <article className="runtime-card">
      <h4>VoIPmonitor</h4>
      <label className="checkbox-row"><input type="checkbox" checked={form.voipmonitor.enabled}
        onChange={(e) => updateVoip({ enabled: e.target.checked })} /> Включена</label>
      <div className="runtime-grid">
        <label>API URL<input value={form.voipmonitor.apiUrl}
          onChange={(e) => updateVoip({ apiUrl: e.target.value })} /></label>
        <label>User<input value={form.voipmonitor.user}
          onChange={(e) => updateVoip({ user: e.target.value })} /></label>
        <label>Password<input type="password"
          placeholder={form.voipmonitor.passwordSet ? '•••••••• (не менять)' : 'пароль'}
          value={password} onChange={(e) => setPassword(e.target.value)} /></label>
        <label>GUI URL<input value={form.voipmonitor.guiUrl}
          onChange={(e) => updateVoip({ guiUrl: e.target.value })} /></label>
        <label>Card URL template<input value={form.voipmonitor.cardUrlTemplate}
          onChange={(e) => updateVoip({ cardUrlTemplate: e.target.value })} /></label>
        <label>Call-ID window<input value={form.voipmonitor.callIdWindow}
          onChange={(e) => updateVoip({ callIdWindow: e.target.value })} /></label>
        <label>Fallback window<input value={form.voipmonitor.fallbackWindow}
          onChange={(e) => updateVoip({ fallbackWindow: e.target.value })} /></label>
        <label>Fallback window max<input value={form.voipmonitor.fallbackWindowMax}
          onChange={(e) => updateVoip({ fallbackWindowMax: e.target.value })} /></label>
        <label>Worker sleep<input value={form.voipmonitor.workerSleep}
          onChange={(e) => updateVoip({ workerSleep: e.target.value })} /></label>
        <label>Lease<input value={form.voipmonitor.lease}
          onChange={(e) => updateVoip({ lease: e.target.value })} /></label>
        <label>Min score<input type="number" value={form.voipmonitor.minScore}
          onChange={(e) => updateVoip({ minScore: Number(e.target.value) })} /></label>
        <label>Disambiguity margin<input type="number" value={form.voipmonitor.disambiguityMargin}
          onChange={(e) => updateVoip({ disambiguityMargin: Number(e.target.value) })} /></label>
        <label>Number suffix len<input type="number" value={form.voipmonitor.numberSuffixLen}
          onChange={(e) => updateVoip({ numberSuffixLen: Number(e.target.value) })} /></label>
        <label>Rate limit / sec<input type="number" value={form.voipmonitor.rateLimitPerSec}
          onChange={(e) => updateVoip({ rateLimitPerSec: Number(e.target.value) })} /></label>
      </div>
      <label className="checkbox-row"><input type="checkbox" checked={form.voipmonitor.useShareUrl}
        onChange={(e) => updateVoip({ useShareUrl: e.target.checked })} /> Use share URL</label>
    </article>

    <article className="runtime-card">
      <h4>Обогащение CDR (PSTN / GeoIP)</h4>
      <p className="runtime-note">Токены FineNumbers, concurrency lookup и фоновый catch-up истории.
        Seed из `.env` только при пустой БД; дальше авторитетны эти параметры (hot-apply ~2 с).</p>
      <label className="checkbox-row"><input type="checkbox" checked={enrichment.pstn.enabled}
        onChange={(e) => updateEnrichment('pstn', { enabled: e.target.checked })} /> PSTN включён</label>
      <div className="runtime-grid">
        <label>PSTN API URL<input value={enrichment.pstn.apiUrl}
          onChange={(e) => updateEnrichment('pstn', { apiUrl: e.target.value })} /></label>
        <label>PSTN token<input type="password"
          placeholder={enrichment.pstn.tokenSet ? '•••••••• (не менять)' : 'токен'}
          value={pstnToken} onChange={(e) => setPstnToken(e.target.value)} /></label>
      </div>
      <label className="checkbox-row"><input type="checkbox" checked={enrichment.geoip.enabled}
        onChange={(e) => updateEnrichment('geoip', { enabled: e.target.checked })} /> GeoIP включён</label>
      <div className="runtime-grid">
        <label>GeoIP API URL<input value={enrichment.geoip.apiUrl}
          onChange={(e) => updateEnrichment('geoip', { apiUrl: e.target.value })} /></label>
        <label>GeoIP token<input type="password"
          placeholder={enrichment.geoip.tokenSet ? '•••••••• (не менять)' : 'токен'}
          value={geoipToken} onChange={(e) => setGeoipToken(e.target.value)} /></label>
        <label>Lookup workers<input type="number" min={1} max={64}
          value={enrichment.workers ?? 24}
          onChange={(e) => setForm((current) => {
            const next = normalizeRuntimeSettings(current)
            return {
              ...current,
              enrichment: { ...next.enrichment!, workers: Number(e.target.value) },
            }
          })} /></label>
      </div>
      <label className="checkbox-row"><input type="checkbox"
        checked={enrichment.catchUp?.enabled ?? true}
        onChange={(e) => setForm((current) => {
          const next = normalizeRuntimeSettings(current)
          return {
            ...current,
            enrichment: {
              ...next.enrichment!,
              catchUp: { ...next.enrichment!.catchUp!, enabled: e.target.checked },
            },
          }
        })} /> Фоновый catch-up истории</label>
      <div className="runtime-grid">
        <label>Catch-up page size<input type="number" min={100} max={5000}
          value={enrichment.catchUp?.pageSize ?? 1000}
          onChange={(e) => setForm((current) => {
            const next = normalizeRuntimeSettings(current)
            return {
              ...current,
              enrichment: {
                ...next.enrichment!,
                catchUp: { ...next.enrichment!.catchUp!, pageSize: Number(e.target.value) },
              },
            }
          })} /></label>
        <label>Catch-up sleep<input value={enrichment.catchUp?.sleep || '2s'}
          onChange={(e) => setForm((current) => {
            const next = normalizeRuntimeSettings(current)
            return {
              ...current,
              enrichment: {
                ...next.enrichment!,
                catchUp: { ...next.enrichment!.catchUp!, sleep: e.target.value },
              },
            }
          })} /></label>
      </div>
    </article>

    <article className="runtime-card">
      <h4>Платформа</h4>
      <div className="runtime-grid">
        <label>ClickHouse admission capacity<input type="number" min={4} max={128}
          value={form.platform.clickhouseAdmissionCapacity}
          onChange={(e) => updatePlatform({ clickhouseAdmissionCapacity: Number(e.target.value) })} /></label>
        <label>Export page size<input type="number" min={100} max={5000}
          value={form.platform.exportPageSize}
          onChange={(e) => updatePlatform({ exportPageSize: Number(e.target.value) })} /></label>
      </div>
      <p className="runtime-note">Admission capacity применяется сразу для новых запросов;
        уже выполняющиеся запросы сохраняют прежние лимиты до завершения.</p>
    </article>

    <article className="runtime-card">
      <h4>Лимиты контейнеров Docker</h4>
      <p className="runtime-note">CPU/RAM для ролей Collector. После сохранения скачайте env-фрагмент и
        выполните `docker compose up -d --force-recreate` на хосте (cgroup применяет Docker).</p>
      <div className="runtime-grid">
        <label>API CPUs<input value={form.containers?.apiCpus || ''}
          onChange={(e) => updateContainers({ apiCpus: e.target.value })} /></label>
        <label>API memory<input value={form.containers?.apiMemory || ''}
          onChange={(e) => updateContainers({ apiMemory: e.target.value })} /></label>
        <label>Export CPUs<input value={form.containers?.exportCpus || ''}
          onChange={(e) => updateContainers({ exportCpus: e.target.value })} /></label>
        <label>Export memory<input value={form.containers?.exportMemory || ''}
          onChange={(e) => updateContainers({ exportMemory: e.target.value })} /></label>
        <label>Maintenance CPUs<input value={form.containers?.maintenanceCpus || ''}
          onChange={(e) => updateContainers({ maintenanceCpus: e.target.value })} /></label>
        <label>Maintenance memory<input value={form.containers?.maintenanceMemory || ''}
          onChange={(e) => updateContainers({ maintenanceMemory: e.target.value })} /></label>
        <label>App (monolith) CPUs<input value={form.containers?.appCpus || ''}
          onChange={(e) => updateContainers({ appCpus: e.target.value })} /></label>
        <label>App (monolith) memory<input value={form.containers?.appMemory || ''}
          onChange={(e) => updateContainers({ appMemory: e.target.value })} /></label>
      </div>
      <div className="dialog-actions">
        <a className="secondary button-link" href="/api/system/runtime-settings/container-limits.env">
          Скачать container-limits.env
        </a>
      </div>
    </article>

    <div className="dialog-actions">
      <button className="primary" disabled={busy} onClick={() => {
        const payload: RuntimeSettings = {
          ...form,
          voipmonitor: {
            ...form.voipmonitor,
            password: password || undefined,
          },
          enrichment: {
            ...enrichment,
            pstn: {
              ...enrichment.pstn,
              token: pstnToken || undefined,
            },
            geoip: {
              ...enrichment.geoip,
              token: geoipToken || undefined,
            },
          },
        }
        void onSave(payload)
      }}>Сохранить параметры</button>
    </div>
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

function devicesPollFingerprint(devices: Device[]) {
  return devices.map((device) => [
    device.id,
    device.enabled ? '1' : '0',
    device.purgeState || '',
    device.timezoneRevision ?? 0,
    device.activeTimezoneRevision ?? 0,
    device.antifraudEnabled ? '1' : '0',
    device.replay?.pending ?? 0,
    device.replay?.processing ?? 0,
    device.replay?.complete ?? 0,
    device.replay?.quarantined ?? 0,
  ].join(':')).join('|')
}

function activeDeviceTimezone(device: Device) {
  return device.activeTimezone || device.timezone
}

function formatCount(value?: number) {
  return Number.isFinite(value) ? Number(value).toLocaleString('ru-RU') : '0'
}

function formatDurationNanos(value?: number) {
  if (!Number.isFinite(value) || Number(value) <= 0) return '—'
  const seconds = Math.round(Number(value) / 1e9)
  if (seconds < 60) return `${seconds} с`
  if (seconds < 3600) return `${Math.round(seconds / 60)} мин`
  return `${(seconds / 3600).toFixed(1)} ч`
}

function formatBytes(value?: number) {
  if (!Number.isFinite(value)) return '—'
  const bytes = Number(value)
  if (bytes < 1024) return `${bytes} Б`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} КБ`
  return `${(bytes / (1024 * 1024)).toFixed(1)} МБ`
}

function formatStorageMB(value?: number) {
  if (!Number.isFinite(value)) return '—'
  return `${formatCount(Math.max(0, Math.round(Number(value) / (1024 * 1024))))} Mb`
}

function formatTime(value?: string, timezone = 'UTC') {
  if (!value) return '—'
  return new Intl.DateTimeFormat('ru-RU', {
    year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit',
    minute: '2-digit', second: '2-digit',
    timeZone: timezone,
  }).format(new Date(value))
}

createRoot(document.getElementById('root')!).render(<App />)
