export type ExportNavigationDataset =
  'calls' | 'syslog' | 'antifraud'

export type ExportTarget = {
  dataset: 'calls' | 'syslog' | 'antifraud'
}

export type ExportJobStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled' | 'expired'

export type ExportJob = {
  id: string
  status: ExportJobStatus
  format: string
  filename?: string
  rowsWritten: number
  estimatedRows?: number
  bytesWritten: number
  error?: string
  createdAt: string
  startedAt?: string
  finishedAt?: string
  expiresAt?: string
}

export type RestoredExportTracking = {
  job: ExportJob | null
  legacyJobID: string | null
}

export type ExportJobDisposition = 'poll' | 'offer_download' | 'clear'

export type CreateExportJobRequest = ExportTarget & {
  q?: string
  format: 'csv_zip'
  from?: string
  to?: string
}

export function exportTarget(dataset: ExportNavigationDataset): ExportTarget {
  if (dataset === 'calls' || dataset === 'antifraud') return { dataset }
  return { dataset: 'syslog' }
}

export function createExportRequest(
  navigationDataset: ExportNavigationDataset,
  query: string,
  from?: string,
  to?: string,
): CreateExportJobRequest {
  return {
    ...exportTarget(navigationDataset),
    ...(query ? { q: query } : {}),
    format: 'csv_zip',
    ...(from ? { from } : {}),
    ...(to ? { to } : {}),
  }
}

export function localDateInTimezone(timezone: string, now = new Date()): string {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: timezone || 'UTC',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).formatToParts(now)
  const value = Object.fromEntries(parts.map((part) => [part.type, part.value]))
  return `${value.year}-${value.month}-${value.day}`
}

export function exportJobsURL(deviceID: string): string {
  return `/devices/${encodeURIComponent(deviceID)}/export-jobs`
}

export function exportJobURL(deviceID: string, jobID: string): string {
  return `${exportJobsURL(deviceID)}/${encodeURIComponent(jobID)}`
}

export function exportDownloadURL(deviceID: string, jobID: string): string {
  return `/api${exportJobURL(deviceID, jobID)}/download`
}

export function exportStorageKey(
  deviceID: string,
  dataset: ExportNavigationDataset,
  date: string,
  query: string,
): string {
  return `collector:export:${deviceID}:${dataset}:${date}:${query}`
}

export function serializeExportTracking(job: ExportJob): string {
  return JSON.stringify({ version: 1, job })
}

export function restoreExportTracking(raw: string | null): RestoredExportTracking {
  if (!raw) return { job: null, legacyJobID: null }
  try {
    const value = JSON.parse(raw) as { version?: unknown; job?: unknown }
    if (value.version === 1 && isExportJob(value.job)) {
      return { job: value.job, legacyJobID: null }
    }
    return { job: null, legacyJobID: null }
  } catch {
    // Releases before v0.1.39 stored only the job ID.
    const legacyJobID = raw.trim()
    return {
      job: null,
      legacyJobID: /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
        .test(legacyJobID) ? legacyJobID : null,
    }
  }
}

export function isExportActive(status: ExportJobStatus): boolean {
  return status === 'queued' || status === 'running'
}

export function canDownloadExport(job: ExportJob, now = Date.now()): boolean {
  return job.status === 'completed' &&
    (!job.expiresAt || new Date(job.expiresAt).getTime() > now)
}

export function exportJobDisposition(job: ExportJob, now = Date.now()): ExportJobDisposition {
  if (isExportActive(job.status)) return 'poll'
  if (canDownloadExport(job, now)) return 'offer_download'
  return 'clear'
}

function isExportJob(value: unknown): value is ExportJob {
  if (!value || typeof value !== 'object') return false
  const candidate = value as Partial<ExportJob>
  const statuses: ExportJobStatus[] = [
    'queued', 'running', 'completed', 'failed', 'cancelled', 'expired',
  ]
  return typeof candidate.id === 'string' && candidate.id !== '' &&
    candidate.status !== undefined && statuses.includes(candidate.status) &&
    typeof candidate.format === 'string' &&
    typeof candidate.rowsWritten === 'number' &&
    typeof candidate.bytesWritten === 'number' &&
    typeof candidate.createdAt === 'string'
}

export function pollDelay(failures: number, active: boolean): number {
  if (!active) return 10_000
  return Math.min(30_000, 2_000 * (2 ** Math.max(0, failures)))
}
