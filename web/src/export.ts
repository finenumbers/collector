export type ExportNavigationDataset =
  'calls' | 'syslog_all' | 'antifraud' | 'alarms' | 'call_trace' | 'sip' | 'isup' |
  'q931' | 'h323' | 'rtp' | 'hardware' | 'ivr' | 'ip_network' | 'ip_connections' |
  'ip_modules' | 'radius' | 'config_history' | 'auth_log' | 'system_journal' | 'unknown'

export type ExportTarget = {
  dataset: 'calls' | 'antifraud' | 'events'
  category?: string
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

export type CreateExportJobRequest = ExportTarget & {
  q?: string
  format: 'csv_zip'
  from?: string
  to?: string
}

export function exportTarget(dataset: ExportNavigationDataset): ExportTarget {
  if (dataset === 'calls' || dataset === 'antifraud') return { dataset }
  return {
    dataset: 'events',
    category: dataset === 'syslog_all' ? 'all' : dataset,
  }
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

export function isExportActive(status: ExportJobStatus): boolean {
  return status === 'queued' || status === 'running'
}

export function canCancelExport(status: ExportJobStatus): boolean {
  return isExportActive(status)
}

export function canDownloadExport(job: ExportJob, now = Date.now()): boolean {
  return job.status === 'completed' &&
    (!job.expiresAt || new Date(job.expiresAt).getTime() > now)
}

export function exportProgress(job: ExportJob): number | null {
  if (!job.estimatedRows || job.estimatedRows <= 0) return null
  return Math.min(1, Math.max(0, job.rowsWritten / job.estimatedRows))
}

export function exportETASeconds(job: ExportJob, now = Date.now()): number | null {
  const progress = exportProgress(job)
  if (job.status !== 'running' || progress === null || progress <= 0 || progress >= 1 || !job.startedAt) {
    return null
  }
  const elapsed = Math.max(0, now - new Date(job.startedAt).getTime()) / 1000
  return Math.max(0, Math.round((elapsed / progress) * (1 - progress)))
}

export function pollDelay(failures: number, active: boolean): number {
  if (!active) return 10_000
  return Math.min(30_000, 2_000 * (2 ** Math.max(0, failures)))
}

export function exportStatusLabel(status: ExportJobStatus): string {
  switch (status) {
    case 'queued': return 'В очереди'
    case 'running': return 'Выполняется'
    case 'completed': return 'Готов'
    case 'failed': return 'Ошибка'
    case 'cancelled': return 'Отменён'
    case 'expired': return 'Срок хранения истёк'
    default: {
      const exhaustive: never = status
      return exhaustive
    }
  }
}

export function formatExportDuration(seconds: number): string {
  if (seconds < 60) return `${seconds} с`
  const minutes = Math.ceil(seconds / 60)
  if (minutes < 60) return `${minutes} мин`
  return `${Math.floor(minutes / 60)} ч ${minutes % 60} мин`
}

export function formatExportBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} Б`
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} КБ`
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} МБ`
  return `${(bytes / 1024 ** 3).toFixed(1)} ГБ`
}

export function exportURL(
  deviceID: string,
  navigationDataset: ExportNavigationDataset,
  query: string,
): string {
  const target = exportTarget(navigationDataset)
  const parameters = new URLSearchParams({ dataset: target.dataset, q: query })
  if (target.category) parameters.set('category', target.category)
  return `/api/devices/${deviceID}/export.xlsx?${parameters.toString()}`
}
