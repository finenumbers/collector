import { describe, expect, it } from 'vitest'
import {
  canCancelExport, canDownloadExport, createExportRequest, type ExportJob, exportDownloadURL,
  exportETASeconds, exportJobsURL, exportJobDisposition, exportJobURL, exportProgress,
  exportStatusLabel, exportStorageKey, exportTarget, formatExportBytes,
  formatExportDuration, isExportActive, localDateInTimezone, pollDelay, restoreExportTracking,
  serializeExportTracking, type ExportJobStatus,
} from './export'

const job = (overrides: Partial<ExportJob> = {}): ExportJob => ({
  id: 'job-1',
  status: 'running',
  format: 'xlsx',
  filename: 'calls.xlsx',
  rowsWritten: 25,
  estimatedRows: 100,
  bytesWritten: 2048,
  createdAt: '2026-07-26T10:00:00Z',
  startedAt: '2026-07-26T10:00:10Z',
  ...overrides,
})

describe('export navigation mapping', () => {
  it.each([
    ['calls', { dataset: 'calls' }],
    ['antifraud', { dataset: 'antifraud' }],
    ['syslog', { dataset: 'syslog' }],
  ] as const)('maps %s to its backend export target', (dataset, expected) => {
    expect(exportTarget(dataset)).toEqual(expected)
  })
})

describe('async export request contract', () => {
  it('builds a CSV.zip request with the selected day and syslog mapping', () => {
    expect(createExportRequest('syslog', 'critical', '2026-07-01', '2026-07-26')).toEqual({
      dataset: 'syslog',
      q: 'critical',
      format: 'csv_zip',
      from: '2026-07-01',
      to: '2026-07-26',
    })
  })

  it('omits empty optional filters', () => {
    expect(createExportRequest('calls', '')).toEqual({ dataset: 'calls', format: 'csv_zip' })
  })

  it('encodes device and job identifiers in every endpoint', () => {
    expect(exportJobsURL('device/one')).toBe('/devices/device%2Fone/export-jobs')
    expect(exportJobURL('device/one', 'job/two')).toBe('/devices/device%2Fone/export-jobs/job%2Ftwo')
    expect(exportDownloadURL('device/one', 'job/two'))
      .toBe('/api/devices/device%2Fone/export-jobs/job%2Ftwo/download')
  })

  it('derives today in the equipment timezone', () => {
    const instant = new Date('2026-07-26T21:30:00Z')
    expect(localDateInTimezone('UTC', instant)).toBe('2026-07-26')
    expect(localDateInTimezone('Asia/Novosibirsk', instant)).toBe('2026-07-27')
  })
})

describe('async export state presentation', () => {
  it.each([
    ['queued', true, true, 'В очереди'],
    ['running', true, true, 'Выполняется'],
    ['completed', false, false, 'Готов'],
    ['failed', false, false, 'Ошибка'],
    ['cancelled', false, false, 'Отменён'],
    ['expired', false, false, 'Срок хранения истёк'],
  ] satisfies [ExportJobStatus, boolean, boolean, string][])(
    'presents %s exhaustively',
    (status, active, cancellable, label) => {
      expect(isExportActive(status)).toBe(active)
      expect(canCancelExport(status)).toBe(cancellable)
      expect(exportStatusLabel(status)).toBe(label)
    },
  )

  it('calculates bounded progress and ETA from observed throughput', () => {
    const running = job()
    expect(exportProgress(running)).toBe(0.25)
    expect(exportETASeconds(running, new Date('2026-07-26T10:00:50Z').getTime())).toBe(120)
    expect(exportProgress(job({ rowsWritten: 125 }))).toBe(1)
  })

  it('uses indeterminate progress when an estimate is unavailable', () => {
    expect(exportProgress(job({ estimatedRows: undefined }))).toBeNull()
    expect(exportETASeconds(job({ estimatedRows: 0 }))).toBeNull()
    expect(exportETASeconds(job({ status: 'queued' }))).toBeNull()
  })

  it('only downloads completed, unexpired exports', () => {
    const now = new Date('2026-07-26T12:00:00Z').getTime()
    expect(canDownloadExport(job({ status: 'completed', expiresAt: undefined }), now)).toBe(true)
    expect(canDownloadExport(job({ status: 'completed', expiresAt: '2026-07-26T13:00:00Z' }), now)).toBe(true)
    expect(canDownloadExport(job({ status: 'completed', expiresAt: '2026-07-26T11:00:00Z' }), now)).toBe(false)
    expect(canDownloadExport(job({ status: 'failed' }), now)).toBe(false)
  })

  it('restores the real completed status without fabricating a queued job', () => {
    const completed = job({
      status: 'completed',
      filename: 'alarms.zip',
      finishedAt: '2026-07-26T10:01:00Z',
    })
    expect(restoreExportTracking(serializeExportTracking(completed))).toEqual({
      job: completed,
      legacyJobID: null,
    })
    expect(exportJobDisposition(completed)).toBe('offer_download')
  })

  it('hydrates legacy job IDs instead of assigning an invented status', () => {
    const legacyJobID = '7845e6d4-b8f1-4d0f-a8d4-c527f6868d02'
    expect(restoreExportTracking(legacyJobID)).toEqual({
      job: null,
      legacyJobID,
    })
    expect(restoreExportTracking('')).toEqual({ job: null, legacyJobID: null })
    expect(restoreExportTracking('{broken-json')).toEqual({ job: null, legacyJobID: null })
    expect(restoreExportTracking('{"version":1,"job":{"id":"partial"}}')).toEqual({
      job: null,
      legacyJobID: null,
    })
  })

  it('never treats polling completion as an automatic download command', () => {
    const now = new Date('2026-07-26T12:00:00Z').getTime()
    expect(exportJobDisposition(job({ status: 'queued' }), now)).toBe('poll')
    expect(exportJobDisposition(job({
      status: 'completed', expiresAt: '2026-07-26T13:00:00Z',
    }), now)).toBe('offer_download')
    expect(exportJobDisposition(job({
      status: 'completed', expiresAt: '2026-07-26T11:00:00Z',
    }), now)).toBe('clear')
    expect(exportJobDisposition(job({ status: 'failed' }), now)).toBe('clear')
  })

  it('isolates persisted jobs across section, date, and query remounts', () => {
    const base = exportStorageKey('device-1', 'syslog', '2026-07-26', '')
    expect(exportStorageKey('device-1', 'antifraud', '2026-07-26', '')).not.toBe(base)
    expect(exportStorageKey('device-1', 'syslog', '2026-07-27', '')).not.toBe(base)
    expect(exportStorageKey('device-1', 'syslog', '2026-07-26', 'critical')).not.toBe(base)
    const completed = job({ status: 'completed' })
    expect(exportJobDisposition(
      restoreExportTracking(serializeExportTracking(completed)).job!,
    )).toBe('offer_download')
  })
})

describe('async export polling and formatting', () => {
  it('backs off active polling and caps the delay', () => {
    expect(pollDelay(0, true)).toBe(2_000)
    expect(pollDelay(1, true)).toBe(4_000)
    expect(pollDelay(10, true)).toBe(30_000)
    expect(pollDelay(10, false)).toBe(10_000)
  })

  it('formats durations for actionable ETA labels', () => {
    expect(formatExportDuration(59)).toBe('59 с')
    expect(formatExportDuration(61)).toBe('2 мин')
    expect(formatExportDuration(3_661)).toBe('1 ч 2 мин')
  })

  it('formats byte counts across units', () => {
    expect(formatExportBytes(500)).toBe('500 Б')
    expect(formatExportBytes(2048)).toBe('2.0 КБ')
    expect(formatExportBytes(2 * 1024 ** 2)).toBe('2.0 МБ')
    expect(formatExportBytes(2 * 1024 ** 3)).toBe('2.0 ГБ')
  })
})
