import { describe, expect, it } from 'vitest'
import {
  canCancelExport, canDownloadExport, createExportRequest, type ExportJob, exportDownloadURL,
  exportETASeconds, exportJobsURL, exportJobURL, exportProgress, exportStatusLabel, exportTarget,
  exportURL, formatExportBytes, formatExportDuration, isExportActive, pollDelay,
  type ExportJobStatus, type ExportNavigationDataset,
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
    ['syslog_all', { dataset: 'events', category: 'all' }],
    ['alarms', { dataset: 'events', category: 'alarms' }],
    ['call_trace', { dataset: 'events', category: 'call_trace' }],
    ['sip', { dataset: 'events', category: 'sip' }],
    ['isup', { dataset: 'events', category: 'isup' }],
    ['q931', { dataset: 'events', category: 'q931' }],
    ['h323', { dataset: 'events', category: 'h323' }],
    ['rtp', { dataset: 'events', category: 'rtp' }],
    ['hardware', { dataset: 'events', category: 'hardware' }],
    ['ivr', { dataset: 'events', category: 'ivr' }],
    ['ip_network', { dataset: 'events', category: 'ip_network' }],
    ['ip_connections', { dataset: 'events', category: 'ip_connections' }],
    ['ip_modules', { dataset: 'events', category: 'ip_modules' }],
    ['radius', { dataset: 'events', category: 'radius' }],
    ['config_history', { dataset: 'events', category: 'config_history' }],
    ['auth_log', { dataset: 'events', category: 'auth_log' }],
    ['system_journal', { dataset: 'events', category: 'system_journal' }],
    ['unknown', { dataset: 'events', category: 'unknown' }],
  ] as const)('maps %s to its backend export target', (dataset, expected) => {
    expect(exportTarget(dataset)).toEqual(expected)
  })

  it('omits category for calls and safely encodes search values', () => {
    const url = exportURL('device-id', 'calls' satisfies ExportNavigationDataset, '+7 999&x')
    expect(url).toBe('/api/devices/device-id/export.xlsx?dataset=calls&q=%2B7+999%26x')
    expect(url).not.toContain('category=')
  })
})

describe('async export request contract', () => {
  it('builds an auto-format request with filters and event mapping', () => {
    expect(createExportRequest('alarms', 'critical', '2026-07-01', '2026-07-26')).toEqual({
      dataset: 'events',
      category: 'alarms',
      q: 'critical',
      format: 'auto',
      from: '2026-07-01',
      to: '2026-07-26',
    })
  })

  it('omits empty optional filters', () => {
    expect(createExportRequest('calls', '')).toEqual({ dataset: 'calls', format: 'auto' })
  })

  it('encodes device and job identifiers in every endpoint', () => {
    expect(exportJobsURL('device/one')).toBe('/devices/device%2Fone/export-jobs')
    expect(exportJobURL('device/one', 'job/two')).toBe('/devices/device%2Fone/export-jobs/job%2Ftwo')
    expect(exportDownloadURL('device/one', 'job/two'))
      .toBe('/api/devices/device%2Fone/export-jobs/job%2Ftwo/download')
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
