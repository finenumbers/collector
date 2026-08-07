import { describe, expect, it } from 'vitest'
import main from './main.tsx?raw'
import { deviceSurfaces, fallbackTemplates } from './equipment'

describe('custom antifraud UI cleanup', () => {
  it('removes legacy SyslogDiagnosticPanel fields and banners', () => {
    expect(main).not.toContain('SyslogDiagnosticPanel')
    expect(main).not.toContain('SyslogDiagnostics')
    expect(main).not.toContain('SyslogBreakdown')
    expect(main).not.toContain('parserProjectionStatus')
    expect(main).not.toContain('correlationStatus')
    expect(main).not.toContain('correlationAssignmentLag')
    expect(main).not.toContain('pendingDirtyBuckets')
    expect(main).not.toContain('unknownNoCategoryEvidence')
    expect(main).not.toContain('latestLifecycleAt')
    expect(main).not.toContain('breakdown.map')
    expect(main).not.toContain('Все Syslog')
    expect(main).not.toContain('Нераспознанное')
  })

  it('exposes runtime settings editor in system settings', () => {
    expect(main).toContain('RuntimeSettingsEditor')
    expect(main).toContain("'/system/runtime-settings'")
    expect(main).toContain('Параметры')
    expect(main).toContain('Обогащение CDR (PSTN / GeoIP)')
    expect(main).toContain('enrichmentApis')
    expect(main).toContain('Лимиты контейнеров Docker')
    expect(main).toContain('container-limits.env')
  })

  it('exposes searchable system audit logs grouped by category', () => {
    expect(main).toContain('SystemAuditLogsPanel')
    expect(main).toContain('/system/audit-logs?limit=300')
    expect(main).toContain('>Логи</button>')
    expect(main).toContain('AUDIT_CATEGORY_LABELS')
    expect(main).toContain('Аутентификация')
  })

  it('loads operational diagnostics from the admin endpoint on demand', () => {
    expect(main).toContain('OperationalDiagnosticsPanel')
    expect(main).toContain("'/system/diagnostics'")
    expect(main).toContain('<summary>Диагностика</summary>')
    expect(main).toContain('projectionQueue')
    expect(main).toContain('projectionDevices')
    expect(main).toContain('classificationGap')
    expect(main).toContain('maxDeviceLagSeconds')
    expect(main).toContain('coverageSloMet')
    expect(main).toContain('Orphans / ambiguity')
    expect(main).toContain('Export · queued / running / oldest')
    expect(main).toContain('projection/requeue-failed')
    expect(main).toContain('Requeue failed')
    expect(main).toContain('max event tip lag')
    expect(main).toContain('openHourStatus')
    expect(main).toContain('open-hour')
  })

  it('wires CDR ingest banner to the real ingest-files API', () => {
    expect(main).toContain('/ingest-files?limit=20')
    expect(main).toContain('CdrIngestBannerLoader')
    expect(main).toContain('CdrIngestBanner')
    expect(main).toContain('SatelPipelineNotice')
  })

  it('removes Syslog browse/find UI while keeping stats and freshness labels', () => {
    expect(main).not.toContain('type EventRow')
    expect(main).not.toContain('function EventsTable')
    expect(main).not.toContain('function EventsRawLog')
    expect(main).not.toContain('function EventDrawer')
    expect(main).not.toContain('syslogFind')
    expect(main).not.toContain('/syslog-messages')
    expect(main).not.toContain("label: 'Сообщения Syslog'")
    expect(main).not.toContain('FileClock')
    expect(main).toContain('Syslog сообщений')
    expect(main).toContain('Последний приём Syslog')
    expect(main).toContain("dataset === 'syslog' ? 'calls'")
  })

  it('shows degraded diagnostics and errors in Russian when present', () => {
    expect(main).toContain('degraded?: boolean')
    expect(main).toContain('errors?: Record<string, string>')
    expect(main).toContain("value.degraded ? 'частичный' : 'полный'")
    expect(main).toContain('Ошибки:')
  })

  it('hides antifraud tab when antifraudEnabled is false', () => {
    const template = fallbackTemplates[0]
    expect(deviceSurfaces({ ...template, antifraudEnabled: false }))
      .toEqual(['calls'])
    expect(deviceSurfaces({ ...template, antifraudEnabled: true }))
      .toEqual(['calls', 'antifraud'])
    expect(main).toContain('deviceSurfaces(device)')
  })

  it('does not expose antifraudMode or vendor mode selectors', () => {
    expect(main).not.toContain('antifraudMode')
    expect(main).not.toContain('Astarta')
    expect(main).not.toContain('Intek')
    expect(main).toContain('antifraudEnabled')
    expect(main).toContain('Используется АнтиФрод')
  })

  it('keeps CallDrawer and AntifraudDrawer as coverage dialogue only', () => {
    expect(main).toContain('function CallDrawer')
    expect(main).toContain('function AntifraudDrawer')
    expect(main).toContain('SharedCallCard')
    expect(main).toContain('Покрытие AntiFraud')
    expect(main).toContain('Цепочка AntiFraud')
    expect(main).toContain('AntiFraud JSON')
    expect(main).toContain('antifraudTranscript')
    expect(main).toContain('formatAntifraudTranscript')
    expect(main).toContain('drawer-header')
    expect(main).not.toContain('Пакеты и атрибуты')
  })
})
