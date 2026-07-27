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

  it('loads operational diagnostics from the admin endpoint on demand', () => {
    expect(main).toContain('OperationalDiagnosticsPanel')
    expect(main).toContain("'/system/diagnostics'")
    expect(main).toContain('<summary>Диагностика</summary>')
    expect(main).toContain('projectionQueue')
    expect(main).toContain('coverageSloMet')
    expect(main).toContain('Orphans / ambiguity')
    expect(main).toContain('Export · queued / running / oldest')
  })

  it('wires CDR ingest banner to the real ingest-files API', () => {
    expect(main).toContain('/ingest-files?limit=20')
    expect(main).toContain('CdrIngestBannerLoader')
    expect(main).toContain('CdrIngestBanner')
    expect(main).toContain('SatelPipelineNotice')
  })

  it('keeps EventRow aligned with syslog_messages API', () => {
    expect(main).toContain('payloadSha256: string')
    expect(main).toContain('truncated?: boolean')
    expect(main).not.toContain('rawPayload: string')
    expect(main).not.toContain('parseStatus: string')
    expect(main).not.toContain("category: string\n  component: string")
  })

  it('hides antifraud tab when antifraudEnabled is false', () => {
    const template = fallbackTemplates[0]
    expect(deviceSurfaces({ ...template, antifraudEnabled: false }))
      .toEqual(['calls', 'syslog'])
    expect(deviceSurfaces({ ...template, antifraudEnabled: true }))
      .toEqual(['calls', 'syslog', 'antifraud'])
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
