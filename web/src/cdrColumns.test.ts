import { describe, expect, it } from 'vitest'
import {
  CDR_PRESETS,
  ELTEX_CDR_COLUMNS,
  ELTEX_SUMMARY_KEYS,
  SATEL_CDR_COLUMNS,
  SATEL_SUMMARY_KEYS,
  defaultCdrPresetId,
  resolvePresetColumns,
} from './cdrColumns'

describe('CDR column presets', () => {
  it('ships Summary as the default preset before «Все данные»', () => {
    expect(CDR_PRESETS.map((preset) => preset.id)).toEqual(['summary', 'all'])
    expect(CDR_PRESETS[0]).toMatchObject({ id: 'summary', label: 'Summary' })
    expect(defaultCdrPresetId()).toBe('summary')
  })

  it('resolves eltex Summary in the agreed order', () => {
    const keys = resolvePresetColumns('eltex', 'summary').map((column) => column.key)
    expect(keys).toEqual(ELTEX_SUMMARY_KEYS)
    expect(keys).toEqual([
      'connectTime',
      'outgoingCgpn',
      'outgoingCdpn',
      'outgoingRedirectingNumber',
      'incomingDescription',
      'outgoingDescription',
      'durationMs',
      'releaseInfo',
      'voipmonitorCardUrl',
    ])
  })

  it('resolves satel Summary in the agreed order', () => {
    const keys = resolvePresetColumns('satel', 'summary').map((column) => column.key)
    expect(keys).toEqual(SATEL_SUMMARY_KEYS)
    expect(keys).toEqual([
      'setupTime',
      'billAni',
      'billDnis',
      'outOrigDnis',
      'srcName',
      'dstName',
      'dpName',
      'durationMs',
      'disconnectText',
      'voipmonitorCardUrl',
    ])
  })

  it('resolves eltex all-columns without rawFields or ingest keys', () => {
    const columns = resolvePresetColumns('eltex', 'all')
    const keys = columns.map((column) => column.key)
    expect(keys).toEqual(ELTEX_CDR_COLUMNS.map((column) => column.key))
    expect(keys).not.toContain('rawFields')
    expect(keys).not.toContain('deviceId')
    expect(keys).not.toContain('fileId')
    expect(keys).not.toContain('rowNumber')
    expect(keys).not.toContain('ingestedAt')
  })

  it('resolves satel all-columns without rawFields', () => {
    const columns = resolvePresetColumns('satel', 'all')
    const keys = columns.map((column) => column.key)
    expect(keys).toEqual(SATEL_CDR_COLUMNS.map((column) => column.key))
    expect(keys).not.toContain('rawFields')
    expect(keys.indexOf('billAniOperator')).toBe(keys.indexOf('billDnis') + 1)
    expect(keys.indexOf('billDnisOperator')).toBe(keys.indexOf('billAniOperator') + 1)
    expect(keys.indexOf('billAniRegion')).toBe(keys.indexOf('billDnisOperator') + 1)
    expect(keys.indexOf('billDnisRegion')).toBe(keys.indexOf('billAniRegion') + 1)
    expect(keys.indexOf('remoteSrcGeoipIso')).toBe(keys.indexOf('remoteDstSigAddress') + 1)
    expect(keys.indexOf('remoteDstAsnOrg')).toBe(keys.indexOf('remoteSrcGeoipIso') + 5)
  })

  it('falls back to Summary for unknown preset ids', () => {
    expect(resolvePresetColumns('eltex', 'unknown').map((column) => column.key))
      .toEqual(ELTEX_SUMMARY_KEYS)
    expect(resolvePresetColumns('satel', 'unknown').map((column) => column.key))
      .toEqual(SATEL_SUMMARY_KEYS)
  })
})
