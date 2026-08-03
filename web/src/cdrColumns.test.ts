import { describe, expect, it } from 'vitest'
import {
  CDR_PRESETS,
  ELTEX_CDR_COLUMNS,
  ELTEX_SUMMARY_KEYS,
  SATEL_CDR_COLUMNS,
  SATEL_GEOIP_KEYS,
  SATEL_OPERATORS_KEYS,
  SATEL_SUMMARY_KEYS,
  cdrPresetsForVendor,
  defaultCdrPresetId,
  eltexPresetFlexShare,
  resolvePresetColumns,
  satelPresetFillWidth,
  satelPresetFlexPairKeys,
  satelPresetFlexShare,
} from './cdrColumns'

describe('CDR column presets', () => {
  it('ships Summary before GeoIP, Операторы, and «Все данные»', () => {
    expect(CDR_PRESETS.map((preset) => preset.id)).toEqual([
      'summary', 'geoip', 'operators', 'all',
    ])
    expect(CDR_PRESETS[0]).toMatchObject({ id: 'summary', label: 'Summary' })
    expect(defaultCdrPresetId()).toBe('summary')
  })

  it('exposes Satel-only presets only for satel vendor', () => {
    expect(cdrPresetsForVendor('satel').map((preset) => preset.id)).toEqual([
      'summary', 'geoip', 'operators', 'all',
    ])
    expect(cdrPresetsForVendor('eltex').map((preset) => preset.id)).toEqual([
      'summary', 'all',
    ])
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

  it('resolves satel GeoIP preset in the agreed order', () => {
    expect(resolvePresetColumns('satel', 'geoip').map((column) => column.key))
      .toEqual(SATEL_GEOIP_KEYS)
    expect(SATEL_GEOIP_KEYS.indexOf('remoteSrcGeoipIso')).toBeLessThan(
      SATEL_GEOIP_KEYS.indexOf('remoteDstGeoipIso'),
    )
    expect(SATEL_GEOIP_KEYS.indexOf('remoteDstGeoipIso')).toBeLessThan(
      SATEL_GEOIP_KEYS.indexOf('remoteSrcGeoipCity'),
    )
  })

  it('resolves satel Операторы preset in the agreed order', () => {
    expect(resolvePresetColumns('satel', 'operators').map((column) => column.key))
      .toEqual(SATEL_OPERATORS_KEYS)
    expect(SATEL_OPERATORS_KEYS).not.toContain('voipmonitorCardUrl')
  })

  it('falls back eltex geoip/operators session values to Summary', () => {
    expect(resolvePresetColumns('eltex', 'geoip').map((column) => column.key))
      .toEqual(ELTEX_SUMMARY_KEYS)
    expect(resolvePresetColumns('eltex', 'operators').map((column) => column.key))
      .toEqual(ELTEX_SUMMARY_KEYS)
  })

  it('uses fill-width and equal-share layout helpers for Satel/Eltex presets', () => {
    expect(satelPresetFillWidth('summary')).toBe(true)
    expect(satelPresetFillWidth('geoip')).toBe(true)
    expect(satelPresetFillWidth('operators')).toBe(true)
    expect(satelPresetFillWidth('all')).toBe(false)
    expect(satelPresetFlexShare('summary')).toEqual({
      keys: ['srcName', 'dstName', 'dpName'],
      className: 'col-flex-3',
    })
    expect(satelPresetFlexShare('geoip')).toEqual({
      keys: ['remoteSrcAsnOrg', 'remoteDstAsnOrg'],
      className: 'col-flex-pair',
    })
    expect(satelPresetFlexShare('operators')).toEqual({
      keys: ['billAniOperator', 'billAniRegion', 'billDnisOperator', 'billDnisRegion'],
      className: 'col-flex-4',
    })
    expect(satelPresetFlexPairKeys('geoip')).toEqual([
      'remoteSrcAsnOrg', 'remoteDstAsnOrg',
    ])
    expect(satelPresetFlexPairKeys('operators')).toEqual([])
    expect(eltexPresetFlexShare('summary')).toEqual({
      keys: ['incomingDescription', 'outgoingDescription', 'releaseInfo'],
      className: 'col-flex-3',
    })
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
