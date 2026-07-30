export type CdrVendor = 'eltex' | 'satel'

export type CdrColumnDef = {
  key: string
  header: string
  align?: 'left' | 'right'
  mono?: boolean
}

export type CdrPreset = {
  id: string
  label: string
  /** 'all' = full registry; string[] only when vendor-agnostic (unused for Summary). */
  columns: 'all' | string[]
}

/** Canonical full Eltex typed CDR columns (no rawFields / ingest keys). */
export const ELTEX_CDR_COLUMNS: CdrColumnDef[] = [
  { key: 'setupTime', header: 'Установка', mono: true },
  { key: 'connectTime', header: 'Соединение', mono: true },
  { key: 'disconnectTime', header: 'Завершение', mono: true },
  { key: 'durationMs', header: 'Длит.', align: 'right' },
  { key: 'releaseCause', header: 'Q.850', align: 'right' },
  { key: 'releaseInfo', header: 'Результат' },
  { key: 'releaseSide', header: 'Сторона' },
  { key: 'incomingDescription', header: 'Входящий маршрут' },
  { key: 'outgoingDescription', header: 'Исходящий маршрут' },
  { key: 'incomingType', header: 'Тип вход' },
  { key: 'outgoingType', header: 'Тип выход' },
  { key: 'incomingIp', header: 'IP вход', mono: true },
  { key: 'outgoingIp', header: 'IP выход', mono: true },
  { key: 'incomingCgpn', header: 'Номер A: вход', mono: true },
  { key: 'outgoingCgpn', header: 'Номер A: выход', mono: true },
  { key: 'incomingCdpn', header: 'Номер B: вход', mono: true },
  { key: 'outgoingCdpn', header: 'Номер B: выход', mono: true },
  { key: 'incomingRedirectingNumber', header: 'Redirecting вход', mono: true },
  { key: 'outgoingRedirectingNumber', header: 'Redirecting выход', mono: true },
  { key: 'incomingNumplan', header: 'Numplan вход' },
  { key: 'outgoingNumplan', header: 'Numplan выход' },
  { key: 'callingNai', header: 'NAI A' },
  { key: 'calledNai', header: 'NAI B' },
  { key: 'incomingE1Stream', header: 'E1 stream вход', mono: true },
  { key: 'incomingE1Channel', header: 'E1 ch вход', mono: true },
  { key: 'outgoingE1Stream', header: 'E1 stream выход', mono: true },
  { key: 'outgoingE1Channel', header: 'E1 ch выход', mono: true },
  { key: 'incomingSipCallId', header: 'SIP Call-ID вход', mono: true },
  { key: 'outgoingSipCallId', header: 'SIP Call-ID выход', mono: true },
  { key: 'incomingSs7Cic', header: 'SS7 CIC вход', align: 'right', mono: true },
  { key: 'outgoingSs7Cic', header: 'SS7 CIC выход', align: 'right', mono: true },
  { key: 'radiusSessionId', header: 'Acct-Session-Id', mono: true },
  { key: 'radiusSessionIdNormalized', header: 'Acct-Session-Id norm', mono: true },
  { key: 'globalCallref', header: 'Global Callref', mono: true },
  { key: 'uniqueTag', header: 'UniqueTag', mono: true },
  { key: 'transferMark', header: 'Transfer' },
  { key: 'rejectingRadiusServer', header: 'Rejecting RADIUS', mono: true },
  { key: 'sequenceNumber', header: 'Seq number', mono: true },
  { key: 'bootEpoch', header: 'Boot epoch', mono: true },
  { key: 'sequence', header: 'Sequence', align: 'right' },
  { key: 'sourceTimezone', header: 'Timezone' },
  { key: 'sourceUtcOffsetMinutes', header: 'UTC offset', align: 'right' },
  { key: 'setupTimeLocal', header: 'Установка local', mono: true },
  { key: 'recordId', header: 'Record ID', mono: true },
  { key: 'voipmonitorCardUrl', header: 'VoIPmonitor' },
]

/** Canonical full Satel typed CDR columns (no rawFields). */
export const SATEL_CDR_COLUMNS: CdrColumnDef[] = [
  { key: 'setupTime', header: 'Установка', mono: true },
  { key: 'connectTime', header: 'Соединение', mono: true },
  { key: 'disconnectTime', header: 'Завершение', mono: true },
  { key: 'outcome', header: 'Результат' },
  { key: 'inAni', header: 'ANI вход', mono: true },
  { key: 'inDnis', header: 'DNIS вход', mono: true },
  { key: 'outAni', header: 'ANI выход', mono: true },
  { key: 'outDnis', header: 'DNIS выход', mono: true },
  { key: 'billAni', header: 'Bill ANI', mono: true },
  { key: 'billDnis', header: 'Bill DNIS', mono: true },
  { key: 'billAniOperator', header: 'Оператор A' },
  { key: 'billDnisOperator', header: 'Оператор B' },
  { key: 'billAniRegion', header: 'Регион A' },
  { key: 'billDnisRegion', header: 'Регион B' },
  { key: 'srcName', header: 'Src маршрут' },
  { key: 'dstName', header: 'Dst маршрут' },
  { key: 'dpName', header: 'DP маршрут' },
  { key: 'durationMs', header: 'Длительность', align: 'right' },
  { key: 'elapsedTime', header: 'Elapsed', align: 'right' },
  { key: 'protocols', header: 'Протоколы' },
  { key: 'inLegProto', header: 'In proto' },
  { key: 'outLegProto', header: 'Out proto' },
  { key: 'inLegTransportProto', header: 'In transport' },
  { key: 'outLegTransportProto', header: 'Out transport' },
  { key: 'disconnectText', header: 'Разъединение' },
  { key: 'disconnectCode', header: 'Код', align: 'right' },
  { key: 'disconnectSuccess', header: 'Успех' },
  { key: 'disconnectInitiator', header: 'Инициатор' },
  { key: 'signalNodeName', header: 'Узел' },
  { key: 'cdrId', header: 'CDR ID', mono: true },
  { key: 'confId', header: 'Conf ID', mono: true },
  { key: 'inLegCallId', header: 'In Call-ID', mono: true },
  { key: 'outLegCallId', header: 'Out Call-ID', mono: true },
  { key: 'srcInLegConfId', header: 'Src conf ID', mono: true },
  { key: 'srcInLegCallId', header: 'Src in Call-ID', mono: true },
  { key: 'srcOutLegCallId', header: 'Src out Call-ID', mono: true },
  { key: 'srcUser', header: 'Src user', mono: true },
  { key: 'dstUser', header: 'Dst user', mono: true },
  { key: 'radiusUser', header: 'RADIUS user', mono: true },
  { key: 'inCpc', header: 'In CPC' },
  { key: 'outCpc', header: 'Out CPC' },
  { key: 'inZone', header: 'In zone' },
  { key: 'outZone', header: 'Out zone' },
  { key: 'inOrigDnis', header: 'In orig DNIS', mono: true },
  { key: 'outOrigDnis', header: 'Out orig DNIS', mono: true },
  { key: 'inAniTypeOfNumber', header: 'In ANI TON' },
  { key: 'inDnisTypeOfNumber', header: 'In DNIS TON' },
  { key: 'outAniTypeOfNumber', header: 'Out ANI TON' },
  { key: 'outDnisTypeOfNumber', header: 'Out DNIS TON' },
  { key: 'inOrigDnisTypeOfNumber', header: 'In orig DNIS TON' },
  { key: 'outOrigDnisTypeOfNumber', header: 'Out orig DNIS TON' },
  { key: 'extAniTypeOfNumber', header: 'Ext ANI TON' },
  { key: 'extDnisTypeOfNumber', header: 'Ext DNIS TON' },
  { key: 'extOrigDnisTypeOfNumber', header: 'Ext orig DNIS TON' },
  { key: 'inAniScreening', header: 'In ANI screening' },
  { key: 'inAniPresentation', header: 'In ANI presentation' },
  { key: 'outAniScreening', header: 'Out ANI screening' },
  { key: 'outAniPresentation', header: 'Out ANI presentation' },
  { key: 'inLrn', header: 'In LRN', mono: true },
  { key: 'retrievedLrn', header: 'Retrieved LRN', mono: true },
  { key: 'lrn', header: 'LRN', mono: true },
  { key: 'extLrn', header: 'Ext LRN', mono: true },
  { key: 'outLrn', header: 'Out LRN', mono: true },
  { key: 'lnpServer', header: 'LNP server' },
  { key: 'srcGatekeeperAddress', header: 'Src GK', mono: true },
  { key: 'remoteSrcSigAddress', header: 'Remote src sig', mono: true },
  { key: 'remoteDstSigAddress', header: 'Remote dst sig', mono: true },
  { key: 'remoteSrcGeoipIso', header: 'GeoIP ISO A' },
  { key: 'remoteSrcGeoipCity', header: 'GeoIP City A' },
  { key: 'remoteSrcAsnOrg', header: 'ASN Org A' },
  { key: 'remoteDstGeoipIso', header: 'GeoIP ISO B' },
  { key: 'remoteDstGeoipCity', header: 'GeoIP City B' },
  { key: 'remoteDstAsnOrg', header: 'ASN Org B' },
  { key: 'remoteSrcMediaAddress', header: 'Remote src media', mono: true },
  { key: 'remoteDstMediaAddress', header: 'Remote dst media', mono: true },
  { key: 'localSrcSigAddress', header: 'Local src sig', mono: true },
  { key: 'localDstSigAddress', header: 'Local dst sig', mono: true },
  { key: 'localSrcMediaAddress', header: 'Local src media', mono: true },
  { key: 'localDstMediaAddress', header: 'Local dst media', mono: true },
  { key: 'inLegCodecs', header: 'In codecs' },
  { key: 'outLegCodecs', header: 'Out codecs' },
  { key: 'srcDisconnectCodes', header: 'Src disc codes' },
  { key: 'dstDisconnectCodes', header: 'Dst disc codes' },
  { key: 'srcDisconnectText', header: 'Src disc text' },
  { key: 'dstDisconnectText', header: 'Dst disc text' },
  { key: 'pdd', header: 'PDD', align: 'right' },
  { key: 'scd', header: 'SCD', align: 'right' },
  { key: 'termElapsedTime', header: 'Term elapsed', align: 'right' },
  { key: 'termSetupTime', header: 'Term setup', mono: true },
  { key: 'termConnectTime', header: 'Term connect', mono: true },
  { key: 'termDisconnectTime', header: 'Term disconnect', mono: true },
  { key: 'termPdd', header: 'Term PDD', align: 'right' },
  { key: 'termScd', header: 'Term SCD', align: 'right' },
  { key: 'srcMediaBytesIn', header: 'Src bytes in', align: 'right' },
  { key: 'srcMediaBytesOut', header: 'Src bytes out', align: 'right' },
  { key: 'dstMediaBytesIn', header: 'Dst bytes in', align: 'right' },
  { key: 'dstMediaBytesOut', header: 'Dst bytes out', align: 'right' },
  { key: 'srcMediaPackets', header: 'Src packets', align: 'right' },
  { key: 'dstMediaPackets', header: 'Dst packets', align: 'right' },
  { key: 'srcMediaPacketsLate', header: 'Src late', align: 'right' },
  { key: 'dstMediaPacketsLate', header: 'Dst late', align: 'right' },
  { key: 'srcMediaPacketsLost', header: 'Src lost', align: 'right' },
  { key: 'dstMediaPacketsLost', header: 'Dst lost', align: 'right' },
  { key: 'srcMinJitter', header: 'Src jitter min', align: 'right' },
  { key: 'srcMaxJitter', header: 'Src jitter max', align: 'right' },
  { key: 'dstMinJitter', header: 'Dst jitter min', align: 'right' },
  { key: 'dstMaxJitter', header: 'Dst jitter max', align: 'right' },
  { key: 'routeRetries', header: 'Route retries', align: 'right' },
  { key: 'outgoingPulses', header: 'Out pulses', align: 'right' },
  { key: 'incomingPulses', header: 'In pulses', align: 'right' },
  { key: 'loopingCycles', header: 'Looping', align: 'right' },
  { key: 'proxyMode', header: 'Proxy mode' },
  { key: 'larFaultReason', header: 'LAR fault' },
  { key: 'mediaGroup', header: 'Media group' },
  { key: 'externalRouter', header: 'External router' },
  { key: 'radiusGroup', header: 'RADIUS group' },
  { key: 'sipRoutingGroup', header: 'SIP routing group' },
  { key: 'authDnis', header: 'Auth DNIS', mono: true },
  { key: 'extAni', header: 'Ext ANI', mono: true },
  { key: 'extDnis', header: 'Ext DNIS', mono: true },
  { key: 'extSigAddress', header: 'Ext sig', mono: true },
  { key: 'inPartnerId', header: 'In partner' },
  { key: 'outPartnerId', header: 'Out partner' },
  { key: 'inEncryption', header: 'In encryption' },
  { key: 'outEncryption', header: 'Out encryption' },
  { key: 'recordType', header: 'Record type' },
  { key: 'lastCdr', header: 'Last CDR' },
  { key: 'cdrDate', header: 'CDR date', mono: true },
  { key: 'parserVersion', header: 'Parser' },
  { key: 'sourceTimezone', header: 'Timezone' },
  { key: 'sourceUtcOffsetMinutes', header: 'UTC offset', align: 'right' },
  { key: 'setupTimeLocal', header: 'Установка local', mono: true },
  { key: 'recordId', header: 'Record ID', mono: true },
  { key: 'voipmonitorCardUrl', header: 'VoIPmonitor' },
]

export const ELTEX_SUMMARY_KEYS = [
  'connectTime',
  'outgoingCgpn',
  'outgoingCdpn',
  'outgoingRedirectingNumber',
  'incomingDescription',
  'outgoingDescription',
  'durationMs',
  'releaseInfo',
  'voipmonitorCardUrl',
]

export const SATEL_SUMMARY_KEYS = [
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
]

export const SATEL_GEOIP_KEYS = [
  'setupTime',
  'billAni',
  'billDnis',
  'remoteSrcGeoipIso',
  'remoteDstGeoipIso',
  'remoteSrcGeoipCity',
  'remoteSrcAsnOrg',
  'remoteDstGeoipCity',
  'remoteDstAsnOrg',
  'durationMs',
  'disconnectText',
  'voipmonitorCardUrl',
]

export const SATEL_OPERATORS_KEYS = [
  'setupTime',
  'billAni',
  'billDnis',
  'billAniOperator',
  'billAniRegion',
  'billDnisOperator',
  'billDnisRegion',
  'durationMs',
  'disconnectText',
]

export const CDR_PRESETS: CdrPreset[] = [
  { id: 'summary', label: 'Summary', columns: ELTEX_SUMMARY_KEYS },
  { id: 'geoip', label: 'GeoIP', columns: SATEL_GEOIP_KEYS },
  { id: 'operators', label: 'Операторы', columns: SATEL_OPERATORS_KEYS },
  { id: 'all', label: 'Все данные', columns: 'all' },
]

const SATEL_ONLY_PRESET_IDS = new Set(['geoip', 'operators'])

const PRESET_STORAGE_PREFIX = 'collector:cdr-preset:'

export function cdrPresetStorageKey(deviceId: string): string {
  return `${PRESET_STORAGE_PREFIX}${deviceId}`
}

export function cdrPresetsForVendor(vendor: CdrVendor): CdrPreset[] {
  if (vendor === 'satel') return CDR_PRESETS
  return CDR_PRESETS.filter((preset) => !SATEL_ONLY_PRESET_IDS.has(preset.id))
}

function columnsByKeys(all: CdrColumnDef[], keys: string[]): CdrColumnDef[] {
  const byKey = new Map(all.map((column) => [column.key, column]))
  return keys.flatMap((key) => {
    const column = byKey.get(key)
    return column ? [column] : []
  })
}

export function resolvePresetColumns(vendor: CdrVendor, presetId: string): CdrColumnDef[] {
  const all = vendor === 'eltex' ? ELTEX_CDR_COLUMNS : SATEL_CDR_COLUMNS
  const available = cdrPresetsForVendor(vendor)
  const known = available.some((preset) => preset.id === presetId)
  const id = known ? presetId : 'summary'
  if (id === 'all') return all
  if (id === 'summary') {
    return columnsByKeys(all, vendor === 'eltex' ? ELTEX_SUMMARY_KEYS : SATEL_SUMMARY_KEYS)
  }
  if (vendor === 'satel' && id === 'geoip') {
    return columnsByKeys(all, SATEL_GEOIP_KEYS)
  }
  if (vendor === 'satel' && id === 'operators') {
    return columnsByKeys(all, SATEL_OPERATORS_KEYS)
  }
  return columnsByKeys(all, vendor === 'eltex' ? ELTEX_SUMMARY_KEYS : SATEL_SUMMARY_KEYS)
}

export function defaultCdrPresetId(): string {
  return CDR_PRESETS[0]?.id || 'summary'
}

/** Full-width Satel presets that use table-fit layout. */
export function satelPresetFillWidth(presetId: string): boolean {
  return presetId === 'summary' || presetId === 'geoip' || presetId === 'operators'
}

/** Keys that share remaining width equally (col-flex-pair). */
export function satelPresetFlexPairKeys(presetId: string): string[] {
  if (presetId === 'geoip') return ['remoteSrcAsnOrg', 'remoteDstAsnOrg']
  if (presetId === 'operators') return ['billAniRegion', 'billDnisRegion']
  return []
}

/** Single column that absorbs leftover width (col-flex). */
export function satelPresetFlexKey(presetId: string): string {
  return presetId === 'summary' ? 'disconnectText' : ''
}
