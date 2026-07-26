import {
  antiFraudOverallText,
  interpretAntiFraudOperation,
  operationTypeLabel,
  terminalReasonLabel,
  terminalStateLabel,
} from './outcomes'

export type CallAntiFraudSummary = {
  projectionStatus: string
  parserVersion: string
  building: boolean
  cdr: {
    recordId: string
    setupTime?: string
    durationMs?: number
    q850Cause?: number
    incomingNumber: string
    incomingDestination: string
    outgoingNumber: string
    outgoingDestination: string
    incomingRoute: string
    outgoingRoute: string
    radiusSessionId: string
  }
  call?: {
    callId: string
    identityKind: string
    identityValue: string
    h323ConfId: string
    callContexts: string[]
    legSessionIds: string[]
    legSessionIdsNormalized: string[]
  }
  operations: CallAntiFraudSummaryOperation[]
  overallStatus: string
  warnings: string[]
}

export type CallAntiFraudSummaryOperation = {
  operationId: string
  occurredAt: string
  type: string
  legDirection: string
  legSessionId: string
  callContext: string
  srcNumberIn: string
  dstNumberIn: string
  srcNumberOut: string
  dstNumberOut: string
  requestIdentifier?: number
  requestCode: string
  responseIdentifier?: number
  responseCode: string
  latencyMs?: number
  retries: number
  terminalState: string
  terminalReason: string
  correlationState: string
  correlationMethod: string
  correlationEvidence: Record<string, string>
}

export type AntiFraudSummaryState =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; summary: CallAntiFraudSummary }

type Props = {
  state: AntiFraudSummaryState
  onRetry: () => void
}

function packetIdentifier(value?: number) {
  return value == null ? '—' : String(value).padStart(3, '0')
}

function legDirectionLabel(value: string) {
  if (value === 'inbound') return 'IN'
  if (value === 'outbound') return 'OUT'
  return '—'
}

function correlationStateLabel(value: string) {
  switch (value) {
    case 'exact': return 'Точное соответствие'
    case 'composite': return 'Составное соответствие'
    case 'linked': return 'Связано'
    case 'ambiguous': return 'Неоднозначно'
    case 'orphan':
    case 'unlinked': return 'Не связано'
    default: return value || '—'
  }
}

function correlationMethodLabel(value: string) {
  switch (value) {
    case 'exact_h323_conf_id': return 'H.323 Conf-ID'
    case 'exact_acct_session': return 'Acct-Session-Id'
    case 'composite_numbers_time': return 'Номера и время'
    default: return value || '—'
  }
}

function OperationRow({ operation }: { operation: CallAntiFraudSummaryOperation }) {
  const result = interpretAntiFraudOperation(operation)
  const delta = operation.correlationEvidence?.timeDeltaMs
  return <li className={`antifraud-operation outcome-${result.outcome}`}>
    <div className="antifraud-operation-main">
      <span className="antifraud-leg" aria-label={`Направление ${legDirectionLabel(operation.legDirection)}`}>
        {legDirectionLabel(operation.legDirection)}
      </span>
      <span className="antifraud-operation-type">
        <strong>{operationTypeLabel(operation.type)}</strong>
        <small>{result.label} · {result.detail}</small>
      </span>
      <span className="antifraud-packets" aria-label="Идентификаторы пакетов запроса и ответа">
        <small>Пакеты</small>
        <strong className="mono">{packetIdentifier(operation.requestIdentifier)}
          {' → '}{packetIdentifier(operation.responseIdentifier)}</strong>
      </span>
      <span className="antifraud-metric">
        <small>Задержка</small><strong>{operation.latencyMs == null ? '—' : `${operation.latencyMs} мс`}</strong>
      </span>
      <span className="antifraud-metric">
        <small>Повторы</small><strong>{operation.retries}</strong>
      </span>
    </div>
    <details className="antifraud-evidence">
      <summary>Доказательства связи</summary>
      <dl>
        <div><dt>Корреляция</dt><dd>{correlationStateLabel(operation.correlationState)}
          {' · '}{correlationMethodLabel(operation.correlationMethod)}</dd></div>
        <div><dt>Сессия плеча</dt><dd className="mono">{operation.legSessionId || '—'}</dd></div>
        <div><dt>Контекст вызова</dt><dd className="mono">{operation.callContext || '—'}</dd></div>
        <div><dt>Конечное состояние</dt><dd>{terminalStateLabel(operation.terminalState)}</dd></div>
        <div><dt>Причина</dt><dd>{terminalReasonLabel(operation.terminalReason)}</dd></div>
        <div><dt>Разница времени</dt><dd>{delta == null || delta === '' ? '—' : `${delta} мс`}</dd></div>
      </dl>
    </details>
  </li>
}

export function AntiFraudSummary({ state, onRetry }: Props) {
  if (state.kind === 'loading') {
    return <section className="antifraud-summary" aria-busy="true" aria-label="Сводка AntiFraud">
      <h4>Сводка AntiFraud</h4>
      <div className="antifraud-summary-state"><span className="antifraud-skeleton" />
        Загружаем связанные операции…</div>
    </section>
  }
  if (state.kind === 'error') {
    return <section className="antifraud-summary" aria-label="Сводка AntiFraud">
      <h4>Сводка AntiFraud</h4>
      <div className="antifraud-summary-state antifraud-summary-error" role="alert">
        <span>Не удалось загрузить сводку: {state.message}</span>
        <button type="button" className="secondary" onClick={onRetry}>Повторить</button>
      </div>
    </section>
  }

  const { summary } = state
  if (summary.building || summary.projectionStatus === 'building') {
    return <section className="antifraud-summary" aria-label="Сводка AntiFraud">
      <h4>Сводка AntiFraud</h4>
      <div className="antifraud-summary-state" role="status">
        Сводка строится: исторические события AntiFraud ещё обрабатываются. Данные появятся после replay.
      </div>
    </section>
  }
  if (summary.operations.length === 0) {
    return <section className="antifraud-summary" aria-label="Сводка AntiFraud">
      <h4>Сводка AntiFraud</h4>
      <div className="antifraud-summary-state">
        Для этого CDR нет связанных операций AntiFraud.
      </div>
    </section>
  }

  const normalizedAliases = summary.call?.legSessionIdsNormalized?.filter(Boolean) || []
  const aliases = new Set(normalizedAliases.length > 0
    ? normalizedAliases
    : summary.call?.legSessionIds?.filter(Boolean) || [])
  return <section className="antifraud-summary" aria-label="Сводка AntiFraud">
    <h4>Сводка AntiFraud</h4>
    <p className="antifraud-overall">
      {antiFraudOverallText(summary.operations, summary.overallStatus)}
    </p>
    <div className="antifraud-call">
      <span><small>Входящий CDR</small><strong className="mono">
        {summary.cdr.incomingNumber || '—'} → {summary.cdr.incomingDestination || '—'}</strong></span>
      <span><small>Маршрутизированный CDR</small><strong className="mono">
        {summary.cdr.outgoingNumber || '—'} → {summary.cdr.outgoingDestination || '—'}</strong></span>
      <span><small>Каноническая identity</small><strong className="mono">
        {summary.call?.identityValue || summary.call?.h323ConfId || '—'}</strong></span>
      <span><small>Алиасы плеч</small><strong>{aliases.size}</strong></span>
    </div>
    <ol className="antifraud-operations" aria-label="Операции AntiFraud">
      {summary.operations.map((operation) =>
        <OperationRow operation={operation} key={operation.operationId} />)}
    </ol>
  </section>
}
