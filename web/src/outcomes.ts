export type CallOutcome = 'success' | 'failure' | 'warning' | 'neutral'

export type AntiFraudOperationInterpretation = {
  outcome: CallOutcome
  label: string
  detail: string
}

export function cdrOutcome(releaseCause?: number): CallOutcome {
  if (releaseCause == null) return 'neutral'
  return releaseCause === 16 ? 'success' : 'failure'
}

export function antifraudOutcome(row: {
  q850Cause?: number
  decision?: string
  completeness?: string
}): CallOutcome {
  if (row.q850Cause != null) return cdrOutcome(row.q850Cause)
  if (row.decision === 'reject' || row.decision === 'verification_reject') return 'failure'
  if ((row.decision === 'accept' || row.decision === 'verification_accept') &&
    row.completeness === 'complete') return 'success'
  if (row.decision === 'timeout_fail_open' ||
    row.decision === 'verification_fail_open') return 'warning'
  return 'neutral'
}

export function outcomeLabel(outcome: CallOutcome): string {
  switch (outcome) {
    case 'success': return 'Успешно'
    case 'failure': return 'Неуспешно'
    case 'warning': return 'Требует внимания'
    default: return 'Нет результата'
  }
}

const operationLabels: Record<string, string> = {
  number: 'Индикация номера',
  save_call: 'Сохранение вызова',
  check_call: 'Проверка вызова',
  accounting: 'Accounting',
}

const terminalLabels: Record<string, string> = {
  outstanding: 'Ожидается ответ',
  response_received: 'Ответ получен',
  verification_accept: 'Проверка принята',
  verification_reject: 'Проверка отклонена',
  verification_fail_open: 'Продолжено без проверки',
  informational: 'Информационный ответ',
  accounting_complete: 'Accounting завершён',
  accounting_incomplete: 'Accounting не завершён',
  incomplete_response: 'Неполный ответ',
  ambiguous: 'Неоднозначный ответ',
  ambiguous_response: 'Неоднозначный ответ',
}

const terminalReasonLabels: Record<string, string> = {
  indication_response: 'Информационный ответ',
  no_block_evidence: 'Признаков блокировки нет',
  timeout_or_unavailable: 'Timeout / сервер недоступен',
  incomplete_response: 'Ответ без запроса',
  unexpected_response: 'Неожиданный ответ',
  ambiguous: 'Неоднозначное соответствие ответа',
  ambiguous_response: 'Неоднозначное соответствие ответа',
  ambiguous_session_collision: 'Несколько CDR с одной сессией',
}

export function operationTypeLabel(value: string): string {
  return operationLabels[value] || value || 'Не определена'
}

export function terminalStateLabel(value: string): string {
  return terminalLabels[value] || value || 'Состояние неизвестно'
}

export function terminalReasonLabel(value: string): string {
  return terminalReasonLabels[value] || value || '—'
}

export function decisionLabel(value: string): string {
  switch (value) {
    case 'accept':
    case 'verification_accept': return 'Проверка принята'
    case 'reject':
    case 'verification_reject': return 'Проверка отклонена'
    case 'timeout_fail_open':
    case 'verification_fail_open': return 'Продолжено без проверки'
    case 'informational': return 'Информационный ответ'
    default: return 'Ожидается / неизвестно'
  }
}

export function interpretAntiFraudOperation(operation: {
  type: string
  terminalState: string
}): AntiFraudOperationInterpretation {
  if (operation.type === 'number' || operation.type === 'save_call') {
    if (operation.terminalState === 'response_received' ||
      operation.terminalState === 'informational') {
      return {
        outcome: 'neutral',
        label: 'Ответ получен',
        detail: 'Признаков блокировки нет',
      }
    }
    if (operation.terminalState === 'outstanding') {
      return { outcome: 'neutral', label: 'Ответ ожидается', detail: 'Решение не сформировано' }
    }
    return {
      outcome: 'neutral',
      label: terminalStateLabel(operation.terminalState),
      detail: terminalReasonLabel(operation.terminalState),
    }
  }

  switch (operation.terminalState) {
    case 'verification_accept':
      return { outcome: 'success', label: 'Проверка принята', detail: 'Вызов продолжен' }
    case 'verification_reject':
      return { outcome: 'failure', label: 'Проверка отклонена', detail: 'Есть признак блокировки' }
    case 'verification_fail_open':
      return {
        outcome: 'warning',
        label: 'Проверка не выполнена',
        detail: 'Вызов продолжен по fail-open',
      }
    default:
      return {
        outcome: 'neutral',
        label: terminalStateLabel(operation.terminalState),
        detail: 'Решение не сформировано',
      }
  }
}

export function antiFraudOverallText(operations: Array<{
  type: string
  terminalState: string
}>, overallStatus?: string): string {
  if (overallStatus === 'blocked') {
    return 'AntiFraud зафиксировал признак блокировки.'
  }
  if (overallStatus === 'fail_open') {
    return 'Проверка AntiFraud не выполнена; вызов продолжен по fail-open.'
  }
  const interpreted = operations.map(interpretAntiFraudOperation)
  const noBlocking = interpreted.every((item) => item.outcome !== 'failure')
  const allResponses = operations.every((item) => [
    'response_received', 'informational', 'verification_accept', 'verification_reject',
  ].includes(item.terminalState))
  if (operations.length === 2 && allResponses && noBlocking) {
    return 'Оба ответа AntiFraud получены; признаков блокировки нет.'
  }
  if (operations.length > 0 && allResponses && noBlocking) {
    return 'Ответы AntiFraud получены; признаков блокировки нет.'
  }
  if (interpreted.some((item) => item.outcome === 'failure')) {
    return 'AntiFraud зафиксировал признак блокировки.'
  }
  return 'Ожидаются ответы AntiFraud; итог не сформирован.'
}
