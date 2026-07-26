import { describe, expect, it } from 'vitest'
import {
  antiFraudOverallText, antifraudOutcome, cdrOutcome, interpretAntiFraudOperation,
  outcomeLabel, terminalReasonLabel, terminalStateLabel,
} from './outcomes'

describe('call outcome semantics', () => {
  it('classifies CDR by Q.850 normal clearing', () => {
    expect(cdrOutcome(16)).toBe('success')
    expect(cdrOutcome(21)).toBe('failure')
    expect(cdrOutcome()).toBe('neutral')
  })

  it('prefers final Q.850 over the AntiFraud decision', () => {
    expect(antifraudOutcome({
      q850Cause: 16, decision: 'reject', completeness: 'complete',
    })).toBe('success')
    expect(antifraudOutcome({
      q850Cause: 34, decision: 'accept', completeness: 'complete',
    })).toBe('failure')
  })

  it('uses complete AntiFraud passage decisions without CDR', () => {
    expect(antifraudOutcome({ decision: 'accept', completeness: 'complete' })).toBe('success')
    expect(antifraudOutcome({ decision: 'reject', completeness: 'complete' })).toBe('failure')
    expect(antifraudOutcome({ decision: 'timeout_fail_open' })).toBe('warning')
    expect(antifraudOutcome({
      decision: 'verification_accept', completeness: 'complete',
    })).toBe('success')
    expect(antifraudOutcome({ decision: 'verification_reject' })).toBe('failure')
    expect(antifraudOutcome({ decision: 'verification_fail_open' })).toBe('warning')
    expect(outcomeLabel('neutral')).toBe('Нет результата')
  })
})

describe('AntiFraud operation wording', () => {
  it('keeps number and save_call responses informational', () => {
    for (const type of ['number', 'save_call']) {
      const result = interpretAntiFraudOperation({ type, terminalState: 'response_received' })
      expect(result).toEqual({
        outcome: 'neutral',
        label: 'Ответ получен',
        detail: 'Признаков блокировки нет',
      })
      expect(JSON.stringify(result).toLocaleLowerCase('ru')).not.toContain('разрешил')
    }
  })

  it('uses verification semantics only for check_call', () => {
    expect(interpretAntiFraudOperation({
      type: 'check_call', terminalState: 'verification_accept',
    }).label).toBe('Проверка принята')
    expect(interpretAntiFraudOperation({
      type: 'check_call', terminalState: 'verification_reject',
    }).outcome).toBe('failure')
    expect(interpretAntiFraudOperation({
      type: 'check_call', terminalState: 'verification_fail_open',
    }).outcome).toBe('warning')
  })

  it('summarizes two received responses neutrally and centralizes terminal labels', () => {
    expect(antiFraudOverallText([
      { type: 'number', terminalState: 'response_received' },
      { type: 'number', terminalState: 'response_received' },
    ])).toBe('Оба ответа AntiFraud получены; признаков блокировки нет.')
    expect(terminalStateLabel('response_received')).toBe('Ответ получен')
    expect(terminalReasonLabel('no_block_evidence')).toBe('Признаков блокировки нет')
  })

  it('uses authoritative blocked and fail-open summary states', () => {
    const operation = [{ type: 'check_call', terminalState: 'verification_fail_open' }]
    expect(antiFraudOverallText(operation, 'fail_open')).toContain('fail-open')
    expect(antiFraudOverallText(operation, 'blocked')).toContain('признак блокировки')
    expect(terminalStateLabel('ambiguous_response')).toBe('Неоднозначный ответ')
    expect(terminalReasonLabel('ambiguous_response'))
      .toBe('Неоднозначное соответствие ответа')
  })
})
