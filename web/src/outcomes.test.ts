import { describe, expect, it } from 'vitest'
import { antifraudOutcome, cdrOutcome, outcomeLabel } from './outcomes'

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
