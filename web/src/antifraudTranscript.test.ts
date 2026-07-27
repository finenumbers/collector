import { describe, expect, it } from 'vitest'
import { canonicalTranscriptSteps, formatAntifraudTranscript } from './antifraudTranscript'

describe('canonical AntiFraud transcript', () => {
  it('keeps every indication attempt including no_response', () => {
    expect(canonicalTranscriptSteps([
      { phase: 'indication', summary: 'number -> Access-Response', xpgkRequestType: 'number' },
      { phase: 'indication', summary: 'number -> no_response', xpgkRequestType: 'number' },
    ])).toEqual([
      'indication: number -> Access-Accept',
      'indication: number -> no_response',
    ])
  })

  it('keeps verification no_response and accounting Stop', () => {
    expect(canonicalTranscriptSteps([
      { phase: 'indication', summary: 'save_call -> Access-Accept', xpgkRequestType: 'save_call' },
      { phase: 'verification', summary: 'check_call -> no_response', xpgkRequestType: 'check_call' },
      { phase: 'accounting', summary: 'Stop -> Accounting-Response', acctStatusType: 'Stop' },
    ])).toEqual([
      'indication: save_call -> Access-Accept',
      'verification: check_call -> no_response',
      'accounting: Stop -> Accounting-Response',
    ])
  })

  it('renders the Satel-style card text with all attempts', () => {
    const text = formatAntifraudTranscript({
      callId: 'call-1',
      acctSessionId: 'session-1',
      participants: { callingNumber: '79001112233', calledNumber: '79005556677' },
      finalDecision: 'not_applicable',
      durationSec: 12,
      disconnectCauseQ850: 16,
      timeline: [
        { phase: 'indication', summary: 'number -> Access-Response', xpgkRequestType: 'number' },
        { phase: 'indication', summary: 'number -> no_response', xpgkRequestType: 'number' },
      ],
    })
    expect(text).toBe([
      'CALL session-1',
      'A: 79001112233',
      'B: 79005556677',
      '',
      '1) indication: number -> Access-Accept',
      '2) indication: number -> no_response',
      '',
      'final_decision=not_applicable',
      'duration_sec=12',
      'disconnect_cause_q850=16',
    ].join('\n'))
  })
})
