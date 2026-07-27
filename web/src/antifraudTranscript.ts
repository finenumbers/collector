export type TranscriptTimelineEvent = {
  phase: string
  summary: string
  xpgkRequestType?: string
  acctStatusType?: string
  decision?: string
}

export type TranscriptCall = {
  callId: string
  acctSessionId?: string
  h323ConfId?: string
  calling?: string
  called?: string
  participants?: { callingNumber?: string; calledNumber?: string }
  finalDecision?: string
  timeline?: TranscriptTimelineEvent[]
}

export type TranscriptCDR = {
  durationMs?: number
  releaseCause?: number
}

type Phase = 'indication' | 'verification' | 'accounting'

function normalizeResponseLabel(label: string): string {
  const trimmed = label.trim()
  switch (trimmed.toLowerCase()) {
    case 'access-response':
    case 'access-accept':
      return 'Access-Accept'
    case 'access-reject':
      return 'Access-Reject'
    case 'accounting-response':
      return 'Accounting-Response'
    case 'no_response':
      return 'no_response'
    default:
      return trimmed
  }
}

function parseStep(summary: string): { request: string; response: string } {
  const [requestPart, responsePart] = summary.split('->').map((part) => part.trim())
  return {
    request: requestPart || summary.trim(),
    response: responsePart ? normalizeResponseLabel(responsePart) : '',
  }
}

function formatAttemptStep(phase: Phase, event: TranscriptTimelineEvent): string {
  const parsed = parseStep(event.summary || '')
  let request = event.xpgkRequestType ||
    (phase === 'accounting' ? (event.acctStatusType || parsed.request) : parsed.request)
  let response = parsed.response
  if (!response && event.decision === 'unavailable_fallback') {
    response = 'no_response'
  }
  if (phase === 'indication') {
    if (!request) request = 'number'
    if (!response) response = 'no_response'
    return `indication: ${request} -> ${response}`
  }
  if (phase === 'verification') {
    if (!request) request = 'check_call'
    if (!response) response = 'no_response'
    return `verification: ${request} -> ${response}`
  }
  if (!request) request = 'Stop'
  if (!response) response = 'no_response'
  return `accounting: ${request} -> ${response}`
}

/** One transcript step per RADIUS attempt (no phase collapse). */
export function canonicalTranscriptSteps(timeline: TranscriptTimelineEvent[] = []): string[] {
  const steps: string[] = []
  for (const event of timeline) {
    const phase = event.phase?.toLowerCase()
    if (phase === 'indication' || phase === 'verification' || phase === 'accounting') {
      steps.push(formatAttemptStep(phase, event))
    }
  }
  return steps
}

function transcriptDuration(value: TranscriptCall & {
  durationSec?: number
  accounting?: { sessionTimeSec?: number }
  sessionDurationSeconds?: number
}, cdr?: TranscriptCDR): number | null {
  const fromAF = value.durationSec ??
    value.accounting?.sessionTimeSec ??
    value.sessionDurationSeconds
  if (fromAF != null && Number.isFinite(fromAF)) return fromAF
  if (cdr?.durationMs != null && Number.isFinite(cdr.durationMs)) {
    return Math.round(cdr.durationMs / 1000)
  }
  return null
}

function transcriptQ850(value: TranscriptCall & {
  disconnectCauseQ850?: number
  accounting?: { disconnectCauseQ850?: number }
}, cdr?: TranscriptCDR): number | null {
  const fromAF = value.disconnectCauseQ850 ?? value.accounting?.disconnectCauseQ850
  if (fromAF != null && Number.isFinite(fromAF)) return fromAF
  if (cdr?.releaseCause != null && Number.isFinite(cdr.releaseCause)) return cdr.releaseCause
  return null
}

/** Satel-style AntiFraud transcript: one line per RADIUS attempt. */
export function formatAntifraudTranscript(
  value: TranscriptCall & {
    durationSec?: number
    disconnectCauseQ850?: number
    accounting?: { sessionTimeSec?: number; disconnectCauseQ850?: number }
    sessionDurationSeconds?: number
  },
  cdr?: TranscriptCDR,
): string {
  const calling = value.participants?.callingNumber || value.calling || '—'
  const called = value.participants?.calledNumber || value.called || '—'
  const callLabel = value.acctSessionId || value.h323ConfId || value.callId
  const lines = [
    `CALL ${callLabel}`,
    `A: ${calling}`,
    `B: ${called}`,
    '',
  ]
  const steps = canonicalTranscriptSteps(value.timeline || [])
  if (!steps.length) {
    lines.push('incomplete: нет шагов RADIUS')
  } else {
    steps.forEach((step, index) => {
      lines.push(`${index + 1}) ${step}`)
    })
  }
  lines.push('')
  lines.push(`final_decision=${value.finalDecision || 'not_applicable'}`)
  lines.push(`duration_sec=${transcriptDuration(value, cdr) ?? '—'}`)
  lines.push(`disconnect_cause_q850=${transcriptQ850(value, cdr) ?? '—'}`)
  return lines.join('\n')
}
