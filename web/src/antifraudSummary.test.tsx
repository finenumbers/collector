// @vitest-environment jsdom
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { renderToStaticMarkup } from 'react-dom/server'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  AntiFraudSummary, AntiFraudSummaryState, CallAntiFraudSummary,
} from './antifraudSummary'

const operation = {
  operationId: 'operation-1',
  occurredAt: '2026-07-26T22:30:31Z',
  type: 'number',
  legDirection: 'inbound',
  legSessionId: '0600000f6a66605866cb3590505c7af3',
  callContext: 'C0000A7',
  srcNumberIn: '9586786161',
  dstNumberIn: '8435999999',
  srcNumberOut: '79586786161',
  dstNumberOut: '78435999999',
  requestIdentifier: 68,
  requestCode: 'access-request',
  responseIdentifier: 68,
  responseCode: 'access-accept',
  latencyMs: 111,
  retries: 0,
  terminalState: 'response_received',
  terminalReason: 'no_block_evidence',
  correlationState: 'linked',
  correlationMethod: 'exact_h323_conf_id',
  correlationEvidence: { timeDeltaMs: '-1000' },
}

const summary: CallAntiFraudSummary = {
  projectionStatus: 'active',
  parserVersion: 'eltex-smg-syslog-v16',
  building: false,
  cdr: {
    recordId: 'cdr-1',
    incomingNumber: '9586786161',
    incomingDestination: '8435999999',
    outgoingNumber: '79586786161',
    outgoingDestination: '78435999999',
    incomingRoute: 'Tattelecom Kazan',
    outgoingRoute: 'PSTN Kazan',
    radiusSessionId: '0600000f 6a666058 66cb3590 505c7af3',
  },
  call: {
    callId: 'call-1',
    identityKind: 'h323_conf_id',
    identityValue: '0600000f6a66605866cb3590505c7af3',
    h323ConfId: '0600000f6a66605866cb3590505c7af3',
    callContexts: ['C0000A7'],
    legSessionIds: ['in', 'out'],
    legSessionIdsNormalized: ['in', 'out'],
  },
  operations: [
    operation,
    {
      ...operation,
      operationId: 'operation-2',
      legDirection: 'outbound',
      requestIdentifier: 7,
      responseIdentifier: 7,
      latencyMs: 99,
    },
  ],
  overallStatus: 'neutral',
  warnings: [],
}

function render(state: AntiFraudSummaryState) {
  return renderToStaticMarkup(<AntiFraudSummary state={state} onRetry={() => undefined} />)
}

describe('Call AntiFraud summary', () => {
  afterEach(() => {
    document.body.replaceChildren()
  })

  it('renders the neutral golden case without claiming an informational response allowed the call', () => {
    const html = render({ kind: 'ready', summary })
    expect(html).toContain('Оба ответа AntiFraud получены; признаков блокировки нет.')
    expect(html).toContain('Ответ получен · Признаков блокировки нет')
    expect(html).toContain('068 → 068')
    expect(html).toContain('007 → 007')
    expect(html.toLocaleLowerCase('ru')).not.toContain('разрешил')
  })

  it.each([
    [{ kind: 'loading' } as AntiFraudSummaryState, 'Загружаем связанные операции'],
    [{
      kind: 'ready',
      summary: { ...summary, building: true, projectionStatus: 'building' },
    } as AntiFraudSummaryState, 'Сводка строится'],
    [{
      kind: 'ready',
      summary: { ...summary, operations: [], call: undefined },
    } as AntiFraudSummaryState, 'нет связанных операций AntiFraud'],
    [{ kind: 'error', message: 'HTTP 500' } as AntiFraudSummaryState, 'Повторить'],
  ])('renders state %# without operation data leakage', (state, expected) => {
    const html = render(state)
    expect(html).toContain(expected)
    if (state.kind === 'ready' && state.summary.operations.length > 0 && !state.summary.building) return
    expect(html).not.toContain('0600000f6a66605866cb3590505c7af3')
  })

  it('exposes expandable correlation evidence without raw payloads', () => {
    const html = render({ kind: 'ready', summary })
    expect(html).toContain('<details')
    expect(html).toContain('<summary>Доказательства связи</summary>')
    expect(html).toContain('Сессия плеча')
    expect(html).toContain('H.323 Conf-ID')
    expect(html).toContain('-1000 мс')
    expect(html).not.toContain('rawPayload')
  })

  it('invokes retry from the error state', async () => {
    const retry = vi.fn()
    const container = document.createElement('div')
    document.body.append(container)
    const root = createRoot(container)
    await act(async () => {
      root.render(<AntiFraudSummary state={{ kind: 'error', message: 'HTTP 500' }} onRetry={retry} />)
    })
    await act(async () => {
      container.querySelector('button')?.click()
    })
    expect(retry).toHaveBeenCalledOnce()
    await act(async () => root.unmount())
  })
})
