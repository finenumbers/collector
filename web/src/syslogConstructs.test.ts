import { describe, expect, it } from 'vitest'
import {
  constructMemberParameters, isTechnicalConstructMember, orderedConstructMembers,
  type ConstructMemberLike,
} from './syslogConstructs'

const member = (
  eventId: string,
  eventTime: string,
  attributes: Record<string, string> = {},
): ConstructMemberLike => ({
  eventId,
  eventTime,
  receivedAt: eventTime,
  attributes,
})

describe('syslog construct members', () => {
  it('orders members chronologically without mutating the response', () => {
    const source = [
      member('later', '2026-07-26T10:02:00Z'),
      member('earlier', '2026-07-26T10:01:00Z'),
    ]

    expect(orderedConstructMembers(source).map((item) => item.eventId))
      .toEqual(['earlier', 'later'])
    expect(source.map((item) => item.eventId)).toEqual(['later', 'earlier'])
  })

  it('recognizes technical fragments hidden by default', () => {
    expect(isTechnicalConstructMember(member('hex', '2026-07-26T10:00:00Z', {
      fragment_kind: 'dotted_hex',
    }))).toBe(true)
    expect(isTechnicalConstructMember(member('body', '2026-07-26T10:00:00Z', {
      message_name: 'INVITE',
    }))).toBe(false)
  })

  it('selects SDP and parameter fields for readable monospace display', () => {
    const parameters = constructMemberParameters(member('sip', '2026-07-26T10:00:00Z', {
      sdp_body: 'v=0',
      request_parameters: 'transport=udp',
      call_context: '42',
    }))

    expect(parameters).toEqual([
      ['sdp_body', 'v=0'],
      ['request_parameters', 'transport=udp'],
    ])
  })
})
