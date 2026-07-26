export type ConstructMemberLike = {
  eventId: string
  receivedAt: string
  eventTime?: string
  attributes: Record<string, string>
}

export function isTechnicalConstructMember(member: ConstructMemberLike): boolean {
  const attributes = member.attributes || {}
  if (attributes.technical === 'true' || attributes.empty_body === 'true') return true
  const kind = (attributes.fragment_kind || '').toLowerCase()
  return kind === 'hex' || kind === 'dotted_hex' || kind === 'digest' || kind === 'empty'
}

export function orderedConstructMembers<T extends ConstructMemberLike>(members: T[]): T[] {
  return [...members].sort((left, right) => {
    const leftTime = Date.parse(left.eventTime || left.receivedAt)
    const rightTime = Date.parse(right.eventTime || right.receivedAt)
    const timeOrder = (Number.isNaN(leftTime) ? 0 : leftTime) -
      (Number.isNaN(rightTime) ? 0 : rightTime)
    return timeOrder || left.eventId.localeCompare(right.eventId)
  })
}

export function constructMemberParameters(
  member: Pick<ConstructMemberLike, 'attributes'>,
): Array<[string, string]> {
  return Object.entries(member.attributes || {}).filter(([name, value]) => {
    const normalized = name.toLowerCase()
    return Boolean(value) && (normalized.includes('sdp') || normalized.includes('param'))
  })
}
