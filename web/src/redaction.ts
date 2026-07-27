const secretKey = /(password|passwd|chap|digest|preimage|authenticator|token|credential|authorization|api[-_]?key|private[-_]?key|shared[-_]?(key|secret))/i
const assignment = /([A-Za-z][A-Za-z0-9_.:-]{0,127})(\s*(?:=|:)\s*)("(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[^\s,;]+)/gi
const authorization = /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi

export function redactDisplayText(value: string): string {
  return value
    .replace(authorization, '$1 [REDACTED]')
    .replace(assignment, (match, key: string, separator: string, raw: string) => {
      if (secretKey.test(key)) return `${key}${separator}[REDACTED]`
      if (!raw.includes('=') && !raw.includes(':')) return match
      const quote = raw.length >= 2 && (raw[0] === '"' || raw[0] === "'") && raw.at(-1) === raw[0]
        ? raw[0] : ''
      const nested = quote ? raw.slice(1, -1) : raw
      return `${key}${separator}${quote}${redactDisplayText(nested)}${quote}`
    })
}

export function redactDisplayValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactDisplayValue)
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>)
      .map(([key, item]) => [key, secretKey.test(key) ? '[REDACTED]' : redactDisplayValue(item)]))
  }
  return typeof value === 'string' ? redactDisplayText(value) : value
}
