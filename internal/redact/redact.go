// Package redact is the single server-side secret classification boundary.
package redact

import (
	"regexp"
	"strings"
	"unicode"
)

const Replacement = "[REDACTED]"

var (
	assignment = regexp.MustCompile(`(?i)([A-Za-z][A-Za-z0-9_.:-]{0,127})(\s*(?:=|:)\s*)("(?:\\.|[^"])*"|'(?:\\.|[^'])*'|[^\s,;]+)`)
	bearer     = regexp.MustCompile(`(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+`)
)

func SecretName(name string) bool {
	normalized := strings.Map(func(character rune) rune {
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			return unicode.ToLower(character)
		}
		return -1
	}, name)
	for _, marker := range []string{
		"password", "passwd", "userpassword", "chap", "digest", "preimage",
		"authenticator", "token", "credential", "authorization", "apikey",
		"privatekey", "sharedkey", "sharedsecret", "clientsecret",
	} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

// Text removes values from key/value forms, including secret-like keys nested
// inside vendor AVPair values. It never includes the removed value in errors.
func Text(value string) string {
	value = bearer.ReplaceAllStringFunc(value, func(match string) string {
		fields := strings.Fields(match)
		if len(fields) == 0 {
			return Replacement
		}
		return fields[0] + " " + Replacement
	})
	value = assignment.ReplaceAllStringFunc(value, func(match string) string {
		parts := assignment.FindStringSubmatch(match)
		if len(parts) != 4 || !SecretName(parts[1]) {
			if len(parts) == 4 && (strings.Contains(parts[3], "=") || strings.Contains(parts[3], ":")) {
				raw := parts[3]
				quote := byte(0)
				if len(raw) >= 2 && (raw[0] == '"' || raw[0] == '\'') && raw[len(raw)-1] == raw[0] {
					quote = raw[0]
					raw = raw[1 : len(raw)-1]
				}
				raw = Text(raw)
				if quote != 0 {
					raw = string(quote) + raw + string(quote)
				}
				return parts[1] + parts[2] + raw
			}
			return match
		}
		return parts[1] + parts[2] + Replacement
	})
	return value
}

func Bytes(value []byte) []byte {
	return []byte(Text(string(value)))
}

func Value(name string, value any) any {
	if SecretName(name) {
		return Replacement
	}
	return value
}
