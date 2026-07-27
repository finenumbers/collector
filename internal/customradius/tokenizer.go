package customradius

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"collector/internal/redact"

	"github.com/google/uuid"
)

type TokenizeResult struct {
	Attributes []Attribute   `json:"attributes"`
	Warnings   []Explanation `json:"warnings,omitempty"`
}

var attributeStart = regexp.MustCompile(`(?m)(?:^|[\s,;])([A-Za-z][A-Za-z0-9_.:-]*)(?:\s*\[(\d+)\])?\s*=\s*`)

// Tokenize extracts every attribute in source order. It accepts quoted,
// escaped, and unquoted values and does not collapse repeated attributes.
func Tokenize(payload []byte, eventID uuid.UUID) TokenizeResult {
	text := string(payload)
	matches := attributeStart.FindAllStringSubmatchIndex(text, -1)
	result := TokenizeResult{Attributes: make([]Attribute, 0, len(matches))}
	for index, match := range matches {
		name := text[match[2]:match[3]]
		valueStart := match[1]
		valueEnd := len(text)
		if index+1 < len(matches) {
			valueEnd = matches[index+1][0]
		}
		raw, malformed := scanValue(text, valueStart, valueEnd)
		numericID := (*int)(nil)
		if match[4] >= 0 {
			parsed, _ := strconv.Atoi(text[match[4]:match[5]])
			numericID = &parsed
		}
		normalizedName := normalizeAttributeName(name)
		value := raw
		if isAVPair(normalizedName) {
			key, nested, found := strings.Cut(value, "=")
			if found {
				normalizedKey := normalizeAttributeName(strings.TrimSpace(key))
				if strings.HasPrefix(normalizedKey, "xpkg-") {
					normalizedKey = "xpgk-" + strings.TrimPrefix(normalizedKey, "xpkg-")
					result.Warnings = append(result.Warnings, Explanation{
						Code: "custom.attribute.xpkg_normalized",
						Text: "The xpkg vendor attribute prefix was normalized to xpgk.",
					})
				}
				attribute := newAttribute(normalizedKey, strings.TrimSpace(key), nested, nested, numericID, eventID)
				result.Attributes = append(result.Attributes, attribute)
				if malformed {
					result.Warnings = append(result.Warnings, malformedQuoteWarning())
				}
				continue
			}
		}
		attribute := newAttribute(normalizedName, name, value, raw, numericID, eventID)
		result.Attributes = append(result.Attributes, attribute)
		if malformed {
			result.Warnings = append(result.Warnings, malformedQuoteWarning())
		}
	}
	return result
}

func scanValue(text string, start, limit int) (string, bool) {
	for start < limit && unicode.IsSpace(rune(text[start])) {
		start++
	}
	if start >= limit {
		return "", false
	}
	if text[start] != '\'' && text[start] != '"' {
		return strings.TrimSpace(strings.TrimRight(text[start:limit], ",;")), false
	}
	quote := text[start]
	var output strings.Builder
	escaped := false
	for cursor := start + 1; cursor < limit; cursor++ {
		character := text[cursor]
		if escaped {
			output.WriteByte(character)
			escaped = false
			continue
		}
		if character == '\\' {
			escaped = true
			continue
		}
		if character == quote {
			return output.String(), false
		}
		output.WriteByte(character)
	}
	if escaped {
		output.WriteByte('\\')
	}
	return output.String(), true
}

func newAttribute(name, displayName, value, raw string, numericID *int, eventID uuid.UUID) Attribute {
	attribute := Attribute{
		Name: name, DisplayName: displayName, Value: strings.TrimSpace(value),
		RawValue: raw, NumericID: numericID, EventID: eventID,
	}
	if redact.SecretName(name) {
		attribute.Value = ""
		attribute.RawValue = ""
		attribute.Redacted = true
	}
	return attribute
}

func normalizeAttributeName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.ReplaceAll(name, "_", "-")
	return name
}

func isAVPair(name string) bool {
	return name == "cisco-avpair" || name == "eltex-avpair" ||
		strings.HasSuffix(name, "-avpair")
}

func isSecretName(name string) bool {
	return redact.SecretName(name)
}

func malformedQuoteWarning() Explanation {
	return Explanation{
		Code: "custom.attribute.malformed_quote",
		Text: "An unterminated quoted attribute value was retained up to the event boundary.",
	}
}
