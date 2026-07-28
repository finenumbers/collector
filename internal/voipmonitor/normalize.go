package voipmonitor

import (
	"strings"
	"unicode"
)

// NormalizeCallID lowercases, trims, and strips a trailing @host suffix.
func NormalizeCallID(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	if at := strings.IndexByte(value, '@'); at > 0 {
		value = value[:at]
	}
	return strings.TrimSpace(value)
}

// CallIDVariants returns lookup keys for a raw Call-ID (normalized + host-stripped form).
func CallIDVariants(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	add := func(v string) {
		v = NormalizeCallID(v)
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	add(raw)
	if at := strings.IndexByte(raw, '@'); at > 0 {
		add(raw[:at])
	}
	return out
}

func digits(value string) string {
	var b strings.Builder
	for _, r := range value {
		if unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func numberSuffixes(value string, primary int) []string {
	d := digits(value)
	if d == "" {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	add := func(n int) {
		if n <= 0 || len(d) < n {
			return
		}
		s := d[len(d)-n:]
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	add(primary)
	add(primary + 1)
	add(primary + 2)
	if primary != 10 {
		add(10)
	}
	if len(d) < primary {
		add(len(d))
	}
	return out
}

func ipEqual(a, b string) bool {
	a = strings.TrimSpace(strings.ToLower(a))
	b = strings.TrimSpace(strings.ToLower(b))
	return a != "" && a == b
}

func abs64(value int64) int64 {
	if value < 0 {
		return -value
	}
	return value
}

func uniqueNonEmpty(values ...string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func sourceCallIDNorms(cdr CDRCandidate) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, raw := range cdr.SIPCallIDs {
		for _, norm := range CallIDVariants(raw) {
			if _, ok := seen[norm]; ok {
				continue
			}
			seen[norm] = struct{}{}
			out = append(out, norm)
		}
	}
	return out
}

func cdrCallerNumbers(cdr CDRCandidate) []string {
	if len(cdr.CallerNumbers) > 0 {
		return cdr.CallerNumbers
	}
	return uniqueNonEmpty(cdr.Caller)
}

func cdrCalledNumbers(cdr CDRCandidate) []string {
	if len(cdr.CalledNumbers) > 0 {
		return cdr.CalledNumbers
	}
	return uniqueNonEmpty(cdr.Called)
}
