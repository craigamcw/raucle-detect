// Package provenance is a Go reference implementation of the Raucle
// Provenance Receipt v1 spec (https://raucle.com/spec/provenance/v1).
//
// It mirrors the Python (promptguard.provenance) and TypeScript
// (@raucle/provenance) reference implementations: same JWS envelope,
// same canonical-JSON bytes, same content-addressed identifiers. A
// receipt emitted by any of the three verifies in the others.
//
// Standard library only (crypto/ed25519, crypto/sha256).
package provenance

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// lessUTF16 orders two strings by UTF-16 code unit (RFC 8785 / JCS §3.2.3),
// matching the TypeScript (a < b) and C# (StringComparer.Ordinal) reference
// encoders. Go's sort.Strings compares UTF-8 bytes (Unicode code-point order),
// which diverges from JCS for non-BMP keys: a surrogate pair (lead unit
// U+D800..U+DBFF) must sort before BMP code points >= U+E000. BMP keys are
// unaffected. Keeping this ordering is what makes the five reference encoders
// byte-identical for objects with non-BMP keys.
func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// canonicalEncode renders a value into canonical-JSON bytes
// (RFC 8785 JCS, minimal subset): sorted object keys, no insignificant
// whitespace, UTF-8. Floats are rejected — the v1 payload schema does
// not use them, and float canonicalisation is the hard part of JCS.
//
// Accepts the small set of types the payload uses: nil, bool, int,
// int64, string, []any, and map[string]any.
func canonicalEncode(v any) ([]byte, error) {
	var sb strings.Builder
	if err := canonicalWrite(&sb, v); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

// CanonicalEncode is an exported wrapper over the package's canonical-JSON
// encoder, used by the cross-language canonicalisation conformance harness
// (reference/canon_conformance.py) to byte-diff §4.3 directly.
func CanonicalEncode(v any) ([]byte, error) { return canonicalEncode(v) }

// Portable safe-integer range (§8.10 #6): the TS port stores numbers as
// IEEE-754 doubles, exact only to ±(2^53-1). Bounding every integer here keeps
// the canonical bytes byte-identical across all five implementations.
const (
	maxSafeInt int64 = 1<<53 - 1
	minSafeInt int64 = -(1<<53 - 1)
)

var errSafeInt = errors.New(
	"canonical-JSON: integer outside the portable safe range [-(2^53-1), 2^53-1]",
)

func safeInt(n int64) bool { return n >= minSafeInt && n <= maxSafeInt }

func canonicalWrite(sb *strings.Builder, v any) error {
	switch t := v.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		if t {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case int:
		if !safeInt(int64(t)) {
			return errSafeInt
		}
		sb.WriteString(strconv.Itoa(t))
	case int64:
		if !safeInt(t) {
			return errSafeInt
		}
		sb.WriteString(strconv.FormatInt(t, 10))
	case float64:
		// JSON unmarshalling yields float64 even for integers, so accept
		// a float64 only when it is integral.
		if t != float64(int64(t)) {
			return errors.New("canonical-JSON: non-integer numbers are not supported in v1")
		}
		if !safeInt(int64(t)) {
			return errSafeInt
		}
		sb.WriteString(strconv.FormatInt(int64(t), 10))
	case string:
		sb.WriteString(encodeJSONString(t))
	case []string:
		sb.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(encodeJSONString(e))
		}
		sb.WriteByte(']')
	case []any:
		sb.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := canonicalWrite(sb, e); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(encodeJSONString(k))
			sb.WriteByte(':')
			if err := canonicalWrite(sb, t[k]); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	default:
		return fmt.Errorf("canonical-JSON: unsupported type %T", v)
	}
	return nil
}

// encodeJSONString writes a JSON string with the minimal escaping JCS
// requires. Matches the escape choices of Python's json.dumps and
// JSON.stringify for the ASCII control set + quote + backslash.
func encodeJSONString(s string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		case '\b':
			sb.WriteString(`\b`)
		case '\f':
			sb.WriteString(`\f`)
		default:
			if r < 0x20 {
				sb.WriteString(fmt.Sprintf(`\u%04x`, r))
			} else {
				sb.WriteRune(r)
			}
		}
	}
	sb.WriteByte('"')
	return sb.String()
}
