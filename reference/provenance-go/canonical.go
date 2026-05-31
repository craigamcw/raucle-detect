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
)

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
		sb.WriteString(strconv.Itoa(t))
	case int64:
		sb.WriteString(strconv.FormatInt(t, 10))
	case float64:
		// JSON unmarshalling yields float64 even for integers, so accept
		// a float64 only when it is integral.
		if t != float64(int64(t)) {
			return errors.New("canonical-JSON: non-integer numbers are not supported in v1")
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
		sort.Strings(keys)
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
