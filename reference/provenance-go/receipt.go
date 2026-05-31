package provenance

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
)

var (
	validOperations = map[string]bool{
		"user_input": true, "model_call": true, "tool_call": true,
		"retrieval": true, "guardrail_scan": true, "agent_handoff": true,
		"sanitisation": true, "merge": true,
	}
	validVerdicts = map[string]bool{
		"ALLOW": true, "BLOCK": true, "SANITISE": true, "NA": true,
	}
	agentIDRe = regexp.MustCompile(`^agent:[a-z0-9][a-z0-9_\-./]{0,127}$`)
	taintRe   = regexp.MustCompile(`^[a-z][a-z0-9_:\-]{0,63}$`)
	hex256Re  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

const (
	jwsTyp = "provenance-receipt/v1"
)

var jwsCrit = []string{"raucle/v1"}

var knownFields = map[string]bool{
	"iss": true, "iat": true, "agent_id": true, "agent_key_id": true,
	"operation": true, "parents": true, "input_hash": true,
	"output_hash": true, "taint": true, "ruleset_hash": true,
	"guardrail_verdict": true, "model": true, "tool": true,
	"corpus": true, "tenant": true,
}

// Payload is the v1 receipt payload (§4).
type Payload struct {
	Iss              string
	Iat              int64
	AgentID          string
	AgentKeyID       string
	Operation        string
	Parents          []string
	InputHash        string
	OutputHash       string
	Taint            []string
	RulesetHash      string // empty means absent
	GuardrailVerdict string // defaults to "NA"
	Model            map[string]any
	Tool             map[string]any
	Corpus           map[string]any
	Tenant           string // empty means absent
	// Extra holds x_-prefixed extension fields (§14).
	Extra map[string]any
}

// Receipt is a signed payload.
type Receipt struct {
	JWS     string
	Payload Payload
	// ID is the content-addressed identifier (§8): hex SHA-256 of the
	// Compact JWS ASCII bytes.
	ID string
}

func b64u(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func b64uDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func sha256Hex(b []byte) string {
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

// Validate enforces the §4 payload rules.
func (p *Payload) Validate() error {
	if !validOperations[p.Operation] {
		return fmt.Errorf("unknown operation: %s", p.Operation)
	}
	verdict := p.GuardrailVerdict
	if verdict == "" {
		verdict = "NA"
	}
	if !validVerdicts[verdict] {
		return fmt.Errorf("unknown verdict: %s", verdict)
	}
	if !agentIDRe.MatchString(p.AgentID) {
		return fmt.Errorf("invalid agent_id: %s", p.AgentID)
	}
	if !hex256Re.MatchString(p.InputHash) {
		return fmt.Errorf("input_hash must be 64-hex SHA-256")
	}
	if !hex256Re.MatchString(p.OutputHash) {
		return fmt.Errorf("output_hash must be 64-hex SHA-256")
	}
	if p.RulesetHash != "" && !hex256Re.MatchString(p.RulesetHash) {
		return fmt.Errorf("ruleset_hash must be 64-hex SHA-256")
	}
	if (p.Operation == "guardrail_scan" || p.Operation == "sanitisation") && p.RulesetHash == "" {
		return fmt.Errorf("%s requires ruleset_hash (§5)", p.Operation)
	}
	if p.Operation == "guardrail_scan" && verdict == "NA" {
		return fmt.Errorf("guardrail_scan requires a concrete verdict")
	}
	if p.Operation == "user_input" && len(p.Parents) > 0 {
		return fmt.Errorf("user_input must have no parents")
	}
	if p.Operation != "user_input" && len(p.Parents) == 0 {
		return fmt.Errorf("%s requires at least one parent", p.Operation)
	}
	for _, t := range p.Taint {
		if !taintRe.MatchString(t) {
			return fmt.Errorf("invalid taint tag: %s", t)
		}
	}
	if !sort.StringsAreSorted(p.Taint) {
		return fmt.Errorf("taint MUST be sorted (§4)")
	}
	if p.Operation == "model_call" && p.Model == nil {
		return fmt.Errorf("model_call requires .model")
	}
	if p.Operation == "tool_call" && p.Tool == nil {
		return fmt.Errorf("tool_call requires .tool")
	}
	if p.Operation == "retrieval" && p.Corpus == nil {
		return fmt.Errorf("retrieval requires .corpus")
	}
	for k := range p.Extra {
		if len(k) < 2 || k[:2] != "x_" {
			return fmt.Errorf("extra field %s must use x_ prefix (§14)", k)
		}
	}
	return nil
}

func (p *Payload) toMap() map[string]any {
	verdict := p.GuardrailVerdict
	if verdict == "" {
		verdict = "NA"
	}
	parents := make([]any, len(p.Parents))
	for i, v := range p.Parents {
		parents[i] = v
	}
	taint := make([]any, len(p.Taint))
	for i, v := range p.Taint {
		taint[i] = v
	}
	m := map[string]any{
		"iss":               p.Iss,
		"iat":               p.Iat,
		"agent_id":          p.AgentID,
		"agent_key_id":      p.AgentKeyID,
		"operation":         p.Operation,
		"parents":           parents,
		"input_hash":        p.InputHash,
		"output_hash":       p.OutputHash,
		"taint":             taint,
		"guardrail_verdict": verdict,
	}
	if p.RulesetHash != "" {
		m["ruleset_hash"] = p.RulesetHash
	}
	if p.Model != nil {
		m["model"] = p.Model
	}
	if p.Tool != nil {
		m["tool"] = p.Tool
	}
	if p.Corpus != nil {
		m["corpus"] = p.Corpus
	}
	if p.Tenant != "" {
		m["tenant"] = p.Tenant
	}
	for k, v := range p.Extra {
		m[k] = v
	}
	return m
}

func payloadFromMap(m map[string]any) (Payload, error) {
	for k := range m {
		if !knownFields[k] && (len(k) < 2 || k[:2] != "x_") {
			return Payload{}, fmt.Errorf("reserved unknown field: %s", k)
		}
	}
	p := Payload{Extra: map[string]any{}}
	getStr := func(k string) string {
		if v, ok := m[k].(string); ok {
			return v
		}
		return ""
	}
	p.Iss = getStr("iss")
	if iat, ok := m["iat"].(float64); ok {
		p.Iat = int64(iat)
	}
	p.AgentID = getStr("agent_id")
	p.AgentKeyID = getStr("agent_key_id")
	p.Operation = getStr("operation")
	p.InputHash = getStr("input_hash")
	p.OutputHash = getStr("output_hash")
	p.RulesetHash = getStr("ruleset_hash")
	p.GuardrailVerdict = getStr("guardrail_verdict")
	p.Tenant = getStr("tenant")
	if arr, ok := m["parents"].([]any); ok {
		for _, e := range arr {
			if s, ok := e.(string); ok {
				p.Parents = append(p.Parents, s)
			}
		}
	}
	if arr, ok := m["taint"].([]any); ok {
		for _, e := range arr {
			if s, ok := e.(string); ok {
				p.Taint = append(p.Taint, s)
			}
		}
	}
	if mm, ok := m["model"].(map[string]any); ok {
		p.Model = mm
	}
	if mm, ok := m["tool"].(map[string]any); ok {
		p.Tool = mm
	}
	if mm, ok := m["corpus"].(map[string]any); ok {
		p.Corpus = mm
	}
	for k, v := range m {
		if len(k) >= 2 && k[:2] == "x_" {
			p.Extra[k] = v
		}
	}
	return p, nil
}

// Emit signs a payload and returns a Receipt.
func Emit(p Payload, priv ed25519.PrivateKey) (Receipt, error) {
	if err := p.Validate(); err != nil {
		return Receipt{}, err
	}
	header := map[string]any{
		"alg":  "EdDSA",
		"typ":  jwsTyp,
		"kid":  p.AgentKeyID,
		"crit": toAnySlice(jwsCrit),
	}
	headerB, err := canonicalEncode(header)
	if err != nil {
		return Receipt{}, err
	}
	payloadB, err := canonicalEncode(p.toMap())
	if err != nil {
		return Receipt{}, err
	}
	signingInput := b64u(headerB) + "." + b64u(payloadB)
	sig := ed25519.Sign(priv, []byte(signingInput))
	jws := signingInput + "." + b64u(sig)
	return Receipt{JWS: jws, Payload: p, ID: sha256Hex([]byte(jws))}, nil
}

// Verify checks a Compact JWS against pub and parses it.
func Verify(jws string, pub ed25519.PublicKey) (Receipt, error) {
	parts := splitN(jws, '.')
	if len(parts) != 3 {
		return Receipt{}, fmt.Errorf("JWS must have three segments")
	}
	headerB, payloadB, sigB := parts[0], parts[1], parts[2]

	hb, err := b64uDecode(headerB)
	if err != nil {
		return Receipt{}, err
	}
	var header map[string]any
	if err := json.Unmarshal(hb, &header); err != nil {
		return Receipt{}, err
	}
	if header["alg"] != "EdDSA" {
		return Receipt{}, fmt.Errorf("unsupported alg: %v", header["alg"])
	}
	if header["typ"] != jwsTyp {
		return Receipt{}, fmt.Errorf("unexpected typ: %v", header["typ"])
	}
	crit, _ := header["crit"].([]any)
	if !containsAny(crit, "raucle/v1") {
		return Receipt{}, fmt.Errorf("crit must include 'raucle/v1'")
	}

	sig, err := b64uDecode(sigB)
	if err != nil {
		return Receipt{}, err
	}
	if !ed25519.Verify(pub, []byte(headerB+"."+payloadB), sig) {
		return Receipt{}, fmt.Errorf("signature invalid")
	}

	pb, err := b64uDecode(payloadB)
	if err != nil {
		return Receipt{}, err
	}
	var pm map[string]any
	if err := json.Unmarshal(pb, &pm); err != nil {
		return Receipt{}, err
	}
	p, err := payloadFromMap(pm)
	if err != nil {
		return Receipt{}, err
	}
	if err := p.Validate(); err != nil {
		return Receipt{}, err
	}
	if header["kid"] != p.AgentKeyID {
		return Receipt{}, fmt.Errorf("header.kid != payload.agent_key_id (§3)")
	}
	return Receipt{JWS: jws, Payload: p, ID: sha256Hex([]byte(jws))}, nil
}

// ── small helpers ─────────────────────────────────────────────────

func toAnySlice(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func containsAny(xs []any, want string) bool {
	for _, x := range xs {
		if s, ok := x.(string); ok && s == want {
			return true
		}
	}
	return false
}

func splitN(s string, sep byte) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

// equalStringSets is used by the chain verifier.
func equalStringSlices(a, b []string) bool {
	return reflect.DeepEqual(a, b)
}
