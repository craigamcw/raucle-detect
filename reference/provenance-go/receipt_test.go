package provenance

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func sha(s string) string {
	d := sha256.Sum256([]byte(s))
	return hex.EncodeToString(d[:])
}

func basePayload() Payload {
	h := sha("hello")
	return Payload{
		Iss:              "https://test.example/raucle",
		Iat:              1748505600,
		AgentID:          "agent:test.scanner",
		AgentKeyID:       "k_test01",
		Operation:        "user_input",
		Parents:          nil,
		InputHash:        h,
		OutputHash:       h,
		Taint:            []string{"untrusted_user"},
		GuardrailVerdict: "NA",
		Extra:            map[string]any{},
	}
}

func mustKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestEmitVerifyRoundtrip(t *testing.T) {
	pub, priv := mustKeys(t)
	r, err := Emit(basePayload(), priv)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Verify(r.JWS, pub)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Payload.AgentID != "agent:test.scanner" {
		t.Fatalf("agent_id mismatch: %s", parsed.Payload.AgentID)
	}
	if parsed.ID != r.ID || len(r.ID) != 64 {
		t.Fatalf("id mismatch/len: %s", parsed.ID)
	}
}

func TestVerifyRejectsDifferentKey(t *testing.T) {
	_, priv := mustKeys(t)
	otherPub, _ := mustKeys(t)
	r, _ := Emit(basePayload(), priv)
	if _, err := Verify(r.JWS, otherPub); err == nil {
		t.Fatal("expected signature failure")
	}
}

func TestVerifyRejectsWrongAlg(t *testing.T) {
	pub, priv := mustKeys(t)
	r, _ := Emit(basePayload(), priv)
	parts := strings.Split(r.JWS, ".")
	badHeader, _ := json.Marshal(map[string]any{
		"alg": "HS256", "typ": jwsTyp, "kid": "k_test01", "crit": []string{"raucle/v1"},
	})
	hb := base64.RawURLEncoding.EncodeToString(badHeader)
	if _, err := Verify(hb+"."+parts[1]+"."+parts[2], pub); err == nil {
		t.Fatal("expected alg rejection")
	}
}

func TestVerifyRequiresCrit(t *testing.T) {
	pub, priv := mustKeys(t)
	r, _ := Emit(basePayload(), priv)
	parts := strings.Split(r.JWS, ".")
	badHeader, _ := json.Marshal(map[string]any{
		"alg": "EdDSA", "typ": jwsTyp, "kid": "k_test01", "crit": []string{},
	})
	hb := base64.RawURLEncoding.EncodeToString(badHeader)
	if _, err := Verify(hb+"."+parts[1]+"."+parts[2], pub); err == nil {
		t.Fatal("expected crit rejection")
	}
}

func TestRejectsUnsortedTaint(t *testing.T) {
	_, priv := mustKeys(t)
	p := basePayload()
	p.Taint = []string{"z_x", "a_y"}
	if _, err := Emit(p, priv); err == nil {
		t.Fatal("expected sorted-taint rejection")
	}
}

func TestNonUserInputRequiresParents(t *testing.T) {
	_, priv := mustKeys(t)
	p := basePayload()
	p.Operation = "model_call"
	p.Model = map[string]any{"provider": "t", "name": "e", "version": "1"}
	if _, err := Emit(p, priv); err == nil {
		t.Fatal("expected parent requirement")
	}
}

func TestChainTopoAndClosure(t *testing.T) {
	_, priv := mustKeys(t)
	r1, _ := Emit(basePayload(), priv)
	p2 := basePayload()
	p2.Operation = "model_call"
	p2.Parents = []string{r1.ID}
	p2.Model = map[string]any{"provider": "t", "name": "e", "version": "1"}
	r2, _ := Emit(p2, priv)
	c, err := BuildChain([]Receipt{r1, r2})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Receipts) != 2 {
		t.Fatalf("expected 2 receipts, got %d", len(c.Receipts))
	}
}

func TestChainRejectsTopoBreak(t *testing.T) {
	_, priv := mustKeys(t)
	r1, _ := Emit(basePayload(), priv)
	p2 := basePayload()
	p2.Operation = "model_call"
	p2.Parents = []string{r1.ID}
	p2.Model = map[string]any{"provider": "t", "name": "e", "version": "1"}
	r2, _ := Emit(p2, priv)
	if _, err := BuildChain([]Receipt{r2, r1}); err == nil {
		t.Fatal("expected topo violation")
	}
}

func TestChainRejectsSilentTaintLoss(t *testing.T) {
	_, priv := mustKeys(t)
	r1, _ := Emit(basePayload(), priv)
	p2 := basePayload()
	p2.Operation = "model_call"
	p2.Parents = []string{r1.ID}
	p2.Taint = nil
	p2.Model = map[string]any{"provider": "t", "name": "e", "version": "1"}
	r2, _ := Emit(p2, priv)
	if _, err := BuildChain([]Receipt{r1, r2}); err == nil {
		t.Fatal("expected taint monotonicity violation")
	}
}

func TestSanitisationMustDeclareRemovedTaint(t *testing.T) {
	_, priv := mustKeys(t)
	r1, _ := Emit(basePayload(), priv)
	p2 := basePayload()
	p2.Operation = "sanitisation"
	p2.Parents = []string{r1.ID}
	p2.Taint = nil
	p2.RulesetHash = sha("rules-v1")
	r2, _ := Emit(p2, priv)
	if _, err := BuildChain([]Receipt{r1, r2}); err == nil {
		t.Fatal("expected x_removed_taint requirement")
	}
}

func TestSanitisationWithDeclaredRemovedPasses(t *testing.T) {
	_, priv := mustKeys(t)
	r1, _ := Emit(basePayload(), priv)
	p2 := basePayload()
	p2.Operation = "sanitisation"
	p2.Parents = []string{r1.ID}
	p2.Taint = nil
	p2.RulesetHash = sha("rules-v1")
	p2.Extra = map[string]any{"x_removed_taint": []any{"untrusted_user"}}
	r2, _ := Emit(p2, priv)
	if _, err := BuildChain([]Receipt{r1, r2}); err != nil {
		t.Fatal(err)
	}
}

// TestCanonicalParity locks the canonical-JSON output to the exact
// bytes the Python + TS reference encoders produce for the same object.
func TestCanonicalParity(t *testing.T) {
	got, err := canonicalEncode(map[string]any{
		"iss": "x", "iat": 1, "parents": []any{"a", "b"},
		"taint": []any{"a_t", "z_t"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"iat":1,"iss":"x","parents":["a","b"],"taint":["a_t","z_t"]}`
	if string(got) != want {
		t.Fatalf("canonical mismatch:\n got=%s\nwant=%s", got, want)
	}
}

var _ = equalStringSlices // keep helper referenced
