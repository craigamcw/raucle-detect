// Command emit is a conformance-harness helper: it reads JSON requests
// {"seed_hex": "...", "payload": {...}} (one per line) from stdin and
// writes {"jws": "...", "id": "..."} (one per line) to stdout, using the
// Go reference implementation. See reference/conformance.py.
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	provenance "github.com/craigamcw/raucle-detect/reference/provenance-go"
)

type req struct {
	SeedHex string         `json:"seed_hex"`
	Payload map[string]any `json:"payload"`
}

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var r req
		if err := json.Unmarshal(line, &r); err != nil {
			fmt.Fprintln(os.Stderr, "decode:", err)
			os.Exit(1)
		}
		seed, _ := hex.DecodeString(r.SeedHex)
		priv := ed25519.NewKeyFromSeed(seed)
		p := provenance.PayloadFromHarness(r.Payload)
		rec, err := provenance.Emit(p, priv)
		if err != nil {
			fmt.Fprintln(os.Stderr, "emit:", err)
			os.Exit(1)
		}
		b, _ := json.Marshal(map[string]string{"jws": rec.JWS, "id": rec.ID})
		out.Write(b)
		out.WriteByte('\n')
	}
}
