# Paper figures

Source files for figures referenced in `paper/DRAFT.md`. The Mermaid sources
render cleanly to SVG/PDF for the camera-ready via the standard Mermaid CLI:

```bash
npm install -g @mermaid-js/mermaid-cli
mmdc -i fig1-trust-graph.mmd -o fig1-trust-graph.pdf
```

For S&P camera-ready submission these should be converted to TikZ to match
the venue's typographic standards. The Mermaid source is the structured
specification; the TikZ version is the typeset output.

## Figures

| File | Used in | Caption |
|---|---|---|
| `fig1-trust-graph.mmd` | §3.4 | The four content-addressed hashes and three Ed25519 signatures that close the trust graph. |
| `fig2-asr-bar.mmd` | §6.2 | Tool-call-mediated attack-success rate across defence configurations on AgentDojo + InjecAgent. Bars filled when measurements land. |
| `fig3-gate-flow.mmd` | §3.3 | The gate's eight-check decision sequence. Each `else` arrow is a deny; only the all-pass path returns ALLOW. |
| `fig4-receipt-anatomy.mmd` | §7.5 | Capability receipt format: eight fields, what each cites or hashes, and the five offline-verifiable properties an external verifier checks. |
| `fig5-cross-org-audit.mmd` | §7.5 | Cross-organisation regulatory audit flow: an FCA examiner verifies a quarter of a bank's agent activity using only the bank's published cryptographic artefacts. No on-premise inspection, no shared secrets. |
| `fig6-three-primitive-flow.mmd` | §3 | End-to-end VCD: Prove → Mint → Gate, with the content-addressed signed artefacts flowing between primitives. Captures the composition rather than each primitive separately. |
