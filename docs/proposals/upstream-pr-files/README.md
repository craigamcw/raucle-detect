# Upstream PR shadow files for `microsoft/agent-governance-toolkit`

This directory holds the artefacts proposed to land in the upstream
Microsoft Agent Governance Toolkit repository as part of the
[AGT PDP plug-in contract proposal](../agt-pdp-contract.md).

```
upstream-pr-files/
├── patch/
│   └── backends-assurance-fields.patch    ← unified diff against
│                                            agent-governance-python/agent-os/
└── tests/
    └── test_backend_decision_assurance_fields.py
                                            ← new test file, dropped into
                                              agent-governance-python/agent-os/tests/
```

## Scope

After reading the upstream repo, the original proposal (a new
`IPolicyProvider` ABC) collapsed into a much smaller change: AGT
already exposes `agent_os.policies.backends.ExternalPolicyBackend` as
the seam for external policy substrates (OPA and Cedar implement it).
The valuable additive piece is **two optional fields on
`BackendDecision`** for offline-verifiable evidence, propagated into
`PolicyDecision.audit_entry` by `PolicyEvaluator`.

- `proof_artefact: Optional[str]` — content-address of an underlying
  proof artefact (e.g. `sha256:...`).
- `verification_pointers: dict[str, str]` — named URLs at which a
  third-party verifier can fetch the deployer's published material.

Existing OPA / Cedar backends are unaffected (fields default to empty;
audit entry omits both keys when absent).

## How to verify locally

```bash
git clone https://github.com/microsoft/agent-governance-toolkit.git /tmp/agt
cd /tmp/agt
git apply /path/to/raucle/docs/proposals/upstream-pr-files/patch/backends-assurance-fields.patch
cp /path/to/raucle/docs/proposals/upstream-pr-files/tests/test_backend_decision_assurance_fields.py \
   agent-governance-python/agent-os/tests/

cd agent-governance-python/agent-os
pip install -e .[dev]
pytest tests/test_backend_decision_assurance_fields.py -v
```

Expected: `4 passed`.

## PR description

The full PR body is in [`../agt-pdp-contract.upstream-pr.md`](../agt-pdp-contract.upstream-pr.md).

## Reference implementation

raucle's integration at [`raucle/integrations/agt.py`](../../../raucle/integrations/agt.py)
will be reworked to implement `ExternalPolicyBackend` directly once
this PR lands. It is **not** included in this proposed PR.
