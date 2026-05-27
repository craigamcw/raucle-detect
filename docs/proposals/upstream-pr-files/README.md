# Upstream PR shadow files for `microsoft/agent-governance-toolkit`

This directory is a **tree-shadow** of the files we propose to land in
the upstream Microsoft Agent Governance Toolkit repository as part of
the [AGT PDP plug-in contract proposal](../agt-pdp-contract.md). Each
file's path here mirrors where it would live in the AGT repo if the
maintainers accept the PR.

```
microsoft/agent-governance-toolkit/
├── agent_os/
│   └── policy_provider.py         ← proposed new module
└── tests/
    └── test_policy_provider.py    ← proposed new test file
```

## Status

- **Self-contained.** The proposed module has no imports from any
  external project — including raucle. It is a pure abstract
  contract.
- **Tested.** ``test_policy_provider.py`` exercises every clause of
  the contract (abstract enforcement, frozen-decision invariants,
  async/sync delegation). 10/10 passing in isolation.
- **Mergeable as-is.** The files are written in AGT's style (no
  raucle naming, no raucle-specific assumptions) so the maintainers
  can merge them verbatim and only need to wire the ``register_provider``
  hook into Agent OS's existing PolicyEngine. The wiring is outside
  the scope of this PR and is left to the maintainers.

## How to verify locally

```bash
# From this directory:
mkdir -p /tmp/agt-pr-shadow/agent_os /tmp/agt-pr-shadow/tests
cp agent_os/policy_provider.py /tmp/agt-pr-shadow/agent_os/
cp tests/test_policy_provider.py /tmp/agt-pr-shadow/tests/
touch /tmp/agt-pr-shadow/agent_os/__init__.py /tmp/agt-pr-shadow/tests/__init__.py
cd /tmp/agt-pr-shadow
PYTHONPATH=. python -m pytest tests/test_policy_provider.py -v
```

Expected: ``10 passed``.

## PR description

The full PR body — including motivation, detailed design, FAQ for the
four open questions, backwards-compatibility analysis, drawbacks and
alternatives — is in [`../agt-pdp-contract.upstream-pr.md`](../agt-pdp-contract.upstream-pr.md).

## Reference implementation

Raucle's reference implementation of this contract is at
[`raucle_detect/integrations/agt.py`](../../../raucle_detect/integrations/agt.py)
in this repository. It is **not** included in this proposed PR;
raucle stays in its own repo. The reference impl is only linked from
the PR body as proof that the contract is implementable and that at
least one production-track project intends to consume it.
