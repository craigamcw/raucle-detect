# Upstream PR: Add a Policy Decision Point plug-in contract to Agent OS

This document is the **ready-to-submit PR body** for an upstream
contribution to [`microsoft/agent-governance-toolkit`](https://github.com/microsoft/agent-governance-toolkit).
It is paired with the tree-shadow files in
[`upstream-pr-files/`](upstream-pr-files/) — those are the actual
files proposed for the AGT repo, runnable in isolation.

The design rationale and broader strategic positioning live in
[`agt-pdp-contract.md`](agt-pdp-contract.md). What follows is what
goes in the GitHub PR description verbatim.

---

## Title

`Agent OS: add an `IPolicyProvider` plug-in contract for external Policy Decision Points`

## Suggested branch name

`feat/agent-os-policy-provider-contract`

## Summary

Adds an abstract ``IPolicyProvider`` interface plus a frozen
``PolicyDecision`` dataclass to ``agent_os/``, defining a stable seam
through which Agent OS's ``PolicyEngine`` can delegate tool-call
authorisation decisions to external providers. The proposed module is
self-contained (no upstream dependencies introduced), tested
(10 contract tests passing), and additive — no existing AGT behaviour
changes when no provider is registered.

## Motivation

Agent OS today supports YAML, OPA/Rego, and Cedar policies interpreted
in-process. This covers the breadth of common enforcement patterns.
A class of deployments — particularly in regulated finance, healthcare,
and government — additionally requires policy decisions whose soundness
is established by methods that do not fit naturally inside the
in-process interpreter loop:

- **SMT verification** that a policy holds over every string a tool's
  JSON Schema admits, producing a content-addressed proof artefact the
  audit chain can cite.
- **Mechanically verified theorems** (e.g. Lean 4) backing the gate's
  soundness claim, where the audit record needs to name the theorem
  identifier so an external verifier can re-check the proof offline.
- **Hardware-attested decision substrates** (TEE-rooted PDPs) whose
  attestation document is required in the audit record.

Embedding any of these in Agent OS itself would expand its scope and
toolchain dependencies considerably. A plug-in seam keeps Agent OS
focused on its current in-process enforcement model while letting
external providers serve the high-assurance verticals where they
already have implementation depth.

## Goals

1. **Minimal contract surface.** Three abstract methods (``name``,
   ``supports``, ``decide``) plus an immutable result type
   (``PolicyDecision``). Subclasses are not forced to implement the
   async variant; the default delegates to the sync method.
2. **Self-describing decisions.** ``PolicyDecision`` carries optional
   ``proof_artefact`` (a content-address of the underlying proof, if
   any) and ``verification_pointers`` (URLs at which a third-party
   verifier can fetch the operator's published material to re-check
   the decision offline). Providers without proofs simply leave these
   empty.
3. **First-match resolution.** ``supports(tool, agent_id)`` lets
   multiple providers coexist; the engine routes each call to the
   first matching provider.
4. **No new dependencies.** The proposed module uses only the standard
   library.
5. **Additive.** Existing AGT users see no change. Registering zero
   providers leaves the in-process engine unchanged.

## Non-goals

- Not opinionated about identity. Providers receive ``agent_id`` as
  AGT's existing identity layer resolves it (SPIFFE, Entra principal,
  raw string). No identity-mapping changes proposed.
- Not a transport spec. The contract is a Python ABC; an equivalent
  gRPC contract for out-of-process providers is sketched in our
  reference design doc but is **not** part of this PR. We propose that
  as a follow-up once the in-process contract lands.
- Not the engine-side ``register_provider`` wiring. This PR proposes
  the contract that Agent OS's PolicyEngine should call into; the
  actual call site (where ``register_provider`` stores the provider,
  how ``supports`` is iterated, ordering vs. the in-process engine) is
  for the AGT maintainers to design in a follow-up. Our intent here
  is to land the contract first, then collaborate on the wiring.

## Detailed design

See [`upstream-pr-files/agent_os/policy_provider.py`](upstream-pr-files/agent_os/policy_provider.py)
for the proposed module in full. The summary:

```python
@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    proof_artefact: str | None = None
    verification_pointers: Mapping[str, str] = field(default_factory=dict)


class IPolicyProvider(ABC):
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def supports(self, tool: str, agent_id: str) -> bool: ...

    @abstractmethod
    def decide(
        self,
        *,
        tool: str,
        agent_id: str,
        arguments: Mapping[str, Any],
        context: Mapping[str, Any] | None = None,
    ) -> PolicyDecision: ...

    async def decide_async(self, *, tool, agent_id, arguments, context=None):
        return self.decide(tool=tool, agent_id=agent_id,
                           arguments=arguments, context=context)
```

### Tests

[`upstream-pr-files/tests/test_policy_provider.py`](upstream-pr-files/tests/test_policy_provider.py)
contains 10 tests covering:

- ABC enforcement: direct instantiation raises; each abstract method
  individually raises when omitted in a subclass.
- ``PolicyDecision`` frozen invariant (assignment raises).
- ``PolicyDecision`` default values for the optional fields.
- Provider round-trip: a stub provider's ``decide()`` is called with
  the expected arguments and the result fields are preserved.
- Async/sync delegation: the default ``decide_async()`` delegates to
  ``decide()``; a subclass that overrides ``decide_async()`` is not
  fallen back to ``decide()``.

All passing on Python 3.12 / pytest 9.

## FAQ (anticipating maintainer review)

### 1. First-match vs all-match resolution?

This PR proposes **first-match**, matching how YAML/OPA/Cedar adapters
already resolve in AGT. Pros: simplest mental model; lowest latency;
no defence-in-depth surprise where two providers disagree and one
silently loses. Cons: if a deployer wants defence-in-depth, they have
to express it explicitly.

Alternative: **all-match with fail-closed veto** (any DENY wins). We
prefer first-match, but if the maintainers prefer all-match-with-veto
for stronger safety defaults, the contract supports either —
``IPolicyProvider`` doesn't pin the resolution strategy.

### 2. Sync vs async by default?

The contract ships both, with the async variant defaulting to delegate
to sync. Rationale: most providers will be sub-millisecond and
sync-friendly (in-memory SMT proof lookups, signature verification);
providers that perform I/O (HSM-backed signers, external authz
services) override the async path explicitly.

Concrete provider example with sub-100µs sync latency: raucle's
``RauclePolicyProvider``, the linked reference implementation.

### 3. Audit-record schema versioning?

The three new optional fields (``policy_provider``,
``policy_proof_artefact``, ``verification_pointers``) need a schema
version on the AGT audit record so future PDP contract changes don't
break older verifiers. **Out of scope for this PR** — we propose
adding the fields as version 2 of the audit record in a follow-up,
with version-1 verifiers ignoring unknown fields. If the maintainers
have a preferred versioning scheme already in mind for the audit
chain, we adapt to it.

### 4. Conflict resolution: in-process engine vs registered provider?

Proposal: in-process **DENY** always wins (fail-closed for AGT's own
policies); in-process **ALLOW** yields to the provider's verdict;
provider **DENY** terminates the call (with both AGT's and the
provider's reasons recorded in the audit chain). This mirrors AGT's
existing fail-closed semantics across the chain.

If the maintainers prefer a different ordering, the contract itself
is agnostic — the engine's resolution loop is where this lives.

## Backwards compatibility

Fully additive:

- No public API of Agent OS changes in this PR.
- Existing deployments using only the in-process YAML/OPA/Cedar engine
  see no behavioural difference (no provider registered ⇒ engine
  falls through to existing logic).
- The three new audit-record fields are optional; older audit
  consumers ignore them.

## Drawbacks

1. **Adds an abstraction.** Even unused, ``IPolicyProvider`` is one
   more concept in Agent OS's documentation. Mitigation: keep the
   module ~150 lines, docstring-heavy, with the test file demonstrating
   intended use.
2. **Surface for divergent semantics.** Multiple providers in the chain
   could produce subtly different behaviours across deployments. The
   first-match-wins (or alternative) ordering must be precisely
   documented.
3. **Implicit contract on the audit chain.** Once providers populate
   ``proof_artefact`` and ``verification_pointers``, AGT's audit chain
   semantics expand to include them. We see this as a feature (the
   audit record gains externally-verifiable structure) but it does
   couple the chain to the contract going forward.

## Alternatives considered

1. **Continue to embed every policy substrate in-process.** Tractable
   for YAML/OPA/Cedar; not tractable for SMT solvers, Lean
   developments, or TEE attestation chains. Rejected because the
   classes of policy substrate involved are unbounded.
2. **A gRPC-only contract.** Allows non-Python providers but adds a
   transport dependency and forces all providers (including pure-Python
   sub-millisecond ones) through serialisation overhead. Rejected as
   the primary contract; we keep gRPC on the table as a future
   complement (see Non-goals).
3. **An OPA/Rego policy stanza that calls out to an HTTP webhook.**
   Already partially possible via OPA's external-data feature, but
   ties external providers to OPA's lifecycle and offers no native
   audit-chain integration. Rejected as the primary mechanism;
   webhook-style external policies can still be implemented as
   ``IPolicyProvider`` instances under this contract if the deployer
   wishes.

## Reference implementation

A working reference implementation of this contract exists at
[github.com/craigamcw/raucle-detect](https://github.com/craigamcw/raucle-detect),
specifically [`raucle_detect/integrations/agt.py`](https://github.com/craigamcw/raucle-detect/blob/main/raucle_detect/integrations/agt.py).
It implements ``IPolicyProvider`` against raucle's existing
SMT-verified capability gate, with 10/10 tests passing. We link it
here as evidence that the contract is implementable and that at least
one production-track project intends to consume it; the raucle project
is **not** part of this PR.

## Acknowledgements

Thanks to the AGT team for shipping the toolkit and for the clarity of
the existing in-process policy engine — the seam this PR proposes
fits naturally into the architecture already in place.

---

## Once accepted

If/when this contract lands upstream:

1. raucle bumps the corresponding `raucle_detect.integrations.agt`
   import to a thin re-export of the upstream symbols (no behaviour
   change for raucle users).
2. We follow up with a smaller PR proposing the audit-record schema
   bump described in FAQ #3.
3. We sketch the gRPC variant in a separate ADR for non-Python
   providers, if there's appetite.

## How to open the PR

```bash
# fork microsoft/agent-governance-toolkit, then:
git clone git@github.com:craigamcw/agent-governance-toolkit.git
cd agent-governance-toolkit
git checkout -b feat/agent-os-policy-provider-contract

# copy the proposed files into place
mkdir -p agent_os tests
cp /path/to/raucle-detect/docs/proposals/upstream-pr-files/agent_os/policy_provider.py agent_os/
cp /path/to/raucle-detect/docs/proposals/upstream-pr-files/tests/test_policy_provider.py tests/

# verify locally
pytest tests/test_policy_provider.py -v   # expect 10 passing

git add agent_os/policy_provider.py tests/test_policy_provider.py
git commit -s -m "Agent OS: add IPolicyProvider plug-in contract for external PDPs"
git push origin feat/agent-os-policy-provider-contract

# open the PR in the GitHub UI, paste the body above (starting at "Title")
```
