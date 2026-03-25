---
name: Detection Rule
about: Propose a new detection rule or pattern
title: "[RULE] "
labels: detection-rule
assignees: craigamcw
---

## Attack Technique

<!-- What attack does this rule detect? -->

## Category

<!-- e.g., direct_injection, jailbreak, data_loss, tool_poisoning, evasion -->

## Pattern

```yaml
- id: COMMUNITY-XXX
  name:
  category:
  technique:
  severity: LOW | MEDIUM | HIGH | CRITICAL
  patterns:
    - 'regex here'
  score: 0.00
```

## Test Cases

**Should match:**
-

**Should NOT match:**
-

## References

<!-- Links to research, CVEs, blog posts about this technique -->
