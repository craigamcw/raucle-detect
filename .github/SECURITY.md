# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Raucle Detect, **do not open a public issue**.

Instead, please report it responsibly by emailing:

**security@raucle.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge your report within 48 hours and aim to provide a fix within 7 days for critical issues.

## Scope

The following are in scope:
- Detection engine bypass or evasion (patterns that should match but don't)
- False negatives on known attack techniques
- CLI or REST server vulnerabilities
- Dependency vulnerabilities

The following are out of scope:
- Deliberately crafted adversarial inputs (prompt injection is the threat model, not a vulnerability in Raucle Detect)
- Performance issues on extremely large inputs

## Disclosure

We follow coordinated disclosure. We will credit reporters in the security advisory unless they prefer to remain anonymous.
