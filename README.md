# VPN Security Assessment

A defensive Network Security / Security Engineering project for evaluating VPN remote-access configuration against identity, endpoint, routing, telemetry, management-plane and cryptographic controls.

The implementation is intentionally **offline**. It consumes synthetic configuration metadata and performs no VPN connections, authentication attempts, scanning or traffic generation.

## Why this project exists
VPN security is broader than choosing a protocol. A defensible remote-access architecture depends on identity assurance, device trust, routing policy, logging, administrative isolation, cryptographic standards and accountable ownership. This repository turns those requirements into explainable, testable controls with remediation and revalidation guidance.

## Architecture
```text
Synthetic VPN profiles
        |
        v
Fail-closed JSON ingestion
        |
        v
Validated VPNProfile model
        |
        v
Security control assessment
        |
        v
Risk + ATT&CK context
        |
        v
Remediation / revalidation report
```

## Control coverage
- MFA enforcement
- certificate/device-bound authentication
- legacy authentication retirement
- managed-device posture
- split-tunnel and protected-DNS relationship
- centralized security logging
- management-plane exposure
- weak/legacy cryptographic declarations
- accountable service ownership

## Important design decisions
**Split tunneling is not automatically treated as a vulnerability.** It is assessed in context. The current engine raises a specific condition when split tunneling is enabled without DNS protection.

Likewise, certificate authentication is presented as an assurance control rather than a universal requirement. Production policy should reflect device management, identity architecture and business constraints.

## Repository structure
```text
src/
  models.py
  assessor.py
  io.py
  reporting.py
  cli.py
data/synthetic_profiles.json
tests/test_assessor.py
docs/architecture-methodology.md
reports/example-assessment.md
.github/workflows/ci.yml
```

## Run locally
Python 3.12+; no third-party dependencies.
```bash
python -m src.cli data/synthetic_profiles.json --output vpn-assessment.md
python -m unittest discover -s tests -v
```

## Risk model
The engine produces deterministic 0–100 prioritization scores. They are not CVSS scores and do not claim exploitability. MFA absence and explicitly weak cryptography receive the strongest weighting, followed by exposed administration, legacy authentication, missing logging and endpoint-posture gaps.

## ATT&CK context
Defensive mappings include **T1078 Valid Accounts**, **T1133 External Remote Services**, **T1071.004 DNS**, **T1562.008 Disable or Modify Cloud Logs**, and **T1190 Exploit Public-Facing Application** where relevant. Mapping is investigative context, not evidence of compromise.

## Remediation lifecycle
`assess -> validate business context -> prioritize -> change under control -> authorized functional/security test -> capture evidence -> close or rework`

Every finding includes a specific validation criterion so remediation is not considered complete solely because a configuration ticket was closed.

## Skills demonstrated
Network security, remote-access architecture, identity security, security configuration review, Python automation, risk prioritization, ATT&CK mapping, remediation assurance, unit testing and CI/CD.

## CI
GitHub Actions runs Python compilation, ten unit tests and an offline CLI smoke test with read-only repository permissions.

## Limitations and safety
This lab does not connect to VPN infrastructure, test credentials, spray passwords, scan endpoints, exploit VPN products, implement tunnels or provide bypass logic. All included profiles are synthetic. Real assessments require explicit authorization, vendor-specific configuration review and safe change/retest procedures.

## Roadmap
- Add policy profiles for workforce, privileged and third-party access.
- Add session timeout and reauthentication controls.
- Add certificate lifecycle and revocation metadata.
- Add HA/resilience and logging-retention governance.
- Add before/after remediation comparison.
- Add JSON/CSV findings export.
