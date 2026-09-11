# VPN Security Assessment Methodology

## Purpose
This project evaluates supplied VPN configuration metadata as a defensive posture exercise. It does not establish network connections or attempt authentication.

## Architecture
`synthetic JSON -> fail-closed model validation -> control checks -> deterministic risk -> ATT&CK context -> remediation/revalidation report`

## Control domains
Identity assurance (MFA, certificate/device-bound factors, legacy authentication), endpoint posture, split-tunnel/DNS governance, centralized logging, management-plane exposure, cryptographic baseline and service ownership.

## Risk model
Scores are deterministic prioritization aids rather than CVSS or exploitability probabilities. MFA absence and declared weak cryptography receive the highest weight. Multiple findings can apply independently to one profile so remediation teams can close controls separately.

## Split tunneling
Split tunneling is not automatically classified as insecure. The engine raises a specific condition only when split tunneling is enabled while DNS protection is absent. Production decisions should consider business requirements, endpoint controls, routing policy, SaaS traffic, monitoring and data-loss risks.

## ATT&CK context
T1078, T1133, T1071.004, T1562.008 and T1190 are used for defensive classification. Mapping does not prove compromise.

## Remediation validation
Each finding contains a post-change validation criterion. Closure should require evidence that the intended identity, routing, telemetry, cryptographic or management-plane control is effective—not merely that configuration work was requested.

## Safety
The lab contains no credential testing, password spraying, VPN exploitation, scanning, tunneling implementation, bypass logic or production targets.
