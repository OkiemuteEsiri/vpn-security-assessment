from collections import Counter
from .models import Finding, VPNProfile


def assess(p: VPNProfile) -> list[Finding]:
    out=[]
    def add(cid,title,sev,score,why,fix,check,attack=()): out.append(Finding(cid,title,sev,score,p.name,why,fix,check,tuple(attack)))
    if not p.mfa: add("VPN-001","MFA not enforced","Critical",92,"Remote access without MFA increases reliance on a single credential factor.","Require phishing-resistant or strong MFA for remote access, with controlled break-glass procedures.","Confirm normal and privileged remote access cannot complete without the approved second factor.",( "T1078","T1133"))
    if p.legacy_auth: add("VPN-002","Legacy authentication enabled","High",80,"Legacy authentication can weaken identity controls and policy enforcement.","Disable legacy authentication after dependency validation and migrate users to the approved authentication flow.","Verify legacy methods are rejected and approved clients still authenticate.",( "T1078","T1133"))
    if not p.certificate_auth: add("VPN-003","Certificate/device-bound authentication absent","Medium",55,"A device-bound factor can strengthen assurance for managed remote endpoints.","Evaluate certificate or equivalent device-bound authentication for managed access tiers.","Validate certificate lifecycle, revocation and expected client access.",( "T1133",))
    if not p.device_posture: add("VPN-004","Device posture not enforced","High",72,"Remote access does not verify minimum endpoint security state.","Require managed-device posture such as supported OS, healthy security controls and approved enrollment.","Test compliant and deliberately non-compliant synthetic device states.",( "T1133","T1078"))
    if p.split_tunnel and not p.dns_protection: add("VPN-005","Split tunneling lacks DNS protection","Medium",62,"Split routing without controlled DNS can reduce visibility and policy consistency.","Define split-tunnel destinations explicitly and enforce approved DNS/security controls.","Verify corporate destinations and DNS queries follow the intended protected path.",( "T1071.004",))
    if not p.logging: add("VPN-006","Security logging disabled","High",75,"Missing authentication and session telemetry weakens detection and incident reconstruction.","Enable centrally retained authentication, session, administrative and policy-change logging.","Generate an authorized test connection and confirm complete timestamped telemetry reaches monitoring.",( "T1562.008",))
    if p.admin_exposed: add("VPN-007","Administrative interface exposed to remote-access zone","High",82,"Administrative management exposure increases attack surface for a sensitive control plane.","Restrict administration to dedicated management networks and strong privileged access controls.","Confirm management access is denied from unapproved remote-access segments.",( "T1133","T1190"))
    if p.encryption.lower() in {"3des","des","rc4","pptp","weak"}: add("VPN-008","Weak cryptographic configuration","Critical",90,"The declared profile uses a legacy or weak cryptographic option.","Migrate to organization-approved modern cryptographic suites and protocols.","Confirm weak negotiation is unavailable and approved clients establish the intended secure profile.",( "T1133",))
    if not p.owner.strip(): add("GOV-001","VPN profile owner missing","Medium",45,"Security exceptions and remediation require accountable ownership.","Assign a service owner and document lifecycle/change responsibility.","Confirm ownership in the service inventory and change process.")
    return sorted(out,key=lambda f:f.score,reverse=True)


def metrics(findings:list[Finding])->dict:
    c=Counter(f.severity for f in findings)
    return {"findings":len(findings),"critical_high":c["Critical"]+c["High"],"highest_score":max((f.score for f in findings),default=0),"severity_counts":dict(c)}
