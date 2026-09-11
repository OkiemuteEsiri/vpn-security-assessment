from dataclasses import dataclass

PROTOCOLS = {"ikev2", "openvpn", "wireguard", "ssl-vpn"}

@dataclass(frozen=True)
class VPNProfile:
    profile_id: str
    name: str
    protocol: str
    mfa: bool
    certificate_auth: bool
    legacy_auth: bool
    split_tunnel: bool
    dns_protection: bool
    device_posture: bool
    logging: bool
    admin_exposed: bool
    encryption: str
    owner: str

    @classmethod
    def from_dict(cls, r: dict) -> "VPNProfile":
        required = ("profile_id","name","protocol","mfa","certificate_auth","legacy_auth","split_tunnel","dns_protection","device_posture","logging","admin_exposed","encryption","owner")
        missing = [k for k in required if k not in r]
        if missing: raise ValueError("missing required fields: " + ", ".join(missing))
        protocol = str(r["protocol"]).lower()
        if protocol not in PROTOCOLS: raise ValueError("unsupported protocol")
        if not str(r["profile_id"]).strip() or not str(r["name"]).strip(): raise ValueError("profile identity cannot be empty")
        return cls(str(r["profile_id"]), str(r["name"]), protocol, bool(r["mfa"]), bool(r["certificate_auth"]), bool(r["legacy_auth"]), bool(r["split_tunnel"]), bool(r["dns_protection"]), bool(r["device_posture"]), bool(r["logging"]), bool(r["admin_exposed"]), str(r["encryption"]), str(r["owner"]))

@dataclass(frozen=True)
class Finding:
    control_id: str
    title: str
    severity: str
    score: int
    profile: str
    rationale: str
    remediation: str
    validation: str
    attack: tuple[str, ...]
