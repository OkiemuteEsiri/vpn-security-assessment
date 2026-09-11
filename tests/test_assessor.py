import unittest
from src.assessor import assess,metrics
from src.models import VPNProfile

def profile(**kw):
    base=dict(profile_id="P1",name="lab",protocol="ikev2",mfa=True,certificate_auth=True,legacy_auth=False,split_tunnel=False,dns_protection=True,device_posture=True,logging=True,admin_exposed=False,encryption="AES-256-GCM",owner="owner")
    base.update(kw); return VPNProfile(**base)

class Tests(unittest.TestCase):
    def test_secure_baseline_clean(self): self.assertEqual(assess(profile()),[])
    def test_missing_mfa_critical(self): self.assertEqual(next(f for f in assess(profile(mfa=False)) if f.control_id=="VPN-001").severity,"Critical")
    def test_legacy_auth(self): self.assertTrue(any(f.control_id=="VPN-002" for f in assess(profile(legacy_auth=True))))
    def test_device_posture(self): self.assertTrue(any(f.control_id=="VPN-004" for f in assess(profile(device_posture=False))))
    def test_split_dns_correlation(self): self.assertTrue(any(f.control_id=="VPN-005" for f in assess(profile(split_tunnel=True,dns_protection=False))))
    def test_logging(self): self.assertTrue(any(f.control_id=="VPN-006" for f in assess(profile(logging=False))))
    def test_admin_exposure(self): self.assertTrue(any(f.control_id=="VPN-007" for f in assess(profile(admin_exposed=True))))
    def test_weak_crypto(self): self.assertTrue(any(f.control_id=="VPN-008" for f in assess(profile(encryption="3DES"))))
    def test_missing_owner(self): self.assertTrue(any(f.control_id=="GOV-001" for f in assess(profile(owner=""))))
    def test_metrics(self): self.assertEqual(metrics(assess(profile(mfa=False)))["critical_high"],1)

if __name__=="__main__": unittest.main()
