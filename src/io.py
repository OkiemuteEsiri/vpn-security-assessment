import json
from pathlib import Path
from .models import VPNProfile

def load_profiles(path:str)->list[VPNProfile]:
    raw=json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw,list): raise ValueError("input must be a JSON array")
    profiles=[VPNProfile.from_dict(x) for x in raw]
    ids=[p.profile_id for p in profiles]
    if len(ids)!=len(set(ids)): raise ValueError("duplicate profile_id")
    return profiles
