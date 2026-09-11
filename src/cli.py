import argparse
from pathlib import Path
from .assessor import assess
from .io import load_profiles
from .reporting import markdown_report

def main():
    p=argparse.ArgumentParser(description="Assess supplied VPN security configuration offline")
    p.add_argument("input"); p.add_argument("--output",default="vpn-assessment.md")
    a=p.parse_args(); findings=[f for profile in load_profiles(a.input) for f in assess(profile)]
    Path(a.output).write_text(markdown_report(findings),encoding="utf-8")
    print(f"Wrote {a.output} with {len(findings)} findings")

if __name__=="__main__": main()
