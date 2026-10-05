#!/usr/bin/env python3
import ast
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import domainbreaker

root = Path(__file__).resolve().parents[1]
source = (root / "domainbreaker.py").read_text(encoding="utf-8")
tree = ast.parse(source)

config = (root / "config" / "goad-light.env").read_text(encoding="utf-8")
assert 'LAB_CIDR="192.168.56.0/24"' in config
for forbidden in ("192.168.56.10", "192.168.56.11", "192.168.56.22", "eddard.stark", "brandon.stark", "jon.snow"):
    assert forbidden not in source.lower(), f"hard-coded scenario knowledge found: {forbidden}"

assert "-just-dc-ntlm" in source
assert "192.168.56.0/24" in source

result = subprocess.run([sys.executable, str(root / "domainbreaker.py"), "--help"], text=True, capture_output=True)
assert result.returncode == 0
assert "complete unattended assessment" in result.stdout

state = {
    "scope": "192.168.56.0/24",
    "hosts": {},
    "domains": {},
    "users": {},
    "hashes": [],
    "access": [],
    "domain_admins": [],
}
json.dumps(state)

with tempfile.TemporaryDirectory() as temporary:
    xml = Path(temporary) / "nmap.xml"
    xml.write_text(
        """<?xml version='1.0'?><nmaprun><host><status state='up'/><address addr='192.168.56.77' addrtype='ipv4'/><hostnames><hostname name='unknown.lab'/></hostnames><ports><port protocol='tcp' portid='88'><state state='open'/><service name='kerberos-sec'/></port><port protocol='tcp' portid='389'><state state='open'/><service name='ldap'/></port></ports></host></nmaprun>""",
        encoding="utf-8",
    )
    parsed = domainbreaker.parse_nmap_xml(xml)
    assert set(parsed["192.168.56.77"]["ports"]) == {"88", "389"}

cracked = domainbreaker.parse_cracked(
    "netntlmv2",
    "DISCOVERED.USER::DISCOVERED:1122334455667788:AABBCCDD:0101|example-password",
)
assert cracked == ("discovered.user", "discovered", "example-password")
print("static checks passed")
