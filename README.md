# GOAD-Light Discovery Driven Domain Breaker

This project performs a resumable, discovery-driven Active Directory assessment inside the authorized GOAD-Light network. It starts without target addresses, hostnames, domains, usernames, passwords, server roles or vulnerability knowledge. The only preconfigured fact is the permitted lab boundary: `192.168.56.0/24`.

## One-button operation

From Kali, run:

```bash
./goadbreaker.sh
```

That is the complete command. The launcher requests `sudo` once at startup when needed, then runs unattended.

It automatically:

1. Confirms Kali has an interface connected to the lab `/24`.
2. Discovers live systems across the subnet.
3. Performs a service-presence sweep when hosts block ping.
4. Scans every TCP port on every discovered non-local system.
5. Fingerprints the open services with Nmap scripts and version detection.
6. Infers domain-controller candidates from observed Kerberos and LDAP services.
7. Discovers naming contexts, domain names and DC hostnames through anonymous LDAP RootDSE.
8. Attempts anonymous LDAP, SMB, SAMR and enum4linux user enumeration.
9. Requests AS-REP material only for usernames actually discovered during enumeration.
10. Uses the local Kali `rockyou.txt` wordlist to test collected material offline.
11. If no credential was recovered, automatically selects the lab-only interface and runs a seven-minute bounded Responder capture.
12. Extracts captured identities, cracks the NetNTLMv2 material and validates recovered credentials against discovered SMB systems.
13. Confirms Domain Admin using recursive authenticated LDAP membership—not merely a `Pwn3d!` label.
14. If the first credential is not DA, performs BloodHound and Certipy collection, requests service tickets from the discovered domain and tests those tickets offline.
15. Generates a sanitized report containing the discovered topology and evidence.
16. After DA is confirmed, automatically collects an NTDS replication proof and produces a hash-free evidence report.

The runner resumes from `state/assessment.json`. Running the same command again continues from collected state instead of repeating completed stages unnecessarily.

## Assessment data flow

```text
Authorized /24
  -> discovered hosts
  -> discovered ports and services
  -> inferred DC candidates
  -> discovered naming contexts and domains
  -> discovered usernames
  -> collected authentication material
  -> recovered credentials
  -> validated host access
  -> authenticated graph and service-ticket evidence
  -> recursive LDAP Domain Admin confirmation
  -> NTDS replication proof
```

Every stage consumes observations from the state file. No GOAD users, domains, server addresses, DA identities or seeded passwords are embedded in the source.

## Kali requirements

Connect Kali to the VMware host-only GOAD network. A NAT adapter may remain connected for package installation; the runner automatically selects an interface whose IPv4 addresses are entirely inside `192.168.56.0/24` before starting Responder.

Install the tools:

```bash
sudo apt update
sudo apt install -y \
  nmap ldap-utils smbclient enum4linux-ng \
  responder hashcat bloodhound.py python3-impacket wordlists
```

Install NetExec and Certipy using their official Kali or project instructions when they are not already available.

Check dependencies without starting an assessment:

```bash
./goadbreaker.sh doctor
```

If Kali only has `rockyou.txt.gz`, the runner automatically expands a private working copy under `state/`.

## Evidence

The most important outputs are:

- `loot/discovery-*.xml`: initial host discovery
- `loot/service-presence-*.xml`: fallback discovery through exposed services
- `loot/ports-*.xml`: complete TCP-port inventory
- `loot/services-*.xml`: service and script fingerprints
- `loot/rootdse-*`: anonymous domain-discovery evidence
- `loot/rpc-users-*`, `loot/nxc-null-users-*`: anonymous enumeration attempts
- `loot/asrep-*`, `loot/netntlmv2-*`, `loot/tgs-*`: collected crackable material
- `loot/validate-*`: password-redacted credential validation
- `state/assessment.json`: protected resumable knowledge base
- `state/events.jsonl`: execution history
- `reports/latest.md`: sanitized final assessment report
- `reports/ntds-proof-*`: NTDS count and SHA-256 evidence without credential hashes

The state file and raw NTDS output contain reusable lab credentials. They are created with restrictive permissions, excluded from Git and must remain inside the isolated lab.

## Optional individual stages

The one-button command is the normal workflow. Individual commands remain available for troubleshooting:

```bash
./goadbreaker.sh recon
./goadbreaker.sh enumerate
./goadbreaker.sh asrep
./goadbreaker.sh responder eth1 --seconds 420
./goadbreaker.sh crack /usr/share/wordlists/rockyou.txt
./goadbreaker.sh validate
./goadbreaker.sh authenticated-enum
./goadbreaker.sh kerberoast
./goadbreaker.sh report
./goadbreaker.sh status
./goadbreaker.sh dump-ntds
```

These commands use the same state and fixed scope. They are not required during the normal unattended run.

## When no automatic path succeeds

A real assessment cannot guarantee Domain Admin in every environment. When the discovered and supported evidence paths do not reach DA, the runner stops with a report and retains the BloodHound and Certipy evidence for analyst review. It does not fabricate a path or blindly modify GPOs, ACLs or group membership merely to force a result.

## Starting over

To begin a genuinely new assessment, archive `loot/`, `state/` and `reports/`, revert all three Windows snapshots together, and run `./goadbreaker.sh` again.

## References

- [Orange Cyberdefense GOAD-Light](https://orange-cyberdefense.github.io/GOAD/labs/GOAD-Light/)
- [Orange Cyberdefense GOAD repository](https://github.com/Orange-Cyberdefense/GOAD)
