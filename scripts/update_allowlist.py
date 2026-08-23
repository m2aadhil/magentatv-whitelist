#!/usr/bin/env python3
"""
Magenta TV / Telekom Deutschland — allowlist maintenance.

Daily job: re-resolve every known domain (via public DoH, bypassing the local
blocker), map IPs to ASN/org (RIPE/ARIN RDAP), discover new candidates
(TLS cert SAN clustering + community scrape), classify each domain, regenerate
the list files, and commit+push the repo if anything changed.

Design goals (per spec):
  * Idempotent  — no new data => zero changes, no commit.
  * Additive    — never auto-deletes rules; stale domains are only flagged.
  * Verified    — a domain is "verified" if it is Telekom/partner-owned by
                  suffix, or resolves into a Telekom ASN. Anything resolving
                  to a non-Telekom ASN stays "unverified" for manual review.

Exit 0 on success. Prints a concise human report to stdout (delivered verbatim
by the cron watchdog; empty/no-change runs stay quiet).
"""

import json
import ipaddress
import os
import re
import socket
import ssl
import subprocess
import sys
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta

REPO = "/opt/data/repos/magentatv-whitelist"
JSON_PATH = os.path.join(REPO, "magentatv-allowlist.json")
GIT_CRED = "/opt/data/home/.git-credentials"

DOH = "https://cloudflare-dns.com/dns-query"
DO_H2 = "https://dns.google/resolve"

# --- classification rules ----------------------------------------------------
TELEKOM_SUFFIXES = (
    ".t-online.de", ".telekom.de", ".telekom.com", ".telekom.net",
    ".telekom-dienste.de", ".t-d1.de", ".magentatv.de", ".magenta.tv",
    ".magentamusik.de", ".magentacloud.de", ".magenta.de", ".tiqcdn.com",
)
PARTNER_SUFFIXES = (
    ".accedo.tv", ".3qsdn.net", ".edgesuite.net", ".akamai.net",
    ".akamaiedge.net", ".cloudfront.net", ".i22hosting.de", ".i22.de",
)
TELEKOM_ORG_TOKENS = (
    "DTAG", "T-SYSTEMS", "T-Online", "TOIAG", "DEUTSCHE TELEKOM", "T-MOBILE",
)
# IP netblocks are only emitted for these (Telekom/partner) orgs — never for
# AWS/Akamai/CloudFront/GCP (shared, rotating). Known-good blocks seeded here.
KNOWN_IP_BLOCKS = {
    "80.158.0.0/17",
    "80.157.192.0/22",
    "217.6.164.0/22",
    "91.242.173.0/24",
}
IP_ORG_TOKENS = ("DTAG", "T-SYSTEMS", "T-Online", "TOIAG", "MEDIENGMBH", "3Q")

# Seed domains (community + prior research). source is informational.
SEED = [
    # base (verified earlier via live DNS + RDAP)
    ("magentatv.de", "seed-base"), ("magenta.tv", "seed-base"),
    ("magentamusik.de", "seed-base"), ("magentacloud.de", "seed-base"),
    ("magenta.de", "seed-base"), ("telekom.de", "seed-base"),
    ("telekom.com", "seed-base"), ("telekom-dienste.de", "seed-base"),
    ("t-online.de", "seed-base"), ("entertain-tv.de", "seed-base"),
    ("idm.telekom.com", "seed-base"), ("login.idm.telekom.com", "seed-base"),
    ("accounts.login.idm.telekom.com", "seed-base"),
    ("sso.idm.telekom.com", "seed-base"),
    ("login-production.lam-idm.gc.telekom.net", "seed-base"),
    ("star.lam-idm.gc.telekom.net", "seed-base"),
    ("login.production-v.p5x.telekom.net", "seed-base"),
    ("login.production-f6s.p5x.telekom.net", "seed-base"),
    ("api.telekom.de", "seed-base"), ("api.telekom.com", "seed-base"),
    ("api.magentatv.de", "seed-base"), ("prod.spacegate.telekom.de", "seed-base"),
    ("tiqcdn.com", "seed-base"), ("web.magentatv.de", "seed-base"),
    ("internet.t-d1.de", "seed-base"), ("ebs10.telekom.de", "seed-base"),
    ("cloud.telekom-dienste.de", "seed-base"),
    ("ingress-group01.i22hosting.de", "seed-base"),
    ("cloud.telekom-dienste.de.cname.i22.de", "seed-base"),
    ("www.magentamusik.de.edgesuite.net", "seed-base"),
    ("a1114.dscr.akamai.net", "seed-base"),
    ("e1195.dscg.akamaiedge.net", "seed-base"),
    ("d1m2yu8slaezx0.cloudfront.net", "seed-base"),
    ("d31vkn4t0cmuc3.cloudfront.net", "seed-base"),
    ("d2jma3uliasueq.cloudfront.net", "seed-base"),
    # community seed (from network-automation prompt)
    ("prod.sngtv.t-online.de", "seed-community"),
    ("originalserver.prod.sngtv.t-online.de", "seed-community"),
    ("api.eu.one.accedo.tv", "seed-community"),
    ("wcps.t-online.de", "seed-community"),
    ("tvhubs.t-online.de", "seed-community"),
    ("sfm.t-online.de", "seed-community"),
    ("main.sl.t-online.de", "seed-community"),
    ("cdn.tv.telekom.net", "seed-community"),
    ("prod.streammanager.telekom-dienste.de", "seed-community"),
    ("ns3.3qsdn.net", "seed-community"),
    # discovered via CNAME chain of the seeds above
    ("wcps.cdn2.tv.telekom.net", "seed-cname"),
    ("tvhubs.cdn2.tv.telekom.net", "seed-cname"),
    ("cdn2.tv.telekom.net", "seed-cname"),
]

# Community sources to scrape for new domains (low trust -> unverified).
SCRAPE_URLS = [
    "https://discourse.pi-hole.net/t/magentatv-und-pi-hole/30947.json",
    "https://discourse.pi-hole.net/t/magentacloud-klappt-nicht-mit-existenten-pi-hole-was-lauft-da-falsch/65131.json",
]

DOMAIN_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\.(?:de|com|net|tv|at|io|cloud)", re.I)


# --- helpers -----------------------------------------------------------------
def http_json(url, timeout=15):
    req = urllib.request.Request(url, headers={"accept": "application/json",
                                               "user-agent": "magentatv-allowlist/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def doh(name, rtype="A"):
    """Resolve via public DoH. Returns (status, ips, cnames)."""
    q = urllib.parse.urlencode({"name": name, "type": rtype})
    try:
        r = http_json(f"{DOH}?{q}", timeout=15)
        ans = r.get("Answer") or []
        ips = [a["data"] for a in ans if a.get("type") == 1]
        cnames = [a["data"].rstrip(".") for a in ans if a.get("type") == 5]
        return r.get("Status", -1), ips, cnames
    except Exception:
        try:
            r = http_json(f"{DO_H2}?{q}", timeout=15)
            ans = r.get("Answer") or []
            ips = [a["data"] for a in ans if a.get("type") == 1]
            cnames = [a["data"].rstrip(".") for a in ans if a.get("type") == 5]
            return r.get("Status", -1), ips, cnames
        except Exception:
            return -1, [], []


def rdap(ip):
    """Return (netname, netblocks, org) from RIPE then ARIN RDAP."""
    for base in (f"https://rdap.db.ripe.net/ip/{ip}",
                 f"https://rdap.arin.net/registry/ip/{ip}"):
        try:
            r = http_json(base, timeout=15)
            name = r.get("name", "?")
            blocks = [f"{e.get('v4prefix','')}/{e.get('length','')}"
                      for e in r.get("cidr0_cidrs", []) if e.get("v4prefix")]
            org = ""
            for e in r.get("entities", []):
                va = e.get("vcardArray")
                if isinstance(va, list) and len(va) > 1:
                    for it in va[1]:
                        if it[0] == "fn":
                            org = it[3]
                            break
                if org:
                    break
            return name, blocks, org
        except Exception:
            continue
    return "?", [], "?"


def local_blocked(name):
    """True if the local resolver sinkholes this name to 0.0.0.0."""
    try:
        infos = socket.getaddrinfo(name, None)
        return any(i[4][0] in ("0.0.0.0", "::") for i in infos)
    except Exception:
        return False


def cert_sans(host):
    """Extract DNS SAN entries from the host's TLS cert (best-effort)."""
    try:
        out = subprocess.run(
            ["timeout", "10", "openssl", "s_client", "-connect", f"{host}:443",
             "-servername", host],
            input=b"", stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=12,
        ).stdout
        out2 = subprocess.run(
            ["openssl", "x509", "-noout", "-ext", "subjectAltName"],
            input=out, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=12,
        ).stdout.decode(errors="ignore")
        return set(m.group(1) for m in re.finditer(r"DNS:([^,\s]+)", out2))
    except Exception:
        return set()


def scrape_candidates():
    """Best-effort extraction of domain-like tokens from community sources."""
    found = set()
    for url in SCRAPE_URLS:
        try:
            data = http_json(url, timeout=15)
            blob = json.dumps(data)
        except Exception:
            try:
                blob = urllib.request.urlopen(
                    urllib.request.Request(url, headers={"user-agent": "Mozilla/5.0"}),
                    timeout=15).read().decode(errors="ignore")
            except Exception:
                continue
        for m in DOMAIN_RE.findall(blob):
            d = m.lower().rstrip(".")
            if d.endswith(TELEKOM_SUFFIXES) or d.endswith(PARTNER_SUFFIXES):
                found.add(d)
    return found


# --- core --------------------------------------------------------------------
def load_state():
    if os.path.exists(JSON_PATH):
        with open(JSON_PATH) as f:
            return json.load(f)
    return {"version": 1, "domains": {}, "ip_netblocks": sorted(KNOWN_IP_BLOCKS)}


def _has_suffix(domain, suffixes):
    for s in suffixes:
        if domain == s[1:] or domain.endswith(s):  # bare apex or subdomain
            return True
    return False


def classify(domain, status, ips, cnames, org):
    if status == 3:  # NXDOMAIN
        return "rejected"
    if _has_suffix(domain, TELEKOM_SUFFIXES) or _has_suffix(domain, PARTNER_SUFFIXES):
        return "verified"
    if ips or cnames:  # resolves
        if any(t in org.upper() for t in TELEKOM_ORG_TOKENS):
            return "verified"
        return "unverified"
    return "unverified"


def _collapse(blocks):
    """Drop any block that is a subnet of a larger block already kept."""
    kept = []
    nets = sorted((ipaddress.ip_network(b) for b in blocks if "/" in b),
                  key=lambda n: (n.prefixlen, int(n.network_address)))
    for n in nets:
        if not any(n.subnet_of(k) for k in kept):
            kept.append(n)
    return sorted(str(k) for k in kept)


def main():
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    state = load_state()
    domains = state.setdefault("domains", {})
    changed = False
    report = {"new_verified": [], "new_unverified": [], "rejected": [],
              "blocked_alerts": [], "stale": [], "errors": []}

    # 1) ensure all seed domains exist in state
    for d, src in SEED:
        if d not in domains:
            domains[d] = {
                "hostname": d, "status": "unverified", "first_seen": today,
                "last_seen": None, "session_phase": "unknown",
                "resolved_asn": "", "ips": [], "source": src,
            }
            changed = True

    # 2) discover candidates from cert SAN clustering + community scrape
    new_candidates = scrape_candidates()
    # cert SAN on verified Telekom hosts (cheap sibling discovery)
    telekom_hosts = [d for d, v in domains.items() if d.endswith(TELEKOM_SUFFIXES)]
    for host in telekom_hosts[:25]:  # cap to keep the run fast
        for san in cert_sans(host):
            san = san.lstrip("*.").lower().rstrip(".")
            if (san.endswith(TELEKOM_SUFFIXES) or san.endswith(PARTNER_SUFFIXES)):
                new_candidates.add(san)
    for c in new_candidates:
        if c not in domains:
            domains[c] = {
                "hostname": c, "status": "unverified", "first_seen": today,
                "last_seen": None, "session_phase": "unknown",
                "resolved_asn": "", "ips": [], "source": "discovered",
            }
            changed = True

    # 3) verify every domain
    ip_orgs = {}  # ip -> (netname, netblocks, org)
    for d, rec in domains.items():
        status, ips, cnames = doh(d)
        if status == -1:
            report["errors"].append(d)
            continue
        asn = ""
        if ips:
            for ip in ips:
                if ip not in ip_orgs:
                    name, blocks, org = rdap(ip)
                    ip_orgs[ip] = (name, blocks, org)
            names = ip_orgs[ips[0]]
            asn = f"{names[0]} | {names[2]}"
            rec["ips"] = sorted(set(ips))
        rec["resolved_asn"] = asn or ""
        old_status = rec.get("status")
        new_status = classify(d, status, ips, cnames, asn)
        rec["status"] = new_status
        if ips or cnames or local_blocked(d):
            rec["last_seen"] = today
        if old_status != new_status:
            changed = True
        if new_status == "rejected" and old_status not in (None, "rejected"):
            report["rejected"].append(d)
        if new_status == "verified" and old_status not in ("verified",):
            report["new_verified"].append(d)
        if new_status == "unverified" and old_status not in ("unverified",):
            report["new_unverified"].append(d)

    # 4) blocked-alert: a verified domain currently sinkholed locally
    for d, rec in domains.items():
        if rec["status"] == "verified" and rec.get("last_seen") == today:
            if local_blocked(d):
                report["blocked_alerts"].append(d)

    # 5) stale flag (>90 days not seen)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%d")
    for d, rec in domains.items():
        ls = rec.get("last_seen")
        if rec["status"] == "verified" and ls and ls < cutoff:
            report["stale"].append(d)

    # 6) rebuild IP netblocks (Telekom/partner orgs only)
    netblocks = set(KNOWN_IP_BLOCKS)
    for ip, (name, blocks, org) in ip_orgs.items():
        if any(t in org.upper() for t in IP_ORG_TOKENS) or any(t in name.upper() for t in IP_ORG_TOKENS):
            netblocks.update(blocks)
    netblocks = _collapse(netblocks)
    if netblocks != state.get("ip_netblocks"):
        state["ip_netblocks"] = netblocks
        changed = True

    # 7) regenerate list files
    verified = sorted(d for d, r in domains.items() if r["status"] == "verified")
    unverified = sorted(d for d, r in domains.items() if r["status"] == "unverified")

    verified_lines = list(verified)
    if unverified:
        verified_lines += [""] + ["# unverified (review before adding)"] + list(unverified)
    domains_txt = "\n".join(verified_lines) + "\n"
    ips_txt = "\n".join(netblocks) + "\n"
    adguard_txt = "\n".join(f"@@||{d}^" for d in verified) + "\n"
    regex_txt = "\n".join(
        r"(\.|^)" + re.escape(d) + r"$" for d in verified
    ) + "\n"

    files = {
        "domains.txt": domains_txt,
        "ips.txt": ips_txt,
        "domains-adguard.txt": adguard_txt,
        "domains-regex.txt": regex_txt,
    }
    for fn, content in files.items():
        p = os.path.join(REPO, fn)
        old = open(p).read() if os.path.exists(p) else ""
        if old != content:
            with open(p, "w") as f:
                f.write(content)
            changed = True

    # 8) write JSON only on a real change (keeps tree clean / idempotent)
    if changed:
        state["last_updated"] = datetime.now(timezone.utc).isoformat()
        tmp = JSON_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(state, f, indent=2, ensure_ascii=False, sort_keys=True)
        os.replace(tmp, JSON_PATH)

    # 9) commit + push if changed
    commit = None
    if changed:
        r = subprocess.run(
            ["git", "-C", REPO, "add", "-A"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        r = subprocess.run(
            ["git", "-C", REPO,
             "-c", f"credential.helper=store --file={GIT_CRED}",
             "-c", "user.name=Aadhil Musthaq",
             "-c", "user.email=musthaqaadhil@gmail.com",
             "commit", "-m", f"chore: allowlist refresh {today}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if r.returncode == 0:
            pr = subprocess.run(
                ["git", "-C", REPO,
                 "-c", f"credential.helper=store --file={GIT_CRED}",
                 "push", "-q", "origin", "main"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if pr.returncode == 0:
                commit = subprocess.run(
                    ["git", "-C", REPO, "rev-parse", "--short", "HEAD"],
                    stdout=subprocess.PIPE).stdout.decode().strip()
            else:
                report["errors"].append("git push failed")

    # 10) report — silent unless something changed or needs attention
    has_alert = (report["new_unverified"] or report["rejected"] or
                 report["blocked_alerts"] or report["stale"] or report["errors"])
    if not changed and not has_alert:
        return 0

    n_verified = sum(1 for r in domains.values() if r["status"] == "verified")
    n_unver = sum(1 for r in domains.values() if r["status"] == "unverified")
    n_rej = sum(1 for r in domains.values() if r["status"] == "rejected")
    lines = [f"📡 Magenta TV allowlist refresh — {today}",
             f"Domains: {len(domains)} total · {n_verified} verified · {n_unver} unverified · {n_rej} rejected"]
    if commit:
        lines.append(f"Updated & pushed ({commit}): {n_verified} verified domains, {len(netblocks)} IP blocks")
    else:
        lines.append("No changes — allowlist already current")
    if report["new_verified"]:
        lines.append("➕ Newly verified: " + ", ".join(report["new_verified"]))
    if report["new_unverified"]:
        lines.append("🟡 Needs review (unverified): " + ", ".join(report["new_unverified"]))
    if report["rejected"]:
        lines.append("🚫 Rejected (NXDOMAIN): " + ", ".join(report["rejected"]))
    if report["blocked_alerts"]:
        lines.append("⚠️ ALERT — verified but blocked locally: " + ", ".join(report["blocked_alerts"]))
    if report["stale"]:
        lines.append("⏳ Stale (>90d unseen, review for removal): " + ", ".join(report["stale"]))
    if report["errors"]:
        lines.append("🔴 Lookup errors: " + ", ".join(report["errors"]))
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
