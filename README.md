# Magenta TV / Telekom Deutschland — Whitelist 🛡️

Domains & IP ranges to **whitelist** so **Magenta TV** (Telekom Deutschland) streams without issues on a **GL.iNet router** running a VPN, AdGuard Home, or any DNS-based blocker.

- ✅ Split-tunnel Magenta TV **out of the VPN** (geo-lock & DRM safe)
- ✅ Allow Magenta TV / Telekom in **AdGuard Home / ad-block**
- ✅ Keep everything else on your VPN / blocker

---

## Why

Magenta TV is **geo-locked to Germany** and **DRM-protected** (Widevine / PlayReady). If your VPN exit is abroad — or your DNS blocker sinkholes Telekom's content CDN — playback breaks. The standard fix is to route Magenta TV / Telekom traffic **directly over your Telekom line, bypassing the VPN**. This repo is the drop-in list for that.

## Files

| File | Format | Use |
|------|--------|-----|
| [`glinet.txt`](glinet.txt) | one filter/line (domains + CIDRs) | **GL.iNet direct import** (VPN Policy / Parental Control) |
| [`domains.txt`](domains.txt) | plain, one per line | AdGuard / ad-block whitelist |
| [`ips.txt`](ips.txt) | CIDR, one per line | firewall / policy routing |
| [`domains-adguard.txt`](domains-adguard.txt) | `@@\|\|domain^` | AdGuard Home custom allowlist rules |
| [`domains-regex.txt`](domains-regex.txt) | Pi-hole regex | Pi-hole allowlist |

---

## GL.iNet — import by URL (firmware v4.7+)

GL.iNet routers (v4.7+) can import rules straight from an online text file. Use the **raw** URL (not the `github.com/.../blob/...` page URL):

```
https://raw.githubusercontent.com/m2aadhil/magentatv-whitelist/main/glinet.txt
```

- **VPN → VPN Policy** → "Based on target domain or IP" → import the URL above.
- **Parental Control → Add a New Ruleset** → import the URL above (domain filters only).

`glinet.txt` follows the GL.iNet format: **one filter per line** — `domain` (matches all subdomains), `subdomain`, or `CIDR` — no comments.

## GL.iNet — VPN split-tunnel (recommended)

This makes Magenta TV bypass the VPN entirely and use your Telekom connection directly — which is what you want for geo-locked German TV.

1. Admin panel → **VPN → VPN Client** → your WireGuard/OpenVPN profile → **Global Options**.
2. Open **VPN Policy** (a.k.a. **Proxy Mode**).
3. Enable **Policy Mode** and select **"Proxy all traffic except the following"**.
4. Add the entries from [`domains.txt`](domains.txt) and [`ips.txt`](ips.txt).
5. Save & apply. Magenta TV now leaves through your Telekom line while everything else stays on the VPN.

> On some firmware versions the rule is labelled **"Based on the target domain or IP"** — add the domains and IPs there. Exact wording differs slightly between firmware 3.x and 4.x.

## GL.iNet — AdGuard Home / ad-block allowlist

- **AdGuard Home** → **Filters → Custom filtering rules** → paste [`domains-adguard.txt`](domains-adguard.txt).
- Built-in **Ad Block** (dnsmasq-based) → whitelist → paste [`domains.txt`](domains.txt).

---

## The lists

### Domains (33)

```
magentatv.de
magenta.tv
magentamusik.de
magentacloud.de
magenta.de
telekom.de
telekom.com
telekom-dienste.de
t-online.de
idm.telekom.com
login.idm.telekom.com
accounts.login.idm.telekom.com
sso.idm.telekom.com
login-production.lam-idm.gc.telekom.net
star.lam-idm.gc.telekom.net
login.production-v.p5x.telekom.net
login.production-f6s.p5x.telekom.net
api.telekom.de
api.telekom.com
api.magentatv.de
prod.spacegate.telekom.de
tiqcdn.com
web.magentatv.de
internet.t-d1.de
ebs10.telekom.de
cloud.telekom-dienste.de
ingress-group01.i22hosting.de
cloud.telekom-dienste.de.cname.i22.de
www.magentamusik.de.edgesuite.net
a1114.dscr.akamai.net
e1195.dscg.akamaiedge.net
d1m2yu8slaezx0.cloudfront.net
d31vkn4t0cmuc3.cloudfront.net
d2jma3uliasueq.cloudfront.net
```

### IP ranges (Telekom-owned, verified via RIPE RDAP)

```
80.158.0.0/17     # Magenta TV / Entertain / Magenta Musik core (T-Systems)
217.6.164.0/22    # magenta.de
```

---

## Notes

- The CDN/API layer (AWS **CloudFront**, **Akamai**, **Google Cloud**) uses **rotating IPs** — always whitelist those **by domain**, never by IP. The IP ranges above only cover Telekom's own service core.
- **`tiqcdn.com`** is the Telekom/T-Systems content CDN most often sinkholed by ad-blockers — keep it whitelisted.
- If Magenta TV still won't play after whitelisting, your VPN exit is almost certainly **outside Germany**. Switch to a German exit, or use the split-tunnel above.

## Auto-maintenance (daily job)

This repo self-updates. A scheduled job runs [`scripts/update_allowlist.py`](scripts/update_allowlist.py) daily and:

1. Re-resolves every domain via public **DoH** (bypassing the local blocker) and maps each IP to its **ASN/org** (RIPE/ARIN RDAP).
2. Discovers new candidates via **TLS cert SAN clustering** (finds sibling `*.sngtv.t-online.de`-style subdomains) and community-source scraping.
3. Classifies each domain:
   - `verified` — Telekom/partner-owned (by suffix or ASN).
   - `unverified` — resolves to a non-Telekom ASN; kept out of the live list, listed for manual review.
   - `rejected` — NXDOMAIN.
4. Regenerates `domains.txt`, `ips.txt`, `domains-adguard.txt`, `domains-regex.txt` and commits+pushes **only when something changed** (idempotent).

State lives in [`magentatv-allowlist.json`](magentatv-allowlist.json) (hostname, status, first/last-seen, ASN, IPs, source). The job is **additive** — it never auto-deletes; stale domains (>90 days unseen) are only flagged. It also alerts if a verified domain starts being sinkholed locally again.

> Live query-log / packet-capture verification (AdGuard Home API, tcpdump) isn't wired up yet — it needs router/AdGuard access. The script is structured so those methods can be plugged in later.

## License

[MIT](LICENSE)
