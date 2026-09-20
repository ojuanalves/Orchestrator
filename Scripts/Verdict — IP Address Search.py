#!/usr/bin/env python3
"""
ip_investigate.py
=================

Technical IP triage tool for attack analysis (brute-force attempts and
unauthorized access against FortiAuthenticator, FortiGate, etc).

Queries several sources in parallel, merges the results internally and
prints a technical dossier. It reports data only: no verdict, no
conclusion.

SOURCES
-------
  Geolocation / ASN
    ipapi.is        geo, ASN, risk flags (datacenter/VPN/proxy/Tor/abuser)
    ip-api.com      geo, ASN, ISP, proxy/hosting/mobile flags
    ipwho.is        geo, ASN, connection details

  Registry / Routing
    RDAP            structured WHOIS: allocation, status, dates, contacts
    RIPEstat        BGP announced prefix, origin ASN, route visibility,
                    authoritative abuse contacts, AS overview,
                    RPKI route origin validation

  DNS
    PTR             reverse DNS
    FCrDNS          forward-confirmed reverse DNS validation
    DNSBL           6 blocklists with return code interpretation
    Tor DNSEL       official Tor Project exit node list

  Address properties
    RFC scope classification, numeric representations, parent networks

USAGE
-----
    python3 ip_investigate.py
    python3 ip_investigate.py 1.2.3.4
    python3 ip_investigate.py 1.2.3.4 --json      structured JSON output
    python3 ip_investigate.py 1.2.3.4 --raw       raw response per source
"""

import ipaddress
import io
import json
import os
import platform
import re
import socket
import sys
import time
import unicodedata
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

TIMEOUT = 10
RETRIES = 2

# Spamhaus publishes error codes in 127.255.255.0/24. They carry no
# reputation meaning and must never be read as a listing.
DNSBL_ERROR_CODES = {
    "127.255.255.252": "Malformed DNSBL zone name in the query",
    "127.255.255.253": "Query sent without a valid reverse-DNS identity",
    "127.255.255.254": "Query blocked: sent through a public/open DNS resolver",
    "127.255.255.255": "Query blocked: resolver exceeded its daily quota",
}

DNSBL_LIST = {
    "zen.spamhaus.org": {
        "label": "Spamhaus ZEN (SBL + CSS + XBL + PBL)",
        "codes": {
            "127.0.0.2": "SBL: verified spam source",
            "127.0.0.3": "SBL CSS: snowshoe spam, automatic listing",
            "127.0.0.4": "XBL: compromised host, open proxy or worm",
            "127.0.0.5": "XBL: compromised host (CBL feed)",
            "127.0.0.6": "XBL: compromised host",
            "127.0.0.7": "XBL: compromised host",
            "127.0.0.9": "SBL DROP/EDROP: hijacked or criminal netblock",
            "127.0.0.10": "PBL: end-user/dynamic range, should not send SMTP",
            "127.0.0.11": "PBL: end-user/dynamic range, ISP policy",
        },
    },
    "bl.spamcop.net": {
        "label": "SpamCop, user-submitted spam reports",
        "codes": {"127.0.0.2": "Reported as a spam source"},
    },
    "b.barracudacentral.org": {
        "label": "Barracuda Reputation Block List",
        "codes": {"127.0.0.2": "Poor reputation: spam or abuse"},
    },
    "dnsbl-1.uceprotect.net": {
        "label": "UCEPROTECT Level 1, single IP",
        "codes": {"127.0.0.2": "Individual IP involved in abuse"},
    },
    "dnsbl.sorbs.net": {
        "label": "SORBS, aggregate of several lists",
        "codes": {
            "127.0.0.2": "Open HTTP proxy",
            "127.0.0.3": "Open SOCKS proxy",
            "127.0.0.4": "Open proxy, other protocols",
            "127.0.0.5": "Open SMTP relay",
            "127.0.0.6": "Spam source",
            "127.0.0.7": "Exploitable web form",
            "127.0.0.8": "Host permits spam by policy",
            "127.0.0.9": "Hijacked netblock or illegal route",
            "127.0.0.10": "Dynamic/end-user address",
            "127.0.0.11": "Missing or generic reverse DNS",
            "127.0.0.12": "Policy: sender not authorised",
            "127.0.0.14": "Zombie, compromised host",
        },
    },
    "cbl.abuseat.org": {
        "label": "CBL (Composite Blocking List), infected machines",
        "codes": {"127.0.0.2": "Infection detected: botnet, worm or open proxy"},
    },
}

TOR_DNSEL = "dnsel.torproject.org"
RIPESTAT = "https://stat.ripe.net/data"

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

W = 64  # report width


def c(text, code):
    return f"\033[{code}m{text}\033[0m"


def section(text):
    bar = "─" * max(0, W - len(text) - 4)
    print("\n" + c(f"╭─ {text} {bar}", "1;36"))


def row(label, value, alert=False, note=None, indent=2, dim=False):
    if value in (None, "", [], {}):
        value = "—"
        dim = True
    width = max(10, 28 - indent)
    if alert:
        style = "1;31"
    elif dim:
        style = "0;90"
    else:
        style = "0"
    line = f"{' ' * indent}{c(label, '0;37'):<{width + 9}} {c(str(value), style)}"
    if note:
        line += c(f"   {note}", "0;90")
    print(line)


def bullet(text, style="0"):
    print(f"      {c(text, style)}")


def norm(s):
    if s is None:
        return ""
    s = unicodedata.normalize("NFKD", str(s)).encode("ASCII", "ignore").decode("ASCII")
    return " ".join(s.lower().split())


def valid_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def get_json(url, headers=None, timeout=TIMEOUT, retries=RETRIES):
    """Returns (data, error, elapsed_ms). Retries on 5xx and network errors."""
    last_err = None
    start = time.time()
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(
                url, headers=headers or {"User-Agent": "ip-investigate/4.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read().decode("utf-8", errors="replace"))
                ms = int((time.time() - start) * 1000)
                if not isinstance(body, dict):
                    return None, f"Unexpected payload: {body}", ms
                return body, None, ms
        except urllib.error.HTTPError as e:
            last_err = f"HTTP {e.code} {e.reason}"
            if e.code < 500:  # client errors will not change on retry
                break
        except urllib.error.URLError as e:
            last_err = f"Network: {e.reason}"
        except json.JSONDecodeError:
            last_err = "Invalid JSON"
            break
        except Exception as e:
            last_err = str(e)
        if attempt < retries:
            time.sleep(0.4 * (attempt + 1))
    return None, last_err, int((time.time() - start) * 1000)


# ---------------------------------------------------------------------------
# Address properties
# ---------------------------------------------------------------------------


def address_properties(ip):
    o = ipaddress.ip_address(ip)
    n = int(o)
    p = {
        "version": f"IPv{o.version}",
        "decimal": n,
        "hex": hex(n),
        "arpa": o.reverse_pointer,
        "is_global": o.is_global,
        "is_private": o.is_private,
        "is_reserved": o.is_reserved,
        "is_multicast": o.is_multicast,
        "is_loopback": o.is_loopback,
        "is_link_local": o.is_link_local,
    }
    if o.version == 4:
        octets = [int(x) for x in ip.split(".")]
        p["binary"] = ".".join(f"{x:08b}" for x in octets)
        p["net_24"] = str(ipaddress.ip_network(f"{ip}/24", strict=False))
        p["net_16"] = str(ipaddress.ip_network(f"{ip}/16", strict=False))
        first = octets[0]
        p["legacy_class"] = ("A" if first < 128 else "B" if first < 192 else
                             "C" if first < 224 else "D (multicast)" if first < 240 else "E (reserved)")
    else:
        p["compressed"] = o.compressed
        p["exploded"] = o.exploded
    return p


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------


def src_ipapi_is(ip):
    d, e, ms = get_json(f"https://api.ipapi.is/?q={ip}")
    return {"error": e, "_ms": ms} if e else {**d, "_ms": ms}


def src_ip_api_com(ip):
    fields = ("status,message,continent,country,countryCode,region,regionName,city,district,"
              "zip,lat,lon,timezone,offset,isp,org,as,asname,reverse,mobile,proxy,hosting,query")
    d, e, ms = get_json(f"http://ip-api.com/json/{ip}?fields={fields}")
    if e:
        return {"error": e, "_ms": ms}
    if d.get("status") == "fail":
        return {"error": d.get("message", "lookup failed"), "_ms": ms}
    return {**d, "_ms": ms}


def src_ipwho_is(ip):
    d, e, ms = get_json(f"https://ipwho.is/{ip}")
    if e:
        return {"error": e, "_ms": ms}
    if d.get("success") is False:
        return {"error": d.get("message", "lookup failed"), "_ms": ms}
    return {**d, "_ms": ms}


def src_rdap(ip):
    d, e, ms = get_json(f"https://rdap.org/ip/{ip}")
    return {"error": e, "_ms": ms} if e else {**d, "_ms": ms}


def _ripe(endpoint, resource):
    d, e, ms = get_json(f"{RIPESTAT}/{endpoint}/data.json?resource={resource}")
    if e:
        return {"error": e, "_ms": ms}
    return {**(d.get("data") or {}), "_ms": ms}


def src_ripe_network(ip):
    return _ripe("network-info", ip)


def src_ripe_abuse(ip):
    return _ripe("abuse-contact-finder", ip)


def src_ripe_routing(ip):
    return _ripe("routing-status", ip)


def src_ripe_as(asn):
    return _ripe("as-overview", f"AS{asn}") if asn else {"error": "ASN not resolved"}


def src_ripe_rpki(asn, prefix):
    if not asn or not prefix:
        return {"error": "ASN or prefix not resolved"}
    d, e, ms = get_json(f"{RIPESTAT}/rpki-validation/data.json?resource=AS{asn}&prefix={prefix}")
    if e:
        return {"error": e, "_ms": ms}
    return {**(d.get("data") or {}), "_ms": ms}


def src_reverse_dns(ip):
    out = {"ptr": None, "fcrdns": None, "ptr_ips": [], "error": None}
    try:
        out["ptr"] = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        out["error"] = "No PTR record"
        return out
    except Exception as e:
        out["error"] = str(e)
        return out
    try:
        _, _, ips = socket.gethostbyname_ex(out["ptr"])
        out["ptr_ips"] = ips
        out["fcrdns"] = ip in ips
    except Exception:
        out["fcrdns"] = False
    return out


def query_dnsbl(ip, zone, meta):
    """Returns listing state, separating real listings from resolver errors."""
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return zone, {"state": "n/a", "detail": "IPv4 only", "label": meta["label"]}
        q = ".".join(reversed(parts)) + "." + zone
        _, _, codes = socket.gethostbyname_ex(q)

        errors = [x for x in codes if x in DNSBL_ERROR_CODES or x.startswith("127.255.255.")]
        if errors:
            reason = DNSBL_ERROR_CODES.get(errors[0], "Query rejected by the blocklist")
            return zone, {"state": "error", "codes": codes, "detail": reason,
                          "label": meta["label"]}

        reasons = [meta["codes"].get(x, f"code {x}, not mapped") for x in codes]
        return zone, {"state": "listed", "codes": codes, "detail": "; ".join(reasons),
                      "label": meta["label"]}
    except socket.gaierror:
        return zone, {"state": "clean", "label": meta["label"]}
    except Exception as e:
        return zone, {"state": "error", "detail": str(e), "label": meta["label"]}


def query_all_dnsbl(ip):
    out = {}
    with ThreadPoolExecutor(max_workers=len(DNSBL_LIST)) as ex:
        for f in [ex.submit(query_dnsbl, ip, z, m) for z, m in DNSBL_LIST.items()]:
            zone, data = f.result()
            out[zone] = data
    return out


def query_tor(ip):
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return {"exit_node": None, "note": "IPv4 only"}
        rev = ".".join(reversed(parts))
        socket.gethostbyname(f"{rev}.80.{rev}.{TOR_DNSEL}")
        return {"exit_node": True}
    except socket.gaierror:
        return {"exit_node": False}
    except Exception as e:
        return {"exit_node": None, "note": str(e)}


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------


def ok(d):
    return d if isinstance(d, dict) and "error" not in d else {}


def sub(d, k):
    v = d.get(k)
    return v if isinstance(v, dict) else {}


def consensus(candidates):
    """[(value, source)] -> (value, [agreeing], [(value, source) disagreeing])"""
    valid = [(v, s) for v, s in candidates if v not in (None, "", [], {})]
    if not valid:
        return None, [], []
    counts = Counter(norm(v) for v, _ in valid)
    winner = counts.most_common(1)[0][0]
    chosen = next(v for v, _ in valid if norm(v) == winner)
    agree = [s for v, s in valid if norm(v) == winner]
    differ = [(v, s) for v, s in valid if norm(v) != winner]
    return chosen, agree, differ


def rdap_entities(rdap):
    """Extracts entities with roles, names, emails and phones."""
    result = []
    for e in (rdap.get("entities") or []):
        if not isinstance(e, dict):
            continue
        item = {"roles": e.get("roles") or [], "handle": e.get("handle"),
                "name": None, "emails": [], "phones": []}
        vcard = e.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1:
            for f in vcard[1]:
                if not (isinstance(f, list) and len(f) > 3):
                    continue
                if f[0] == "fn":
                    item["name"] = f[3]
                elif f[0] == "email":
                    item["emails"].append(f[3])
                elif f[0] == "tel":
                    item["phones"].append(str(f[3]))
        result.append(item)
    return result


def rir_from_rdap(rdap):
    """Derives the authoritative RIR from RDAP metadata."""
    port43 = (rdap.get("port43") or "").lower()
    for rir in ("lacnic", "ripe", "arin", "apnic", "afrinic"):
        if rir in port43:
            return rir.upper()
    for link in (rdap.get("links") or []):
        if isinstance(link, dict):
            href = (link.get("href") or "").lower()
            for rir in ("lacnic", "ripe", "arin", "apnic", "afrinic"):
                if rir in href:
                    return rir.upper()
    return None


def merge(ip, b):
    ipapi, ipcom, ipwho = ok(b["ipapi_is"]), ok(b["ip_api_com"]), ok(b["ipwho_is"])
    rdap = ok(b["rdap"])
    rnet, rabuse, rrout = ok(b["ripe_network"]), ok(b["ripe_abuse"]), ok(b["ripe_routing"])
    ras, rpki = ok(b["ripe_as"]), ok(b["ripe_rpki"])

    loc, asn_i, comp = sub(ipapi, "location"), sub(ipapi, "asn"), sub(ipapi, "company")
    conn, sec = sub(ipwho, "connection"), sub(ipwho, "security")
    tzw = ipwho.get("timezone")
    tzw = tzw.get("id") if isinstance(tzw, dict) else tzw

    country = consensus([
        (f"{loc.get('country')} ({loc.get('country_code')})" if loc.get("country") else None, "ipapi.is"),
        (f"{ipcom.get('country')} ({ipcom.get('countryCode')})" if ipcom.get("country") else None, "ip-api.com"),
        (f"{ipwho.get('country')} ({ipwho.get('country_code')})" if ipwho.get("country") else None, "ipwho.is"),
    ])
    if country[0] is None and rdap.get("country"):
        country = (rdap["country"], ["RDAP"], [])

    city = consensus([
        (f"{loc.get('city')}, {loc.get('state')}" if loc.get("city") else None, "ipapi.is"),
        (f"{ipcom.get('city')}, {ipcom.get('regionName')}" if ipcom.get("city") else None, "ip-api.com"),
        (f"{ipwho.get('city')}, {ipwho.get('region')}" if ipwho.get("city") else None, "ipwho.is"),
    ])

    tz = consensus([(loc.get("timezone"), "ipapi.is"), (ipcom.get("timezone"), "ip-api.com"), (tzw, "ipwho.is")])

    def cfmt(la, lo):
        if la is None or lo is None:
            return None
        try:
            return f"{float(la):.4f}, {float(lo):.4f}"
        except (TypeError, ValueError):
            return None

    cands = [(v, s) for v, s in (
        (cfmt(loc.get("latitude"), loc.get("longitude")), "ipapi.is"),
        (cfmt(ipcom.get("lat"), ipcom.get("lon")), "ip-api.com"),
        (cfmt(ipwho.get("latitude"), ipwho.get("longitude")), "ipwho.is")) if v]
    if cands:
        def near(v):
            la, lo = v.split(", ")
            return f"{float(la):.1f},{float(lo):.1f}"
        win = Counter(near(v) for v, _ in cands).most_common(1)[0][0]
        coords = (next(v for v, _ in cands if near(v) == win),
                  [s for v, s in cands if near(v) == win],
                  [(v, s) for v, s in cands if near(v) != win])
    else:
        coords = (None, [], [])

    raw_as = ipcom.get("as") or ""
    asn_com = raw_as.split()[0].replace("AS", "") if raw_as else None
    ripe_asns = rnet.get("asns") or []
    asn = consensus([
        (str(asn_i.get("asn")) if asn_i.get("asn") else None, "ipapi.is"),
        (asn_com, "ip-api.com"),
        (str(conn.get("asn")) if conn.get("asn") else None, "ipwho.is"),
        (str(ripe_asns[0]) if ripe_asns else None, "RIPEstat"),
    ])

    isp = consensus([
        (comp.get("name") or ipapi.get("org"), "ipapi.is"),
        (ipcom.get("isp"), "ip-api.com"),
        (conn.get("isp") or conn.get("org"), "ipwho.is"),
    ])

    entities = rdap_entities(rdap)
    rdap_abuse_emails = []
    for e in entities:
        if "abuse" in [r.lower() for r in e["roles"]]:
            rdap_abuse_emails.extend(e["emails"])

    abuse_contacts = rabuse.get("abuse_contacts") or []
    if not abuse_contacts:
        abuse_contacts = rdap_abuse_emails

    as_abuse = asn_i.get("abuse") or comp.get("abuse")
    if not as_abuse and rdap_abuse_emails:
        as_abuse = ", ".join(dict.fromkeys(rdap_abuse_emails))

    rir = ipapi.get("rir") or rabuse.get("authoritative_rir") or rir_from_rdap(rdap)

    # BGP announced prefix and RDAP allocation are different facts, kept apart.
    bgp_prefix = consensus([
        (asn_i.get("route"), "ipapi.is"),
        (rnet.get("prefix"), "RIPEstat"),
    ])
    rdap_allocation = rdap.get("handle")

    def flag(cands):
        hits = [s for v, s in cands if v]
        return bool(hits), hits

    sources = (("ipapi.is", "ipapi_is"), ("ip-api.com", "ip_api_com"), ("ipwho.is", "ipwho_is"),
               ("RDAP", "rdap"), ("RIPEstat network", "ripe_network"),
               ("RIPEstat abuse", "ripe_abuse"), ("RIPEstat routing", "ripe_routing"),
               ("RIPEstat AS", "ripe_as"), ("RIPEstat RPKI", "ripe_rpki"))

    return {
        "ip": ip,
        "properties": b["properties"],
        "country": country, "city": city, "timezone": tz, "coords": coords,
        "continent": ipcom.get("continent") or ipwho.get("continent"),
        "postal": ipcom.get("zip") or ipwho.get("postal"),
        "district": ipcom.get("district") or None,
        "utc_offset": ipcom.get("offset"),
        "asn": asn,
        "as_name": ras.get("holder") or asn_i.get("descr") or ipcom.get("asname"),
        "as_type": asn_i.get("type") or ras.get("type"),
        "as_domain": asn_i.get("domain") or conn.get("domain"),
        "as_abuse": as_abuse,
        "as_announced": ras.get("announced"),
        "as_block": (ras.get("block") or {}).get("resource") if isinstance(ras.get("block"), dict) else None,
        "rir": rir,
        "isp": isp,
        "bgp_prefix": bgp_prefix,
        "bgp_origins": [f"AS{a}" for a in ripe_asns],
        "rdap_allocation": rdap_allocation,
        "rdap": rdap, "entities": entities,
        "abuse_contacts": list(dict.fromkeys(abuse_contacts)),
        "routing": rrout, "rpki": rpki,
        "org_type": comp.get("type"),
        "datacenter": sub(ipapi, "datacenter").get("datacenter"),
        "dns": b["dns"], "dnsbl": b["dnsbl"], "tor": b["tor"],
        "is_datacenter": flag([(ipapi.get("is_datacenter"), "ipapi.is"), (ipcom.get("hosting"), "ip-api.com")]),
        "is_vpn": flag([(ipapi.get("is_vpn"), "ipapi.is"), (sec.get("vpn"), "ipwho.is")]),
        "is_proxy": flag([(ipapi.get("is_proxy"), "ipapi.is"), (ipcom.get("proxy"), "ip-api.com"), (sec.get("proxy"), "ipwho.is")]),
        "is_tor": flag([(ipapi.get("is_tor"), "ipapi.is"), (sec.get("tor"), "ipwho.is"), (b["tor"].get("exit_node"), "Tor DNSEL")]),
        "is_mobile": flag([(ipapi.get("is_mobile"), "ipapi.is"), (ipcom.get("mobile"), "ip-api.com")]),
        "is_abuser": flag([(ipapi.get("is_abuser"), "ipapi.is")]),
        "is_crawler": flag([(ipapi.get("is_crawler"), "ipapi.is")]),
        "is_satellite": flag([(ipapi.get("is_satellite"), "ipapi.is")]),
        "is_bogon": flag([(ipapi.get("is_bogon"), "ipapi.is")]),
        "timings": {n: b[k].get("_ms") for n, k in sources
                    if isinstance(b[k], dict) and b[k].get("_ms") and not b[k].get("error")},
        "errors": {n: b[k].get("error") for n, k in sources if isinstance(b[k], dict) and b[k].get("error")},
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


def row_consensus(label, resolved, indent=2):
    value, agree, differ = resolved
    note = None
    if value is not None:
        if differ:
            note = "differs: " + "; ".join(f"{s}={v}" for v, s in differ)
        elif len(agree) > 1:
            note = f"{len(agree)} sources agree"
        elif agree:
            note = agree[0]
    row(label, value, alert=bool(differ), note=note, indent=indent)


def report(m):
    p = m["properties"]

    section("ADDRESS")
    row("IP", m["ip"])
    row("Version", p["version"])
    row("Decimal", f"{p['decimal']:,}".replace(",", " "))
    row("Hexadecimal", p["hex"])
    if "binary" in p:
        row("Binary", p["binary"])
        row("Legacy class", p["legacy_class"])
        row("Parent /24", p["net_24"])
        row("Parent /16", p["net_16"])
    row("ARPA pointer", p["arpa"])
    scopes = [k[3:].replace("_", "-") for k in
              ("is_private", "is_reserved", "is_multicast", "is_loopback", "is_link_local") if p.get(k)]
    row("Scope", ", ".join(scopes) if scopes else "global, routable", alert=bool(scopes))
    if m["is_bogon"][0]:
        row("Bogon", "YES", alert=True, note="ipapi.is")

    section("GEOLOCATION")
    row_consensus("Country", m["country"])
    row_consensus("City, region", m["city"])
    row("District", m["district"])
    row("Continent", m["continent"])
    row("Postal code", m["postal"])
    row_consensus("Time zone", m["timezone"])
    if m["utc_offset"] is not None:
        hours = m["utc_offset"] / 3600
        row("UTC offset", f"{hours:+.0f}")
    row_consensus("Coordinates", m["coords"])

    section("AUTONOMOUS SYSTEM")
    asn_v = m["asn"][0]
    row_consensus("ASN", (f"AS{asn_v}" if asn_v else None, m["asn"][1], m["asn"][2]))
    row("AS name", m["as_name"])
    row_consensus("ISP", m["isp"])
    row("AS type", m["as_type"])
    row("AS domain", m["as_domain"])
    row("Announced in BGP", "yes" if m["as_announced"] else ("no" if m["as_announced"] is False else None),
        note="RIPEstat" if m["as_announced"] is not None else None)
    row("AS number block", m["as_block"], note="RIPEstat" if m["as_block"] else None)
    row("Authoritative RIR", (m["rir"] or "").upper() or None)

    section("ROUTING AND BGP")
    row_consensus("Announced prefix", m["bgp_prefix"])
    row("RDAP allocation", m["rdap_allocation"], note="registry block, wider than the BGP prefix")
    row("Origin AS", ", ".join(m["bgp_origins"]) if m["bgp_origins"] else None, note="RIPEstat")

    rt = m["routing"]
    if rt:
        vis = sub(rt, "visibility")
        v4 = sub(vis, "v4")
        if v4:
            seen, total = v4.get("ris_peers_seeing"), v4.get("total_ris_peers")
            pct = f" ({seen / total * 100:.0f}%)" if seen and total else ""
            row("BGP visibility", f"{seen} of {total} RIS peers{pct}", note="RIPEstat")
        fs, ls = sub(rt, "first_seen"), sub(rt, "last_seen")
        row("First seen in BGP", fs.get("time"), note="RIPEstat" if fs.get("time") else None)
        row("Last seen in BGP", ls.get("time"), note="RIPEstat" if ls.get("time") else None)

    rpki = m["rpki"]
    if rpki and rpki.get("status"):
        st = rpki["status"]
        meaning = {
            "valid": "a ROA authorises this AS to announce this prefix",
            "invalid": "announcement contradicts the published ROA",
            "invalid_asn": "ROA exists but authorises a different AS",
            "invalid_length": "prefix is more specific than the ROA allows",
            "unknown": "no ROA published for this prefix",
        }.get(st, "")
        row("RPKI validation", st, alert=st.startswith("invalid"), note=meaning)
        for roa in (rpki.get("validating_roas") or [])[:3]:
            if isinstance(roa, dict):
                bullet(f"ROA  AS{roa.get('origin')}  {roa.get('prefix')}  maxLen={roa.get('max_length')}  [{roa.get('validity')}]")

    section("REGISTRY (RDAP)")
    rd = m["rdap"]
    if rd:
        row("Allocation handle", rd.get("handle"))
        row("Object name", rd.get("name"))
        if rd.get("startAddress") and rd.get("endAddress"):
            row("Allocated range", f"{rd['startAddress']} – {rd['endAddress']}")
        row("Allocation type", rd.get("type"))
        row("Registry country", rd.get("country"))
        row("Object status", ", ".join(rd.get("status") or []) or None)
        for ev in (rd.get("events") or []):
            if isinstance(ev, dict) and ev.get("eventAction") in ("registration", "last changed", "last modified"):
                date = (ev.get("eventDate") or "")[:10]
                row(ev["eventAction"].capitalize(), date)

        if m["entities"]:
            print()
            print(c("      Registered contacts", "0;36"))
            for e in m["entities"]:
                roles = ", ".join(e["roles"]) or "unspecified"
                name = e["name"] or e["handle"] or "unnamed"
                row(roles, name, indent=6)
                for em in e["emails"]:
                    bullet(f"  {em}", "0;90")
                for ph in e["phones"]:
                    bullet(f"  {ph}", "0;90")
    else:
        row("RDAP", "unavailable", alert=True)

    if m["abuse_contacts"]:
        print()
        row("Abuse reporting", ", ".join(m["abuse_contacts"]))

    section("DNS")
    dns = m["dns"]
    row("PTR record", dns.get("ptr") or dns.get("error"), dim=not dns.get("ptr"))
    if dns.get("ptr"):
        fc = dns.get("fcrdns")
        row("FCrDNS", "valid" if fc else "FAILED", alert=fc is False,
            note="hostname resolves back to this IP" if fc else "hostname does not resolve back to this IP")
        if dns.get("ptr_ips"):
            row("Hostname resolves to", ", ".join(dns["ptr_ips"]), indent=6)

    section("INFRASTRUCTURE FLAGS")
    for label, key in (("Datacenter / hosting", "is_datacenter"), ("VPN", "is_vpn"),
                       ("Proxy", "is_proxy"), ("Tor exit node", "is_tor"),
                       ("Mobile network", "is_mobile"), ("Known crawler", "is_crawler"),
                       ("Satellite", "is_satellite"), ("Flagged as abuser", "is_abuser")):
        val, srcs = m[key]
        row(label, "YES" if val else "no", alert=val, note=", ".join(srcs) if srcs else None)
    row("Datacenter name", m["datacenter"]) if m["datacenter"] else None
    row("Organisation type", m["org_type"]) if m["org_type"] else None

    section("DNS BLOCKLISTS")
    listed = [z for z, d in m["dnsbl"].items() if d["state"] == "listed"]
    errored = [z for z, d in m["dnsbl"].items() if d["state"] == "error"]
    for zone, d in m["dnsbl"].items():
        st = d["state"]
        if st == "listed":
            row(zone, "LISTED", alert=True, note=", ".join(d.get("codes", [])))
            bullet(d.get("detail", ""), "1;31")
            bullet(d.get("label", ""), "0;90")
        elif st == "clean":
            row(zone, "clean", note=d.get("label"))
        elif st == "error":
            row(zone, "no result", dim=True, note=d.get("detail"))
            bullet(d.get("label", ""), "0;90")
        else:
            row(zone, "not applicable", dim=True, note=d.get("detail"))

    tor = m["tor"]
    if tor.get("exit_node") is True:
        row("Tor DNSEL", "CONFIRMED EXIT NODE", alert=True)
    elif tor.get("exit_node") is False:
        row("Tor DNSEL", "not an exit node")
    else:
        row("Tor DNSEL", "no result", dim=True, note=tor.get("note"))

    if errored:
        print()
        bullet("Some blocklists refused the query. Spamhaus and CBL reject lookups", "0;33")
        bullet("sent through public DNS resolvers such as 8.8.8.8 or 1.1.1.1.", "0;33")
        bullet("Point the machine at your ISP resolver or a local one to get a result.", "0;33")

    section("COLLECTION DIAGNOSTICS")
    if m["timings"]:
        slowest = max(m["timings"].values())
        row("Sources queried", f"{len(m['timings'])} responded, slowest {slowest} ms")
        for name, ms in sorted(m["timings"].items(), key=lambda x: -x[1]):
            bullet(f"{name:<20} {ms:>5} ms", "0;90")
    if m["errors"]:
        print()
        row("Sources unavailable", str(len(m["errors"])), alert=True)
        for name, err in m["errors"].items():
            bullet(f"{name:<20} {err}", "0;90")
    else:
        row("Sources unavailable", "none")
    print()


def raw_dump(b):
    section("RAW RESPONSES")
    for name, key in (("ipapi.is", "ipapi_is"), ("ip-api.com", "ip_api_com"), ("ipwho.is", "ipwho_is"),
                      ("RDAP", "rdap"), ("RIPEstat network-info", "ripe_network"),
                      ("RIPEstat abuse-contact", "ripe_abuse"), ("RIPEstat routing-status", "ripe_routing"),
                      ("RIPEstat as-overview", "ripe_as"), ("RIPEstat rpki-validation", "ripe_rpki"),
                      ("DNS", "dns"), ("DNSBL", "dnsbl"), ("Tor", "tor")):
        print(c(f"\n   {name}", "1;36"))
        text = json.dumps(b.get(key), indent=2, ensure_ascii=False, default=str)
        print("   " + text.replace("\n", "\n   "))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


VERDICT_BANNER = r"""
 __      __ ______ _____   _____  _____ _____ _______
 \ \    / /|  ____|  __ \ |  __ \|_   _/ ____|__   __|
  \ \  / / | |__  | |__) || |  | | | || |       | |
   \ \/ /  |  __| |  _  / | |  | | | || |       | |
    \  /   | |____| | \ \ | |__| |_| || |____   | |
     \/    |______|_|  \_\|_____/|_____\_____|  |_|
"""


def investigate(ip, raw=False, as_json=False):
    if not as_json:
        print(c(VERDICT_BANNER, "1;35"))
        print(c("╔" + "═" * W + "╗", "1;35"))
        print(c(f"║{'IP INTELLIGENCE REPORT':^{W}}║", "1;35"))
        print(c(f"║{ip:^{W}}║", "1;37"))
        print(c(f"║{time.strftime('%Y-%m-%d %H:%M:%S'):^{W}}║", "0;90"))
        print(c("╚" + "═" * W + "╝", "1;35"))
        print(c("\n  Applying verdict...", "0;90"), end="", flush=True)

    b = {"properties": address_properties(ip)}

    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = {
            "ipapi_is": ex.submit(src_ipapi_is, ip),
            "ip_api_com": ex.submit(src_ip_api_com, ip),
            "ipwho_is": ex.submit(src_ipwho_is, ip),
            "rdap": ex.submit(src_rdap, ip),
            "ripe_network": ex.submit(src_ripe_network, ip),
            "ripe_abuse": ex.submit(src_ripe_abuse, ip),
            "ripe_routing": ex.submit(src_ripe_routing, ip),
            "dns": ex.submit(src_reverse_dns, ip),
            "dnsbl": ex.submit(query_all_dnsbl, ip),
            "tor": ex.submit(query_tor, ip),
        }
        for k, f in futs.items():
            b[k] = f.result()

    rnet = ok(b["ripe_network"])
    asns = rnet.get("asns") or []
    asn = str(asns[0]) if asns else (str(sub(ok(b["ipapi_is"]), "asn").get("asn") or "") or None)
    prefix = rnet.get("prefix") or sub(ok(b["ipapi_is"]), "asn").get("route")

    with ThreadPoolExecutor(max_workers=2) as ex:
        fa, fr = ex.submit(src_ripe_as, asn), ex.submit(src_ripe_rpki, asn, prefix)
        b["ripe_as"], b["ripe_rpki"] = fa.result(), fr.result()

    if not as_json:
        print("\r" + " " * 30 + "\r", end="")

    merged = merge(ip, b)

    if as_json:
        print(json.dumps(merged, indent=2, ensure_ascii=False, default=str))
        return

    # Capture the report to stdout AND to a buffer, so it can be saved
    # to a .txt file when the window closes.
    buf = io.StringIO()
    tee = _Tee(sys.stdout, buf)
    old_stdout = sys.stdout
    sys.stdout = tee
    try:
        report(merged)
        if raw:
            raw_dump(b)
    finally:
        sys.stdout = old_stdout

    save_report_txt(ip, buf.getvalue())


class _Tee:
    """Writes to two streams at once (console + in-memory buffer)."""
    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for s in self.streams:
            s.write(data)

    def flush(self):
        for s in self.streams:
            s.flush()


ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def save_report_txt(ip, text):
    """Strips ANSI colors and writes the report next to the script."""
    clean = ANSI_RE.sub("", text)
    safe_ip = ip.replace(":", "-")
    stamp = time.strftime("%Y%m%d_%H%M%S")
    filename = f"verdict_{safe_ip}_{stamp}.txt"

    try:
        base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    except Exception:
        base_dir = os.getcwd()

    path = os.path.join(base_dir, filename)
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"IP INTELLIGENCE REPORT - {ip}\n")
            f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(clean)
        print(c(f"\n  Report saved to: {path}", "0;90"))
    except Exception as e:
        print(c(f"\n  Could not save report file: {e}", "1;31"))


def pause_on_windows():
    if platform.system() == "Windows":
        input("\nPress ENTER to close...")


def main():
    try:
        flags = [a for a in sys.argv[1:] if a.startswith("--")]
        args = [a for a in sys.argv[1:] if not a.startswith("--")]
        ip = args[0].strip() if args else input("IP address to investigate: ").strip()

        if not valid_ip(ip):
            print(c(f"Not a valid IP address: '{ip}'", "1;31"))
            pause_on_windows()
            sys.exit(1)

        investigate(ip, raw="--raw" in flags, as_json="--json" in flags)

    except KeyboardInterrupt:
        print(c("\nInterrupted.", "0;90"))
    except Exception as e:
        print(c(f"\nUnexpected error: {e}", "1;31"))
        import traceback
        traceback.print_exc()
    finally:
        if "--json" not in sys.argv[1:]:
            pause_on_windows()


if __name__ == "__main__":
    main()
