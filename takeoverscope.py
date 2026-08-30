#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
 _____  _    _  _______ _____     _______ ____  ____   ____ ___  ____  _____
|_   _|/ \\  | |/ / ____/ _ \\ \\   / / ____|  _ \\/ ___| / ___/ _ \\|  _ \\| ____|
  | | / _ \\ | ' /|  _|| | | \\ \\ / /|  _| | |_) \\___ \\| |  | | | | |_) |  _|
  | |/ ___ \\| . \\| |__| |_| |\\ V / | |___|  _ < ___) | |__| |_| |  __/| |___
  |_/_/   \\_\\_|\\_\\_____\\___/  \\_/  |_____|_| \\_\\____/ \\____\\___/|_|   |_____|

TakeoverScope — Subdomain Takeover & Dangling CNAME Detector
Made by Mindless — Founder & CEO of Linxploit
https://linxploit.com | https://linxploit.com/founder

WHAT THIS TOOL DOES:
    TakeoverScope resolves each subdomain's CNAME chain (a normal DNS
    query) and, where it points to a known third-party hosting service,
    makes a single ordinary HTTP GET request to see whether that
    service still shows an "unclaimed resource" page — the same signal
    every public subdomain-takeover checklist (e.g. EdOverflow's
    can-i-take-over-xyz) is built around.

    TakeoverScope NEVER attempts to actually claim, register, or take
    over anything. It reports that a subdomain *appears* takeover-
    vulnerable based on DNS + a public fingerprint match — confirming
    and remediating it (or responsibly disclosing it) is on you.

    Fingerprints for hosting services change over time as providers
    update their error pages. Keep the fingerprint list current (see
    --fingerprints to supply your own) and always confirm manually
    before reporting a finding.

    Only assess domains you own or are explicitly authorized to test.
"""

import argparse
import concurrent.futures
import csv
import json
import os
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

import requests
import dns.resolver
import dns.exception
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)
requests.packages.urllib3.disable_warnings()  # noqa

TOOL_NAME = "TakeoverScope"
VERSION = "1.0.0"
AUTHOR = "Mindless"
ORG = "Linxploit"
SITE = "https://linxploit.com"
PORTFOLIO = "https://linxploit.com/founder"

# --------------------------------------------------------------------------- #
#  UI toolkit
# --------------------------------------------------------------------------- #

GRADIENT = [
    "\033[38;5;124m", "\033[38;5;130m", "\033[38;5;136m", "\033[38;5;142m",
    "\033[38;5;178m", "\033[38;5;214m", "\033[38;5;215m", "\033[38;5;223m",
    "\033[38;5;252m", "\033[38;5;255m",
]
RESET = Style.RESET_ALL
DIM = Style.DIM
BOLD = Style.BRIGHT

C_SAFE = Fore.GREEN + BOLD
C_INFO = Fore.CYAN
C_UNKNOWN = Fore.WHITE + DIM
C_SUSPICIOUS = Fore.YELLOW + BOLD
C_VULN = Fore.RED + BOLD
C_MUTE = Fore.WHITE + DIM
C_ACC = "\033[38;5;208m" + BOLD  # amber accent

VERDICT_COLOR = {
    "VULNERABLE": C_VULN, "SUSPICIOUS": C_SUSPICIOUS, "UNKNOWN_SERVICE": C_UNKNOWN,
    "NOT_VULNERABLE": C_SAFE, "NOT_APPLICABLE": C_MUTE, "ERROR": C_MUTE,
}
VERDICT_ORDER = {
    "VULNERABLE": 0, "SUSPICIOUS": 1, "UNKNOWN_SERVICE": 2,
    "NOT_VULNERABLE": 3, "NOT_APPLICABLE": 4, "ERROR": 5,
}


def supports_unicode() -> bool:
    enc = (sys.stdout.encoding or "").lower()
    return "utf" in enc


UNICODE_OK = supports_unicode()

BOX = {
    "tl": "╔" if UNICODE_OK else "+", "tr": "╗" if UNICODE_OK else "+",
    "bl": "╚" if UNICODE_OK else "+", "br": "╝" if UNICODE_OK else "+",
    "h": "═" if UNICODE_OK else "-", "v": "║" if UNICODE_OK else "|",
    "lt": "╠" if UNICODE_OK else "+", "rt": "╣" if UNICODE_OK else "+",
    "thin": "─" if UNICODE_OK else "-",
    "check": "✔" if UNICODE_OK else "OK", "cross": "✘" if UNICODE_OK else "X",
    "warn": "⚠" if UNICODE_OK else "!", "spark": "✦" if UNICODE_OK else "*",
    "dot": "•" if UNICODE_OK else "*", "ghost": "👻" if UNICODE_OK else "[!]",
    "link": "🔗" if UNICODE_OK else "->",
}

BANNER_ART = r"""
 _____  _    _  _______ _____     _______ ____  ____   ____ ___  ____  _____
|_   _|/ \  | |/ / ____/ _ \ \   / / ____|  _ \/ ___| / ___/ _ \|  _ \| ____|
  | | / _ \ | ' /|  _|| | | \ \ / /|  _| | |_) \___ \| |  | | | | |_) |  _|
  | |/ ___ \| . \| |__| |_| |\ V / | |___|  _ < ___) | |__| |_| |  __/| |___
  |_/_/   \_\_|\_\_____\___/  \_/  |_____|_| \_\____/ \____\___/|_|   |_____|
""".rstrip("\n")

BANNER_ART_ASCII = r"""
 ___ _  _ ____ ____ _  _ ____ ____ ____
  |  |__| |___ |  | |  | |___ |__/ |__/
  |  |  | |___ |__|  \/  |___ |  \ |  \
""".rstrip("\n")

import re as _re  # noqa: E402
ANSI_RE = _re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


def gradient_line(text: str) -> str:
    out = []
    n = max(len(GRADIENT) - 1, 1)
    for i, ch in enumerate(text):
        color = GRADIENT[int((i / max(len(text) - 1, 1)) * n)]
        out.append(color + ch)
    return "".join(out) + RESET


def render_banner():
    art = BANNER_ART if UNICODE_OK else BANNER_ART_ASCII
    width = max(len(strip_ansi(line)) for line in art.splitlines()) + 6

    print()
    for line in art.splitlines():
        print(gradient_line(line))
    print()

    tagline = f"{BOX['spark']} Subdomain Takeover & Dangling CNAME Detector {BOX['spark']}"
    print(C_ACC + tagline.center(width) + RESET)
    sub = f"v{VERSION} · Detection only. Never claims or registers anything."
    print(C_MUTE + sub.center(width) + RESET)
    print()
    info_box(
        [
            f"{BOX['dot']} Author   : {AUTHOR}  ({ORG} — Founder & CEO)",
            f"{BOX['dot']} Website  : {SITE}",
            f"{BOX['dot']} Portfolio: {PORTFOLIO}",
        ],
        title="ABOUT",
        color=Fore.MAGENTA,
    )


def info_box(lines: List[str], title: str = "", color: str = Fore.CYAN, width: Optional[int] = None):
    content_width = width or (max((len(strip_ansi(l)) for l in lines), default=20) + 4)
    top = f"{color}{BOX['tl']}{BOX['h'] * content_width}{BOX['tr']}{RESET}"
    bot = f"{color}{BOX['bl']}{BOX['h'] * content_width}{BOX['br']}{RESET}"
    print(top)
    if title:
        pad = content_width - len(title) - 2
        left = pad // 2
        right = pad - left
        print(f"{color}{BOX['v']}{RESET} {' ' * left}{BOLD}{title}{RESET}{' ' * right} {color}{BOX['v']}{RESET}")
        print(f"{color}{BOX['lt']}{BOX['h'] * content_width}{BOX['rt']}{RESET}")
    for line in lines:
        pad = max(content_width - len(strip_ansi(line)) - 1, 0)
        print(f"{color}{BOX['v']}{RESET} {Fore.WHITE}{line}{RESET}{' ' * pad}{color}{BOX['v']}{RESET}")
    print(bot)


def section(title: str, color: str = Fore.CYAN):
    print(f"\n{color}[ {title} ]{RESET}")
    print(color + BOX["thin"] * 60 + RESET)


def hr(color=C_MUTE, width=72):
    print(color + BOX["h"] * width + RESET)


# --------------------------------------------------------------------------- #
#  Fingerprint database
# --------------------------------------------------------------------------- #
# Public, widely-documented signatures — the same category of information
# published by community projects like EdOverflow/can-i-take-over-xyz and
# used by tools such as subjack/tko-subs/nuclei. These fingerprints DO
# change as providers update their error pages — keep this list current
# and pass --fingerprints to override/extend it.

DEFAULT_FINGERPRINTS = [
    {"service": "GitHub Pages", "cname": ["github.io", "github.map.fastly.net"],
     "http": ["There isn't a GitHub Pages site here"], "nxdomain_confirms": True},
    {"service": "Heroku", "cname": ["herokuapp.com", "herokudns.com", "herokussl.com"],
     "http": ["no such app", "There's nothing here, yet"], "nxdomain_confirms": True},
    {"service": "AWS S3", "cname": ["s3.amazonaws.com", "s3-website", "s3.dualstack"],
     "http": ["NoSuchBucket", "The specified bucket does not exist"], "nxdomain_confirms": False},
    {"service": "Shopify", "cname": ["myshopify.com"],
     "http": ["Sorry, this shop is currently unavailable"], "nxdomain_confirms": True},
    {"service": "Fastly", "cname": ["fastly.net"],
     "http": ["Fastly error: unknown domain"], "nxdomain_confirms": False},
    {"service": "Surge.sh", "cname": ["surge.sh"],
     "http": ["project not found"], "nxdomain_confirms": True},
    {"service": "Bitbucket", "cname": ["bitbucket.io"],
     "http": ["Repository not found"], "nxdomain_confirms": True},
    {"service": "Tumblr", "cname": ["tumblr.com"],
     "http": ["Whatever you were looking for doesn't currently exist"], "nxdomain_confirms": True},
    {"service": "Unbounce", "cname": ["unbounce.com"],
     "http": ["The requested URL was not found on this server"], "nxdomain_confirms": True},
    {"service": "WordPress.com", "cname": ["wordpress.com"],
     "http": ["Do you want to register"], "nxdomain_confirms": True},
    {"service": "Zendesk", "cname": ["zendesk.com"],
     "http": ["Help Center Closed"], "nxdomain_confirms": True},
    {"service": "Webflow", "cname": ["webflow.io", "proxy-ssl.webflow.com"],
     "http": ["The page you are looking for doesn't exist or has been moved"], "nxdomain_confirms": True},
    {"service": "Ghost", "cname": ["ghost.io"],
     "http": ["The thing you were looking for is no longer here"], "nxdomain_confirms": True},
    {"service": "Pantheon", "cname": ["pantheonsite.io"],
     "http": ["The gods are wise", "404 error unknown site"], "nxdomain_confirms": True},
    {"service": "Cargo Collective", "cname": ["cargocollective.com"],
     "http": ["404 Not Found"], "nxdomain_confirms": True},
    {"service": "Help Scout", "cname": ["helpscoutdocs.com"],
     "http": ["No settings were found for this company"], "nxdomain_confirms": True},
    {"service": "UserVoice", "cname": ["uservoice.com"],
     "http": ["This UserVoice subdomain is currently available"], "nxdomain_confirms": True},
    {"service": "Intercom", "cname": ["custom.intercom.help"],
     "http": ["This page is reserved for artistic dogs"], "nxdomain_confirms": True},
    {"service": "Netlify", "cname": ["netlify.app"],
     "http": ["Not Found - Request ID"], "nxdomain_confirms": True},
    {"service": "Azure", "cname": ["azurewebsites.net", "cloudapp.net", "blob.core.windows.net"],
     "http": ["404 Web Site not found"], "nxdomain_confirms": False},
]


def load_fingerprints(path: Optional[str]) -> List[dict]:
    if not path:
        return DEFAULT_FINGERPRINTS
    if not os.path.isfile(path):
        print(C_VULN + f"[!] Fingerprint file not found: {path}" + RESET)
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        custom = json.load(f)
    if not isinstance(custom, list):
        print(C_VULN + "[!] Fingerprint file must contain a JSON array." + RESET)
        sys.exit(1)
    return custom


# --------------------------------------------------------------------------- #
#  Data model
# --------------------------------------------------------------------------- #

@dataclass
class ScanResult:
    hostname: str
    cname_chain: List[str] = field(default_factory=list)
    final_target: Optional[str] = None
    matched_service: Optional[str] = None
    target_resolves: Optional[bool] = None
    http_status: Optional[int] = None
    http_fingerprint_matched: Optional[str] = None
    verdict: str = "NOT_APPLICABLE"
    note: str = ""
    error: Optional[str] = None
    duration_s: float = 0.0


# --------------------------------------------------------------------------- #
#  DNS resolution
# --------------------------------------------------------------------------- #

def resolve_cname_chain(hostname: str, resolver: dns.resolver.Resolver, max_depth: int = 8) -> List[str]:
    """Follow the CNAME chain as far as it goes. Returns an empty list if
    the hostname has no CNAME (i.e. it's an A/AAAA record directly, or
    doesn't resolve at all)."""
    chain = []
    current = hostname
    seen = set()
    for _ in range(max_depth):
        if current in seen:
            break
        seen.add(current)
        try:
            answer = resolver.resolve(current, "CNAME")
            target = str(answer[0].target).rstrip(".")
            chain.append(target)
            current = target
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout,
                dns.resolver.NoNameservers):
            break
    return chain


def target_resolves(hostname: str, resolver: dns.resolver.Resolver) -> Optional[bool]:
    """True if the hostname resolves to *something* (A, AAAA, or CNAME),
    False if it's a confirmed NXDOMAIN, None if the check was inconclusive
    (timeout, server failure, etc.) — kept distinct so we never treat an
    inconclusive DNS check as evidence of a takeover."""
    for rtype in ("A", "AAAA", "CNAME"):
        try:
            resolver.resolve(hostname, rtype)
            return True
        except dns.resolver.NXDOMAIN:
            return False
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            continue
        except dns.exception.Timeout:
            return None
    return False


# --------------------------------------------------------------------------- #
#  Classification
# --------------------------------------------------------------------------- #

def match_fingerprint(target: str, fingerprints: List[dict]) -> Optional[dict]:
    target_lower = target.lower()
    for fp in fingerprints:
        if any(indicator.lower() in target_lower for indicator in fp.get("cname", [])):
            return fp
    return None


def check_http_fingerprint(hostname: str, fp: dict, timeout: int) -> Optional[str]:
    for scheme in ("https", "http"):
        try:
            resp = requests.get(f"{scheme}://{hostname}", timeout=timeout, verify=False,
                                 headers={"User-Agent": f"Mozilla/5.0 ({TOOL_NAME}/{VERSION})"})
            for needle in fp.get("http", []):
                if needle.lower() in resp.text.lower():
                    return needle
            return None
        except requests.exceptions.RequestException:
            continue
    return None


def scan_target(hostname: str, resolver: dns.resolver.Resolver, fingerprints: List[dict],
                 timeout: int, skip_http: bool) -> ScanResult:
    result = ScanResult(hostname=hostname)
    start = time.perf_counter()

    try:
        chain = resolve_cname_chain(hostname, resolver)
        result.cname_chain = chain

        if not chain:
            resolves = target_resolves(hostname, resolver)
            if resolves is False:
                result.verdict = "NOT_APPLICABLE"
                result.note = "No CNAME, and the hostname itself doesn't resolve (NXDOMAIN)."
            else:
                result.verdict = "NOT_APPLICABLE"
                result.note = "No CNAME record — resolves directly (A/AAAA) or is inconclusive."
            result.duration_s = round(time.perf_counter() - start, 2)
            return result

        result.final_target = chain[-1]
        fp = match_fingerprint(result.final_target, fingerprints)

        target_resolves_result = target_resolves(result.final_target, resolver)
        result.target_resolves = target_resolves_result

        if fp is None:
            if target_resolves_result is False:
                result.verdict = "SUSPICIOUS"
                result.note = (f"CNAME points to '{result.final_target}', which doesn't resolve "
                                f"(NXDOMAIN) — a dangling record even though it's not in the known "
                                f"service fingerprint list. Worth manual review.")
            else:
                result.verdict = "UNKNOWN_SERVICE"
                result.note = (f"CNAME points to '{result.final_target}', not in the fingerprint "
                                f"database — outside this tool's known-service coverage.")
            result.duration_s = round(time.perf_counter() - start, 2)
            return result

        result.matched_service = fp["service"]

        if target_resolves_result is False and fp.get("nxdomain_confirms", True):
            result.verdict = "VULNERABLE"
            result.note = (f"CNAME points to a {fp['service']} hostname that no longer resolves "
                            f"(NXDOMAIN) — classic dangling-CNAME takeover pattern.")
            result.duration_s = round(time.perf_counter() - start, 2)
            return result

        if not skip_http:
            matched_text = check_http_fingerprint(hostname, fp, timeout)
            result.http_fingerprint_matched = matched_text
            if matched_text:
                result.verdict = "VULNERABLE"
                result.note = (f"CNAME points to {fp['service']}, and the response body matches "
                                f"its 'unclaimed resource' fingerprint ('{matched_text}').")
            else:
                result.verdict = "NOT_VULNERABLE"
                result.note = f"CNAME points to {fp['service']}, but the resource appears claimed and active."
        else:
            result.verdict = "SUSPICIOUS" if target_resolves_result is not True else "NOT_VULNERABLE"
            result.note = f"CNAME points to {fp['service']}; HTTP fingerprint check skipped (--skip-http)."

    except Exception as e:  # noqa
        result.error = str(e)
        result.verdict = "ERROR"

    result.duration_s = round(time.perf_counter() - start, 2)
    return result


# --------------------------------------------------------------------------- #
#  Reporting
# --------------------------------------------------------------------------- #

def print_result(result: ScanResult, verbose: bool):
    color = VERDICT_COLOR.get(result.verdict, C_MUTE)

    if result.error:
        print(f"{C_MUTE}[ {result.hostname} ]{RESET} {C_VULN}error: {result.error}{RESET}")
        return

    print(f"{color}[ {result.verdict:<15} ]{RESET} {Fore.WHITE}{result.hostname}{RESET}")

    if result.cname_chain:
        chain_str = " → ".join(result.cname_chain)
        print(f"          {C_MUTE}{BOX['link']} CNAME: {result.hostname} → {chain_str}{RESET}")
    if result.matched_service:
        print(f"          {C_MUTE}service: {result.matched_service}{RESET}")
    if result.target_resolves is False:
        print(f"          {C_VULN}target does not resolve (NXDOMAIN){RESET}")

    if verbose or result.verdict in ("VULNERABLE", "SUSPICIOUS"):
        print(f"          {color}› {result.note}{RESET}")
    print()


def print_summary(results: List[ScanResult]):
    section("SCAN SUMMARY", Fore.MAGENTA)
    counts = {}
    for r in results:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1

    for level in ["VULNERABLE", "SUSPICIOUS", "UNKNOWN_SERVICE", "NOT_VULNERABLE", "NOT_APPLICABLE", "ERROR"]:
        if level in counts:
            color = VERDICT_COLOR.get(level, C_MUTE)
            dots = (BOX["dot"] * counts[level]) if UNICODE_OK else ("*" * counts[level])
            print(f"  {color}{level:<16}{RESET} : {color}{counts[level]:>3}{RESET}  {color}{dots}{RESET}")

    vulnerable = [r for r in results if r.verdict == "VULNERABLE"]
    if vulnerable:
        print(f"\n  {C_VULN}{BOX['warn']} {len(vulnerable)} likely-vulnerable subdomain(s) — verify manually before disclosure:{RESET}")
        for r in vulnerable:
            print(f"    {C_VULN}{BOX['dot']} {r.hostname} → {r.final_target} ({r.matched_service}){RESET}")

    print(f"\n  {BOLD}Total hostnames scanned:{RESET} {len(results)}")
    print()


def save_json(results: List[ScanResult], path: str):
    data = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "author": AUTHOR,
        "organization": ORG,
        "results": [asdict(r) for r in results],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def save_csv(results: List[ScanResult], path: str):
    fields = ["hostname", "final_target", "matched_service", "target_resolves",
              "verdict", "note", "error"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in results:
            row = asdict(r)
            writer.writerow({k: row.get(k) for k in fields})


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #

def load_targets(args) -> List[str]:
    targets = []
    if args.domain:
        targets.append(args.domain.strip())
    if args.list:
        if not os.path.isfile(args.list):
            print(C_VULN + f"[!] File not found: {args.list}" + RESET)
            sys.exit(1)
        with open(args.list, "r", encoding="utf-8") as f:
            targets.extend(line.strip() for line in f if line.strip() and not line.startswith("#"))
    return targets


def confirm_authorization(skip: bool) -> bool:
    if skip:
        return True
    print()
    print(f"{C_SUSPICIOUS}{BOX['warn']} TakeoverScope performs DNS lookups and, for matched services, "
          f"one HTTP GET per subdomain.{RESET}")
    print(f"{C_SUSPICIOUS}{BOX['warn']} It never claims or registers anything — but only assess domains "
          f"you OWN or are AUTHORIZED to test.{RESET}")
    try:
        answer = input(f"\n{BOLD}Type 'yes' to confirm you are authorized: {RESET}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer == "yes"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="takeoverscope",
        description=f"{TOOL_NAME} — Subdomain Takeover & Dangling CNAME Detector by {AUTHOR} ({ORG})",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  takeoverscope.py -d blog.example.com\n"
            "  takeoverscope.py -l subdomains.txt --threads 10 -o report.json\n"
            "  takeoverscope.py -l subdomains.txt --fingerprints custom.json -v\n"
        ),
    )
    parser.add_argument("-d", "--domain", help="Single subdomain/hostname to check")
    parser.add_argument("-l", "--list", help="File with one subdomain per line (e.g. passive recon output)")
    parser.add_argument("--fingerprints", help="Path to a custom JSON fingerprint file (overrides the built-in list)")
    parser.add_argument("-t", "--timeout", type=int, default=8, help="DNS/HTTP timeout in seconds (default: 8)")
    parser.add_argument("--threads", type=int, default=10, help="Concurrent hostnames checked in parallel (default: 10)")
    parser.add_argument("--resolver", action="append",
                         help="Custom DNS resolver IP to use (repeatable). Defaults to the system resolver.")
    parser.add_argument("--skip-http", action="store_true",
                         help="Skip the HTTP fingerprint check — DNS/NXDOMAIN signals only (faster, noisier)")
    parser.add_argument("-o", "--output", help="Save results to file (.json or .csv, inferred from extension)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show the reasoning note for every result")
    parser.add_argument("--yes", action="store_true", help="Skip the authorization confirmation prompt")
    parser.add_argument("--no-banner", action="store_true", help="Suppress the ASCII banner")
    parser.add_argument("--version", action="store_true", help="Show version information and exit")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.version:
        print(f"{TOOL_NAME} v{VERSION} — by {AUTHOR} ({ORG})")
        return

    if not args.no_banner:
        render_banner()

    targets = load_targets(args)
    if not targets:
        parser.print_help()
        print(C_VULN + "\n[!] No target provided. Use -d/--domain or -l/--list.\n" + RESET)
        sys.exit(1)

    fingerprints = load_fingerprints(args.fingerprints)

    if not confirm_authorization(args.yes):
        print(C_VULN + "\n[!] Authorization not confirmed. Aborting.\n" + RESET)
        sys.exit(1)

    resolver = dns.resolver.Resolver()
    resolver.lifetime = args.timeout
    resolver.timeout = args.timeout
    if args.resolver:
        resolver.nameservers = args.resolver

    section(f"SCANNING {len(targets)} HOSTNAME(S)", Fore.CYAN)
    print(f"  {C_MUTE}fingerprints={len(fingerprints)} services  threads={args.threads}  "
          f"timeout={args.timeout}s  http-check={'off' if args.skip_http else 'on'}{RESET}\n")

    results: List[ScanResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {
            pool.submit(scan_target, host, resolver, fingerprints, args.timeout, args.skip_http): host
            for host in targets
        }
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    order = {h: i for i, h in enumerate(targets)}
    results.sort(key=lambda r: (VERDICT_ORDER.get(r.verdict, 9), order.get(r.hostname, 0)))

    for result in results:
        print_result(result, args.verbose)

    print_summary(results)

    if args.output:
        ext = os.path.splitext(args.output)[1].lower()
        if ext == ".csv":
            save_csv(results, args.output)
        else:
            save_json(results, args.output)
        print(C_SAFE + f"{BOX['check']} Report saved to: {args.output}\n" + RESET)

    hr(C_MUTE, 72)
    print(C_ACC + f"  {TOOL_NAME} · Made by {AUTHOR} — Founder & CEO of {ORG}" + RESET)
    print(C_MUTE + f"  {SITE}  |  {PORTFOLIO}" + RESET)
    hr(C_MUTE, 72)
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(C_SUSPICIOUS + "\n\n[!] Interrupted by user. Exiting.\n" + RESET)
        sys.exit(130)
