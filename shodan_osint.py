#!/usr/bin/env python3
"""
Shodan OSINT CLI — Passive recon & asset intelligence
Usage: python shodan_osint.py [command] [options]
"""

import argparse
import json
import os
import sys
import requests
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.columns import Columns
from rich.prompt import Prompt

console = Console()

SHODAN_BASE = "https://api.shodan.io"

# ──────────────────────────────────────────────
# API KEY MANAGEMENT
# ──────────────────────────────────────────────

CONFIG_FILE = os.path.expanduser("~/.shodan_osint_key")

def load_key():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            return f.read().strip()
    return os.environ.get("SHODAN_API_KEY", "")

def save_key(key):
    with open(CONFIG_FILE, "w") as f:
        f.write(key.strip())
    console.print(f"[green]✔ API key saved to {CONFIG_FILE}[/green]")

def get_key(args_key=None):
    key = args_key or load_key()
    if not key:
        console.print("[red]No API key found.[/red] Set it with:\n  python shodan_osint.py setkey YOUR_KEY\nor export SHODAN_API_KEY=YOUR_KEY")
        sys.exit(1)
    return key

# ──────────────────────────────────────────────
# HTTP HELPER
# ──────────────────────────────────────────────

def shodan_get(path, key, params=None):
    params = params or {}
    params["key"] = key
    try:
        r = requests.get(f"{SHODAN_BASE}{path}", params=params, timeout=15)
        if r.status_code == 401:
            console.print("[red]Error 401:[/red] Invalid API key.")
            sys.exit(1)
        if r.status_code == 402:
            console.print("[yellow]Error 402:[/yellow] This query requires a paid Shodan plan.")
            sys.exit(1)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        console.print("[red]Connection error.[/red] Check your internet connection.")
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        console.print(f"[red]HTTP Error:[/red] {e}")
        sys.exit(1)

# ──────────────────────────────────────────────
# EXPORT HELPER
# ──────────────────────────────────────────────

def export_data(data, fmt, filename=None):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if not filename:
        filename = f"shodan_recon_{ts}"
    if fmt == "json":
        path = f"{filename}.json"
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        console.print(f"[green]✔ Exported JSON → {path}[/green]")
    elif fmt == "txt":
        path = f"{filename}.txt"
        with open(path, "w") as f:
            f.write(json.dumps(data, indent=2))
        console.print(f"[green]✔ Exported TXT → {path}[/green]")

# ──────────────────────────────────────────────
# COMMANDS
# ──────────────────────────────────────────────

def cmd_host(args):
    key = get_key(args.key)
    console.print(f"\n[bold cyan]⦿ Host Lookup:[/bold cyan] {args.ip}\n")

    data = shodan_get(f"/shodan/host/{args.ip}", key)

    # Summary cards
    cards = [
        Panel(f"[bold]{len(data.get('ports', []))}[/bold]\n[dim]Open Ports[/dim]", expand=True),
        Panel(f"[bold red]{len(data.get('vulns', {}))}[/bold red]\n[dim]Vulns[/dim]", expand=True),
        Panel(f"[bold]{data.get('country_code', '?')}[/bold]\n[dim]Country[/dim]", expand=True),
        Panel(f"[bold]{len(data.get('data', []))}[/bold]\n[dim]Services[/dim]", expand=True),
    ]
    console.print(Columns(cards))

    # Basic info table
    info = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    info.add_column("Key", style="dim", width=18)
    info.add_column("Value")
    rows = [
        ("IP", data.get("ip_str", "")),
        ("Hostname(s)", ", ".join(data.get("hostnames", [])) or "—"),
        ("Org", data.get("org", "—")),
        ("ISP", data.get("isp", "—")),
        ("ASN", data.get("asn", "—")),
        ("OS", data.get("os", "—")),
        ("Location", f"{data.get('city','—')}, {data.get('country_name','—')}"),
        ("Last updated", data.get("last_update", "—")),
    ]
    for k, v in rows:
        info.add_row(k, str(v))
    console.print(Panel(info, title="Basic Info", border_style="blue"))

    # Ports
    ports = data.get("ports", [])
    if ports:
        pt = Table(title="Open Ports", box=box.SIMPLE_HEAVY, show_header=True)
        pt.add_column("Port", style="green")
        pt.add_column("Transport")
        pt.add_column("Product")
        pt.add_column("Version")
        for svc in data.get("data", []):
            pt.add_row(
                str(svc.get("port", "")),
                svc.get("transport", ""),
                svc.get("product", svc.get("_shodan", {}).get("module", ""))[:40],
                svc.get("version", "")[:20],
            )
        console.print(pt)

    # Tags
    tags = data.get("tags", [])
    if tags:
        console.print(f"\n[bold]Tags:[/bold] " + "  ".join(f"[cyan]{t}[/cyan]" for t in tags))

    # Vulns
    vulns = list(data.get("vulns", {}).keys())
    if vulns:
        vt = Table(title="Vulnerabilities", box=box.SIMPLE_HEAVY)
        vt.add_column("CVE", style="red bold")
        vt.add_column("CVSS")
        vt.add_column("Summary")
        for cve_id, info_v in data.get("vulns", {}).items():
            vt.add_row(
                cve_id,
                str(info_v.get("cvss", "—")),
                (info_v.get("summary", "—") or "—")[:80],
            )
        console.print(vt)
    else:
        console.print("\n[green]No known vulnerabilities found.[/green]")

    if args.export:
        export_data(data, args.export, f"host_{args.ip.replace('.','_')}")


def cmd_domain(args):
    key = get_key(args.key)
    console.print(f"\n[bold cyan]⦿ Domain Recon:[/bold cyan] {args.domain}\n")

    data = shodan_get(f"/dns/domain/{args.domain}", key)

    console.print(Panel(
        f"[bold]{data.get('domain', args.domain)}[/bold]\n"
        f"Subdomains: [cyan]{len(data.get('subdomains', []))}[/cyan]  |  "
        f"More available: {'Yes' if data.get('more') else 'No'}",
        title="Domain Overview", border_style="blue"
    ))

    subs = data.get("subdomains", [])
    if subs:
        st = Table(title=f"Subdomains ({len(subs)})", box=box.SIMPLE_HEAVY)
        st.add_column("Subdomain", style="cyan")
        st.add_column("Full hostname")
        for s in subs:
            st.add_row(s, f"{s}.{args.domain}")
        console.print(st)
    else:
        console.print("[yellow]No subdomains found.[/yellow]")

    tags = data.get("tags", [])
    if tags:
        console.print(f"\n[bold]Tags:[/bold] " + "  ".join(f"[cyan]{t}[/cyan]" for t in tags))

    if args.export:
        export_data(data, args.export, f"domain_{args.domain.replace('.','_')}")


def cmd_org(args):
    key = get_key(args.key)
    if args.asn:
        query = f"asn:{args.target}"
        label = f"ASN: {args.target}"
    else:
        query = f'org:"{args.target}"'
        label = f"Org: {args.target}"

    console.print(f"\n[bold cyan]⦿ Org / ASN Asset Discovery:[/bold cyan] {label}\n")
    data = shodan_get("/shodan/host/search", key, {"query": query})

    total = data.get("total", 0)
    console.print(f"[bold]Total exposed assets:[/bold] [red]{total:,}[/red]\n")

    matches = data.get("matches", [])
    if matches:
        t = Table(title=f"Top {len(matches)} Hosts", box=box.SIMPLE_HEAVY)
        t.add_column("IP", style="cyan")
        t.add_column("Port", style="green")
        t.add_column("Org")
        t.add_column("Country")
        t.add_column("Product")
        for m in matches[:20]:
            t.add_row(
                m.get("ip_str", ""),
                str(m.get("port", "")),
                (m.get("org") or m.get("isp") or "—")[:30],
                m.get("country_code", "?"),
                (m.get("product") or "—")[:30],
            )
        console.print(t)
    else:
        console.print("[yellow]No results.[/yellow]")

    if args.export:
        export_data(data, args.export, f"org_{args.target.replace(' ','_')}")


def cmd_cve(args):
    key = get_key(args.key)
    console.print(f"\n[bold cyan]⦿ CVE Exposure Hunt:[/bold cyan] {args.cve}\n")

    data = shodan_get("/shodan/host/search", key, {"query": f"vuln:{args.cve}"})
    total = data.get("total", 0)

    console.print(Panel(
        f"[red bold]{total:,}[/red bold] hosts exposed to [bold]{args.cve}[/bold]",
        title="Exposure Summary", border_style="red"
    ))

    matches = data.get("matches", [])
    if matches:
        t = Table(title=f"Sample Vulnerable Hosts", box=box.SIMPLE_HEAVY)
        t.add_column("IP", style="cyan")
        t.add_column("Port", style="green")
        t.add_column("Org")
        t.add_column("Country")
        t.add_column("OS")
        for m in matches[:20]:
            t.add_row(
                m.get("ip_str", ""),
                str(m.get("port", "")),
                (m.get("org") or "—")[:28],
                m.get("country_code", "?"),
                (m.get("os") or "—")[:20],
            )
        console.print(t)
    else:
        console.print("[green]No exposed hosts found.[/green]")

    if args.export:
        export_data(data, args.export, f"cve_{args.cve.replace('-','_')}")


def cmd_email(args):
    console.print(f"\n[bold cyan]⦿ Email Format Inference:[/bold cyan] {args.domain}\n")

    formats = [
        ("{first}.{last}@" + args.domain, "john.doe@" + args.domain),
        ("{first}{last}@" + args.domain, "johndoe@" + args.domain),
        ("{first}@" + args.domain, "john@" + args.domain),
        ("{f}{last}@" + args.domain, "jdoe@" + args.domain),
        ("{first}_{last}@" + args.domain, "john_doe@" + args.domain),
        ("{last}.{first}@" + args.domain, "doe.john@" + args.domain),
        ("{first}-{last}@" + args.domain, "john-doe@" + args.domain),
        ("{f}.{last}@" + args.domain, "j.doe@" + args.domain),
    ]

    t = Table(title=f"Common Email Formats — {args.domain}", box=box.SIMPLE_HEAVY)
    t.add_column("Pattern", style="cyan")
    t.add_column("Example", style="dim")
    for pattern, example in formats:
        t.add_row(pattern, example)
    console.print(t)

    console.print("\n[dim]Tip: Cross-reference with Hunter.io, Clearbit, or LinkedIn to confirm the actual format.[/dim]")

    if args.export:
        export_data({"domain": args.domain, "formats": [f[0] for f in formats]}, args.export, f"email_{args.domain.replace('.','_')}")


def cmd_search(args):
    key = get_key(args.key)
    console.print(f"\n[bold cyan]⦿ Custom Search:[/bold cyan] {args.query}\n")

    data = shodan_get("/shodan/host/search", key, {"query": args.query})
    total = data.get("total", 0)
    console.print(f"[bold]Total results:[/bold] [cyan]{total:,}[/cyan]\n")

    matches = data.get("matches", [])
    if matches:
        t = Table(box=box.SIMPLE_HEAVY)
        t.add_column("IP", style="cyan")
        t.add_column("Port", style="green")
        t.add_column("Org")
        t.add_column("Country")
        t.add_column("Product")
        t.add_column("Hostnames")
        for m in matches[:20]:
            t.add_row(
                m.get("ip_str", ""),
                str(m.get("port", "")),
                (m.get("org") or "—")[:28],
                m.get("country_code", "?"),
                (m.get("product") or "—")[:28],
                ", ".join(m.get("hostnames", []))[:30] or "—",
            )
        console.print(t)
    else:
        console.print("[yellow]No results.[/yellow]")

    if args.export:
        export_data(data, args.export, "search_results")


def cmd_myip(args):
    key = get_key(args.key)
    data = shodan_get("/tools/myip", key)
    console.print(f"\n[bold]Your public IP:[/bold] [cyan]{data}[/cyan]\n")


def cmd_account(args):
    key = get_key(args.key)
    data = shodan_get("/api-info", key)
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    t.add_column("Key", style="dim", width=20)
    t.add_column("Value")
    for k, v in data.items():
        t.add_row(str(k), str(v))
    console.print(Panel(t, title="Account / API Info", border_style="blue"))


# ──────────────────────────────────────────────
# CLI SETUP
# ──────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog="shodan_osint",
        description="[bold red]Shodan OSINT CLI[/bold red] — Passive recon & asset intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python shodan_osint.py setkey YOUR_API_KEY
  python shodan_osint.py host 8.8.8.8
  python shodan_osint.py host 8.8.8.8 --export json
  python shodan_osint.py domain example.com
  python shodan_osint.py org "Globe Telecom"
  python shodan_osint.py org AS4775 --asn
  python shodan_osint.py cve CVE-2021-44228
  python shodan_osint.py email target.com
  python shodan_osint.py search 'port:3389 country:PH'
  python shodan_osint.py myip
  python shodan_osint.py account
        """
    )
    parser.add_argument("--key", "-k", help="Shodan API key (overrides saved key)")

    sub = parser.add_subparsers(dest="command", metavar="command")
    sub.required = True

    # setkey
    p_sk = sub.add_parser("setkey", help="Save your Shodan API key")
    p_sk.add_argument("apikey", help="Your Shodan API key")

    # host
    p_host = sub.add_parser("host", help="Host/IP lookup")
    p_host.add_argument("ip", help="Target IP address")
    p_host.add_argument("--export", choices=["json","txt"], help="Export results")

    # domain
    p_domain = sub.add_parser("domain", help="Domain & subdomain recon")
    p_domain.add_argument("domain", help="Target domain (e.g. example.com)")
    p_domain.add_argument("--export", choices=["json","txt"], help="Export results")

    # org
    p_org = sub.add_parser("org", help="Org / ASN asset discovery")
    p_org.add_argument("target", help='Org name (e.g. "Google LLC") or ASN (e.g. AS15169)')
    p_org.add_argument("--asn", action="store_true", help="Treat target as ASN")
    p_org.add_argument("--export", choices=["json","txt"], help="Export results")

    # cve
    p_cve = sub.add_parser("cve", help="CVE vulnerability search")
    p_cve.add_argument("cve", help="CVE ID (e.g. CVE-2021-44228)")
    p_cve.add_argument("--export", choices=["json","txt"], help="Export results")

    # email
    p_email = sub.add_parser("email", help="Email format inference")
    p_email.add_argument("domain", help="Target domain")
    p_email.add_argument("--export", choices=["json","txt"], help="Export results")

    # search
    p_search = sub.add_parser("search", help="Custom Shodan search query")
    p_search.add_argument("query", help="Shodan query string (e.g. 'port:22 country:PH')")
    p_search.add_argument("--export", choices=["json","txt"], help="Export results")

    # myip
    sub.add_parser("myip", help="Show your public IP address")

    # account
    sub.add_parser("account", help="Show API key info & query credits")

    return parser


def main():
    parser = build_parser()

    if len(sys.argv) == 1:
        console.print(Panel.fit(
            "[bold red]Shodan OSINT CLI[/bold red]\n"
            "[dim]Passive recon & asset intelligence[/dim]\n\n"
            "  [cyan]host[/cyan]      IP/host lookup\n"
            "  [cyan]domain[/cyan]    Domain & subdomain recon\n"
            "  [cyan]org[/cyan]       Org / ASN asset discovery\n"
            "  [cyan]cve[/cyan]       CVE vulnerability hunt\n"
            "  [cyan]email[/cyan]     Email format inference\n"
            "  [cyan]search[/cyan]    Custom Shodan query\n"
            "  [cyan]myip[/cyan]      Your public IP\n"
            "  [cyan]account[/cyan]   API key info\n"
            "  [cyan]setkey[/cyan]    Save API key\n\n"
            "Run [bold]python shodan_osint.py --help[/bold] for full usage.",
            title="Usage", border_style="red"
        ))
        sys.exit(0)

    args = parser.parse_args()

    if args.command == "setkey":
        save_key(args.apikey)
        return

    dispatch = {
        "host": cmd_host,
        "domain": cmd_domain,
        "org": cmd_org,
        "cve": cmd_cve,
        "email": cmd_email,
        "search": cmd_search,
        "myip": cmd_myip,
        "account": cmd_account,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
