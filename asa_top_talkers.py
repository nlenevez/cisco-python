#!/usr/bin/env python3
import argparse
import csv
import ipaddress
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional, Tuple, Iterable


# Tries to match common ASA conn lines that include "... bytes <N>"
# Example-ish patterns ASA may emit:
#   TCP outside:1.2.3.4/443 inside:10.0.0.5/51514 ... bytes 123456 ...
#   UDP inside:10.0.0.5/5353 outside:224.0.0.251/5353 ... bytes 2048
#
# This regex focuses on:
#   - first endpoint:  <ifname>:<ip>/<port?>
#   - second endpoint: <ifname>:<ip>/<port?>
#   - bytes: "bytes <number>" somewhere later in the line
CONN_RE = re.compile(
    r"""
    ^\s*
    (?P<proto>[A-Za-z0-9]+)\s+                                 # TCP/UDP/ICMP/...
    (?P<if1>[^:\s]+):(?P<ip1>\d{1,3}(?:\.\d{1,3}){3})(?:/(?P<p1>\d+))?\s+
    (?P<if2>[^:\s]+):(?P<ip2>\d{1,3}(?:\.\d{1,3}){3})(?:/(?P<p2>\d+))?
    .*?
    \bbytes\s+(?P<bytes>\d+)\b
    """,
    re.VERBOSE | re.IGNORECASE
)

# Some ASA outputs include IPv6; if you need it, add another regex.
# For now we keep it IPv4-only because ASA formats vary a lot.


@dataclass(frozen=True)
class FlowKey:
    src_ip: str
    dst_ip: str


def is_valid_ipv4(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return True
    except Exception:
        return False


def parse_conn_lines(lines: Iterable[str]) -> Iterable[Tuple[str, str, int]]:
    """
    Yields tuples of (ip1, ip2, bytes) from each parsable line.
    We treat ip1 as "endpoint A" and ip2 as "endpoint B" as shown by ASA.
    """
    for ln in lines:
        m = CONN_RE.search(ln)
        if not m:
            continue
        ip1 = m.group("ip1")
        ip2 = m.group("ip2")
        if not (is_valid_ipv4(ip1) and is_valid_ipv4(ip2)):
            continue
        b = int(m.group("bytes"))
        yield ip1, ip2, b


def human_bytes(n: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    f = float(n)
    for u in units:
        if f < 1024.0 or u == units[-1]:
            if u == "B":
                return f"{int(f)} {u}"
            return f"{f:.2f} {u}"
        f /= 1024.0
    return f"{int(n)} B"


def within_prefix(ip: str, prefixes) -> bool:
    if not prefixes:
        return True
    addr = ipaddress.IPv4Address(ip)
    return any(addr in p for p in prefixes)


def main():
    ap = argparse.ArgumentParser(
        description="Parse Cisco ASA 'show conn/show connection' output and produce top-talkers by bytes."
    )
    ap.add_argument("-i", "--input", default="-", help="Input file (default: stdin). Use '-' for stdin.")
    ap.add_argument("-n", "--top", type=int, default=20, help="Number of rows to show (default: 20).")
    ap.add_argument(
        "--mode",
        choices=["src", "dst", "pair"],
        default="pair",
        help="Aggregate by: src IP, dst IP, or src->dst pair (default: pair)."
    )
    ap.add_argument(
        "--include",
        action="append",
        default=[],
        help="Only include flows where BOTH endpoints are inside these CIDRs. Repeatable. Example: --include 10.0.0.0/8"
    )
    ap.add_argument(
        "--either-include",
        action="append",
        default=[],
        help="Only include flows where EITHER endpoint matches these CIDRs. Repeatable."
    )
    ap.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Exclude flows where EITHER endpoint matches these CIDRs. Repeatable."
    )
    ap.add_argument("--csv", default="", help="Write CSV to this path (optional).")
    ap.add_argument("--no-human", action="store_true", help="Do not print human-readable byte sizes.")
    args = ap.parse_args()

    def parse_prefix_list(lst):
        out = []
        for item in lst:
            try:
                out.append(ipaddress.IPv4Network(item, strict=False))
            except Exception as e:
                ap.error(f"Bad CIDR '{item}': {e}")
        return out

    include_both = parse_prefix_list(args.include)
    include_either = parse_prefix_list(args.either_include)
    exclude_any = parse_prefix_list(args.exclude)

    if args.input == "-":
        lines = sys.stdin
    else:
        lines = open(args.input, "r", encoding="utf-8", errors="replace")

    # Aggregations
    by_src = defaultdict(int)
    by_dst = defaultdict(int)
    by_pair = defaultdict(int)

    total_lines = 0
    parsed_lines = 0

    try:
        for ip1, ip2, b in parse_conn_lines(lines):
            total_lines += 1

            # Exclude if either endpoint hits an excluded prefix
            if exclude_any and (not within_prefix(ip1, [p for p in exclude_any if True]) or True):
                # We'll do proper logic below; this odd line avoids linting in some editors.
                pass

            if exclude_any:
                a = ipaddress.IPv4Address(ip1)
                c = ipaddress.IPv4Address(ip2)
                if any(a in p for p in exclude_any) or any(c in p for p in exclude_any):
                    continue

            # Include logic
            if include_both:
                a = ipaddress.IPv4Address(ip1)
                c = ipaddress.IPv4Address(ip2)
                if not (any(a in p for p in include_both) and any(c in p for p in include_both)):
                    continue

            if include_either:
                a = ipaddress.IPv4Address(ip1)
                c = ipaddress.IPv4Address(ip2)
                if not (any(a in p for p in include_either) or any(c in p for p in include_either)):
                    continue

            parsed_lines += 1
            by_src[ip1] += b
            by_dst[ip2] += b
            by_pair[(ip1, ip2)] += b
    finally:
        if args.input != "-":
            lines.close()

    if args.mode == "src":
        items = sorted(by_src.items(), key=lambda kv: kv[1], reverse=True)
        header = ["src_ip", "bytes", "human_bytes"]
    elif args.mode == "dst":
        items = sorted(by_dst.items(), key=lambda kv: kv[1], reverse=True)
        header = ["dst_ip", "bytes", "human_bytes"]
    else:
        items = sorted(by_pair.items(), key=lambda kv: kv[1], reverse=True)
        header = ["src_ip", "dst_ip", "bytes", "human_bytes"]

    top_items = items[: args.top]

    # Print report
    print(f"Parsed connections: {parsed_lines} (from {total_lines} matched lines; others ignored by parser)")
    print(f"Mode: {args.mode} | Top: {args.top}")
    print()

    # Column widths for a clean console table
    rows = []
    for k, v in top_items:
        hb = "" if args.no_human else human_bytes(v)
        if args.mode in ("src", "dst"):
            rows.append((k, str(v), hb))
        else:
            src, dst = k
            rows.append((src, dst, str(v), hb))

    # Compute widths
    widths = [len(h) for h in header]
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(cell))

    def fmt_row(r):
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(r))

    print(fmt_row(tuple(header)))
    print("  ".join("-" * w for w in widths))
    for r in rows:
        print(fmt_row(r))

    # CSV output
    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(header)
            for r in rows:
                w.writerow(r)
        print()
        print(f"Wrote CSV: {args.csv}")


if __name__ == "__main__":
    main()
