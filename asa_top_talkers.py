#!/usr/bin/env python3
"""
asa_top_talkers_delta.py

Compute top-talkers *delta bytes* between two Cisco ASA "show connection/show conn"
snapshots taken at different times.

Designed for ASA output lines like:
  TCP Gateway  192.168.21.180:50525 LAN  172.15.39.29:80, idle 0:00:11, bytes 11113, flags UIOB

Features:
- Two input files: --before (t1) and --after (t2)
- Aggregate by src, dst, or pair (default: pair)
- Delta = after - before
- Drop negative deltas by default (use --allow-negative to keep)
- Optional include/exclude CIDR filters
- Optional CSV output
- Debug stats and sample skipped lines with reasons

Python: 3.12+
"""

import argparse
import csv
import ipaddress
import re
from collections import defaultdict
from typing import Optional


# Matches your ASA format:
#   TCP Gateway  192.168.21.180:50525 LAN  172.15.39.29:80, ... bytes 11113, ...
#
# Notes:
# - label1/label2 are words like Gateway/LAN/Outside/Inside/etc
# - bytes can be "11113" or "12,345"
LINE_RE = re.compile(
    r"""
    ^\s*
    (?P<proto>\S+)\s+
    (?P<label1>\S+)\s+
    (?P<ip1>\d{1,3}(?:\.\d{1,3}){3}):(?P<p1>\d+)\s+
    (?P<label2>\S+)\s+
    (?P<ip2>\d{1,3}(?:\.\d{1,3}){3}):(?P<p2>\d+)
    .*?
    \bbytes\s+(?P<bytes>[0-9][0-9,]*)\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

BYTES_RE = re.compile(r"\bbytes\s+(?P<bytes>[0-9][0-9,]*)\b", re.IGNORECASE)
IPPORT_RE = re.compile(r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d+)")


def is_valid_ipv4(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return True
    except Exception:
        return False


def parse_conn_line(line: str) -> Optional[tuple[str, str, int]]:
    """
    Returns (ip1, ip2, bytes) if parsable, else None.

    ip1/ip2 are taken in the order presented on the line:
      <label1> ip1:port1 <label2> ip2:port2
    """
    m = LINE_RE.search(line)
    if not m:
        return None

    ip1 = m.group("ip1")
    ip2 = m.group("ip2")
    if not (is_valid_ipv4(ip1) and is_valid_ipv4(ip2)):
        return None

    b = int(m.group("bytes").replace(",", ""))
    return ip1, ip2, b


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


def parse_prefix_list(cidrs: list[str]) -> list[ipaddress.IPv4Network]:
    out: list[ipaddress.IPv4Network] = []
    for item in cidrs:
        out.append(ipaddress.IPv4Network(item, strict=False))
    return out


def endpoint_matches(ip: str, prefixes: list[ipaddress.IPv4Network]) -> bool:
    if not prefixes:
        return False
    addr = ipaddress.IPv4Address(ip)
    return any(addr in p for p in prefixes)


def flow_allowed(
    ip1: str,
    ip2: str,
    include_both: list[ipaddress.IPv4Network],
    include_either: list[ipaddress.IPv4Network],
    exclude_any: list[ipaddress.IPv4Network],
) -> bool:
    # Exclude if either endpoint matches any excluded prefix
    if exclude_any and (endpoint_matches(ip1, exclude_any) or endpoint_matches(ip2, exclude_any)):
        return False

    # If include_both specified, BOTH endpoints must match at least one of those prefixes
    if include_both:
        if not (endpoint_matches(ip1, include_both) and endpoint_matches(ip2, include_both)):
            return False

    # If include_either specified, at least one endpoint must match
    if include_either:
        if not (endpoint_matches(ip1, include_either) or endpoint_matches(ip2, include_either)):
            return False

    return True


def aggregate_file(
    path: str,
    mode: str,
    include_both: list[ipaddress.IPv4Network],
    include_either: list[ipaddress.IPv4Network],
    exclude_any: list[ipaddress.IPv4Network],
    debug_sample: int = 0,
) -> tuple[dict[tuple[str, ...], int], dict[str, int]]:
    """
    Returns (agg, stats)
    stats includes:
      - total_lines
      - lines_with_bytes_token
      - lines_with_two_ipports
      - parsed_flows
      - filtered_flows
    """
    agg: dict[tuple[str, ...], int] = defaultdict(int)
    stats: dict[str, int] = defaultdict(int)
    debug_shown = 0

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            stats["total_lines"] += 1

            if BYTES_RE.search(line):
                stats["lines_with_bytes_token"] += 1

            if len(IPPORT_RE.findall(line)) >= 2:
                stats["lines_with_two_ipports"] += 1

            parsed = parse_conn_line(line)
            if not parsed:
                if debug_sample and debug_shown < debug_sample:
                    debug_shown += 1
                    reasons = []
                    if not BYTES_RE.search(line):
                        reasons.append("no 'bytes N' token")
                    if len(IPPORT_RE.findall(line)) < 2:
                        reasons.append("fewer than 2 IP:port patterns")
                    if reasons:
                        print(f"[DEBUG skip] {', '.join(reasons)} :: {line.strip()[:220]}")
                    else:
                        # It had bytes and two IP:port patterns, but didn't match the exact LINE_RE layout
                        print(f"[DEBUG skip] format mismatch :: {line.strip()[:220]}")
                continue

            ip1, ip2, b = parsed
            stats["parsed_flows"] += 1

            if not flow_allowed(ip1, ip2, include_both, include_either, exclude_any):
                stats["filtered_flows"] += 1
                continue

            if mode == "src":
                key = (ip1,)
            elif mode == "dst":
                key = (ip2,)
            else:
                key = (ip1, ip2)

            agg[key] += b

    return agg, dict(stats)


def compute_delta(
    before: dict[tuple[str, ...], int],
    after: dict[tuple[str, ...], int],
    allow_negative: bool,
) -> dict[tuple[str, ...], int]:
    out: dict[tuple[str, ...], int] = {}
    keys = set(before.keys()) | set(after.keys())
    for k in keys:
        d = after.get(k, 0) - before.get(k, 0)
        if (not allow_negative) and d < 0:
            continue
        out[k] = d
    return out


def main():
    ap = argparse.ArgumentParser(
        description="Compute top-talkers deltas from two Cisco ASA 'show connection/show conn' snapshots."
    )
    ap.add_argument("--before", required=True, help="Older snapshot file (t1).")
    ap.add_argument("--after", required=True, help="Newer snapshot file (t2).")
    ap.add_argument("-n", "--top", type=int, default=20, help="Number of rows to show (default: 20).")
    ap.add_argument("--mode", choices=["src", "dst", "pair"], default="pair",
                    help="Aggregate by src IP, dst IP, or src->dst pair (default: pair).")
    ap.add_argument("--include", action="append", default=[],
                    help="Only include flows where BOTH endpoints match these CIDRs (repeatable).")
    ap.add_argument("--either-include", action="append", default=[],
                    help="Only include flows where EITHER endpoint matches these CIDRs (repeatable).")
    ap.add_argument("--exclude", action="append", default=[],
                    help="Exclude flows where EITHER endpoint matches these CIDRs (repeatable).")
    ap.add_argument("--allow-negative", action="store_true",
                    help="Show negative deltas too (default: drop them).")
    ap.add_argument("--csv", default="", help="Write CSV to this path (optional).")
    ap.add_argument("--no-human", action="store_true", help="Do not print human-readable byte sizes.")
    ap.add_argument("--debug-sample", type=int, default=0,
                    help="Print N sample skipped lines with reasons to help tune parsing.")
    args = ap.parse_args()

    try:
        include_both = parse_prefix_list(args.include)
        include_either = parse_prefix_list(args.either_include)
        exclude_any = parse_prefix_list(args.exclude)
    except Exception as e:
        ap.error(f"CIDR parse error: {e}")

    before_agg, before_stats = aggregate_file(
        args.before, args.mode, include_both, include_either, exclude_any, debug_sample=args.debug_sample
    )
    after_agg, after_stats = aggregate_file(
        args.after, args.mode, include_both, include_either, exclude_any, debug_sample=args.debug_sample
    )

    delta = compute_delta(before_agg, after_agg, allow_negative=args.allow_negative)
    items = sorted(delta.items(), key=lambda kv: kv[1], reverse=True)
    top_items = items[: args.top]

    def show_stats(label: str, st: dict[str, int], path: str):
        print(f"{label}: {path}")
        print(f"  total lines             : {st.get('total_lines', 0)}")
        print(f"  lines w/ 'bytes' token   : {st.get('lines_with_bytes_token', 0)}")
        print(f"  lines w/ >=2 IP:port     : {st.get('lines_with_two_ipports', 0)}")
        print(f"  parsed flows             : {st.get('parsed_flows', 0)}")
        print(f"  filtered flows           : {st.get('filtered_flows', 0)}")
        print()

    show_stats("BEFORE", before_stats, args.before)
    show_stats("AFTER ", after_stats, args.after)
    print(f"Mode: {args.mode} | Top: {args.top} | Negative deltas: {'shown' if args.allow_negative else 'dropped'}")
    print()

    if args.mode == "pair":
        header = ["src_ip", "dst_ip", "delta_bytes", "delta_human", "after_bytes", "after_human"]
    elif args.mode == "src":
        header = ["src_ip", "delta_bytes", "delta_human", "after_bytes", "after_human"]
    else:
        header = ["dst_ip", "delta_bytes", "delta_human", "after_bytes", "after_human"]

    rows: list[tuple[str, ...]] = []
    for key, dbytes in top_items:
        after_bytes = after_agg.get(key, 0)
        dh = "" if args.no_human else human_bytes(dbytes)
        ah = "" if args.no_human else human_bytes(after_bytes)

        if args.mode == "pair":
            src, dst = key
            rows.append((src, dst, str(dbytes), dh, str(after_bytes), ah))
        else:
            (ip,) = key
            rows.append((ip, str(dbytes), dh, str(after_bytes), ah))

    if not rows:
        print("No rows to display (no parsable flows or all deltas filtered).")
        print("Tip: run with --debug-sample 10 to see why lines are being skipped.")
        return

    # Pretty-print table
    widths = [len(h) for h in header]
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], len(cell))

    def fmt_row(r: tuple[str, ...]) -> str:
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(r))

    print(fmt_row(tuple(header)))
    print("  ".join("-" * w for w in widths))
    for r in rows:
        print(fmt_row(r))

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
