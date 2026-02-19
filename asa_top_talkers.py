#!/usr/bin/env python3
"""
asa_top_talkers_delta.py

Parse Cisco ASA 'show conn/show connection' snapshots and produce a top-talkers report.

Supports:
- Two input files (--before and --after) to compute deltas (after - before)
- Sorting by delta (default) OR totals (--sort-by after|before|delta)
- Aggregation modes: pair (src_ip->dst_ip), src, dst
- CIDR include/exclude filters
- Interface label matching (from ASA output like "TCP Gateway <ip:port> LAN <ip:port> ... bytes N ...")
  * --iface X       : match either interface label
  * --iface-src X   : match first interface label (left side)
  * --iface-dst X   : match second interface label (right side)
- CSV output
- Debug stats / sample skipped lines

Works with ASA lines like:
  TCP Gateway  192.168.21.180:50525 LAN  172.15.39.29:80, idle 0:00:11, bytes 11113, flags UIOB

Note: "bytes" will match only digits (e.g., "11113") and will NOT match "11113,22".
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
# bytes matcher: digits only, and NOT followed by ",<digit>" (prevents matching "12345,67")
LINE_RE = re.compile(
    r"""
    ^\s*
    (?P<proto>\S+)\s+
    (?P<iface1>\S+)\s+
    (?P<ip1>\d{1,3}(?:\.\d{1,3}){3}):(?P<p1>\d+)\s+
    (?P<iface2>\S+)\s+
    (?P<ip2>\d{1,3}(?:\.\d{1,3}){3}):(?P<p2>\d+)
    .*?
    \bbytes\s+(?P<bytes>\d+)(?!,\d)
    """,
    re.IGNORECASE | re.VERBOSE,
)

BYTES_RE = re.compile(r"\bbytes\s+(?P<bytes>\d+)(?!,\d)", re.IGNORECASE)
IPPORT_RE = re.compile(r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d+)", re.IGNORECASE)


def is_valid_ipv4(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return True
    except Exception:
        return False


def parse_conn_line(line: str) -> Optional[tuple[str, str, str, str, int]]:
    """
    Returns (iface1, ip1, iface2, ip2, bytes) if parsable, else None.
    """
    m = LINE_RE.search(line)
    if not m:
        return None

    iface1 = m.group("iface1")
    iface2 = m.group("iface2")
    ip1 = m.group("ip1")
    ip2 = m.group("ip2")

    if not (is_valid_ipv4(ip1) and is_valid_ipv4(ip2)):
        return None

    b = int(m.group("bytes"))
    return iface1, ip1, iface2, ip2, b


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
    if exclude_any and (endpoint_matches(ip1, exclude_any) or endpoint_matches(ip2, exclude_any)):
        return False

    if include_both:
        if not (endpoint_matches(ip1, include_both) and endpoint_matches(ip2, include_both)):
            return False

    if include_either:
        if not (endpoint_matches(ip1, include_either) or endpoint_matches(ip2, include_either)):
            return False

    return True


def iface_matches(val: str, target: Optional[str]) -> bool:
    if not target:
        return True
    return val.lower() == target.lower()


def aggregate_file(
    path: str,
    mode: str,
    include_both: list[ipaddress.IPv4Network],
    include_either: list[ipaddress.IPv4Network],
    exclude_any: list[ipaddress.IPv4Network],
    iface_any: Optional[str],
    iface_src: Optional[str],
    iface_dst: Optional[str],
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
      - iface_filtered_flows
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
                        print(f"[DEBUG skip] format mismatch :: {line.strip()[:220]}")
                continue

            iface1, ip1, iface2, ip2, b = parsed
            stats["parsed_flows"] += 1

            # Interface filters
            if iface_any:
                if iface1.lower() != iface_any.lower() and iface2.lower() != iface_any.lower():
                    stats["iface_filtered_flows"] += 1
                    continue
            if iface_src and iface1.lower() != iface_src.lower():
                stats["iface_filtered_flows"] += 1
                continue
            if iface_dst and iface2.lower() != iface_dst.lower():
                stats["iface_filtered_flows"] += 1
                continue

            # CIDR filters
            if not flow_allowed(ip1, ip2, include_both, include_either, exclude_any):
                stats["filtered_flows"] += 1
                continue

            # Aggregation key
            if mode == "src":
                key = (ip1,)
            elif mode == "dst":
                key = (ip2,)
            else:
                key = (ip1, ip2)

            agg[key] += b

    return agg, dict(stats)


def main():
    ap = argparse.ArgumentParser(
        description="Compute top-talkers from two Cisco ASA 'show conn' snapshots (delta + totals, with filters)."
    )
    ap.add_argument("--before", required=True, help="Older snapshot file (t1).")
    ap.add_argument("--after", required=True, help="Newer snapshot file (t2).")
    ap.add_argument("-n", "--top", type=int, default=20, help="Number of rows to show (default: 20).")

    ap.add_argument(
        "--mode",
        choices=["src", "dst", "pair"],
        default="pair",
        help="Aggregate by src IP, dst IP, or src->dst pair (default: pair).",
    )

    ap.add_argument(
        "--sort-by",
        choices=["delta", "after", "before"],
        default="delta",
        help="Sort by delta (default), or by totals in after/before snapshot.",
    )

    ap.add_argument("--include", action="append", default=[],
                    help="Only include flows where BOTH endpoints match these CIDRs (repeatable).")
    ap.add_argument("--either-include", action="append", default=[],
                    help="Only include flows where EITHER endpoint matches these CIDRs (repeatable).")
    ap.add_argument("--exclude", action="append", default=[],
                    help="Exclude flows where EITHER endpoint matches these CIDRs (repeatable).")

    ap.add_argument("--iface", help="Only include flows where EITHER interface label matches this value.")
    ap.add_argument("--iface-src", help="Only include flows where the FIRST (left) interface label matches.")
    ap.add_argument("--iface-dst", help="Only include flows where the SECOND (right) interface label matches.")

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
        args.before,
        args.mode,
        include_both,
        include_either,
        exclude_any,
        iface_any=args.iface,
        iface_src=args.iface_src,
        iface_dst=args.iface_dst,
        debug_sample=args.debug_sample,
    )
    after_agg, after_stats = aggregate_file(
        args.after,
        args.mode,
        include_both,
        include_either,
        exclude_any,
        iface_any=args.iface,
        iface_src=args.iface_src,
        iface_dst=args.iface_dst,
        debug_sample=args.debug_sample,
    )

    keys = set(before_agg.keys()) | set(after_agg.keys())

    rows_data: list[tuple[tuple[str, ...], int, int, int]] = []
    for k in keys:
        before_bytes = before_agg.get(k, 0)
        after_bytes = after_agg.get(k, 0)
        delta_bytes = after_bytes - before_bytes

        if (not args.allow_negative) and delta_bytes < 0:
            continue

        rows_data.append((k, before_bytes, after_bytes, delta_bytes))

    if args.sort_by == "delta":
        rows_data.sort(key=lambda x: x[3], reverse=True)
    elif args.sort_by == "after":
        rows_data.sort(key=lambda x: x[2], reverse=True)
    else:
        rows_data.sort(key=lambda x: x[1], reverse=True)

    top_items = rows_data[: args.top]

    def show_stats(label: str, st: dict[str, int], path: str):
        print(f"{label}: {path}")
        print(f"  total lines             : {st.get('total_lines', 0)}")
        print(f"  lines w/ 'bytes' token   : {st.get('lines_with_bytes_token', 0)}")
        print(f"  lines w/ >=2 IP:port     : {st.get('lines_with_two_ipports', 0)}")
        print(f"  parsed flows             : {st.get('parsed_flows', 0)}")
        print(f"  iface-filtered flows     : {st.get('iface_filtered_flows', 0)}")
        print(f"  cidr-filtered flows      : {st.get('filtered_flows', 0)}")
        print()

    show_stats("BEFORE", before_stats, args.before)
    show_stats("AFTER ", after_stats, args.after)
    print(f"Mode: {args.mode} | Sort: {args.sort_by} | Top: {args.top} | Negative deltas: {'shown' if args.allow_negative else 'dropped'}")
    if args.iface or args.iface_src or args.iface_dst:
        print(f"Interface filter: iface={args.iface!r} iface_src={args.iface_src!r} iface_dst={args.iface_dst!r}")
    print()

    if args.mode == "pair":
        header = [
            "src_ip", "dst_ip",
            "delta_bytes", "delta_human",
            "after_bytes", "after_human",
            "before_bytes", "before_human",
        ]
    else:
        header = [
            "ip",
            "delta_bytes", "delta_human",
            "after_bytes", "after_human",
            "before_bytes", "before_human",
        ]

    rows: list[tuple[str, ...]] = []
    for key, before_bytes, after_bytes, dbytes in top_items:
        bh = "" if args.no_human else human_bytes(before_bytes)
        ah = "" if args.no_human else human_bytes(after_bytes)
        dh = "" if args.no_human else human_bytes(dbytes)

        if args.mode == "pair":
            src, dst = key
            rows.append((src, dst, str(dbytes), dh, str(after_bytes), ah, str(before_bytes), bh))
        else:
            (ip,) = key
            rows.append((ip, str(dbytes), dh, str(after_bytes), ah, str(before_bytes), bh))

    if not rows:
        print("No rows to display (no parsable flows or all rows filtered).")
        print("Tip: run with --debug-sample 10 and/or remove filters to see what is being skipped.")
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
