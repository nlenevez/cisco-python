#!/usr/bin/env python3
import argparse
import csv
import ipaddress
import re
from collections import defaultdict
from typing import Dict, Iterable, Tuple, List, Optional


CONN_RE = re.compile(
    r"""
    ^\s*
    (?P<proto>[A-Za-z0-9]+)\s+
    (?P<if1>[^:\s]+):(?P<ip1>\d{1,3}(?:\.\d{1,3}){3})(?:/(?P<p1>\d+))?\s+
    (?P<if2>[^:\s]+):(?P<ip2>\d{1,3}(?:\.\d{1,3}){3})(?:/(?P<p2>\d+))?
    .*?
    \bbytes\s+(?P<bytes>\d+)\b
    """,
    re.VERBOSE | re.IGNORECASE
)


def is_valid_ipv4(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return True
    except Exception:
        return False


def parse_conn_lines(lines: Iterable[str]) -> Iterable[Tuple[str, str, int]]:
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


def parse_prefix_list(cidrs: List[str]) -> List[ipaddress.IPv4Network]:
    out: List[ipaddress.IPv4Network] = []
    for item in cidrs:
        out.append(ipaddress.IPv4Network(item, strict=False))
    return out


def endpoint_matches(ip: str, prefixes: List[ipaddress.IPv4Network]) -> bool:
    if not prefixes:
        return False
    addr = ipaddress.IPv4Address(ip)
    return any(addr in p for p in prefixes)


def flow_allowed(
    ip1: str,
    ip2: str,
    include_both: List[ipaddress.IPv4Network],
    include_either: List[ipaddress.IPv4Network],
    exclude_any: List[ipaddress.IPv4Network],
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
    include_both: List[ipaddress.IPv4Network],
    include_either: List[ipaddress.IPv4Network],
    exclude_any: List[ipaddress.IPv4Network],
) -> Tuple[Dict[Tuple[str, ...], int], int, int]:
    """
    Returns: (aggregation_dict, parsed_lines, matched_lines)
      - matched_lines: lines that matched the regex
      - parsed_lines: matched + passed filters (counted into agg)
    """
    agg: Dict[Tuple[str, ...], int] = defaultdict(int)
    matched = 0
    parsed = 0

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for ip1, ip2, b in parse_conn_lines(f):
            matched += 1
            if not flow_allowed(ip1, ip2, include_both, include_either, exclude_any):
                continue
            parsed += 1

            if mode == "src":
                key = (ip1,)
            elif mode == "dst":
                key = (ip2,)
            else:
                key = (ip1, ip2)

            agg[key] += b

    return agg, parsed, matched


def compute_delta(
    before: Dict[Tuple[str, ...], int],
    after: Dict[Tuple[str, ...], int],
    allow_negative: bool,
) -> Dict[Tuple[str, ...], int]:
    out: Dict[Tuple[str, ...], int] = {}
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
        help="Only include flows where BOTH endpoints are inside these CIDRs. Repeatable."
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
    ap.add_argument(
        "--allow-negative",
        action="store_true",
        help="Show negative deltas too (by default they are dropped)."
    )
    ap.add_argument("--csv", default="", help="Write CSV to this path (optional).")
    ap.add_argument("--no-human", action="store_true", help="Do not print human-readable byte sizes.")
    args = ap.parse_args()

    try:
        include_both = parse_prefix_list(args.include)
        include_either = parse_prefix_list(args.either_include)
        exclude_any = parse_prefix_list(args.exclude)
    except Exception as e:
        ap.error(f"CIDR parse error: {e}")

    before_agg, before_parsed, before_matched = aggregate_file(
        args.before, args.mode, include_both, include_either, exclude_any
    )
    after_agg, after_parsed, after_matched = aggregate_file(
        args.after, args.mode, include_both, include_either, exclude_any
    )

    delta = compute_delta(before_agg, after_agg, allow_negative=args.allow_negative)

    # Sort by delta descending, then show top
    items = sorted(delta.items(), key=lambda kv: kv[1], reverse=True)
    top_items = items[: args.top]

    if args.mode == "pair":
        header = ["src_ip", "dst_ip", "delta_bytes", "delta_human", "after_bytes", "after_human"]
    elif args.mode == "src":
        header = ["src_ip", "delta_bytes", "delta_human", "after_bytes", "after_human"]
    else:
        header = ["dst_ip", "delta_bytes", "delta_human", "after_bytes", "after_human"]

    print(f"BEFORE matched: {before_matched}, included: {before_parsed} ({args.before})")
    print(f"AFTER  matched: {after_matched}, included: {after_parsed} ({args.after})")
    print(f"Mode: {args.mode} | Top: {args.top} | Negative deltas: {'shown' if args.allow_negative else 'dropped'}")
    print()

    rows = []
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

    # Pretty table
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
