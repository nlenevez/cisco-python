#!/usr/bin/env python3
import argparse
import csv
import ipaddress
import re
from collections import defaultdict
from typing import Dict, Iterable, Tuple, List


# Find "bytes 12345" anywhere
BYTES_RE = re.compile(r"\bbytes\s+(?P<bytes>\d+)\b", re.IGNORECASE)

# Find endpoints anywhere: something like "outside:1.2.3.4/443" or "inside:10.0.0.5/51514"
# This is intentionally permissive about interface names.
ENDPOINT_RE = re.compile(
    r"(?P<ifname>[^:\s]+):(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?:/(?P<port>\d+))?",
    re.IGNORECASE,
)


def is_valid_ipv4(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return True
    except Exception:
        return False


def parse_conn_line(line: str) -> Tuple[str, str, int] | None:
    """
    Returns (ip1, ip2, bytes) if we can extract two endpoints and bytes.
    """
    bm = BYTES_RE.search(line)
    if not bm:
        return None
    b = int(bm.group("bytes"))

    eps = ENDPOINT_RE.findall(line)
    # eps is list of tuples: (ifname, ip, port)
    if len(eps) < 2:
        return None

    # take first two endpoints
    ip1 = eps[0][1]
    ip2 = eps[1][1]

    if not (is_valid_ipv4(ip1) and is_valid_ipv4(ip2)):
        return None

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
    if exclude_any and (endpoint_matches(ip1, exclude_any) or endpoint_matches(ip2, exclude_any)):
        return False

    if include_both:
        if not (endpoint_matches(ip1, include_both) and endpoint_matches(ip2, include_both)):
            return False

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
    debug_sample: int = 0,
) -> Tuple[Dict[Tuple[str, ...], int], Dict[str, int]]:
    """
    Returns (agg, stats)
    stats includes:
      - total_lines
      - bytes_lines
      - endpoint_lines
      - parsed_flows
      - filtered_flows
    """
    agg: Dict[Tuple[str, ...], int] = defaultdict(int)
    stats = defaultdict(int)
    debug_shown = 0

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            stats["total_lines"] += 1

            if BYTES_RE.search(line):
                stats["bytes_lines"] += 1

            eps = ENDPOINT_RE.findall(line)
            if len(eps) >= 2:
                stats["endpoint_lines"] += 1

            parsed = parse_conn_line(line)
            if not parsed:
                if debug_sample and debug_shown < debug_sample:
                    debug_shown += 1
                    reason = []
                    if not BYTES_RE.search(line):
                        reason.append("no 'bytes N'")
                    if len(eps) < 2:
                        reason.append("fewer than 2 endpoints")
                    if reason:
                        print(f"[DEBUG skip] {', '.join(reason)} :: {line.strip()[:200]}")
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
    ap.add_argument("--mode", choices=["src", "dst", "pair"], default="pair")
    ap.add_argument("--include", action="append", default=[], help="BOTH endpoints must match these CIDRs.")
    ap.add_argument("--either-include", action="append", default=[], help="EITHER endpoint must match these CIDRs.")
    ap.add_argument("--exclude", action="append", default=[], help="Exclude if EITHER endpoint matches these CIDRs.")
    ap.add_argument("--allow-negative", action="store_true", help="Show negative deltas too.")
    ap.add_argument("--csv", default="", help="Write CSV to this path (optional).")
    ap.add_argument("--no-human", action="store_true", help="Do not print human-readable byte sizes.")
    ap.add_argument("--debug-sample", type=int, default=0, help="Print N skipped line samples with reasons.")
    args = ap.parse_args()

    include_both = parse_prefix_list(args.include)
    include_either = parse_prefix_list(args.either_include)
    exclude_any = parse_prefix_list(args.exclude)

    before_agg, before_stats = aggregate_file(
        args.before, args.mode, include_both, include_either, exclude_any, debug_sample=args.debug_sample
    )
    after_agg, after_stats = aggregate_file(
        args.after, args.mode, include_both, include_either, exclude_any, debug_sample=args.debug_sample
    )

    delta = compute_delta(before_agg, after_agg, allow_negative=args.allow_negative)
    items = sorted(delta.items(), key=lambda kv: kv[1], reverse=True)
    top_items = items[: args.top]

    def show_stats(label, st, path):
        print(f"{label}: {path}")
        print(f"  total lines      : {st.get('total_lines', 0)}")
        print(f"  lines w/ 'bytes'  : {st.get('bytes_lines', 0)}")
        print(f"  lines w/ endpoints: {st.get('endpoint_lines', 0)}")
        print(f"  parsed flows      : {st.get('parsed_flows', 0)}")
        print(f"  filtered flows    : {st.get('filtered_flows', 0)}")
        print()

    show_stats("BEFORE", before_stats, args.before)
    show_stats("AFTER ", after_stats, args.after)

    if args.mode == "pair":
        header = ["src_ip", "dst_ip", "delta_bytes", "delta_human", "after_bytes", "after_human"]
    elif args.mode == "src":
        header = ["src_ip", "delta_bytes", "delta_human", "after_bytes", "after_human"]
    else:
        header = ["dst_ip", "delta_bytes", "delta_human", "after_bytes", "after_human"]

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

    if not rows:
        print("No rows to display (no parsable flows or all deltas filtered).")
        return

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
