#!/usr/bin/env python3
"""Parse Cisco configs for 'shape average' and print, on one line, the shaped
rate plus the policy-map it lives in, the interface the policy is attached to,
and that interface's description.

Handles hierarchical (parent/child) policy-maps: a shaper in a child policy is
reported against whatever interface the parent is attached to.

Each config file is parsed in its own namespace, so identical policy-map or
interface names on different routers are never cross-joined.

Usage:
    ./shape-average-report.py < router-config.txt
    ./shape-average-report.py config1.txt config2.txt
    ./shape-average-report.py configs/*.cfg
"""
import re
import sys

RE_POLICY = re.compile(r'^policy-map\s+(?:type\s+\S+\s+)?(\S+)')
RE_INTF   = re.compile(r'^interface\s+(\S+)')
RE_CLASS  = re.compile(r'^\s+class\s+(\S+)')
RE_SHAPE  = re.compile(r'^\s*shape\s+average\s+(percent\s+)?(\d+)\s*(\S*)')
RE_DESC   = re.compile(r'^\s+description\s+(.*)')
RE_SVCPOL = re.compile(r'^\s+service-policy\s+(?:type\s+\S+\s+)?(?:(input|output)\s+)?(\S+)')
RE_HOST   = re.compile(r'^hostname\s+(\S+)')

MULT = {'bps': 1, 'kbps': 1e3, 'mbps': 1e6, 'gbps': 1e9}


def parse(lines):
    policies, interfaces = {}, {}
    hostname = ''
    cur_pol = cur_intf = cur_class = None

    for raw in lines:
        line = raw.rstrip()
        if not line.strip():
            continue
        if line.strip() == '!':                      # '!' closes the current block
            cur_pol = cur_intf = cur_class = None
            continue

        if not line[0].isspace():                    # top-level line
            cur_pol = cur_intf = cur_class = None
            m = RE_HOST.match(line)
            if m:
                hostname = m.group(1)
                continue
            m = RE_POLICY.match(line)
            if m:
                cur_pol = m.group(1)
                policies.setdefault(cur_pol, {'shapes': [], 'children': set()})
                continue
            m = RE_INTF.match(line)
            if m:
                cur_intf = m.group(1)
                interfaces.setdefault(cur_intf, {'desc': '', 'policies': []})
            continue

        if cur_pol:                                  # inside a policy-map
            m = RE_CLASS.match(line)
            if m:
                cur_class = m.group(1)
                continue
            m = RE_SHAPE.match(line)
            if m:
                pct, val, unit = m.group(1), int(m.group(2)), m.group(3)
                policies[cur_pol]['shapes'].append(
                    (cur_class or '-', line.strip(), val, unit, bool(pct)))
                continue
            m = RE_SVCPOL.match(line)                # nested child policy
            if m:
                policies[cur_pol]['children'].add(m.group(2))
        elif cur_intf:                               # inside an interface
            m = RE_DESC.match(line)
            if m:
                interfaces[cur_intf]['desc'] = m.group(1).strip()
                continue
            m = RE_SVCPOL.match(line)
            if m:
                interfaces[cur_intf]['policies'].append((m.group(1) or '-', m.group(2)))

    return hostname, policies, interfaces


def attachments(policy, interfaces, parents, seen=None):
    """Interfaces this policy is attached to, directly or via a parent policy.

    Deduplicated: a diamond (one child under two parents on the same interface)
    must not produce the same row twice.
    """
    seen = seen or set()
    if policy in seen:
        return []
    seen.add(policy)

    out = [(name, d, i['desc']) for name, i in interfaces.items()
           for d, p in i['policies'] if p == policy]
    for parent in parents.get(policy, ()):
        out.extend(attachments(parent, interfaces, parents, seen))
    return list(dict.fromkeys(out))


def rate_mbps(val, unit, is_pct):
    if is_pct:
        return f'{val}%'
    mult = MULT.get(unit.lower(), 1) if unit.isalpha() else 1
    return f'{val * mult / 1e6:g}'


def rows_for(source, lines):
    """Build report rows for a single config, in its own namespace."""
    hostname, policies, interfaces = parse(lines)
    label = hostname or source

    parents = {}
    for name, pol in policies.items():
        for child in pol['children']:
            parents.setdefault(child, set()).add(name)

    rows = []
    for pname, pol in policies.items():
        for cls, raw, val, unit, is_pct in pol['shapes']:
            attached = attachments(pname, interfaces, parents) or [('(unattached)', '-', '')]
            for intf, direction, desc in attached:
                rows.append([label, intf, direction, desc or '(no description)',
                             pname, cls, raw, rate_mbps(val, unit, is_pct)])
    return rows


def main():
    rows = []
    if len(sys.argv) > 1:
        for path in sys.argv[1:]:
            with open(path) as fh:
                rows += rows_for(path.split('/')[-1], fh.readlines())
    else:
        rows += rows_for('stdin', sys.stdin.readlines())

    # Belt and braces: identical rows from a repeated input file collapse here.
    rows = [list(r) for r in dict.fromkeys(tuple(r) for r in rows)]
    if not rows:
        sys.exit(0)

    hdr = ['HOST', 'INTERFACE', 'DIR', 'DESCRIPTION', 'POLICY-MAP', 'CLASS', 'SHAPE', 'MBPS']
    widths = [max(len(r[i]) for r in [hdr] + rows) for i in range(len(hdr))]
    for row in [hdr] + sorted(rows):
        print('  '.join(c.ljust(w) for c, w in zip(row, widths)).rstrip())


if __name__ == '__main__':
    main()
