#!/usr/bin/env python3
"""asa_policy_report.py -- turn a Cisco ASA running-config into a readable
SpreadsheetML 2003 workbook (a single plain-XML .xml file, NOT a zip).

The output opens directly in Excel and LibreOffice (File > Open). Because the
format is flat XML it is also greppable/diffable as text, and this script has
NO third-party dependencies -- Python standard library only.

Parses network/service objects, object-groups (network/service/protocol/
icmp-type), extended access-lists and their interface bindings (access-group),
resolves the object/group references, and writes these sheets:

  * Summary            -- counts + ACL-to-interface bindings
  * Security Policy    -- one row per ACE, with source/dest/service resolved
  * Network Objects    -- name / type / value
  * Service Objects    -- name / protocol / ports
  * Network Groups     -- group / members / fully-resolved leaves
  * Service Groups     -- group / members / fully-resolved ports
  * Expanded Policy    -- (optional, --expand) ACEs exploded to the cartesian
                         product of resolved src x dst x service

Usage:
    asa_policy_report.py running-config.txt
    asa_policy_report.py running-config.txt -o policy.xml --expand

Best-effort parser: anything it can't interpret is preserved in the "Raw"
column so nothing is silently dropped.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from collections import OrderedDict
from xml.sax.saxutils import escape, quoteattr

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
PORT_OPS = ("eq", "neq", "lt", "gt")


# --------------------------------------------------------------------------- #
# Model
# --------------------------------------------------------------------------- #
class Config:
    """Symbol tables built from the config, plus resolution helpers."""

    def __init__(self):
        self.net_objects = OrderedDict()   # name -> {"kind","value","desc","raw"}
        self.svc_objects = OrderedDict()   # name -> {"protocol","detail","desc","raw"}
        self.net_groups = OrderedDict()    # name -> {"desc","members":[...]}
        self.svc_groups = OrderedDict()    # name -> {"protocol","desc","members":[...]}
        self.proto_groups = OrderedDict()  # name -> {"desc","members":[...]}
        self.icmp_groups = OrderedDict()   # name -> {"desc","members":[...]}
        self.acls = OrderedDict()          # name -> [ace,...]
        self.bindings = OrderedDict()      # acl_name -> "direction/interface"

    # ---- network resolution -------------------------------------------- #
    def resolve_net_object(self, name, seen=None):
        seen = seen or set()
        if name in seen:
            return [f"<loop:{name}>"]
        seen = seen | {name}
        obj = self.net_objects.get(name)
        if not obj:
            return [f"<undefined object {name}>"]
        return [obj["value"]]

    def resolve_net_group(self, name, seen=None):
        seen = seen or set()
        if name in seen:
            return [f"<loop:{name}>"]
        seen = seen | {name}
        grp = self.net_groups.get(name)
        if not grp:
            return [f"<undefined group {name}>"]
        out = []
        for m in grp["members"]:
            if m["type"] == "object":
                out += self.resolve_net_object(m["value"], seen)
            elif m["type"] == "group":
                out += self.resolve_net_group(m["value"], seen)
            else:
                out.append(m["value"])
        return out

    # ---- service resolution -------------------------------------------- #
    def resolve_svc_object(self, name, seen=None):
        seen = seen or set()
        if name in seen:
            return [f"<loop:{name}>"]
        obj = self.svc_objects.get(name)
        if not obj:
            return [f"<undefined service {name}>"]
        detail = obj["detail"]
        return [f"{obj['protocol']} {detail}".strip()]

    def resolve_svc_group(self, name, seen=None):
        seen = seen or set()
        if name in seen:
            return [f"<loop:{name}>"]
        seen = seen | {name}
        grp = self.svc_groups.get(name)
        if grp:
            proto = grp.get("protocol") or ""
            out = []
            for m in grp["members"]:
                if m["type"] == "object":
                    out += self.resolve_svc_object(m["value"], seen)
                elif m["type"] == "group":
                    out += self.resolve_svc_group(m["value"], seen)
                elif m["type"] == "port":
                    out.append(f"{proto}/{m['value']}".strip("/") if proto else m["value"])
                else:
                    out.append(m["value"])
            return out
        # protocol object-group used where a service group was expected
        if name in self.proto_groups:
            return self.resolve_proto_group(name, seen)
        return [f"<undefined service-group {name}>"]

    def resolve_proto_group(self, name, seen=None):
        seen = seen or set()
        if name in seen:
            return [f"<loop:{name}>"]
        seen = seen | {name}
        grp = self.proto_groups.get(name)
        if not grp:
            return [f"<undefined protocol-group {name}>"]
        out = []
        for m in grp["members"]:
            if m["type"] == "group":
                out += self.resolve_proto_group(m["value"], seen)
            else:
                out.append(m["value"])
        return out


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #
def parse_service_body(tokens):
    """tokens after 'service'/'service-object' -> (protocol, detail_string)."""
    if not tokens:
        return ("", "")
    proto = tokens[0]
    rest = tokens[1:]
    parts = []
    i = 0
    while i < len(rest):
        t = rest[i]
        if t in ("source", "destination"):
            side = t
            op = rest[i + 1] if i + 1 < len(rest) else ""
            if op == "range":
                parts.append(f"{side} range {rest[i+2]}-{rest[i+3]}")
                i += 4
            elif op in PORT_OPS:
                parts.append(f"{side} {op} {rest[i+2]}")
                i += 3
            else:
                parts.append(f"{side} {op}")
                i += 2
        else:
            parts.append(t)
            i += 1
    return (proto, " ".join(parts))


def parse_config(text):
    cfg = Config()
    block = None          # ("kind", name)
    lines = text.splitlines()

    for raw_line in lines:
        line = raw_line.rstrip()
        if not line.strip() or line.lstrip().startswith("!"):
            block = None
            continue

        indented = line[0] in " \t"
        stripped = line.strip()
        tok = stripped.split()

        # ---- sub-command lines (belong to current block) --------------- #
        if indented and block:
            kind, name = block
            _parse_subline(cfg, kind, name, tok, stripped)
            continue

        block = None  # a non-indented line ends any block

        # ---- object network / service --------------------------------- #
        if tok[:2] == ["object", "network"]:
            name = tok[2]
            cfg.net_objects[name] = {"kind": "", "value": "", "desc": "", "raw": ""}
            block = ("net_object", name)
        elif tok[:2] == ["object", "service"]:
            name = tok[2]
            cfg.svc_objects[name] = {"protocol": "", "detail": "", "desc": "", "raw": ""}
            block = ("svc_object", name)

        # ---- object-group variants ------------------------------------ #
        elif tok[:2] == ["object-group", "network"]:
            name = tok[2]
            cfg.net_groups[name] = {"desc": "", "members": []}
            block = ("net_group", name)
        elif tok[:2] == ["object-group", "service"]:
            name = tok[2]
            proto = tok[3] if len(tok) > 3 else ""
            cfg.svc_groups[name] = {"protocol": proto, "desc": "", "members": []}
            block = ("svc_group", name)
        elif tok[:2] == ["object-group", "protocol"]:
            name = tok[2]
            cfg.proto_groups[name] = {"desc": "", "members": []}
            block = ("proto_group", name)
        elif tok[:2] == ["object-group", "icmp-type"]:
            name = tok[2]
            cfg.icmp_groups[name] = {"desc": "", "members": []}
            block = ("icmp_group", name)
        elif tok[0] == "object-group":
            # user/security/other group types we don't model -- skip cleanly
            block = ("ignore", tok[2] if len(tok) > 2 else "")

        # ---- access-list / access-group ------------------------------- #
        elif tok[0] == "access-list":
            _parse_access_list(cfg, tok, stripped)
        elif tok[0] == "access-group":
            # access-group NAME {in|out} interface IFACE
            if len(tok) >= 5 and tok[2] in ("in", "out") and tok[3] == "interface":
                cfg.bindings[tok[1]] = f"{tok[2]} / {tok[4]}"

    return cfg


def _parse_subline(cfg, kind, name, tok, stripped):
    if tok[0] == "description":
        desc = stripped[len("description"):].strip()
        target = {
            "net_object": cfg.net_objects, "svc_object": cfg.svc_objects,
            "net_group": cfg.net_groups, "svc_group": cfg.svc_groups,
            "proto_group": cfg.proto_groups, "icmp_group": cfg.icmp_groups,
        }.get(kind)
        if target and name in target:
            target[name]["desc"] = desc
        return

    if kind == "net_object":
        o = cfg.net_objects[name]
        o["raw"] = stripped
        if tok[0] == "host":
            o["kind"], o["value"] = "host", f"host {tok[1]}"
        elif tok[0] == "subnet":
            o["kind"], o["value"] = "subnet", " ".join(tok[1:])
        elif tok[0] == "range":
            o["kind"], o["value"] = "range", f"{tok[1]}-{tok[2]}"
        elif tok[0] == "fqdn":
            o["kind"], o["value"] = "fqdn", tok[-1]

    elif kind == "svc_object":
        if tok[0] == "service":
            proto, detail = parse_service_body(tok[1:])
            cfg.svc_objects[name].update(protocol=proto, detail=detail, raw=stripped)

    elif kind == "net_group":
        m = _parse_network_member(tok)
        if m:
            cfg.net_groups[name]["members"].append(m)

    elif kind == "svc_group":
        m = _parse_service_member(tok)
        if m:
            cfg.svc_groups[name]["members"].append(m)

    elif kind == "proto_group":
        if tok[0] == "protocol-object":
            cfg.proto_groups[name]["members"].append({"type": "proto", "value": tok[1]})
        elif tok[0] == "group-object":
            cfg.proto_groups[name]["members"].append({"type": "group", "value": tok[1]})

    elif kind == "icmp_group":
        if tok[0] == "icmp-object":
            cfg.icmp_groups[name]["members"].append({"type": "icmp", "value": tok[1]})
        elif tok[0] == "group-object":
            cfg.icmp_groups[name]["members"].append({"type": "group", "value": tok[1]})


def _parse_network_member(tok):
    if tok[0] == "network-object":
        if tok[1] == "host":
            return {"type": "host", "value": f"host {tok[2]}"}
        if tok[1] == "object":
            return {"type": "object", "value": tok[2]}
        return {"type": "subnet", "value": " ".join(tok[1:])}
    if tok[0] == "group-object":
        return {"type": "group", "value": tok[1]}
    return None


def _parse_service_member(tok):
    if tok[0] == "port-object":
        if tok[1] == "range":
            return {"type": "port", "value": f"{tok[2]}-{tok[3]}"}
        return {"type": "port", "value": " ".join(tok[1:])}
    if tok[0] == "service-object":
        if tok[1] == "object":
            return {"type": "object", "value": tok[2]}
        proto, detail = parse_service_body(tok[1:])
        return {"type": "service", "value": f"{proto} {detail}".strip()}
    if tok[0] == "group-object":
        return {"type": "group", "value": tok[1]}
    return None


def _parse_addr(tokens, i):
    """Return (display, ref_or_None, next_index). ref = (kind, name)."""
    t = tokens[i]
    if t in ("any", "any4", "any6"):
        return (t, None, i + 1)
    if t == "host":
        return (f"host {tokens[i+1]}", None, i + 2)
    if t == "interface":
        return (f"interface {tokens[i+1]}", None, i + 2)
    if t == "object":
        return (f"object {tokens[i+1]}", ("object", tokens[i + 1]), i + 2)
    if t == "object-group":
        return (f"group {tokens[i+1]}", ("object-group", tokens[i + 1]), i + 2)
    if ":" in t:  # bare IPv6 host or prefix
        return (t, None, i + 1)
    if IPV4_RE.match(t) and i + 1 < len(tokens) and IPV4_RE.match(tokens[i + 1]):
        return (f"{t} {tokens[i+1]}", None, i + 2)
    return (t, None, i + 1)


def _parse_port(tokens, i, svc_groups):
    if i >= len(tokens):
        return (None, i)
    t = tokens[i]
    if t in PORT_OPS:
        return (f"{t} {tokens[i+1]}", i + 2)
    if t == "range":
        return (f"range {tokens[i+1]}-{tokens[i+2]}", i + 3)
    if t == "object-group" and i + 1 < len(tokens) and tokens[i + 1] in svc_groups:
        return (f"group {tokens[i+1]}", i + 2)
    return (None, i)


def _parse_access_list(cfg, tok, stripped):
    name = tok[1]
    cfg.acls.setdefault(name, [])
    rest = tok[2:]
    i = 0
    if i < len(rest) and rest[i] == "line":
        i += 2

    if i < len(rest) and rest[i] == "remark":
        cfg.acls[name].append({"kind": "remark", "text": " ".join(rest[i + 1:]), "raw": stripped})
        return

    acl_type = ""
    if i < len(rest) and rest[i] in ("extended", "standard"):
        acl_type = rest[i]
        i += 1

    ace = {"kind": "ace", "type": acl_type, "raw": stripped,
           "action": "", "protocol": "", "service_ref": None,
           "src": "", "src_ref": None, "src_port": "",
           "dst": "", "dst_ref": None, "dst_port": "", "options": ""}
    try:
        if i < len(rest) and rest[i] in ("permit", "deny"):
            ace["action"] = rest[i]
            i += 1

        # protocol
        if rest[i] == "object":
            ace["protocol"] = f"object {rest[i+1]}"
            ace["service_ref"] = ("object", rest[i + 1])
            i += 2
        elif rest[i] == "object-group":
            ace["protocol"] = f"group {rest[i+1]}"
            ace["service_ref"] = ("object-group", rest[i + 1])
            i += 2
        else:
            ace["protocol"] = rest[i]
            i += 1

        if acl_type == "standard":
            # standard: only a destination network follows
            ace["dst"], ace["dst_ref"], i = _parse_addr(rest, i)
        else:
            ace["src"], ace["src_ref"], i = _parse_addr(rest, i)
            ace["src_port"], i = _parse_port(rest, i, cfg.svc_groups)
            ace["dst"], ace["dst_ref"], i = _parse_addr(rest, i)
            ace["dst_port"], i = _parse_port(rest, i, cfg.svc_groups)

        ace["options"] = " ".join(rest[i:])
    except IndexError:
        ace["options"] = (ace["options"] + " [parse-truncated]").strip()

    cfg.acls[name].append(ace)


# --------------------------------------------------------------------------- #
# Resolution helpers for report rows
# --------------------------------------------------------------------------- #
def _resolve_addr_ref(cfg, ref):
    if not ref:
        return ""
    kind, nm = ref
    leaves = cfg.resolve_net_object(nm) if kind == "object" else cfg.resolve_net_group(nm)
    return ", ".join(leaves)


def _resolve_service_ref(cfg, ref):
    if not ref:
        return ""
    kind, nm = ref
    if kind == "object":
        return ", ".join(cfg.resolve_svc_object(nm))
    if nm in cfg.svc_groups:
        return ", ".join(cfg.resolve_svc_group(nm))
    if nm in cfg.proto_groups:
        return ", ".join(cfg.resolve_proto_group(nm))
    return f"<undefined {nm}>"


# --------------------------------------------------------------------------- #
# SpreadsheetML 2003 output (flat XML -- no zip, no dependencies)
# --------------------------------------------------------------------------- #
STYLES = """\
  <Styles>
   <Style ss:ID="Default" ss:Name="Normal">
    <Alignment ss:Vertical="Top"/>
    <Font ss:FontName="Calibri" ss:Size="11"/>
   </Style>
   <Style ss:ID="hdr">
    <Font ss:FontName="Calibri" ss:Size="11" ss:Bold="1" ss:Color="#FFFFFF"/>
    <Interior ss:Color="#1F3864" ss:Pattern="Solid"/>
    <Alignment ss:Vertical="Center" ss:WrapText="1"/>
   </Style>
   <Style ss:ID="title"><Font ss:FontName="Calibri" ss:Size="13" ss:Bold="1" ss:Color="#1F3864"/></Style>
   <Style ss:ID="kbold"><Font ss:FontName="Calibri" ss:Size="11" ss:Bold="1"/></Style>
   <Style ss:ID="permit">
    <Font ss:FontName="Calibri" ss:Size="11" ss:Bold="1" ss:Color="#006100"/>
    <Interior ss:Color="#C6EFCE" ss:Pattern="Solid"/>
   </Style>
   <Style ss:ID="deny">
    <Font ss:FontName="Calibri" ss:Size="11" ss:Bold="1" ss:Color="#9C0006"/>
    <Interior ss:Color="#FFC7CE" ss:Pattern="Solid"/>
   </Style>
   <Style ss:ID="remark">
    <Font ss:FontName="Calibri" ss:Size="11" ss:Italic="1" ss:Color="#7F6000"/>
    <Interior ss:Color="#FFF2CC" ss:Pattern="Solid"/>
    <Alignment ss:Vertical="Top" ss:WrapText="1"/>
   </Style>
   <Style ss:ID="wrap"><Alignment ss:Vertical="Top" ss:WrapText="1"/></Style>
  </Styles>"""


class Sheet:
    def __init__(self, name, widths, header=None, freeze=False, autofilter=False):
        self.name = name
        self.widths = widths          # column widths, in "characters"
        self.header = header          # list[str] or None
        self.freeze = freeze          # freeze the (header) top row
        self.autofilter = autofilter  # add an AutoFilter over the header
        self.rows = []                # list[list[(value, style_id|None)]]

    def add(self, cells):
        self.rows.append(cells)


def _cell_xml(value, style):
    if value is None or value == "":
        return f'    <Cell ss:StyleID={quoteattr(style)}/>\n' if style else "    <Cell/>\n"
    is_num = isinstance(value, int) and not isinstance(value, bool)
    dtype = "Number" if is_num else "String"
    data = escape(str(value))
    sattr = f' ss:StyleID={quoteattr(style)}' if style else ""
    return f'    <Cell{sattr}><Data ss:Type="{dtype}">{data}</Data></Cell>\n'


def _sheet_xml(sheet):
    ncols = len(sheet.widths)
    nrows = len(sheet.rows) + (1 if sheet.header else 0)
    out = [f'  <Worksheet ss:Name={quoteattr(sheet.name)}>\n']
    out.append(f'   <Table ss:ExpandedColumnCount="{ncols}" '
               f'ss:ExpandedRowCount="{max(nrows,1)}" x:FullColumns="1" x:FullRows="1">\n')
    for w in sheet.widths:
        out.append(f'    <Column ss:Width="{round(w * 5.25, 1)}"/>\n')

    if sheet.header:
        out.append("   <Row>\n")
        for h in sheet.header:
            out.append("  " + _cell_xml(h, "hdr"))
        out.append("   </Row>\n")

    for row in sheet.rows:
        out.append("   <Row>\n")
        for value, style in row:
            out.append("  " + _cell_xml(value, style))
        out.append("   </Row>\n")

    out.append("   </Table>\n")

    if sheet.autofilter and sheet.header:
        out.append(f'   <AutoFilter x:Range="R1C1:R1C{ncols}" '
                   f'xmlns="urn:schemas-microsoft-com:office:excel"/>\n')
    if sheet.freeze:
        out.append(
            '   <WorksheetOptions xmlns="urn:schemas-microsoft-com:office:excel">\n'
            "    <FreezePanes/>\n    <FrozenNoSplit/>\n"
            "    <SplitHorizontal>1</SplitHorizontal>\n"
            "    <TopRowBottomPane>1</TopRowBottomPane>\n"
            "    <ActivePane>2</ActivePane>\n   </WorksheetOptions>\n"
        )
    out.append("  </Worksheet>\n")
    return "".join(out)


def build_document(cfg, expand=False):
    sheets = [
        _sheet_summary(cfg),
        _sheet_policy(cfg),
        _sheet_net_objects(cfg),
        _sheet_svc_objects(cfg),
        _sheet_net_groups(cfg),
        _sheet_svc_groups(cfg),
    ]
    if expand:
        sheets.append(_sheet_expanded(cfg))

    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>\n',
        '<?mso-application progid="Excel.Sheet"?>\n',
        '<Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet"\n'
        ' xmlns:o="urn:schemas-microsoft-com:office:office"\n'
        ' xmlns:x="urn:schemas-microsoft-com:office:excel"\n'
        ' xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet"\n'
        ' xmlns:html="http://www.w3.org/TR/REC-html40">\n',
        STYLES + "\n",
    ]
    parts.extend(_sheet_xml(s) for s in sheets)
    parts.append("</Workbook>\n")
    return "".join(parts)


def _sheet_summary(cfg):
    s = Sheet("Summary", [30, 26, 10])
    s.add([("Cisco ASA Security Policy Report", "title")])
    s.add([])
    s.add([("Counts", "kbold")])
    for label, n in [
        ("Network objects", len(cfg.net_objects)),
        ("Service objects", len(cfg.svc_objects)),
        ("Network object-groups", len(cfg.net_groups)),
        ("Service object-groups", len(cfg.svc_groups)),
        ("Protocol object-groups", len(cfg.proto_groups)),
        ("ICMP-type object-groups", len(cfg.icmp_groups)),
        ("Access-lists", len(cfg.acls)),
        ("Total ACEs", sum(len(a) for a in cfg.acls.values())),
    ]:
        s.add([(label, None), (n, None)])
    s.add([])
    s.add([("Interface bindings (access-group)", "kbold")])
    s.add([("ACL", "hdr"), ("Direction / Interface", "hdr"), ("ACEs", "hdr")])
    for acl in cfg.acls:
        s.add([(acl, None), (cfg.bindings.get(acl, "(not bound)"), None), (len(cfg.acls[acl]), None)])
    return s


def _sheet_policy(cfg):
    header = ["ACL", "Applied", "#", "Action", "Protocol", "Source", "Src Port",
              "Destination", "Dst Port", "Service (resolved)", "Options",
              "Resolved Source", "Resolved Destination", "Remark", "Raw"]
    widths = [16, 16, 4, 8, 14, 22, 12, 22, 12, 30, 16, 30, 30, 26, 44]
    s = Sheet("Security Policy", widths, header=header, freeze=True, autofilter=True)
    wrapcols = {9, 11, 12, 13, 14}  # 0-based indexes of wrapped columns

    for acl, aces in cfg.acls.items():
        pending_remark = ""
        seq = 0
        for ace in aces:
            if ace["kind"] == "remark":
                pending_remark = (pending_remark + " | " + ace["text"]).strip(" |") if pending_remark else ace["text"]
                cells = [(acl, "remark"), ("", "remark"), ("", "remark"),
                         ("remark", "remark"), ("", "remark"), ("", "remark"),
                         ("", "remark"), ("", "remark"), ("", "remark"), ("", "remark"),
                         ("", "remark"), ("", "remark"), ("", "remark"),
                         (ace["text"], "remark"), (ace["raw"], "remark")]
                s.add(cells)
                continue

            seq += 1
            values = [
                acl, cfg.bindings.get(acl, ""), seq, ace["action"], ace["protocol"],
                ace["src"], ace["src_port"] or "", ace["dst"], ace["dst_port"] or "",
                _resolve_service_ref(cfg, ace["service_ref"]), ace["options"],
                _resolve_addr_ref(cfg, ace["src_ref"]), _resolve_addr_ref(cfg, ace["dst_ref"]),
                pending_remark, ace["raw"],
            ]
            cells = []
            for idx, v in enumerate(values):
                if idx == 3:  # Action
                    style = "permit" if v == "permit" else "deny" if v == "deny" else None
                elif idx in wrapcols:
                    style = "wrap"
                else:
                    style = None
                cells.append((v, style))
            s.add(cells)
            pending_remark = ""
    return s


def _sheet_net_objects(cfg):
    s = Sheet("Network Objects", [28, 10, 34, 40],
              header=["Name", "Type", "Value", "Description"], freeze=True, autofilter=True)
    for name, o in cfg.net_objects.items():
        s.add([(name, None), (o["kind"], None), (o["value"], None), (o["desc"], "wrap")])
    return s


def _sheet_svc_objects(cfg):
    s = Sheet("Service Objects", [28, 10, 34, 40],
              header=["Name", "Protocol", "Ports / Detail", "Description"], freeze=True, autofilter=True)
    for name, o in cfg.svc_objects.items():
        s.add([(name, None), (o["protocol"], None), (o["detail"], None), (o["desc"], "wrap")])
    return s


def _members_text(members):
    return "\n".join(
        (f"object {m['value']}" if m["type"] == "object"
         else f"group {m['value']}" if m["type"] == "group"
         else m["value"])
        for m in members
    )


def _sheet_net_groups(cfg):
    s = Sheet("Network Groups", [28, 34, 40, 30],
              header=["Group", "Members (as configured)", "Resolved leaves", "Description"],
              freeze=True, autofilter=True)
    for name, g in cfg.net_groups.items():
        s.add([(name, None), (_members_text(g["members"]), "wrap"),
               ("\n".join(cfg.resolve_net_group(name)), "wrap"), (g["desc"], "wrap")])
    return s


def _sheet_svc_groups(cfg):
    s = Sheet("Service Groups", [28, 10, 34, 40, 30],
              header=["Group", "Protocol", "Members (as configured)",
                      "Resolved ports/services", "Description"],
              freeze=True, autofilter=True)
    for name, g in cfg.svc_groups.items():
        s.add([(name, None), (g.get("protocol", ""), None), (_members_text(g["members"]), "wrap"),
               ("\n".join(cfg.resolve_svc_group(name)), "wrap"), (g["desc"], "wrap")])
    return s


def _sheet_expanded(cfg, cap=5000):
    header = ["ACL", "Applied", "Action", "Protocol", "Source", "Src Port",
              "Destination", "Dst Port", "Service"]
    s = Sheet("Expanded Policy", [16, 16, 8, 14, 24, 12, 24, 12, 24],
              header=header, freeze=True, autofilter=True)
    count = 0
    truncated = False
    for acl, aces in cfg.acls.items():
        for ace in aces:
            if ace["kind"] != "ace":
                continue
            srcs = _resolve_addr_ref(cfg, ace["src_ref"]).split(", ") if ace["src_ref"] else [ace["src"]]
            dsts = _resolve_addr_ref(cfg, ace["dst_ref"]).split(", ") if ace["dst_ref"] else [ace["dst"]]
            svcs = _resolve_service_ref(cfg, ace["service_ref"]).split(", ") if ace["service_ref"] else [ace["protocol"]]
            for src in srcs:
                for dst in dsts:
                    for svc in svcs:
                        if count >= cap:
                            truncated = True
                            break
                        astyle = "permit" if ace["action"] == "permit" else "deny" if ace["action"] == "deny" else None
                        s.add([(acl, None), (cfg.bindings.get(acl, ""), None), (ace["action"], astyle),
                               (ace["protocol"], None), (src, None), (ace["src_port"] or "", None),
                               (dst, None), (ace["dst_port"] or "", None), (svc, None)])
                        count += 1
    if truncated:
        s.add([(f"[truncated at {cap} rows -- use per-ACL views for full detail]", "kbold")])
    return s


# --------------------------------------------------------------------------- #
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Render a Cisco ASA config as a readable SpreadsheetML 2003 (.xml) report.")
    ap.add_argument("config", help="Path to the ASA running-config text file")
    ap.add_argument("-o", "--output", help="Output .xml path (default: <config>.xml)")
    ap.add_argument("--expand", action="store_true",
                    help="Add an 'Expanded Policy' sheet (ACEs exploded to resolved leaves)")
    args = ap.parse_args(argv)

    with open(args.config, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()

    cfg = parse_config(text)
    doc = build_document(cfg, expand=args.expand)

    out = args.output or (os.path.splitext(args.config)[0] + ".xml")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(doc)

    print(f"Wrote {out}")
    print(f"  network objects : {len(cfg.net_objects)}")
    print(f"  service objects : {len(cfg.svc_objects)}")
    print(f"  network groups  : {len(cfg.net_groups)}")
    print(f"  service groups  : {len(cfg.svc_groups)}")
    print(f"  access-lists    : {len(cfg.acls)} ({sum(len(a) for a in cfg.acls.values())} lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
