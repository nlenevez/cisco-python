#!/bin/sh
#
# ise-tacacs-parse.sh - extract UserName, device IP, and command from Cisco
#                       ISE TACACS+ command-accounting syslogs.
#
# Input is raw syslog as received from ISE. Real observed line (segment 0 of
# a 2-segment message; the receiving daemon has stripped the <PRI>):
#
#   Aug 31 10:07:20 ISEHOST1 CISE_TACACS_Accounting 0003597785 2 0 \
#     2026-08-31 10:07:20.279 +10:00 0080868889 3300 NOTICE Tacacs-Accounting: \
#     TACACS+ Accounting with Command, ..., Device IP Address=192.168.1.2, \
#     CmdSet=[ CmdAV=show running-config <cr> ], ..., User=netadmin, ...
#
# ISE fragments long accounting messages into several syslog lines that share
# a header:
#
#       [<PRI>]<syslog ts> <host> CISE_<Category> <msg-id> <total-seg> <seg-no> ...
#
# so a record's command / device IP can span multiple lines. This script
# anchors on the "CISE_" mnemonic (independent of the <PRI>/timestamp/host
# prefix and of msg-id length), reassembles segments sharing a message-id in
# order, then extracts fields. Segments may arrive out of order; incomplete
# messages are flushed best-effort at EOF (segment 0 usually already carries
# User/CmdSet/Device IP, so records still emit even if a later segment is lost).
#
# Output: one tab-separated record per command-accounting message:
#       <username>\t<device_ip>\t<command>
# Only messages carrying a non-empty command attribute are emitted.
#
# Robustness:
#   - Attributes split on "," and trimmed, so both ", " and "," delimiters work.
#   - Field-name fallbacks:
#       username : User -> UserName
#       device   : NAS-IP-Address -> Device IP Address -> NAS-IP
#   - Command: ISE records it either as a plain  CmdAV=<command>  or wrapped
#     in an AV-set  CmdSet=[ CmdAV=<command> <cr> ] . Both are handled: the
#     bracket wrapper is unwrapped, the inner CmdAv= marker and a trailing
#     <cr> terminator stripped, leaving the bare command. Candidate top-level
#     fields (first present wins) default to "CmdSet CmdAV CmdAv Cmd";
#     override without editing:
#
#         ISE_CMD_FIELD="CmdAV CmdSet" ise-tacacs-parse.sh ise.log
#
#     To see the real attribute names in your logs (no values printed):
#         grep -m1 CISE_TACACS_Accounting ise.log \
#           | awk -F, '{for(i=1;i<=NF;i++){e=index($i,"=");\
#             if(e)print substr($i,1,e-1)}}'
#
# Troubleshooting: set ISE_DEBUG=1 to print a per-stage counter summary to
# stderr, e.g.
#         ISE_DEBUG=1 ise-tacacs-parse.sh logfile.txt >/dev/null
#
# Usage:
#   ise-tacacs-parse.sh /var/log/remote/ise.log
#   grep npl ise.log | ise-tacacs-parse.sh | sort -u
#   tail -F /var/log/remote/ise.log | ise-tacacs-parse.sh
#
set -eu

awk -v CMDKEYS="${ISE_CMD_FIELD:-CmdSet CmdAV CmdAv Cmd}" -v DEBUG="${ISE_DEBUG:-}" '
function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }

# Parse one fully-reassembled message body and print the wanted fields.
function emit(msg,   n, attrs, i, eq, left, val, m, w, key, kv, user, ip, cmd, cn, ck, ci) {
    d_emitcall++
    n = split(msg, attrs, /,/)          # bare comma; ", " handled by trim()
    for (i = 1; i <= n; i++) {
        eq = index(attrs[i], "=")
        if (eq == 0) continue
        left = trim(substr(attrs[i], 1, eq - 1))
        val  = trim(substr(attrs[i], eq + 1))
        # only the first field may still trail the message header; reduce it
        # to the last whitespace token before "=". Later fields keep their
        # full key, so multi-word keys like "Device IP Address" survive.
        if (i == 1) { m = split(left, w, /[ \t]+/); key = w[m] }
        else          key = left
        kv[key] = val
    }

    user = ("User" in kv) ? kv["User"] : \
           (("UserName" in kv) ? kv["UserName"] : "")

    if      ("NAS-IP-Address"    in kv) ip = kv["NAS-IP-Address"]
    else if ("Device IP Address" in kv) ip = kv["Device IP Address"]
    else if ("NAS-IP"            in kv) ip = kv["NAS-IP"]
    else                                ip = ""

    # command lands in CmdSet on some records, CmdAV on others; take the
    # first candidate present and non-empty
    cmd = ""
    cn = split(CMDKEYS, ck, /[ ,]+/)
    for (ci = 1; ci <= cn; ci++)
        if (ck[ci] in kv && kv[ck[ci]] != "") { cmd = kv[ck[ci]]; break }

    # ISE wraps the command as an AV-set:  CmdSet=[ CmdAV=show running-config <cr> ]
    # unwrap the brackets and drop the inner CmdAv= marker(s) to leave the
    # bare command line
    if (cmd ~ /^\[/) {
        sub(/^\[[ \t]*/, "", cmd)
        sub(/[ \t]*\]$/, "", cmd)
        gsub(/[Cc]md[Aa][Vv]=/, "", cmd)
        cmd = trim(cmd)
    }
    sub(/[ \t]*<cr>[ \t]*$/, "", cmd)   # drop ISE trailing terminator marker
    cmd = trim(cmd)
    if (user == "") d_nouser++
    if (cmd == "") { d_nocmd++; return }   # command-accounting records only

    d_emitted++
    printf "%s\t%s\t%s\n", user, ip, cmd
}

{
    sub(/\r$/, "")                      # tolerate CRLF logs
    d_lines++

    p = index($0, "CISE_")
    if (p == 0) { d_nocise++; next }
    rest = substr($0, p)
    if (!match(rest, /^CISE_[A-Za-z0-9_]+[ ]+[0-9]+[ ]+[0-9]+[ ]+[0-9]+[ ]+/)) { d_noanchor++; next }
    d_anchored++

    prefix = substr(rest, 1, RLENGTH)
    body   = substr(rest, RLENGTH + 1)
    split(prefix, pf, /[ ]+/)
    msgid = pf[2]
    total = pf[3] + 0
    seg   = pf[4] + 0

    if (total <= 1) { d_single++; emit(body); next }

    sk = msgid SUBSEP seg
    if (!(sk in segtext)) {
        segtext[sk] = body
        segcount[msgid]++
        segtotal[msgid] = total
    }
    if (segcount[msgid] >= total) {
        d_completed++
        full = ""
        for (s = 0; s < total; s++) full = full segtext[msgid SUBSEP s]
        emit(full)
        for (s = 0; s < total; s++) delete segtext[msgid SUBSEP s]
        delete segcount[msgid]
        delete segtotal[msgid]
    }
}

END {
    for (m in segcount) {
        d_flushed++
        full = ""
        for (s = 0; s < segtotal[m]; s++)
            if ((m SUBSEP s) in segtext) full = full segtext[m SUBSEP s]
        if (full != "") emit(full)
    }
    if (DEBUG != "") {
        printf "ISE_DEBUG lines=%d no-CISE_=%d header-mismatch=%d anchored=%d " \
               "single-seg=%d multi-completed=%d multi-flushed-at-eof=%d " \
               "emit-calls=%d emitted=%d skipped-no-command=%d no-user=%d\n", \
               d_lines, d_nocise, d_noanchor, d_anchored, d_single, d_completed, \
               d_flushed, d_emitcall, d_emitted, d_nocmd, d_nouser > "/dev/stderr"
    }
}
' "$@"
