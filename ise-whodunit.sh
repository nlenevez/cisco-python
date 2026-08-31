#!/bin/sh
# ============================ CONFIG (edit me) ==============================
# Usernames to exclude from the output, space- or comma-separated. Leave empty
# to exclude nobody. Matching is exact (case-sensitive). Can also be supplied
# from the environment, e.g.
#     EXCLUDE_USERS="rancid svc-mon" ./ise-tacacs-parse.sh ise.log
EXCLUDE_USERS="${EXCLUDE_USERS:-}"

# Log file to read when nothing is piped in and no file argument is given.
DEFAULT_LOG="${DEFAULT_LOG:-/var/log/tacacs-log}"
# ===========================================================================
#
# ise-tacacs-parse.sh - extract timestamp, UserName, device IP, and command
#                       from Cisco ISE TACACS+ command-accounting syslogs.
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
# the timestamp/User/CmdSet/Device IP, so records still emit if a later
# segment is lost).
#
# Output: one line per command-accounting message:
#       YY-MM-DD HH:MM:SS [username] [device-ip] [command]
# The timestamp is ISE's own record timestamp, shortened to a 2-digit year.
# Only messages carrying a non-empty command attribute are emitted, and any
# user listed in EXCLUDE_USERS is dropped.
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
#     override with  ISE_CMD_FIELD="CmdAV CmdSet" ...
#
# Troubleshooting: set ISE_DEBUG=1 to print a per-stage counter summary to
# stderr, e.g.  ISE_DEBUG=1 ise-tacacs-parse.sh logfile.txt >/dev/null
#
# Usage:
#   ise-tacacs-parse.sh                     # reads DEFAULT_LOG (no pipe/args)
#   ise-tacacs-parse.sh /var/log/tacacs-log.0
#   cat /var/log/tacacs-log | ise-tacacs-parse.sh
#   grep npl ise.log | ise-tacacs-parse.sh | sort
#   tail -F /var/log/remote/ise.log | ise-tacacs-parse.sh
#
set -eu

# With no file arguments and nothing piped in (stdin is a terminal), fall back
# to DEFAULT_LOG. A pipe or redirect on stdin is read as usual; explicit file
# arguments always win.
if [ "$#" -eq 0 ] && [ -t 0 ]; then
    if [ ! -r "$DEFAULT_LOG" ]; then
        echo "ise-tacacs-parse.sh: nothing piped in and default log '$DEFAULT_LOG' is not readable" >&2
        exit 1
    fi
    set -- "$DEFAULT_LOG"
fi

awk -v CMDKEYS="${ISE_CMD_FIELD:-CmdSet CmdAV CmdAv Cmd}" \
    -v EXCLUDE="${EXCLUDE_USERS:-}" \
    -v DEBUG="${ISE_DEBUG:-}" '
function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }

BEGIN {
    ne = split(EXCLUDE, ea, /[ ,]+/)
    for (ei = 1; ei <= ne; ei++)
        if (ea[ei] != "") EXSET[ea[ei]] = 1
}

# Parse one fully-reassembled message body and print the wanted fields.
function emit(msg,   n, attrs, i, eq, left, val, m, w, key, kv, user, ip, cmd, cn, ck, ci, ts) {
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

    # ISE record timestamp leads the body: YYYY-MM-DD HH:MM:SS.mmm +TZ
    # keep YY-MM-DD HH:MM:SS (drop century, fractional seconds and TZ)
    ts = ""
    if (match(msg, /[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]/))
        ts = substr(msg, RSTART + 2, RLENGTH - 2)

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

    # unwrap  CmdSet=[ CmdAV=show running-config <cr> ]  to the bare command
    if (cmd ~ /^\[/) {
        sub(/^\[[ \t]*/, "", cmd)
        sub(/[ \t]*\]$/, "", cmd)
        gsub(/[Cc]md[Aa][Vv]=/, "", cmd)
        cmd = trim(cmd)
    }
    sub(/[ \t]*<cr>[ \t]*$/, "", cmd)   # drop ISE trailing terminator marker
    cmd = trim(cmd)

    if (user == "") d_nouser++
    if (cmd == "") { d_nocmd++; return }        # command-accounting records only
    if (user in EXSET) { d_excluded++; return } # user on the exclude list

    d_emitted++
    printf "%s [%s] [%s] [%s]\n", ts, user, ip, cmd
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
               "emit-calls=%d emitted=%d excluded=%d skipped-no-command=%d no-user=%d\n", \
               d_lines, d_nocise, d_noanchor, d_anchored, d_single, d_completed, \
               d_flushed, d_emitcall, d_emitted, d_excluded, d_nocmd, d_nouser > "/dev/stderr"
    }
}
' "$@"
