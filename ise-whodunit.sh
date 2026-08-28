#!/bin/sh
#
# ise-tacacs-parse.sh - extract UserName, device IP, and CmdAV from Cisco ISE
#                       TACACS+ command-accounting syslogs.
#
# Input is raw syslog as received from ISE. Real observed line (segment 0 of
# a 2-segment message; the receiving daemon has stripped the <PRI>):
#
#   Aug 25 15:22:19 ISE001 CISE_TACACS_Accounting 00039283948 2 0 \
#     2026-08-25 12:23:34 +10:00 003892940 3300 NOTICE Tacacs-Accounting: \
#     TACACS+ Accounting with Command, User=..., CmdAV=..., NAS-IP-Address=...
#
# ISE fragments long accounting messages into several syslog lines; each
# carries the same header:
#
#       [<PRI>]<syslog ts> <host> CISE_<Category> <msg-id> <total-seg> <seg-no> ...
#
# so a single logical record (and its CmdAV / Device IP Address) can be
# spread across multiple lines. This script anchors on the "CISE_" mnemonic
# - so it is independent of the <PRI>/timestamp/host prefix and of the
# message-id length - then reassembles all segments that share a message-id,
# in segment order, before parsing. Segments may arrive out of order.
# Incomplete messages (e.g. a dropped UDP segment) are flushed best-effort
# at end of input.
#
# Reads file(s) named on the command line, or stdin if none. Emits one
# tab-separated record per command-accounting message:
#
#       <username>\t<device_ip>\t<command>
#
# Only messages carrying a non-empty CmdAV are emitted, so auth / session
# records drop out.
#
# Field-name fallbacks cover common ISE variations:
#   username : User      -> UserName
#   device   : NAS-IP-Address -> Device IP Address -> NAS-IP
#
# NB: attributes are assumed ", "-separated (comma-space) and the command
# attribute assumed named CmdAV. If your logs differ, adjust split(msg,...)
# and the "CmdAV" lookup below.
#
# Usage:
#   ise-tacacs-parse.sh /var/log/remote/ise.log
#   grep npl ise.log | ise-tacacs-parse.sh | sort -u
#   tail -F /var/log/remote/ise.log | ise-tacacs-parse.sh
#
set -eu

awk '
function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }

# Parse one fully-reassembled message body and print the wanted fields.
function emit(msg,   n, attrs, i, eq, left, val, m, w, key, kv, user, ip, cmd) {
    delete kv
    n = split(msg, attrs, /, /)
    for (i = 1; i <= n; i++) {
        eq = index(attrs[i], "=")
        if (eq == 0) continue
        left = substr(attrs[i], 1, eq - 1)
        val  = trim(substr(attrs[i], eq + 1))
        if (i == 1) {
            # first field may still trail the message header; the real key
            # is the last whitespace-delimited token before the "="
            m = split(left, w, /[ \t]+/)
            key = w[m]
        } else {
            # keep multi-word keys such as "Device IP Address" intact
            key = trim(left)
        }
        kv[key] = val
    }

    user = ("User" in kv) ? kv["User"] : \
           (("UserName" in kv) ? kv["UserName"] : "")

    if      ("NAS-IP-Address"    in kv) ip = kv["NAS-IP-Address"]
    else if ("Device IP Address" in kv) ip = kv["Device IP Address"]
    else if ("NAS-IP"            in kv) ip = kv["NAS-IP"]
    else                                ip = ""

    cmd = ("CmdAV" in kv) ? kv["CmdAV"] : ""
    if (cmd == "") return        # command-accounting records only

    printf "%s\t%s\t%s\n", user, ip, cmd
}

{
    # Anchor on the ISE mnemonic so we are independent of whatever
    # timestamp/host prefix the receiving syslog daemon prepends, and of
    # the message-id length.
    p = index($0, "CISE_")
    if (p == 0) next
    rest = substr($0, p)
    if (!match(rest, /^CISE_[A-Za-z0-9_]+[ ]+[0-9]+[ ]+[0-9]+[ ]+[0-9]+[ ]+/)) next

    prefix = substr(rest, 1, RLENGTH)
    body   = substr(rest, RLENGTH + 1)
    split(prefix, pf, /[ ]+/)
    msgid = pf[2]
    total = pf[3] + 0
    seg   = pf[4] + 0

    if (total <= 1) { emit(body); next }   # single-segment message

    sk = msgid SUBSEP seg
    if (!(sk in segtext)) {                 # ignore duplicate retransmits
        segtext[sk] = body
        segcount[msgid]++
        segtotal[msgid] = total
    }
    if (segcount[msgid] >= total) {
        full = ""
        for (s = 0; s < total; s++) full = full segtext[msgid SUBSEP s]
        emit(full)
        for (s = 0; s < total; s++) delete segtext[msgid SUBSEP s]
        delete segcount[msgid]
        delete segtotal[msgid]
    }
}

END {
    # best-effort flush of messages that never completed
    for (m in segcount) {
        full = ""
        for (s = 0; s < segtotal[m]; s++)
            if ((m SUBSEP s) in segtext) full = full segtext[m SUBSEP s]
        if (full != "") emit(full)
    }
}
' "$@"
