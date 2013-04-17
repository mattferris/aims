Runtime Options
===============

There are a number of runtime options that can be specified. These options are defined in the ruleset using `option`. `option` expects the option name and option value. Option values should be quoted with the exception of `on` and `off`.

    option strict on
    option log-prefix "bad packets"

*Core* options specifically affect the way aims processes the ruleset. All other options specify defaults that are used by various clauses when compiling rules.

Core options
------------

### strict

    option strict { on | off }

Defaults to `off`.

When `strict` is set to `on`, most warnings become full errors. For example, when `strict` is set to `off`, using `port` without `proto` causes aims to assume `proto all` and issue a warning. In the same scenario, if `strict` is set to `on`, aims issues an error and exists.

### debug

    option debug { on | off }

Defaults to `off`.

When `debug` is set to `on`, aims displays debugging messages.

### inline-comments

    option inline-comments { on | off }

Defaults to `off`.

When `inline-comments` is set to `on`, aims uses inline comments (lines starting with `#`) as the comment for rules immediately following the comment. A blank line clears the comment for rules following the blank line. For example:

    # allow ssh connections
    accept in eth1 proto tcp to port 22 reverse

    accept out eth0 proto udp to port 53 reverse

The first rule will be given the comment "allow ssh connections", but the second rule won't because the empty line clears the comment.

### origin-comments

    option origin-comments { on | off }

Defaults to `off`.

When `origin-comments` is set to `on`, aims sets the comment of each rule to the filename and line number of the original aims rule that the iptables rule was generated from.

### state-module

    option state-module { "state" | "conntrack" }

Defaults to `state`.

`state-module` determines which iptables state tracking module to use. `state` refers to `-m state`, and `conntrack` refers to `-m conntrack`. While both modules offer stateful connection tracking, `conntrack` is the newer and more fully-featured of the two. See `iptables(8)` for more information.

Logging options
---------------

### log-level

    option log-level { 0-7 | "debug" | "info" | "notice" | "warning" | "error" | "crit" | "alert" | "panic" }

If specified `log-level` globally sets the log level for all `log` clauses.

### log-prefix

    option log-prefix "<prefix>"

If specified, rules with `log` specified will have log output prefixed with `<prefix>`.

### log-tcp-sequence

    option log-tcp-sequence { on | off }

Defaults to `off`.

When `log-tcp-sequence` is set to `on`, rules with `log` specified will also include TCP sequence numbers in the log output.

### log-tcp-options

    option log-tcp-options { on | off }

Defaults to `off`.

When `log-tcp-options` is set to `on`, rules with `log` specified will also include TCP options in the the log output.

### log-uid

    option log-uid { on | off }

Defaults to `off`.

When `log-uid` is set to `on`, rules with log specified will also include the UID of the user who generated the packet (if possible).
