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

### ipv6

    option ipv6 { on | off }

Defaults to `on`.

When `ipv6` is set to `on`, an `ip6tables` command will be generated for every rule that doesn't reference an IPv4 address or an `inet` family set. When set to `off`, `ip6tables` commands will still be generated for rules explicitly referring to IPv6 addresses or `inet6` family sets.

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

Set options
-----------

### set-counters

    option set-counters { on | off }

Defaults to `off`.

When `set-counters` is set to `on`, set's created by aims will have counters enabled by default. This can be overridden on a per-set basis via the `counters` option (i.e. `set <name> ( counters on )`.

### set-family

    option set-family { "inet" | "inet6" }

Defaults to `inet`.

Determines the default address family of sets: `inet` for IPv4, and `inet6` for IPv6. This can be overridden on a per-set basis via the `family` option (i.e. `set <name> ( family "inet" )`.

### set-timeout

    option set-timeout "<seconds>"

If specified, determines the default timeout (in seconds) of sets. This can be overridden on a per-set basis via the `timeout` option (i.e. `set <name> ( timeout "3600" )`.

### set-flags

    option set-flags "<flags>"

If specified, determines the default flags of set entries. This can be overridden on a per-rule basis via the `flags` option (i.e. `set <name> ( flags "src" )`). Multiple flags can be specified, separating flags with a comma (i.e. `dst,src`). Possible flags are: `dst` and `src`.

### set-exist

    option set-exist { on | off }

Defaults to `on`.

When `set-exist` is set to `on`, no errors will be generated when adding duplicate sets, or reset timers on duplicate entries to sets. This can be overridden on a per-rule basis via the `exist` option (i.e. `match for input to port 22 add-to <name> ( exist off )`)
