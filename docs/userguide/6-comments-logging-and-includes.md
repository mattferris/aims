Comments, Logging and Includes
=============================

Comments
--------

In this context, *comments* refers to comments added to the compiled rules. These comments are visible when running `iptables -L` and allow you to understand where compiled rules have come from.

There are two different types of comments that can be added to compiled rules, *origin* comments and *inline* comments. *Origin* comments add a comment to every compiled rule identifying the filename and line number of the original aims rule that generated it. *inline* comments use ruleset comments (those lines starting with `#`) as the comments for compiled rules.

When *inline* and *origin* comments are enabled, *inline* comments take precedence over *origin* comments. Rules that don't have *inline* comments to apply will have *origin* comments applied instead.

### Origin comments

The option `origin-comments` controls whether origin comments are added to compiled rules or not. The default value of this option is `on`, which enables origin comments. Setting this option to `off` disables origin comments.

### Inline comments

The option `inline-comments` controls whether inline comments are added to compiled rules or not. The default value of this option is `off`. Setting this option `of` enables inline comments.

When inline comments are enabled, aims tracks the last comment line it has seen and uses the content as a comment for each rule that follows the comment line. If a blank line is encountered, aims discards the comment. For rules that generate multiple compiled rules, each compiled rule will have the comment applied to it.

    # this comment will be added to the following rule
    accept in eth0 proto tcp to port 80

    # this comment will be discarded because no rules immediately follow it

    # this comment will be added to all the following rules
    accept in eth0 proto tcp to port { 80, 443 } reverse
    accept out eth0 proto udp to port 53 reverse
    match out eth0 nat-to 10.39.20.143

Logging
-------

Packets that match a given rule can be logged using `log`. Logged packets are sent to syslog with an optional log level and prefix.
`log` can be specified in both action rules and match rules. Using match rules allows packets to be logged in a non-terminating way, which is to say the packet can be logged but will continue to traverse the ruleset.

    # log all incoming HTTP requests
    accept in eth0 log proto tcp to port 80

    # log ssh attempts, but don't stop rule processing
    match in eth0 log proto tcp to port 22

There are a number of options that affect how and what will be logged. These are `log-level`, `log-prefix`, `log-tcp-sequence`, `log-tcp-options`, and `log-uid` (ee [Runtime Options](/software/aims/docs/2.0/runtime-options) for a full overview of these options). While these options can be set globally via `option`, they can also be set locally for each rule by enclosing them in parethesis.

    # prefix log entries with "foobar" and include tcp sequence numbers
    match in eth0 log ( log-prefix "foobar", log-tcp-sequence on ) proto tcp to port 25 reverse

The use of `reverse` in the above rule means we will also log packets flowing in the opposite direction.

Includes
--------

Includes allow you to include rules from other files into the current file using `include`. aims creates a new scope for the included rules, copying variables from the current scope. Modifications made to the included scope doesn't affect the current scope. For example, if the file `aims.rules` contains

    foo = 192.168.0.1
    include "more.rules"
    accept in eth0 from $foo

and `more.rules` contains

    accept in eth0 from $foo
    foo = 192.168.4.60
    accept in eth0 from $foo

then `$foo` in the `accept` rule in `aims.rules` resolves to `192.168.0.1`. `$foo` in the first `accept` rule in `more.rules` will resolve to `192.168.0.1`, while `$foo` in the second `accept` rule resolves to the new value `192.168.4.60`.

File paths are relative to the including file. File paths starting with `/` are treated as absolute paths.
