% aims.rules(5) aims rule syntax
% Matt Ferris <matt@bueller.ca>
% May 14, 2014

# NAME

aims.rules - aims rules file

# DESCRIPTION

aims is a scripting language designed to facilitate the creation of firewall rulesets for iptables. As iptables is a tool for configuring the underlying netfilter framework, aims is a tool for creating a series of iptables commands that reflect the intent of the provided ruleset.

Rulesets are plain-text files with a series of rules. Rules define packet filtering criteria, packet mangling criteria, specify runtime options, and define macros. Each rule exists on it's own line. Rules can span multiple lines if the line ends with `\`. Comments are lines starting with `#`.

    # this line is a comment

    # the following rule spans multiple lines
    accept in eth0 proto tcp \
        from { 192.168.0.1, 192.168.0.5 } \
        to port 22 reverse

aims provides many benefits over traditional iptables-based rulesets including strict rule checking, rule expansion, and simplied rule syntax. Building a ruleset using aims is not only simpler and safer for novice users, it's expressive syntax and powerful macro and expansion features allow vetran users to create smaller rulesets which are easier to manage.

Philosophy
----------

aims isn't intended to be a simpler way of writing iptables rules. In fact, it will most likely not re-implement every feature currently available in iptables. Features that fit into "*the aims way*" of doing things will be included.

### Consistency

iptables includes a lot of features. Many of these features are provide by modules with overlapping functionality and are configured in unique ways. Where possible, aims provides a consistent method of configuring such features. aims takes advantage of iptables features when doing so integrates nicely into aims existing featureset.

### Simplicity

aims syntax strives to be as simple as possible. This simplicity is built upon the aforementioned consistency in addition to a plain-language vocabulary. Terms are chosen which reflect the intent of the action they represent. Novice users should be able to use a subset of features to easily create functional and secure rulesets without feeling overwhelmed by firewall or network terminology. It should be equally easily for vetran users to create more complex rulesets that are manageable.

### Security

When things work the same (consistency) and are easy to use (simplicity) it's much easier to create more secure rulesets and make fewer mistakes while doing so. Yet, mistakes are bound to happen. When they do, aims tries to protect you from them where possible. During parsing, rulesets undergo a lot of analysis to determine if each rule is logically and syntactically correct. If configured to do so, aims can fix some problems, otherwise aims will tell you what needs to be fixed.

Rule checking
-------------

Many iptables option are mutually exclusive, or are dependent on other options. While vetrans will be aware of these cases, novices most likely will not. When loading a ruleset, aims will check the validity of each rule before executing any iptables commands. Invalid rules will produce an error, or where possible, aims will provide a valid substitution and produce a warning.

For example, iptables requires that a protocol be defined before a destination or source port can be used. If a filtering rule defines a port without a protocol, aims will assume any protocol `-p any` and resume compilation but issue a warning letting the user know what has occured. It is possible to disable substitutions by using *strict mode*.

Rule expansion
--------------

When filtering connections, there are usually multiple rules required to encompass packets in both directions. aims provides numerous shortcuts to generating these rules. For example, allowing SSH connections to a server with a drop policy in iptables requires two rules, aims requires only one using the `reverse` clause. `reverse` tells aims to create a rule for packets travelling in the opposition direction.

Dealing with lists of IP addresses or ports in iptables is cumbersome. aims allows you to create a list of ports, interfaces, and IP addresses in one rule, and then creates a new rule for each combination of list items. In this way, aims can save you from writing potentionally large numbers of iptables rules.

Additionally, dealing with NAT rules is drastically simplified as any filtering rule can incorporate NAT criteria.

Rule syntax
-----------

As a command-line tool, iptables is limited to a syntax that is easy for a shell to understand. aims syntax is designed to be easily understood by people, and reads almost like a sentence. Here's an example of an iptables rule that allows SSH, and the equivalent rule written in aims.

    iptables -A INPUT -i eth0 -p tcp --dport 22 -j ACCEPT
    accept in eth0 to port 22

# FILTERING

Filtering rules are the heart of any firewall. The vast majority of rules in any ruleset will be filtering rules.

Rule syntax
-----------

Filtering rules use the following syntax:

*`action`* `{` `for` *`chain`* `|` `{` `in` `|` `out` `}` *`interface`* `}` `[` `log` `]` `[` *`match criteria`* `]` `[` `reverse` `]`

While it is possible to define some clauses in any number of alternative orders, using the above convention means your ruleset will be readable to others as well.

Policies
--------

*Policies* defined the default *action* for every packet that doesn't match a rule in a given chain. It is good practice to deny all packets by default and then allow the packets you want. The available policies are `accept`, `drop`, and `reject`. These policies refer to the filter *actions* outlined below.

    # deny all packets by default
    policy drop for input
    policy drop for output
    policy drop for forward

Actions
-------

*Actions* define what happens to packets matching the rule. The three filtering actions are `accept`, `drop`, and `reject`. `accept` allows the packet through the firewall. `drop` silently discards the packet. `reject` discards the packet but sends and message back to the sender. Every filtering rule must specify an action first.

### reject-with

By default, when rejecting packets, the sender receives a *port unavailable* (`icmp-port-unavailable`) message. You can specify an alternative message using `reject-with`. Alternative messages are: `icmp-net-unreachable`, `icmp-host-unreachable`, `icmp-proto-unreachable`, `icmp-net-prohibited`, `icmp-host-prohibited`, `icmp-admin-prohibited`, and `tcp-reset` (for TCP packets only).

    reject in eth0 reject-with icmp-host-unreachable

Chains
------

There are five built-in chains that iptables uses: *prerouting*, *input*, *forward*, *output*, and *postrouting*. Different chains are valid in different contexts. Filtering rules are only valid for *input*, *output*, and *forward* chains. aims will display an error if *prerouting* or *postrouting* are defined in filtering rules. Every filtering rule must specify a chain.

Chains are defined explicity using `for` or implicitly using `in` or `out`. If a chain is specified using `for`, then `in` and `out` don't affect the chain. If `for` isn't specified then `in` implies the *input* chain and `out` implies the *output* chian. If both `in` and `out` are specified in the same rule, then the *forward* chain is implied.

    # allow all packets in the forward chain
    accept for forward

    # deny all packets in the input chain
    drop for input

You can create custom in addition to the built-in chains using `chain`. You can direct matched packets to custom chains using `send-
to`.

    # define a custom chain
    chain foo_chain

    # add a rule to the custom chain
    accept for foo_chain from $good_ips reverse

    # drop all unmatched traffic in the custom chain
    drop for foo_chain

    # send packets to the custom chain
    match in eth0 proto tcp to port 22 send-to foo_chain reverse

Interfaces
----------

On firewalls with more than one interface, specify interfaces in rules is generally a good idea. Interfaces are specified using `in` and `out`. `in` matches ingress traffic and `out` matches egress traffic. Forward rules may specify both `in` and `out` to isolate traffic traversing the firewall between two specific interfaces. aims creates a list of interfaces before parsing a ruleset and attempts to verify that each interface specified exists. If an interface doesn't appear to exist, aims issues a warning.

    # allow all packets coming in through eth0 (assumes the input chain)
    accept in eth0

    # allow all packets in the forward chain leaving through eth1
    accept for forward out eth1

    # allow packets coming in through eth0 and leaving out through eth1 (assumes the forward chain)
    accept in eth0 out eth1

Protocols
---------

Filter rules can specify a protocol to match using `proto`. aims will issue an error if it doesn't recognize the protocol specified. By default, aims allows `icmp`, `tcp, `udp`, and `all`. aims also allows protocols defined in `/etc/protocols`.

    # deny ping packets
    drop in eth0 proto icmp

IP addresses and port numbers
-----------------------------

Filtering rules will commonly need to match the source and/or destination IP address of packets. This is accomplished using `from` to match source addresses and `to` to match destination addresses.

    # deny packets from 192.168.0.2
    drop in eth0 from 192.168.0.2

    # allow connections to 10.34.2.10 in the forward chain
    accept for forward to 10.34.2.10
    accept for forward from 10.34.2.10

Packets can further be isolated by specifying a source or destination port as well using `port`. When specifying a port, a protocol must also be specified. If *strict mode* isn't enabled, rules defining a `port` without `proto` will have `proto all` added and aims will issue a warning. If *strict mode* is enabled, aims issues an error and exits.

    # allow ssh connections
    accept in eth0 proto tcp to port 22
    accept out eth0 proto tcp from port 22

    # allow the machine to query a time server using ntp (port 123)
    accept out eth0 proto udp to 172.16.74.21 port 123
    accept in eth0 proto udp from 172.16.74.21 port 123

Interface names can be used to specify addresses associated with the interface. Using interfaces instead of IP addresses makes rulesets more dynamic and portable, as the interface information is read when the ruleset is loaded. By specifying the name of the interface, aims uses the IP address assigned to the interface. For example, a rule specifying traffic to local IP address 10.90.4.2 could be written as

    accept for input proto tcp to eth1 port 22

which is equivalent to

    accept for input proto tcp to 10.90.4.2 port 22

### Interfaces as source and destination addresses

Additionally, it's possible to use the network and broadcast addresses of the interface by using the `:network` and `:broadcast` modifiers.

    accept for forward proto tcp from eth1:network to port 80
    drop in eth1 from eth1:broadcast

which are equivalent to

    accept for forward proto tcp from 10.90.4.0/24 to port 80
    drop in eth1 from 10.90.4.255

Simplified connection filtering
-------------------------------

When using default deny policies, filtering connections takes a little more consideration. Rules have to be created for packets travelling in both directions, from client to server and from server back to client. For example, an SMTP connection would required the following two rules:

    # client to server
    accept in eth0 proto tcp to port 22

    # server to client
    accept out eth0 proto tcp from port 22

To simplify things a little, and to reduce the number of rules you need to write, aims can create the *reverse* rule for you automatically using `reverse`.

    # allow smtp connections
    accept in eth0 proto tcp to port 22 reverse

The second rule can be ommitted as aims will create it for you.

Stateful filtering
------------------

Whereas packet filtering matches the properties of individual packets, stateful filtering matches the properties of individual connections. Existing connections are allowed implicity while new connections are scrutinized more closely. The advantage of stateful filtering is that it takes less time for a packet to traverse the ruleset, but the ruleset consumes more memory as the kernel needs to track the state of every connection. Connection states can be matched using `state`, where states are `invalid`, `new`, `established`, `related`, `untracked`, `snat`, or `dnat`.

From iptables(8)

    Possible states are INVALID meaning that the packet could not be identified for
    some  reason  which  includes running out of memory and ICMP errors which don't
    correspond  to  any  known  connection,  ESTABLISHED meaning that the packet is
    associated  with  a  connection  which has seen packets in both directions, NEW
    meaning  that  the packet has started a new connection, or otherwise associated
    with  a  connection  which has not seen packets in both directions, and RELATED
    meaning that the packet is starting a new connection, but is associated with an
    existing connection, such as an FTP data transfer, or an ICMP error.  UNTRACKED
    meaning that the packet is not tracked at all.

A typical stateful ruleset would look like:

    # deny all traffic by default
    policy drop for input
    policy drop for output

    # allow existing connections
    accept for input state established
    accept for input state related

    # allow inbound ssh connections
    accept in eth0 proto tcp to port 22 state new

    # allow outbound ntp connections
    accept out eth0 proto tcp to port 123 state new

NETWORK ADDRESS TRANSLATION (NAT)
=================================

NAT rules modify packet information and can be used in filtering rules and can be defined using the non-filtering action `match`. `match` rules don't allow or deny packets and thus, provide a way of performing actions on packets without filtering them.

Redirects/Port forwarding (DNAT)
--------------------------------

Redirects change the destination address and/or port number of matched packets and are specified with `rdr-to`. As with `from` and `to`, `port` can be used to specify a port number if `proto` has also been specified.

rdr-to` is only valid for *prerouting* and *output* chains. If no chain is specified using `for`, *prerouting* is assumed. If a rule specifies a chain (using `for`) other than *prerouting* or *output* an error will be issued and aims will exit.

    # redirect incoming packets to port 2222 to local port 22
    match in eth0 proto tcp to port 2222 rdr-to port 22

    # redirect connections to local port 80 to dmz web server at 10.39.2.11
    match in eth0 proto tcp to port 80 rdr-to 10.39.2.11

On systems running a kernel version of 2.6.22 or later, the port value *random* can be specified without an IP address, which randomizes the port mapping used by `rdr-to`.

    # use randomized port forwarding
    match out eth0 rdr-to port random

On systems running a kernel version of 2.6.29-rc2 or later, then port value *persistent* can be specified without an IP address, whi
ch gives a client the same source/destination address for each connection.

    # use persistent mapping for redirects
    match out eth0 rdr-to port persistent

Traditional NAT (SNAT/Masquerade)
---------------------------------

NAT is traditionally used to modify the source address and/or port number of matched packets and is typically used on a network gateway to share one or more public IP addresses with one or more privately addressed devices. This type of NAt is sometimes referred to as *IP masquerading*. NAT rules are setup using `nat-to` in the same fashion as `rdr-to`.

`nat-to` is only valid for the *postrouting* chain. If no chain is specified using `for`, *postrouting* is assumed. If a rule specifies a chain (using `for`) other than *postrouting* an error will be issued and aims will exit.

    # NAT LAN clients to the public IP of the gateway
    match out eth0 nat-to 175.16.74.29

    # NAT lan clients and allow traffic in forward chain
    match in eth1 out eth0 nat-to 175.16.74.29

On systems running a kernel version of 2.6.21 or later, the port value *random* can be specified without an IP address, which randomizes the port mapping used by `nat-to`.

    # use randomized port mapping for NAT
    match out eth0 nat-to port random

On systems running a kernel version of 2.6.29-rc2 or later, then port value *persistent* can be specified without an IP address, which gives a client the same source/destination address for each connection.

    # use persistent mapping for NAT
    match out eth0 nat-to port persistent

LISTS AND MACROS
================

Utilizing lists and macros in your rulesets can help to reduce the amount of rules you need to maintain and make the remaining maintenance as easy as possible.

Lists
-----

Multiple values can be defined as a list within a rule. When aims parses the rule, it expands the list and produces a new rule for each item in the list. Lists are enclosed in braces (`{` and `}`) and items are separated by commas. Whitespace is optional in lists, but recommended to improve readability.

For example, you could specify multiple IP addresses in a list.

    accept in eth0 proto tcp from { 192.168.0.15, 192.168.0.23 } to port 22

aims turns this into

    accept in eth0 proto tcp from 192.168.0.15 to port 22
    accept in eth0 proto tcp from 192.168.0.23 to port 22

Chains, interfaces, protocols, IP addresses, and port numbers can all be specified as a list of items. You can even include multiple lists in one rule.

    accept in eth0 proto tcp from { 192.168.0.15, 192.168.0.23 } to port { 22, 25, 80, 443 }

aims turns this into

    accept in eth0 proto tcp from 192.168.0.15 to port 22
    accept in eth0 proto tcp from 192.168.0.15 to port 25
    accept in eth0 proto tcp from 192.168.0.15 to port 80
    accept in eth0 proto tcp from 192.168.0.15 to port 443
    accept in eth0 proto tcp from 192.168.0.23 to port 22
    accept in eth0 proto tcp from 192.168.0.23 to port 25
    accept in eth0 proto tcp from 192.168.0.23 to port 80
    accept in eth0 proto tcp from 192.168.0.23 to port 443

It is easy to see how utilizing lists can save a lot of typing. A common use of lists for setting policies. Instead of setting a policy for each chain, set the policy for a list of chains.

    # setting policies without a list
    policy drop for input
    policy drop for forward
    policy drop for output

    # setting policies with a list
    policy drop for { input, forward, output }

It's possible for a list to contain another list, which is useful when using macros (see below).

Lists can be populated from files using `file`. The file path is relative to the current file, unless the file path starts with `/`. Each line in the file is an item in the list. Lines starting with `#` are comments and are ignored, as are blank lines. Populating lists from files is valid only when defining macros (see below).

If `ips.txt` contains

    # joe's computer
    192.168.0.34

    # jane's computer
    192.168.0.47

and the ruleset contains

    hosts = file "ips.txt"
    accept in eth0 proto tcp from $hosts to port 22

this is equivalent to writing

    accept in eth0 proto tcp from { 192.168.0.34, 192.168.0.47 } to port 22

Macros
------

Macros allow values to be defined once and referenced many times in a ruleset. Macros are defined using equals `=`, with the macro name on the left and the value on the right. Whitespace is optional. Quoting values ensures aims won't attempt to interpret the value, which may have unexpected results. Once defined, macros are referenced by preceeding the macro name with a circumflex (dollar sign) `$`. aims replaces the macro name with the stored value and processes the rule.

    ext_if = "eth0"
    accept in $ext_if

In addition to storing simple values, macros can also store rule clauses.

    dns_match = "proto udp to port 53"
    accept in eth0 $dns_match
    accept in eth1 $dns_match

aims expands the macro `$dns_match` resulting in

    accept in eth0 proto udp to port 53
    accept in eth1 proto udp to port 53

Macros can also store lists.

    ext_if = "eth0"
    allowed_hosts = { 192.168.0.15, 192.168.0.23 }
    allowed_ports =  { 22, 25, 80, 443 }
    accept in $ext_if proto tcp from $allowed_hosts to port $allowed_ports

Lists can be created using macros. If a macro in a list is a list itself, the values will simply be added to the existing list.

    first_list = { 192.168.0.3, 192.168.0.98 }
    second_list = { 192.168.0.246, $first_list }

`$second_list` now contains 192.168.0.246, 192.168.0.3, and 192.168.0.98.

Macros are the best tool to use to create highly manageable rulesets. By storing commonly used values in macros, it's possible to change one, ten, or even a hundred rules by changing one value. When combined with lists, macros provide maximum flexibility and a potentially huge reduction in the number of rules you'll need to write.

RUNTIME OPTIONS
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

COMMENTS, LOGGING AND INCLUDES
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

EXAMPLES
========

Below are some examples of common firewall scenarios. These examples not only demonstrate how to use aims, they demonstrate some of the advantages that aims provides (more concise, easier to understand, etc...). Each example also details the number of aims rules and the number of iptables rules produced after compilation. These numbers demonstrate how many fewer aims rules are required to produce the same rulset.

Simple gateway
--------------

This is a typical setup for a simple gateway firewall. LAN clients are NAT'd, remote access is allowed via SSH and port forwarding is used to forward port 3389 on the gateway to a client running Remote Desktop Protocol on the LAN.

    option strict on
    option inline-comments on

    pub_if   = "eth0"
    lan_if   = "eth1"
    rdp_host = "192.168.0.22"

    # use a drop policy
    policy drop for { input, output, forward }

    # nat lan traffic destined for the internet
    match out $pub_if nat-to $pub_if

    # allow ssh access to the gateway
    accept in { $pub_if, $lan_if } proto tcp to port 22 reverse

    # allow outbound ntp and dns requests on the gateway
    accept out $pub_if proto udp to port { 53, 123 } reverse

    # allow lan traffic to be forwarded through the gateway
    accept in $lan_if out $pub_if from $lan_if:network reverse

    # forward rdp traffic to client on the lan
    accept in $pub_if proto tcp to port 3389 rdr-to $rdp_host

6 rules (20 rules after compilation)

DMZ firewall
------------

In this example, we have a DMZ with a number of servers hosting various services (HTTP/HTTPS, SMTP, IMAP). Access to the DMZ is filtered through a public-facing gateway. The DMZ is privately addressed.

    option strict on
    option inline-comments on

    pub_if = "eth0"
    dmz_if = "eth1"

    mgmt_ips = { 188.13.165.2, 188.13.167.49, 188.13.168.23 }

    web_server  = "10.0.5.50"
    smtp_server = "10.0.5.51"
    imap_server = "10.0.5.52"
    all_servers = { $web_server, $smtp_server, $imap_server }

    # use a drop policy
    policy drop for { input, output, forward }

    # nat dmz traffic
    match out $pub_if from $all_servers nat-to $pub_if

    #
    # ssh management
    #
    # in order to allow ssh access to dmz servers, we need to setup an rdr-to rule and
    # then a forward rule (using in and out interfaces) for traffic in both directions
    #

    # allow ssh access from management ips to web server
    accept in $pub_if proto tcp from $mgmt_ips to port 2250 rdr-to $web_server port 22
    accept in $pub_if out $dmz_if proto tcp from $mgmt_ips to $web_server port 22 reverse

    # allow ssh access from management ips to smtp server
    accept in $pub_if proto tcp from $mgmt_ips to port 2251 rdr-to $smtp_server port 22
    accept in $pub_if out $dmz_if proto tcp from $mgmt_ips to $smtp_server port 22 reverse

    # allow ssh access from management ips to imap server
    accept in $pub_if proto tcp from $mgmt_ips to port 2252 rdr-to $imap_server port 22
    accept in $pub_if out $dmz_if proto tcp from $mgmt_ips to $smtp_server port 22 reverse

    #
    # service forwarding
    #
    # similar to ssh access, we need to use rdr-to to forward the port and then a
    # forward rule to handle the forwarded traffic
    #

    # allow incoming http/https to web server
    accept in $pub_if proto tcp to port { 80, 443 } rdr-to $web_server
    accept in $pub_if out $dmz_if to $web_server port { 80, 443 } reverse

    # allow smtp to smtp server
    accept in $pub_if proto tcp to port 25 rdr-to $smtp_server
    accept in $pub_if out $dmz_if to $smtp_server port 25 reverse

    # allow imap to imap server (imap on 143 and imaps on 993)
    accept in $pub_if proto tcp to port { 143, 993 } rdr-to $imap_server
    accept in $pub_if out $dmz_if to $imap_server port { 143, 993 } reverse

    #
    # remote service access
    #
    # dmz servers need to access remote services such as dns, ntp, smtp, http/https
    #

    # allow outbound dns, ntp traffic
    accept in $dmz_if out $pub_if proto udp from $all_servers to port { 53, 123 } reverse

    # allow outbound http/https traffic
    accept in $dmz_if out $pub_if proto tcp from $web_server to port { 80, 443 } reverse

    # allow outbound smtp traffic
    accept in $dmz_if out $pub_if proto tcp from $smtp_server to port 25 reverse

17 rules (63 rules after compilation)

# SEE ALSO

`aims` (8)

http://www.bueller.ca/software/aims
