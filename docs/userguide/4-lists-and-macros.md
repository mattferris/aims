Lists and Macros
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
