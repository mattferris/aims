aims
====

aims is a Linux firewalling language inspired by OpenBSD's pf syntax, but flavoured with terms that are familiar to users of iptables. It attempts to provide a more robust method of creating and managing rulesets. Bottom line: you'll write less and do more when using aims over iptables.

Rule expansion
--------------

aims does the tedious work for you. Have a list of non-contigous IPs that you want to block? In iptables, you'd have to write:

```
iptables -A INPUT -s 192.168.3.47 -j REJECT
iptables -A INPUT -s 172.16.50.25 -j REJECT
iptables -A INPUT -s 10.98.74.231 -j REJECT
```

But in aims, you could simply write:

```
reject for input from { 192.168.3.47, 172.16.50.25, 10.98.74.231 }
```

Better yet, need to whitelist SSH traffic to your server?

### iptables

```
iptables -A INPUT -s 192.168.3.47 -p tcp --dport 22 -j ACCEPT
iptables -A OUTPUT -d 192.168.3.47 -p tcp --sport 22 -j ACCEPT
```

### aims

```
accept for input proto tcp from 192.168.3.47 to port 22 reverse
```

`reverse` tells aims to create a rule matching traffic in the opposite direction.

Macros
------

Commonly used values can be stored in macros. For example, you could create a list of management IPs and reference them in multiple rules.

```
mgmt_iface = "vlan20"
mgmt_addrs = { 192.168.3.47, 172.16.50.25, 10.98.74.231 }

# allow management to access ssh and https
accept in $mgmt_iface proto tcp from $mgmt_addrs to port { 22, 443 } reverse

# allow management to use snmp
accept in $mgmt_iface proto udp from $mgmt_addrs to port 161
accept in $mgmt_iface proto udp from port 162 to $mgmt_addrs
```

Sets
----

Sets (utlizes `ipset`), can be used for dynamic matching.

```
# define the blacklist, pre-loading addresses from a file
set <blacklist> add file "blacklist.txt"

# drop packets from hosts in the blacklist
drop in eth0 from <blacklist>

# blacklist hosts that attempt to connect to SSH
match in eth0 proto tcp to port 22 add-to <blacklist> ( flags "src" )
```

The sets can also be managed using `ipset` while the ruleset is loaded.

See also
--------

Complete documentation is available in the `docs/` directory.
