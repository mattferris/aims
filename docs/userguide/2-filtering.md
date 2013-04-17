re the heart of any firewall. The vast majority of rules in any ruleset will be filtering rules.

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
