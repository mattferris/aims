Network Address Translation (NAT)
=================================

NAT rules modify packet information and can be used in filtering rules and can be defined using the non-filtering action `match`. `match` rules don't allow or deny packets and thus, provide a way of performing actions on packets without filtering them.

Redirects/Port forwarding (DNAT)
--------------------------------

Redirects change the destination address and/or port number of matched packets and are specified with `rdr-to`. As with `from` and `to`, `port` can be used to specify a port number if `proto` has also been specified.

`rdr-to` is only valid for *prerouting* and *output* chains. If no chain is specified using `for`, *prerouting* is assumed. If a rule specifies a chain (using `for`) other than *prerouting* or *output* an error will be issued and aims will exit.

    # redirect incoming packets to port 2222 to local port 22
    match in eth0 proto tcp to port 2222 rdr-to port 22

    # redirect connections to local port 80 to dmz web server at 10.39.2.11
    match in eth0 proto tcp to port 80 rdr-to 10.39.2.11 reverse

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
