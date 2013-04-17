Examples
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
