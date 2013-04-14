#!/usr/bin/perl
#
# This module is part of aims, an iptables scripting language.
# http://bueller.ca/software/aims
#
# Copyright (c) 2013 Matt Ferris
# Released under the BSD 2-clause license
# http://bueller.ca/software/aims/license
#
package Aims::NetAddr;

use strict;
use warnings;

use Exporter qw(import);
our @EXPORT_OK = qw(ip2net ip2bcast ip2int int2ip nethasip);


##
# ip2network
#
# Return the network address of a given ip/mask
#
# $addr The ip/mask to examine
#
sub ip2net
{
    my $addr = shift;
    my ($ip, $mask) = split(/\//, $addr);
    if ($mask eq '') {
        $mask = '255.255.255.255';
    }
    elsif ($mask =~ /^[0-9]+$/) {
        $mask = 2**32 - (2**(32-$mask));
    }
    else {
        $mask = ip2int($mask);
    }
    return int2ip(ip2int($ip) & $mask);
}


##
# ip2bcast
#
# Return the broadcast address of agiven ip/mask
#
# $addr The ip/mask to examine
#
sub ip2bcast
{
    my $addr = shift;
    my ($ip, $mask) = split(/\//, $addr);
    if ($mask eq '') {
        $mask = '255.255.255.255';
    }
    elsif ($mask =~ /^[0-9]+$/) {
        $mask = 2**32 - (2**(32-$mask));
    }
    else {
        $mask = ip2int($mask);
    }
    return int2ip((ip2int($ip) & $mask) + (~$mask));
}


##
# ip2int
#
# Convert an dotted-quad ip to an int
#
# $ip The ip to convert
#
sub ip2int
{
    my $ip = shift;
    return unpack('N', pack('C4', split(/\./, $ip)));
}


##
# int2ip
#
# Convert an int ip to dotted-quad
#
# $ip The binary ip to convert
#
sub int2ip
{
    my $ip = shift;
    return join('.', unpack('C4', pack('N', $ip)));
}


##
# nethasip
#
# Check that an ip exists in a subnet
#
# $net The subnet
# $ip The ip
#
# Returns 1 if ip is in net, otherwise returns 0
#
sub nethasip
{
    my $net = shift;
    my $ip = shift;

    my ($netip, $mask) = split(/\//, $net);

    if (ip2net("$ip/$mask") eq $netip) {
        return 1;
    }
    else {
        return 0;
    }
}


1;
