% aims(8) Advanced IPTables Management Script Interpreter
% Matt Ferris <matt@bueller.ca>
% September 11, 2013

# NAME

aims - Advanced IPTables Management Script Interpreter

# SYNOPSIS

aims check *file*  
aims help  
aims load *file*  
aims safe-load *file*  
aims show *file*  
aims unload

# DESCRIPTION

aims is a scripting language designed to facilitate the creation of firewall rulesets for iptables. As iptables is a tool for configuring the underlying netfilter framework, aims is a tool for creating a series of iptables commands that reflect the intent of the provided ruleset.

# OPTIONS

## check

Check the syntax of the rules in *file*.

## help

Print usage information.

## load

Parse and load the rules in *file* into iptables. Any errors encountered will produce a message and any rules that have been added to iptables will be flushed.

## safe-load

Load the rules in *file* but unload the rules after 5 seconds unless SIGINT (ctrl-c) is received. This makes it safe to load rules remotely as loading rules that drop your connection will be flushed automatically, restoring connectivity.

## unload

Flushes the loaded rules from iptables.

# SEE ALSO

aims.rules(5)

http://www.bueller.ca/software/aims
