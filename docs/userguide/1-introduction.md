Introduction
============

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
