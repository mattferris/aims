#!/usr/bin/perl
#
# This module is part of aims, an iptables scripting language.
#
#
package Aims::Main;

use strict;
use warnings;

use File::Spec;

use Aims::NetAddr qw (ip2net ip2bcast);
use Aims::Grammar qw($grammar);
use Aims::Error qw(error warn debug);

use Mexpar::Lexer qw(lex prepare);
use Mexpar::Parser qw(parse ontoken);
use Mexpar::Error qw(delegate mkerrmsg);

use Exporter qw(import);
our @EXPORT_OK = qw(
    compile getcompiled
    newscope endscope getscope
    getlines copyline addline
    getrule newrule skiprule ruleskipped getruleset
    getoption setoption
    getvar setvar
    getcomment setcomment
    ifexists protoexists getifaddr getifnet getifbcast getifmask if2host iproute
    bracelist parenlist
    tokenpos protocheck
);


prepare($grammar);


#
# Define a delegate error handler
#
delegate(sub {
    my $msg = mkerrmsg(@_);
    my $scope = getscope();
    my $file = $scope->{'file'};
    error("$file: $msg");
});


my $protocols = loadprotos();
my $interfaces = loadifs();
my $routes = loadroutes();
my $compiled = [];
my $scopes = [];


# default options
my $defoptions = {
    'inline-comments' => 'off',
    'origin-comments' => 'off',
    'debug' => 'off',
    'log-level' => '',
    'log-prefix' => '',
    'log-tcp-sequence' => 'off',
    'log-tcp-options' => 'off',
    'log-uid' => 'off',
    'strict' => 'off',
};


##
# dovars
# 
# Process variables for the $line
#
# $line The line to process
#
sub dovars
{
    my $line = shift;
    my $scope = getscope();
    my $variables = $scope->{'variables'};

    # replace any variables on the line
    my $i=0;
    foreach my $t (@$line) {
        if ($t->{'type'} eq 'T_VARIABLE') {
            my $varname = substr($t->{'value'}, 1);

            if (!defined($variables->{$varname})) {
                error({
                    code => 'E_UNDEFINED_VARIABLE',
                    file => $t->{'file'},
                    line => $t->{'line'},
                    char => $t->{'char'},
                    name => $t->{'value'}
                });
            }

            my $varval = $variables->{$varname};
            foreach my $vt (@$varval) {
                $vt->{'file'} = $scope->{'file'};
                $vt->{'line'} = $t->{'line'};
                $vt->{'char'} = $t->{'char'};
            }
            splice(@$line, $i, 1, @$varval);

            # if the next token is a string and they are adjacent,
            # combine them into one string and re-lex them
            my $nextt = $line->[$i+1];
            my $adjacent = $t->{'char'}+length($t->{'value'}) == $nextt->{'char'};
            if (defined($nextt) && $nextt->{'type'} eq 'T_STRING' && $adjacent) {
                # make a string from the var tokens
                my $vals = [];
                foreach my $v (@$varval) {
                    push(@$vals, $v->{'value'});
                }

                # lex the string and replace the current and next tokens
                # with the result
                my $str = join(' ', @$vals).$nextt->{'value'};
                my $tokens = lex($grammar, [ $str ]);
                pop(@$tokens); # pop the EOF token
                splice(@$line, $i, 2, @$tokens);
            }
        }
        $i++;
    }

    # process any variable declarations
    my $hastokens = @$line > 1;
    my $vardef = $hastokens && $line->[0]->{'type'} eq 'T_STRING' && $line->[1]->{'type'} eq 'T_EQUALS';
    if ($vardef) {
        my $varname = $line->[0]->{'value'};
        my $varval = [];
        if ($line->[2]->{'type'} eq 'T_QUOTED_STRING') {
             my $t = $line->[2];
             $t->{'type'} = 'T_STRING';
             push(@$varval, $t);
        }
        else {
            for (my $i=2; $i<$#{$line}; $i++) {
                push(@$varval, $line->[$i]);
            }
        }
        $variables->{$varname} = $varval;
    }
}


##
# compile
#
# Compile the rules in $file
#
# $file The filename containing the rules to compile
#
# Return a compiled list of rules
#
sub compile
{
    my $file = shift;
    my $scope = newscope();

    $scope->{'file'} = $file;
    my $lines = $scope->{'lines'};
    my $ruleset = $scope->{'ruleset'};

    if (!(-f $file)) {
        error({code=>'E_FILE_NOT_FOUND', file=>$file});
    }

    open(my $fh, $file) || error('E_FOPEN_FAILED', $file);
    my $tokens = lex($grammar, $fh);
    close($fh);

    # break tokens into lines and process variables
    my $i = 0;
    my $j = 0;
    $lines->[0] = [];
    foreach my $t (@$tokens) {
        $t->{'file'} = $file;
        push(@{$lines->[$i]}, $t);
        $j++;
        if ($t->{'type'} =~ /T_NEWLINE|T_EOF/) {
            $i++;
            $lines->[$i] = [];
        }
    }

    while (my $line = shift(@$lines)) {
        next if @$line == 0; # don't loop over empty lines

        newrule();
        $scope->{'line'} = $line;
        dovars($line);

        # check that rule starts with an action or variable string
        my $hastokens = @$line > 1;
        my $vardef = $hastokens && $line->[0]->{'type'} eq 'T_STRING' && $line->[1]->{'type'} eq 'T_EQUALS';
        my $comment = $hastokens && $line->[0]->{'type'} eq 'T_COMMENT';
        my $action = $hastokens && $line->[0]->{'type'} =~ /^T_ACTION.*/;
        if ($hastokens && !$comment && !$action && !$vardef) {
            error({
                code => 'E_BAD_FIRST_TOKEN',
                file => $line->[0]->{'file'},
                line => $line->[0]->{'line'},
                type => $line->[0]->{'type'},
                value => $line->[0]->{'value'},
            });
        }

        parse($grammar, $line);

        next if ruleskipped();

        my $rule = getrule();
        my $target = $rule->{'target'};
        $target = '-j '.$target if $rule->{'command'} ne '-P';
        my $mexp = join(' ', @{$rule->{'matchexp'}});
        my $cmt = "-m comment --comment '$rule->{'comment'}'";
        my $texp = join(' ', @{$rule->{'targetexp'}});
        my $cmd = "iptables $rule->{'command'} $rule->{'chain'}";
        $cmd .= " -t $rule->{'table'}" if $rule->{'table'} ne '';
        $cmd .= " $mexp" if $mexp ne '';
        $cmd .= " $cmt" if $rule->{'comment'} ne '';
        $cmd .= " $target";
        $cmd .= " $texp" if $texp ne '';
        push(@$compiled, $cmd);
    }

    endscope();
}


##
# getcompiled
#
# Get the compiled output
#
sub getcompiled
{
    return $compiled;
}


##
# newscope
#
# Create a new scope
#
# Returns the newly create scope
#
sub newscope
{
    my $scope = {
        file => '',
        line => [],
        lines => [],
        rule => {},
        ruleset => [],
        comment => '',
        variables => {},
        options => {},
    };

    if (@$scopes == 0) {
        # if this is the first scope, define default options
        $scope->{'options'} = $defoptions;
    }

    push(@$scopes, $scope);

    return $scope;
}


##
# getscope
#
# Returns the current scope
#
sub getscope
{
    return $scopes->[$#{$scopes}];
}


##
# endscope
#
# Close the current scope
#
sub endscope
{
    pop(@$scopes);
}


##
# addline
#
# Add a line to the process next
#
# $line The line to add
#
sub addline
{
    my $line = shift;
    my $lines = getlines();
    unshift(@$lines, $line);
}


##
# skiprule
#
# Set the compile flag of the current rule to 0
#
sub skiprule
{
    my $rule = getrule();
    $rule->{'compile'} = 0;
}


##
# ruleskipped
#
# Determine if the rule's compile flag is set to 0
#
# Returns 1 if compile is 0, and 0 if compile is 1
#
sub ruleskipped
{
    my $rule = getrule();
    return $rule->{'compile'} == 0;
}


##
# getlines
#
# Returns the list of lines from the current scope
#
sub getlines
{
    my $scope = getscope();
    return $scope->{'lines'};
}


##
# getrule
#
# Returns the current rule in the current scope
#
sub getrule
{
    my $scope = getscope();
    return $scope->{'rule'};
}


##
# getruleset
#
# Returns the ruleset for the current scope
#
sub getruleset
{
    my $scope = getscope();
    return $scope->{'ruleset'};
}


##
# getoption
#
# Returns the value for $option for the most local scope
#
# $option The name of the option
#
# Returns the value of $options
#
sub getoption
{
    my $option = shift;
    my $value;

    for (my $i=$#{$scopes}; $i>=0; $i--) {
        if (defined($scopes->[$i]->{'options'}->{$option})) {
            $value = $scopes->[$i]->{'options'}->{$option};
        }
    }

    return $value;
}


##
# setoption
#
# Set the value of $option for the current scope
#
sub setoption
{
    my $option = shift;
    my $value = shift;
    my $scope = getscope();
    $scope->{'options'}->{$option} = $value;
}


##
# getvar
#
# Returns the value for $var for the most local scope
#
# $var The name of the variable
#
# Returns the value of $var
#
sub getvar
{
    my $var = shift;
    my $value;

    for (my $i=$#{$scopes}; $i>=0; $i--) {
        if (defined($scopes->[$i]->{'variables'}->{$var})) {
            $value = $scopes->[$i]->{'variables'}->{$var};
        }
    }

    return $value;
}


##
# setvar
#
# Set the value of $var for the current scope
#
sub setvar
{
    my $var = shift;
    my $value = shift;
    my $scope = getscope();
    $scope->{'variables'}->{$var} = $value;
}


##
# newrule
#
# Return a new rule struct
#
sub newrule
{
    my $scope = getscope();
    my $rule = {
        compile => 1, # rules like 'option' set this to 0 and are ignored
        command => '-A',
        chain => '',
        table => '',
        target => '',
        matchexp => [],
        comment => '',
        targetexp => [],
    };
    $scope->{'rule'} = $rule;
    return $rule;
}


##
# copyline
#
# Create a deep copy of the lines tokens
#
# $line The line to copy
#
# Returns a copy of $line
#
sub copyline
{
    my $tokens = shift;

    my $newline = [];
    foreach my $t (@$tokens) {
        my $newt = {};
        foreach my $k (keys(%$t)) {
            $newt->{$k} = $t->{$k};
        }
        push(@$newline, $newt);
    }

    return $newline;
}


##
# getcomment
#
# Return the comment for the current scope
#
sub getcomment
{
    my $scope = getscope();
    return $scope->{'comment'};
}


##
# setcomment
#
# Set the comment for the current scope
#
# $comment The comment to set
#
sub setcomment
{
    my $comment = shift;
    my $scope = getscope();
    $scope->{'comment'} = $comment;
}


##
# bracelist
#
# Destructively process a brace list in $line
#
# $pos The position of the opening brace
# $line The line to process
#
# Returns a list of values
#
sub bracelist
{
    my $pos = shift;
    my $line = shift;

    my $list = [];

    # start at the next token, which is the first list item
    my $bracelen = 1;
    my $depth = 1;
    for (my $i=1; $i<@$line; $i++) {
        my $t = $line->[$pos+$i];
        if ($t->{'type'} eq 'T_CLOSE_BRACE') {
            $depth--;
            if ($depth == 0) {
                $bracelen++;
                last;
            }
        }
        elsif ($t->{'type'} eq 'T_OPEN_BRACE') {
            $depth++;
        }
        elsif ($t->{'type'} ne 'T_COMMA') {
            push(@$list, $t);
        }
        $bracelen++;
    }

    # use reverse to put the new rules in the order the values are in the list
    foreach my $t (reverse(@$list)) {
        my $newline = copyline($line);
        splice(@$newline, $pos, $bracelen, $t);
        addline($newline);
    }

    # don't compile the current rule
    if (@$list > 0) {
        skiprule();
    }
}


##
# parenlist
#
# Descrutively process a parenthetical list in $line
#
# $pos The position of the opening parenthesis
# $line The line to process
#
# Returns a hash of options
#
sub parenlist
{
    my $pos = shift;
    my $line = shift;

    my $opts = {};

    # start at the next token, which is the first option/value pair
    my $parenlen = 1;
    for (my $i=1; $i<@$line; $i++) {
        if ($line->[$pos+$i]->{'type'} eq 'T_CLOSE_PARENTHESIS') {
            $parenlen++;
            last;
        }
        if ($line->[$pos+$i]->{'type'} ne 'T_COMMA') {
            my $opt = $line->[$pos+$i]->{'value'};
            my $val = $line->[$pos+$i+1]->{'value'};
            $opts->{$opt} = $val;
            $i++;
        }
        $parenlen++;
    }

    splice(@$line, $pos, $parenlen);
    $line->[$pos-1]->{'options'} = $opts;
}


##
# loadprotos
#
# Load protocols from /etc/protocols
#
sub loadprotos
{
    my $protos = {};

    if (-f '/etc/protocols') {
        open(my $fh, '/etc/protocols')
            || error({code=>'E_FILE_READ_FAILED', file=>'/etc/protocols', reason=>$?});

        while (<$fh>) {
            my ($name, $rest) = split(/\s/);
            $protos->{$name} = 1;
        }

        close($fh);
    }
    else {
        # if we can't read /etc/protocols, use defaults
        $protos = {tcp=>1, udp=>1, icmp=>1, all=>1};
    }

    return $protos;
}


##
# protoexists
#
# Determine if $proto exists
#
# $proto The protocol to check
#
# Returns true if $proto exists, else returns 0
#
sub protoexists
{
    my $proto = shift;
    return defined($protocols->{$proto});
}


##
#
# Load interfaces
#
sub loadifs
{
    my $ifs;

    open(my $in, "ip address|")
        || error({code=>'E_PIPE_READ_FAILED', reason=>$!});

    my $curif;
    while (<$in>) {
        if (/^[0-9]+: ([^:]+):/) {
            $curif = $1;
            $ifs->{$curif} = {};
        }

        if (defined($curif)) {
            if (/^\s+link\/ether\s([^\s]+)\s/) {
                $ifs->{$curif}->{'mac'} = $1;
            }
            elsif (/^\s+inet\s([^\s]+)\s/) {
                my ($addr, $mask) = split(/\//, $1);
                $ifs->{$curif}->{'inet'} = $addr;
                $ifs->{$curif}->{'inetmask'} = $mask;
            }
            elsif (/^\s+inet6\s([^\s]+)\s/) {
                my ($addr, $mask) = split(/\//, $1);
                $ifs->{$curif}->{'inet6'} = $addr;
                $ifs->{$curif}->{'inet6mask'} = $mask;
            }
        }
    }

    close($in);

    return $ifs;
}


##
# ifexists
#
# Determine if an interface exists
#
# $if The name of the interface
#
# Returns 1 if $if exists, else returns 0
#
sub ifexists
{
    my $if = shift;
    return defined($interfaces->{$if});
}


##
# getifnet
#
# Get network address for $if
#
# $if The interface to get the address from
#
sub getifnet
{
    my $if = shift;
    my $info = $interfaces->{$if};
    return ip2net("$info->{'inet'}/$info->{'inetmask'}");
}


##
# getifbcast
#
# Get broadcast address for $if
#
# $if The interface to get the address from
#
sub getifbcast
{
    my $if = shift;
    my $info = $interfaces->{$if};
    return ip2bcast("$info->{'inet'}/$info->{'inetmask'}");
}


##
# getifaddr
#
# Get address for $if
#
# $if The interface to get the address from
#
sub getifaddr
{
    my $if = shift;
    return $interfaces->{$if}->{'inet'};
}


##
# getifmask
#
# Get netmask for $if
#
# $if The interface to get the netmask from
#
sub getifmask
{
    my $if = shift;
    return $interfaces->{$if}->{'inetmask'};
}


##
# if2host
#
# Resolve an interface host declaration
#
# $host The declaration to resolve
#
sub if2host
{
    my $host = shift;
    # is the host value an interface?
    if ($host =~ /^(lo|(eth|tun|tap|vlan)[0-9]+)/) {
        # resolve the interface to an address
        my ($if, $prop) = split(/:/, $host);
        if (ifexists($if)) {
            if (defined($prop) && $prop ne '') {
                if ($prop eq 'network') {
                    $host = getifnet($if).'/'.getifmask($if);
                }
                elsif ($prop eq 'broadcast') {
                    $host = getifbcast($if);
                }
            }
            else {
                $host = getifaddr($if);
            }
        }
    }
    return $host
}


##
# loadroutes
#
sub loadroutes
{
    my $routes = {};

    open(my $in, 'netstat -rn|')
        || error({code=>'E_PIPE_READ_FAILED', reason=>$!});

    my $curroute;
    while (<$in>) {
        next if /^(Kernel|Destination)/;
        my ($dst, $gw, $mask, $flags, $mss, $win, $irtt, $if) = split(/\s/);
        $routes->{"$dst/$mask"} = {gw=>$gw, if=>$if};
    }

    close($in);

    return $routes;
}


##
# iproute
#
# Get routing information for an ip
#
# $ip The ip to lookup
#
# Returns a hashref with keys gateway and interface
#
sub iproute
{
    my $ip = shift;

    my $route;
    foreach my $r (keys(%$routes)) {
        if (nethasip($r, $ip)) {
            $route = $r;
            last;
        }
    }

    return $route;
}


##
# tokenpos
#
# Return the index of a given token in a rule
#
# $type Type of token to search for
# $line The line to search
#
# Return index if token is found, else return -1
#
sub tokenpos
{
    my $type = shift;
    my $line = shift;

    my $index = -1;

    for (my $i=0; $i<@$line; $i++) {
        if ($line->[$i]->{'type'} eq $type) {
            $index = $i;
            last;
        }
    }

    return $index;
}


##
# protocheck
#
# Check if the rule specifies a protocol, if not throw an error
#
# $token The token currently being processed
# $rule The (optional) rule to check, or the current rule if none defined
#
# Return 1 if a protocol is specified, else returns 0
#
sub protocheck
{
    my $token = shift;
    my $rule = shift;
    $rule = getrule() if !defined($rule);

    # make sure a proto has been specified
    my $hasproto = 0;
    foreach my $exp (@{$rule->{'matchexp'}}) {
        if ($exp =~ /^-p\s.+$/) {
             $hasproto = 1;
             last;
        }
    }

    if (!$hasproto) {
        my $err = {
            file => $token->{'file'},
            line => $token->{'line'},
            char => $token->{'char'}
        };

        if (getoption('strict') eq 'on') {
            $err->{'code'} = 'E_PORT_WITHOUT_PROTOCOL';
            error($err);
        }
        else {
            $err->{'code'} = 'W_PORT_WITHOUT_PROTOCOL';
            warn($err);
            push(@{$rule->{'matchexp'}}, '-p all');
        }
    }

    return $hasproto;
}


1;
