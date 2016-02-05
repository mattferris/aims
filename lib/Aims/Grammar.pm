#!/usr/bin/perl
#
# This module is part of aims, an iptables scripting language.
# http://bueller.ca/software/aims
#
# Copyright (c) 2014 Matt Ferris
# Released under the BSD 2-clause license
# http://bueller.ca/software/aims/license
#
package Aims::Grammar;

use strict;
use warnings;

use Exporter qw(import);
our @EXPORT_OK = qw($grammar);

use vars qw($grammar);

$grammar = {
  ignore => '^(T_WHITESPACE)$',
  eof => 'T_EOF',
  eol => 'T_NEWLINE',
  rules => [
    {
      type => 'T_WHITESPACE',
      pattern => '^(\s+)$',
    },
    {
      type => 'T_NEWLINE',
      pattern => '',
      value => "\n",
    },
    {
      type => 'T_ARRAY',
      pattern => '',
      value => [],
    },
    {
      type => 'T_BACKSLASH',
      pattern => '^(\\\)$',
    },
    {
      type => 'T_EOF',
      pattern => '',
      value => 'EOF',
    },
    {
      type => 'T_QUOTED_STRING',
      pattern => '^"([^"]+)"$',
    },
    {
      type => 'T_EVAL_STRING',
      pattern => '^`([^`]+)`$',
    },
    {
      type => 'T_COMMA',
      pattern => '^(\,)$',
    },
    {
      type => 'T_OPEN_BRACE',
      pattern => '^(\{)$',
      next => [ 'T_QUOTED_STRING|T_STRING|T_IPV4|T_IPV6|T_VARIABLE|T_OPEN_BRACE|T_CLOSE_BRACE' ],
      min => 1,
      separator => 'T_COMMA',
      stop => 'T_CLOSE_BRACE',
    },
    {
      type => 'T_CLOSE_BRACE',
      pattern => '^(\})$',
    },
    {
      type => 'T_OPEN_PARENTHESIS',
      pattern => '^(\()$',
      next => [ 'T_STRING', 'T_QUOTED_STRING|T_BOOL_ON|T_BOOL_OFF' ],
      min => 1,
      separator => 'T_COMMA',
      stop => 'T_CLOSE_PARENTHESIS',
    },
    {
      type => 'T_CLOSE_PARENTHESIS',
      pattern => '^(\))$',
    },
    {
      type => 'T_EQUALS',
      pattern => '^(=)$',
    },
    {
      type => 'T_VARIABLE',
      pattern => '^\$([a-zA-Z0-9_]+)$',
    },
    {
      type => 'T_COMMENT',
      pattern => "^(#.*)\$",
    },
    {
      type => 'T_IPV4',
      pattern => '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2}|))$'
    },
    {
      type => 'T_IPV6',
      pattern => '^\[([0-9a-fA-F:]+(\/\d{1,3}|))\]$'
    },
    {
      type => 'T_STRING',
      pattern => '^([^\s,\"\{\}\(\)\=\$]+)$',
      sub  => [
        {
          type => 'T_ANY',
          pattern => '^(any)$',
        },
        {
          type => 'T_CLAUSE',
          pattern => '^[a-z-]+$',
          sub  => [
            {
              type => 'T_ACTION',
              pattern => '^(accept|drop|reject|policy|option|include|match|chain)$',
              sub  => [
                {
                  type => 'T_ACTION_ACCEPT',
                  pattern  => '^(accept)$',
                  next  => ['T_CLAUSE_FOR|T_CLAUSE_IN|T_CLAUSE_OUT'],
                },
                {
                  type => 'T_ACTION_DROP',
                  pattern  => '^(drop)$',
                  next  => ['T_CLAUSE_FOR|T_CLAUSE_IN|T_CLAUSE_OUT'],
                },
                {
                  type => 'T_ACTION_REJECT',
                  pattern => '^(reject)$',
                  next  => ['T_CLAUSE_FOR|T_CLAUSE_IN|T_CLAUSE_OUT'],
                },
                {
                  type => 'T_ACTION_POLICY',
                  pattern  => '^(policy)$',
                  next  => ['T_ACTION_ACCEPT|T_ACTION_DROP|T_ACTION_REJECT'],
                },
                {
                  type => 'T_ACTION_OPTION',
                  pattern  => '^(option)$',
                  next  => ['T_STRING', 'T_QUOTED_STRING|T_BOOL_ON|T_BOOL_OFF'],
                },
                {
                  type => 'T_ACTION_INCLUDE',
                  pattern  => '^(include)$',
                  next  => ['T_QUOTED_STRING'],
                },
                {
                  type => 'T_ACTION_MATCH',
                  pattern  => '^(match)$',
                  next  => ['T_CLAUSE_FOR|T_CLAUSE_IN|T_CLAUSE_OUT'],
                },
                {
                  type => 'T_ACTION_CHAIN',
                  pattern  => '^(chain)$',
                  next  => ['T_STRING|T_QUOTED_STRING|T_OPEN_BRACE|T_ARRAY|T_VARIABLE'],
                },
              ],
            },
            {
              type => 'T_CLAUSE_FOR',
              pattern => '^(for)$',
              next  => ['T_STRING|T_QUOTED_STRING|T_OPEN_BRACE|T_ARRAY|T_VARIABLE'],
            },
            {
              type => 'T_CLAUSE_TABLE',
              pattern => '^(table)$',
              next  => ['T_STRING|T_QUOTED_STRING|T_VARIABLE'],
            },
            {
              type => 'T_CLAUSE_IN',
              pattern => '^(in)$',
              next  => ['T_STRING|T_QUOTED_STRING|T_OPEN_BRACE|T_ARRAY|T_VARIABLE'],
            },
            {
              type => 'T_CLAUSE_OUT',
              pattern => '^(out)$',
              next  => ['T_STRING|T_QUOTED_STRING|T_OPEN_BRACE|T_ARRAY|T_VARIABLE'],
            },
            {
              type => 'T_CLAUSE_PROTO',
              pattern => '^(proto)$',
              next => ['T_STRING|T_QUOTED_STRING|T_OPEN_BRACE|T_ARRAY|T_VARIABLE'],
            },
            {
              type => 'T_CLAUSE_FROM',
              pattern => '^(from)$',
              next => ['T_OPEN_BRACE|T_ARRAY|T_CLAUSE_PORT|T_VARIABLE|T_STRING|T_IPV4|T_IPV6|T_QUOTED_STRING|T_ANY'],
            },
            {
              type => 'T_CLAUSE_TO',
              pattern => '^(to)$',
              next => ['T_OPEN_BRACE|T_ARRAY|T_CLAUSE_PORT|T_VARIABLE|T_STRING|T_QUOTED_STRING|T_ANY'],
            },
            {
              type => 'T_CLAUSE_PORT',
              pattern => '^(port)$',
              next => ['T_OPEN_BRACE|T_ARRAY|T_VARIABLE|T_STRING|T_QUOTED_STRING'],
            },
            {
              type => 'T_CLAUSE_STATE',
              pattern => '^(state)$',
              next => ['T_OPEN_BRACE|T_ARRAY|T_VARIABLE|T_STRING|T_QUOTED_STRING'],
            },
            {
              type => 'T_CLAUSE_RDR_TO',
              pattern => '^(rdr-to)$',
              next => ['T_VARIABLE|T_ARRAY|T_STRING|T_QUOTED_STRING|T_CLAUSE_PORT'],
            },
            {
              type => 'T_CLAUSE_NAT_TO',
              pattern => '^(nat-to)$',
              next => ['T_VARIABLE|T_ARRAY|T_STRING|T_QUOTED_STRING|T_CLAUSE_PORT'],
            },
            {
              type => 'T_CLAUSE_MASQ_TO',
              pattern => '^(masq-to)$',
              next => ['T_VARIABLE|T_STRING|T_QUOTED_STRING'],
            },
            {
              type => 'T_CLAUSE_REJECT_WITH',
              pattern => '^(reject-with)$',
              next => ['T_VARIABLE|T_STRING|T_QUOTED_STRING'],
            },
            {
              type => 'T_CLAUSE_REVERSE',
              pattern => '^(reverse)$',
            },
            {
              type => 'T_CLAUSE_LOG',
              pattern => '^(log)$',
            },
            {
              type => 'T_CLAUSE_FILE',
              pattern => '^(file)$',
            },
            {
              type => 'T_CLAUSE_SENDTO',
              pattern => '^(send-to)$',
              next => ['T_VARIABLE|T_STRING|T_QUOTED_STRING'],
            },
          ],
        },
        {
          type => 'T_BOOL',
          pattern => '^(on|off)$',
          sub  => [
            {
              type => 'T_BOOL_ON',
              pattern => '^(on)$',
            },
            {
              type => 'T_BOOL_OFF',
              pattern => '^(off)$',
            },
          ],
        },
      ],
    },
  ],
};

1;
