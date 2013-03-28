package Mex::Grammars::aims;

use strict;
use warnings;

use Exporter qw(import);
our @EXPORT_OK = qw($grammar);

use vars qw($grammar);

$grammar = {
  ignore => '^(T_WHITESPACE|T_NEWLINE)$',
  rules => [
    {
      type => 'T_WHITESPACE',
      pattern => '^(\s+)$',
    },
    {
      type => 'T_QUOTED_STRING',
      pattern => '^"([^"]+)"$',
    },
    {
      type => 'T_STRING',
      pattern => '^([^\s]+)$',
      sub  => [
        {
          type => 'T_OPTION',
          pattern => '^([a-zA-Z_]\.[a-zA-Z_]+)$',
        },
        {
          type => 'T_OPEN_BRACE',
          pattern => '^(\{)$',
        },
        {
          type => 'T_CLOSE_BRACE',
          pattern => '^(\})$',
        },
        {
          type => 'T_OPEN_PARENTHESES',
          pattern => '^(\()$',
        },
        {
          type => 'T_CLOSE_PARENTHESES',
          pattern => '^(\))$',
        },
        {
          type => 'T_CLAUSE',
          pattern => '^[a-z-]+$',
          sub  => [
            {
              type => 'T_ACTION',
              pattern => '^(accept|drop|reject|policy|nat|log|option|include)$',
              sub  => [
                {
                  type => 'T_ACTION_ACCEPT',
                  pattern  => '^(accept)$',
                  next  => ['T_WHITESPACE', 'T_CLAUSE_FOR|T_CLAUSE_IN|T_CLAUSE_OUT'],
                },
                {
                  type => 'T_ACTION_DROP',
                  pattern  => '^(drop)$',
                  next  => ['T_WHITESPACE', 'T_CLAUSE_FOR|T_CLAUSE_IN|T_CLAUSE_OUT'],
                },
                {
                  type => 'T_ACTION_REJECT',
                  pattern => '^(reject)$',
                  next  => ['T_WHITESPACE', 'T_CLAUSE_FOR|T_CLAUSE_IN|T_CLAUSE_OUT'],
                },
                {
                  type => 'T_ACTION_POLICY',
                  pattern  => '^(policy)$',
                  next  => ['T_WHITESPACE', 'T_CLAUSE_DROP'],
                },
                {
                  type => 'T_ACTION_NAT',
                  pattern  => '^(nat)$',
                  next  => ['T_WHITESPACE', 'T_CLAUSE_FOR|T_CLAUSE_IN|T_CLAUSE_OUT'],
                },
                {
                  type => 'T_ACTION_LOG',
                  pattern  => '^(log)$',
                  next  => ['T_WHITESPACE', 'T_CLAUSE_FOR|T_CLAUSE_IN|T_CLAUSE_OUT'],
                },
                {
                  type => 'T_ACTION_OPTION',
                  pattern  => '^(option)$',
                  next  => ['T_WHITESPACE', 'T_OPTION', 'T_WHITESPACE', 'T_QUOTED_STRING|T_OPTION_BOOL'],
                },
                {
                  type => 'T_ACTION_INCLUDE',
                  pattern  => '^(include)$',
                  next  => ['T_WHITESPACE', 'T_QUOTED_STRING'],
                },
              ],
            },
            {
              type => 'T_CLAUSE_FOR',
              pattern => '^(for)$',
              next  => ['T_STRING'],
            },
            {
              type => 'T_CLAUSE_IN',
              pattern => '^(in)$',
              next  => ['T_VALUE_NETIF'],
            },
            {
              type => 'T_CLAUSE_OUT',
              pattern => '^(out)$',
              next  => ['T_VALUE_NETIF'],
            },
            {
              type => 'T_CLAUSE_PROTO',
              pattern => '^(proto)$',
              next => ['T_VALUE_PROTOCOL'],
            },
            {
              type => 'T_CLAUSE_FROM',
              pattern => '^(from)$',
              next => ['T_VALUE_HOST|T_CLAUSE_PORT'],
            },
            {
              type => 'T_CLAUSE_TO',
              pattern => '^(to)$',
              next => ['T_VALUE_HOST|T_CLAUSE_PORT'],
            },
            {
              type => 'T_CLAUSE_PORT',
              pattern => '^(port)$',
              next => ['T_VALUE_PORT'],
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
        {
          type => 'T_VALUE_NETIF',
          pattern => '^(eth[0-9]+(|:[0-9]+(|\.[0-9]+)(|\.[0-9]+)))$',
        },
        {
          type => 'T_VALUE_PROTOCOL',
          pattern => '^(tcp|ucp|icmp)$',
        },
        {
          type => 'T_VALUE_HOST',
          pattern => '^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$',
        },
        {
          type => 'T_VALUE_PORT',
          pattern => '^([0-9]{1,5})$',
        },
      ],
    },
  ],
};

1;
