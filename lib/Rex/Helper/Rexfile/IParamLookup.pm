#
# (c) Jan Gehring <jan.gehring@gmail.com>
#
# vim: set ts=3 sw=3 tw=0:
# vim: set expandtab:

package Rex::Helper::Rexfile::IParamLookup;

use strict;
use warnings;

# VERSION

use Devel::Caller;
use Data::Dumper;
require Rex::Exporter;
require Rex::Commands;

use Rex::Ext::ParamLookup;
use base qw(Rex::Exporter);
use vars qw (@EXPORT);

@EXPORT = qw(iparam_lookup);

sub iparam_lookup {
  my ( $param_key, $default, $prompt, $in_stream ) = @_;

  $value = param_lookup($param_key);

  if ( $value ) {
    return $value;
  }

  if ( !$in_stream ) {
    $in_stream = STDIN;
  }

  if ( $prompt ) {
    say $prompt;
  } else {
    say "Enter value for key \"$param_key\" [$default]: ";
  }

  $value = <$in_stream>;
  chomp( $value );

  if ( length $value ) {
    return $default;
  }

  return value;

}

1;

=pod

=head1 NAME

Rex::Helper::Rexfile::ParamLookup - A command to manage task parameters.

A command to manage task parameters. Additionally it register the parameters as template values.

This module also looks inside a CMDB (if present) for a valid key.


=head1 SYNOPSIS

 task "setup", sub {
   my $var = param_lookup "param_name", "default_value";
 };

=head1 LOOKUP

First I<param_lookup> checks the task parameters for a valid parameter. If none is found and if a CMDB is used, it will look inside the cmdb.

If your module is named "Rex::NTP" than it will first look if the key "Rex::NTP::param_name" exists. If it doesn't exists it checks for the key "param_name".

=cut
