#
# (c) Jan Gehring <jan.gehring@gmail.com>
#
# vim: set ts=2 sw=2 tw=0:
# vim: set expandtab:

package Rex::Interface::Exec::Chroot;

use strict;
use warnings;

# VERSION

use Rex::Config;
use Rex::Interface::Exec::Local;
use Rex::Interface::Exec::SSH;
use Rex::Helper::Encode;
use Rex::Interface::File::Local;
use Rex::Interface::File::SSH;

use Rex::Commands;
use Rex::Helper::Path;

use base 'Rex::Interface::Exec::Base';

sub new {
  my $that  = shift;
  my $proto = ref($that) || $that;
  my $self  = {@_};

  bless( $self, $proto );

  return $self;
}

sub exec {
  my ( $self, $cmd, $path, $option ) = @_;

  my $newroot = $option->{newroot};

  if ( exists $option->{cwd} ) {
    $cmd = "cd " . $option->{cwd} . " && $cmd";
  }

  if ( exists $option->{path} ) {
    $path = $option->{path};
  }

  my ( $exec, $file, $shell );
  if ( my $ssh = Rex::is_ssh() ) {
    if ( ref $ssh eq "Net::OpenSSH" ) {
      $exec = Rex::Interface::Exec->create("OpenSSH");
      $file = Rex::Interface::File->create("OpenSSH");
    }
    else {
      $exec = Rex::Interface::Exec->create("SSH");
      $file = Rex::Interface::File->create("SSH");
    }
  }
  else {
    $exec = Rex::Interface::Exec->create("Local");
    $file = Rex::Interface::File->create("Local");
  }
  $shell = Rex::Interface::Shell->create("Sh"); # we're using sh for chroot

  Rex::Logger::debug("Chroot: Executing: $cmd");

  #my $sudo_options     = Rex::get_current_connection()->{sudo_options};
  my $chroot_options =
      Rex::get_current_connection_object()->get_current_chroot_options;
  my $chroot_newroot = $chroot_options->{newroot};
  my $chroot_options_str = "";
  #if ( exists $chroot_options->{user} ) {
  #    $chroot_options_str .= " -u " . $chroot_options->{user};
  #}

  my $chroot_command = "chroot $chroot_options_str $chroot_newroot";

  $shell->set_locale("C");
  $shell->path($path);

  if ( Rex::Config->get_source_global_profile ) {
      $shell->source_global_profile(1);
  }

  if ( Rex::Config->get_source_profile ) {
      $shell->source_profile(1);
  }

  if ( exists $option->{env} ) {
      $shell->set_environment( $option->{env} );
  }

    # escape some special shell things
    # $option->{preprocess_command} = sub {
    #   my ($_cmd) = @_;
    #   $_cmd =~ s/\\/\\\\/gms;
    #   $_cmd =~ s/"/\\"/gms;
    #   $_cmd =~ s/\$/\\\$/gms;
    # };

  $shell->set_inner_shell(1);

    # $cmd =~ s/\\/\\\\/gms;
    # $cmd =~ s/"/\\"/gms;
    # $cmd =~ s/\$/\\\$/gms;

# Calling sudo with sh(1) in this case we don't need to respect current user shell, pass _force_sh flag to ssh layer
# $option->{_force_sh} = 1;

  $option->{prepend_command} = $chroot_command;

  my $real_exec = $shell->exec( $cmd, $option );
  Rex::Logger::debug("chroot: exec: $real_exec");

  return $exec->direct_exec( $real_exec, $option );
}

sub _exec {
  my ( $self, $cmd, $path, $option ) = @_;

  my ( $exec, $file, $shell );
  if ( my $ssh = Rex::is_ssh() ) {
    if ( ref $ssh eq "Net::OpenSSH" ) {
      $exec = Rex::Interface::Exec->create("OpenSSH");
    }
    else {
      $exec = Rex::Interface::Exec->create("SSH");
    }
  }
  else {
    $exec = Rex::Interface::Exec->create("Local");
  }

  return $exec->_exec( $cmd, $option );
}

1;
