#
# (c) Jan Gehring <jan.gehring@gmail.com>
#
# vim: set ts=2 sw=2 tw=0:
# vim: set expandtab:

package Rex::Interface::File::Chroot;

use strict;
use warnings;

# VERSION

use Fcntl;
use File::Basename;
require Rex::Commands;
use Rex::Interface::Fs;
use Rex::Interface::File::Base;
use Rex::Helper::Path;
use base qw(Rex::Interface::File::Base);

sub new {
  my $that  = shift;
  my $proto = ref($that) || $that;
  my $self  = $proto->SUPER::new(@_);

  bless( $self, $proto );

  return $self;
}

sub open {
  my ( $self, $mode, $file ) = @_;

  if ( my $ssh = Rex::is_ssh() ) {
    if ( ref $ssh eq "Net::OpenSSH" ) {
      $self->{fh} = Rex::Interface::File->create("OpenSSH");
    }
    else {
      $self->{fh} = Rex::Interface::File->create("SSH");
    }
  }
  else {
    $self->{fh} = Rex::Interface::File->create("Local");
  }

  # always use current logged in user for sudo fs operations
  # Rex::get_current_connection_object()->push_chroot_options( {} );

  $self->{mode}    = $mode;
  $self->{file}    = $file;
  #if ( $self->_fs->is_file($file) ) {
  #
  #  # resolving symlinks
  #  while ( my $link = $self->_fs->readlink($file) ) {
  #    if ( $link !~ m/^\// ) {
  #      $file = dirname($file) . "/" . $link;
  #    }
  #    else {
  #      $file = $link;
  #    }
  #    $link = $self->_fs->readlink($link);
  #  }
  #}

  my $resolved_path = $self->_fs->_resolve_path( $file );

  $self->{fh}->open( $mode, $resolved_path );

  # Rex::get_current_connection_object()->pop_chroot_options();

  return $self->{fh};
}

sub read {
  my ( $self, $len ) = @_;
  return $self->{fh}->read($len);
}

sub write {
  my ( $self, $buf ) = @_;
  $self->{fh}->write($buf);
}

sub seek {
  my ( $self, $pos ) = @_;
  $self->{fh}->seek($pos);
}

sub close {
  my ($self) = @_;

  return unless $self->{fh};

  #Rex::get_current_connection_object()->push_chroot_options( {} );

  $self->{fh}->close;

  $self->{fh} = undef;

  #Rex::get_current_connection_object()->pop_chroot_options();

  $self = undef;
}

sub _fs {
  my ($self) = @_;
  return Rex::Interface::Fs->create("Chroot");
}

1;
