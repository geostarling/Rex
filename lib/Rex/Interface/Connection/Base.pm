#
# (c) Jan Gehring <jan.gehring@gmail.com>
#
# vim: set ts=2 sw=2 tw=0:
# vim: set expandtab:

package Rex::Interface::Connection::Base;

use strict;
use warnings;

# VERSION

use Rex::Interface::Fs;
use Rex::Interface::Exec;

sub new {
  my $that  = shift;
  my $proto = ref($that) || $that;
  my $self  = {@_};

  bless( $self, $proto );

  $self->{__sudo_options__} = [];

  return $self;
}

sub error                 { die("Must be implemented by Interface Class"); }
sub connect               { die("Must be implemented by Interface Class"); }
sub disconnect            { die("Must be implemented by Interface Class"); }
sub get_connection_object { die("Must be implemented by Interface Class"); }
sub is_connected          { die("Must be implemented by Interface Class"); }
sub is_authenticated      { die("Must be implemented by Interface Class"); }
sub get_connection_type   { die("Must be implemented by Interface Class") }
sub reconnect             { }

sub get_fs_connection_object {
  my ($self) = @_;
  return $self;
}

sub get_fs {
  my $fs = Rex::Interface::Fs->create;
  return $fs;
}

sub get_exec {
  my $exec = Rex::Interface::Exec->create;
  return $exec;
}

sub server {
  my ($self) = @_;
  return $self->{server};
}

sub get_auth_user {
  my ($self) = @_;

  if ( exists $self->{__auth_info__} ) {
    return $self->{__auth_info__}->{user};
  }

  return "";
}

sub get_auth {
  my ($self) = @_;

  if ( exists $self->{__auth_info__} ) {
    return $self->{__auth_info__};
  }
}

sub push_sudo_options {
  my ( $self, @option ) = @_;
  if ( ref $option[0] eq "HASH" ) {
    push @{ $self->{__sudo_options__} }, $option[0];
  }
  else {
    push @{ $self->{__sudo_options__} }, {@option};
  }
}

sub get_current_sudo_options {
  my ($self) = @_;
  return $self->{__sudo_options__}->[-1];
}

sub push_use_sudo {
  my ( $self, $use ) = @_;
  push @{ $self->{__use_sudo__} }, $use;
}

sub get_current_use_sudo {
  my ($self) = @_;

  if ( $self->{is_sudo} ) {
    return 1;
  }
  return $self->{__use_sudo__}->[-1];
}

sub pop_sudo_options {
  my ($self) = @_;
  pop @{ $self->{__sudo_options__} };
}

sub pop_use_sudo {
  my ($self) = @_;
  pop @{ $self->{__use_sudo__} };
}

sub run_sudo_unmodified {
  my ( $self, $code ) = @_;
  $self->push_sudo_options( {} );
  $code->();
  $self->pop_sudo_options();
}

sub push_chroot_options {
    my ( $self, @option ) = @_;
    if ( ref $option[0] eq "HASH" ) {
        push @{ $self->{__chroot_options__} }, $option[0];
    }
    else {
        push @{ $self->{__chroot_options__} }, {@option};
    }
}

sub get_current_chroot_options {
    my ($self) = @_;
    return $self->{__chroot_options__}->[-1];
}

sub push_use_chroot {
    my ( $self, $use ) = @_;
    push @{ $self->{__use_chroot__} }, $use;
}

sub get_current_use_chroot {
    my ($self) = @_;

    if ( $self->{is_chroot} ) {
        return 1;
    }
    return $self->{__use_chroot__}->[-1];
}

sub pop_chroot_options {
    my ($self) = @_;
    pop @{ $self->{__chroot_options__} };
}

sub pop_use_chroot {
    my ($self) = @_;
    pop @{ $self->{__use_chroot__} };
}

1;
