#
# (c) Jan Gehring <jan.gehring@gmail.com>
#
# vim: set ts=2 sw=2 tw=0:
# vim: set expandtab:

package Rex::Interface::Fs::Chroot;

use strict;
use warnings;

# VERSION

require Rex::Commands;
use Rex::Interface::Fs::Base;
use Rex::Helper::Path;
use Rex::Helper::Encode;
use JSON::XS;
use base qw(Rex::Interface::Fs::Base);
use Data::Dumper;

sub new {
  my $that  = shift;
  my $proto = ref($that) || $that;
  my $self  = $proto->SUPER::new(@_);

  bless( $self, $proto );

  return $self;
}

sub _resolve_path {
    my ( $self, $path ) = @_;
    my $current_options =
        Rex::get_current_connection_object()->get_current_chroot_options;
    my $newroot = $current_options->{newroot};
    my $out = $self->_exec("readlink -f $path");
    chomp $out;
    my $result;
    ($result) = $self->_normalize_path( $newroot . "./" . $out );
    return $result;
}

sub ls {
  my ( $self, $path ) = @_;
  $DB::single = 1;
  my $resolved_path = $self->_resolve_path( $path );

  return $self->_fs()->ls( $resolved_path );
}

sub upload {
  my ( $self, $source, $target ) = @_;

  my $resolved_source = $self->_resolve_path( $source );
  my $resolved_target = $self->_resolve_path( $target );

  return $self->_fs()->upload( $resolved_source, $resolved_target );
}

sub download {
  my ( $self, $source, $target ) = @_;

  my $resolved_source = $self->_resolve_path( $source );
  my $resolved_target = $self->_resolve_path( $target );

  return $self->_fs()->download( $resolved_source, $resolved_target );
}

sub is_dir {
  my ( $self, $path ) = @_;
  my $resolved_path = $self->_resolve_path( $path );
  return $self->_fs()->is_dir( $path );
}

sub is_file {
  my ( $self, $path ) = @_;
  my $resolved_path = $self->_resolve_path( $path );
  return $self->_fs()->is_file( $path );
}

sub unlink {
    my ( $self, @files ) = @_;
    return $self->_fs()->unlink( map { $self->_resolve_path($_) } @files );
}

sub mkdir {
    my ( $self, $dir ) = @_;
    my $resolved_path = $self->_resolve_path( $dir );
    return $self->_fs()->mkdir( $resolved_path );
}

sub stat {
  my ( $self, $file ) = @_;
  my $resolved_path = $self->_resolve_path( $file );
  return $self->_fs()->stat( $resolved_path );
}

sub is_readable {
    my ( $self, $file ) = @_;
    my $resolved_path = $self->_resolve_path( $file );
    return $self->_fs()->is_readable( $resolved_path );
}

sub is_writable {
    my ( $self, $file ) = @_;
    my $resolved_path = $self->_resolve_path( $file );
    return $self->_fs()->is_writable( $resolved_path );
}

sub readlink {
    my ( $self, $file ) = @_;
    my $resolved_path = $self->_resolve_path( $file );
    return $self->_fs()->readlink( $resolved_path );
}

sub rename {
  my ( $self, $old, $new ) = @_;
  my $resolved_old = $self->_resolve_path( $old );
  my $resolved_new = $self->_resolve_path( $new );
  return $self->_fs()->rename( $resolved_old, $resolved_new );
}

# TODO!!
#sub glob {
#  my ( $self, $glob ) = @_;
#
#}

sub _exec {
  my ( $self, $cmd, $path, $option ) = @_;
  my $exec = Rex::Interface::Exec->create("Chroot");
  return $exec->exec( $cmd, $path, $option );
}

sub _fs {
    my $fh;
    if ( my $o = Rex::is_ssh() ) {
        if ( ref $o eq "Net::OpenSSH" ) {
            $fh = Rex::Interface::Fs->create("OpenSSH");
        }
        else {
            $fh = Rex::Interface::Fs->create("SSH");
        }
    }
    else {
        $fh = Rex::Interface::Fs->create("Local");
    }
    return $fh;
}


1;
