#
# (c) Jiri Spacek <spaceji3@fit.cvut.cz>
#
# vim: set ts=2 sw=2 tw=0:
# vim: set expandtab:

package Rex::Pkg::Alpine;

use strict;
use warnings;

# VERSION

use Rex::Helper::Run;
use Rex::Commands::File;
use Rex::Commands::Fs;

use Rex::Pkg::Base;
use base qw(Rex::Pkg::Base);

sub new {
  my $that  = shift;
  my $proto = ref($that) || $that;
  my $self  = $proto->SUPER::new(@_);

  bless( $self, $proto );

  $self->{commands} = {
    install           => 'apk -q add %s',
    install_version   => 'apk -q add %s=%s',
    update_system     => 'apk -q upgrade',
    remove            => 'apk -q del %s',
    purge             => 'apk -q --purge del %s',
    update_package_db => 'apk -q update',
  };

  return $self;
}

sub bulk_install {
  my ( $self, $packages_aref, $option ) = @_;

  delete $option->{version}; # makes no sense to specify the same version for several packages

  $self->update( "@{$packages_aref}", $option );

  return 1;
}

sub get_installed {
  my ( $self, $pkg ) = @_;
  my @pkgs;
  my $apkinfo_cmd;
  if ($pkg) {
    $apkinfo_cmd = 'apk info -d ' . $pkg;
  } else {
    $apkinfo_cmd = 'apk info -v';
  }
  my @lines = i_run $apkinfo_cmd;

  if ($pkg) {
      if (!@lines) {
          my $desc_line = $lines[0];
          if ( $desc_line =~ m/^(.*)-(\d.*) description:$/ ) {
              push(
                  @pkgs,
                  {
                      name         => $1,
                      version      => $2
                  }
                  );
          }
      }
  } else {
      for my $line (@lines) {
          if ( $line =~ m/^(.*)-(\d.*)$/ ) {
              push(
                  @pkgs,
                  {
                      name         => $1,
                      version      => $2
                  }
                  );
          }
      }
  }

  return @pkgs;
}

sub diff_package_list {
  my ( $self, $list1, $list2 ) = @_;

  my @old_installed = @{$list1};
  my @new_installed = @{$list2};

  my @modifications;

  # getting modifications of old packages
OLD_PKG:
  for my $old_pkg (@old_installed) {
  NEW_PKG:
    for my $new_pkg (@new_installed) {
      if ( $old_pkg->{name} eq $new_pkg->{name} )
      {

        # flag the package as found in new package list,
        # to find removed and new ones.
        $old_pkg->{found} = 1;
        $new_pkg->{found} = 1;

        if ( $old_pkg->{version} ne $new_pkg->{version} ) {
          push @modifications, { %{$new_pkg}, action => 'updated' };
        }
        next OLD_PKG;
      }
    }
  }

  # getting removed old packages
  push @modifications, map { $_->{action} = 'removed'; $_ }
    grep { !exists $_->{found} } @old_installed;

  # getting new packages
  push @modifications, map { $_->{action} = 'installed'; $_ }
    grep { !exists $_->{found} } @new_installed;

  map { delete $_->{found} } @modifications;

  return @modifications;
}


1;
