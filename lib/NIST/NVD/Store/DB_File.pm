package NIST::NVD::Store::DB_File;

use NIST::NVD::Store::Base;
use base qw{NIST::NVD::Store::Base};

use warnings;
use strict;

our $VERSION = '0.05';

use Carp;

use Storable qw(thaw);
use IO::Uncompress::Bunzip2 qw(bunzip2 $Bunzip2Error);
use DB_File;

=head2 new


=cut

sub new {
  my( $class, %args ) = @_;
  $class = ref $class || $class;

  my $args = { filename => [ qw{ database idx_cpe } ],
	       database => [ qw{ database idx_cpe } ],
	       required => [ qw{ database idx_cpe } ],
	     };

  my $fail = 0;
  foreach my $req_arg ( @{$args->{required}} ){
    unless( $args{$req_arg} ){
      carp "'$req_arg' is a required argument to __PACKAGE__::new\n";
      $fail++;
    }
  }
  return if $fail;

  my $self = {};
  foreach my $arg ( keys %args ){
    if( grep { $_ eq $arg } @{ $args->{filename} } ){
      unless( -f $args{$arg} ){
	carp "$arg file '$args{$arg}' does not exist\n";
	$fail++;
      }
    }
    if( grep { $_ eq $arg } @{ $args->{database} } ){
      my %tied_hash;
      $self->{$arg} = \%tied_hash;
      $self->{"$arg.db"} = tie %tied_hash, 'DB_File', $args{$arg}, O_RDONLY;

      unless( $self->{"$arg.db"} ){
	carp "failed to open database '$args{$arg}': $!";
	$fail++;
      }
    }
  }
  return if $fail;

	bless $self, $class;

}

=head2 get_cve_for_cpe

=cut

sub get_cve_for_cpe {
  my( $self, %args ) = @_;

  my $frozen;

  my $result = $self->{'idx_cpe.db'}->get($args{cpe}, $frozen);

  unless( $result == 0 ){
    carp "failed to retrieve CVEs for CPE '$args{cpe}': $!\n";
    return;
  }

  my $cve_ids = eval { thaw $frozen };
  if( @$ ){
    carp "Storable::thaw had a major malfunction: $@";
    return;
  }

	return $cve_ids
}

=head2 get_cve


=cut

sub get_cve {
  my( $self, %args ) =  @_;

  my $compressed;

  my $result = $self->{'database.db'}->get($args{cve_id}, $compressed);

  unless( $result == 0 ){
    carp "failed to retrieve CVE '$args{cve_id}': $!\n";
    return;
  }

  my $frozen;

  my $status = bunzip2( \$compressed, \$frozen );
  unless( $status ){
    carp "bunzip2 failed: $Bunzip2Error\n";
    return;
  }

  my $entry = eval { thaw $frozen };
  if( @$ ){
    carp "Storable::thaw had a major malfunction.";
    return;
  }

  return $entry;
}

1;
