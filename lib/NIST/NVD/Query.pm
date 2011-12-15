package NIST::NVD::Query;

use warnings;
use strict;

use Storable qw(thaw);
use IO::Uncompress::Bunzip2 qw(bunzip2 $Bunzip2Error);
use DB_File;

=head1 NAME

NIST::NVD::Query - Query the NVD database

=head1 VERSION

Version 0.02

=cut

our $VERSION = '0.02';


=head1 SYNOPSIS

This module allows you to look up vulnerability data from the NVD
database

    use NIST::NVD::Query;

    # use convert_nvdcve to generate these files from the XML dumps at
    # http://nvd.nist.gov/download.cfm

    my( $path_to_db, $path_to_idx_cpe ) = @ARGV;

    my $q = NIST::NVD::Query->new( database => $path_to_db,
                                   idx_cpe  => $path_to_idx_cpe,
                                  );

    # Given a Common Platform Enumeration urn, returns a list of known
    # CVE IDs

    my $cve_id_list = $q->cve_for_cpe( cpe => 'cpe:/a:zaal:tgt:1.0.6' );

    my @entry;

    foreach my $cve_id ( @$cve_id_list ){

      # Given a CVE ID, returns a CVE entry

      my $entry = $q->cve( cve_id => $cve_id );
      push( @entry, $entry );

      print $entry->{'vuln:summary'};
    }

=head1 EXPORT

=head1 SUBROUTINES/METHODS

=head2 new

=head3 Required arguments:

    database: path to BDB database of NVD entries
    idx_cpe:  path to BDB database of mappings from CPE URNs to CVE IDs

=head3 Example

    my $q = NIST::NVD::Query->new( database => $path_to_db,
                                   idx_cpe  => $path_to_idx_cpe,
                                  );

=cut

sub new {
  my $class = shift();
  $class = ref $class || $class;

  my %args = @_;

  my $fail = 0;
  foreach my $req_arg ( qw{ database idx_cpe } ){
    unless( $args{$req_arg} ){
      print STDERR "'$req_arg' is a required argument to __PACKAGE__::new\n";
      $fail++;
    }
  }
  return undef if $fail;

  foreach my $filename_arg ( qw{ database idx_cpe } ){
    unless( -f $args{$filename_arg} ){
      print STDERR "$filename_arg file '$args{$filename_arg}' does not exist\n";
      $fail++;
    }
  }
  return undef if $fail;

  my $self = {};

  foreach my $db_arg ( qw{ database idx_cpe } ){
    my %tied_hash;
    $self->{$db_arg} = \%tied_hash;
    $self->{"$db_arg.db"} = tie %tied_hash, 'DB_File', $args{$db_arg}, O_RDONLY;

    unless( $self->{"$db_arg.db"} ){
      print STDERR "failed to open database '$args{$db_arg}': $!";
      $fail++;
    }
  }
  return undef if $fail;

  bless $self, $class;
}

=head2 cve_for_cpe

Returns a list of CVE IDs for a given CPE URN.

=head3 Required argument

    cpe: CPE URN  Example:

    'cpe:/a:zaal:tgt:1.0.6'

=head3 Return Value

Returns a reference to an array of CVE IDs.  Example:

    $cve_id_list = [
      'CVE-1999-1587',
      'CVE-1999-1588',
    ]

=head3 Example

    my $cve_id_list = $q->cve_for_cpe( cpe => 'cpe:/a:zaal:tgt:1.0.6' );

=cut

sub cve_for_cpe {
  my $self = shift;
  my %args = @_;

  my $frozen;

  my $result = $self->{'idx_cpe.db'}->get($args{cpe}, $frozen);

  unless( $result == 0 ){
    print STDERR "failed to retrieve CVEs for CPE '$args{cpe}': $!\n";
    return undef;
  }

  my $cve_ids = eval { thaw $frozen };
  if( @$ ){
    print STDERR "Storable::thaw had a major malfunction.";
    return undef;
  }

  return $cve_ids;
}

=head2 cve

=cut

sub cve {
  my $self = shift;
  my %args = @_;

  my $compressed;

  my $result = $self->{'database.db'}->get($args{cve_id}, $compressed);

  unless( $result == 0 ){
    print STDERR "failed to retrieve CVE '$args{cve_id}': $!\n";
    return undef;
  }

  my $frozen;

  my $status = bunzip2( \$compressed, \$frozen );
  unless( $status ){
    print STDERR "bunzip2 failed: $Bunzip2Error\n";
    return undef;
  }

  my $entry = eval { thaw $frozen };
  if( @$ ){
    print STDERR "Storable::thaw had a major malfunction.";
    return undef;
  }

  return $entry;
}

=head1 AUTHOR

C.J. Adams-Collier, C<< <cjac at f5.com> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-nist-nvd at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=NIST-NVD>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.


=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc NIST::NVD::Query


You can also look for information at:

=over 4

=item * Common Vulnerabilities and Exposures

L<http://cve.mitre.org/>

=item * Common Platform Enumeration

L<http://cpe.mitre.org/>

=item * NIST National Vulnerability Database

L<http://nvd.nist.gov/download.cfm>

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=NIST-NVD>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/NIST-NVD>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/NIST-NVD>

=item * Search CPAN

L<http://search.cpan.org/dist/NIST-NVD/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2011 C.J. Adams-Collier.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1; # End of NIST::NVD::Query
