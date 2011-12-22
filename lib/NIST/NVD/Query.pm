package NIST::NVD::Query;

use warnings;
use strict;

use Storable qw(thaw);
use IO::Uncompress::Bunzip2 qw(bunzip2 $Bunzip2Error);
use DB_File;

use Carp;

=head1 NAME

NIST::NVD::Query - Query the NVD database

=head1 VERSION

Version 0.04

=cut

our $VERSION = '0.04';


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
  my( $self, %args ) = @_;

  unless( exists $args{cpe} ){
    carp qq{"cpe" is a required argument to __PACKAGE__::cve_for_cpe\n};
  }

  my $frozen;

  my $result = $self->{'idx_cpe.db'}->get($args{cpe}, $frozen);

  unless( $result == 0 ){
    carp "failed to retrieve CVEs for CPE '$args{cpe}': $!\n";
    return;
  }

  my $cve_ids = eval { thaw $frozen };
  if( @$ ){
    carp "Storable::thaw had a major malfunction.";
    return;
  }

  return $cve_ids;
}

=head2 cve

Returns a list of CVE IDs for a given CPE URN.

=head3 Required argument

    cve_id: CPE URN  Example:

    'CVE-1999-1587'

=head3 Return Value

Returns a reference to a hash representing a CVE entry:

  my $nvd_cve_entry =
    {
     'vuln:vulnerable-configuration' => [ ... ],
     'vuln:vulnerable-software-list' => [ ... ],
     'vuln:cve-id'                   => 'CVE-1999-1587',
     'vuln:discovered-datetime'      => '...',
     'vuln:published-datetime'       => '...',
     'vuln:last-modified-datetime'   => '...',
     'vuln:cvss'                     => {...},
     'vuln:cwe'                      => 'CWE-ID',
     'vuln:references'               => [ { attr => {...},
					    'vuln:references' => [ {...}, ... ],
					    'vuln:source'     => '...',
					  } ],
     'vuln:summary'                  => '...',
     'vuln:security-protection'      => '...',
     'vuln:assessment_check'         => { 'check0 name' => 'check0 value',
					  ... },
     'vuln:scanner',                 => [ { 'vuln:definition' => { 'vuln attr0 name' => 'vuln attr0 value'
								   ... } } ],
    };

=cut


sub cve {
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

Copyright 2011 F5 Networks, Inc.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1; # End of NIST::NVD::Query
