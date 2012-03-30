package NIST::NVD::Update;

use warnings;
use strict;

=head1 NAME

NIST::NVD::Update - Update local cache of vulnerabilities from XML file

=head1 VERSION

Version 0.10

=cut

our $VERSION = '0.10';

=head1 SYNOPSIS

    use NIST::NVD::Query;

    # use convert_nvdcve to generate these files from the XML dumps at
    # http://nvd.nist.gov/download.cfm

    my $u = NIST::NVD::Update->new(
        store => $some_store,
        %args
    );

=head1 SUBROUTINES/METHODS

=head2 new

  # See NIST::NVD::Storage::DB_File for an example
  my $NVD_Updater = NIST::NVD::Update->new( store => $store_type, %args );

=cut

sub new {
  my( $class, %args ) = @_;
  $class = ref $class || $class;

	my $store = $args{store} || "DB_File";

	my $db_class = "NIST::NVD::Store::$store";
	eval "use $db_class";

	die "unable to use $db_class: $@" if $@;

	my $db = $db_class->new( $db_class->_get_default_args(), %args );
	return unless $db;

  bless { store => $db }, $class;
}


=head2 put_cve_idx_cpe

 my $result = put_cve_idx_cpe ( $cpe_urn, $cve_list )

=cut

sub put_cve_idx_cpe {
	my $self = shift;
	# TODO: Validate

	my $result = $self->{store}->put_cve_idx_cpe(@_);

	return $result;
}

=head2 put_cwe_idx_cpe

 my $result = put_cwe_idx_cpe ( $cpe_urn, $cwe_id )

=cut

sub put_cwe_idx_cpe {
	my $self = shift;

	my $result = $self->{store}->put_cwe_idx_cpe(@_);

	return $result
}

=head2 put_cpe

 my $result = put_cpe ( $cpe_urn )

=cut

sub put_cpe {
	my $self = shift;
	# TODO: Validate

	my $result = $self->{store}->put_cpe(@_);

	return $result;
}


=head2 put_nvd_entries

 my $N = lots();

 my $result = put_nvd_entries ( { NVD_ID0 => $data_about_NVD_ID[0],
																	NVD_ID1 => $data_about_NVD_ID[1],
#																	...
																	"NVD_ID$N" => $data_about_NVD_ID[$N],
 } )

=cut

sub put_nvd_entries {
	my $self = shift;

	my $result = $self->{store}->put_nvd_entries(@_);

	return $result;
}


=head2 put_cwe_data

 my $N = lots();

 my $result = put_cwe_data ( { CWE_ID0 => $data_about_CWE_ID[0],
                               CWE_ID1 => $data_about_CWE_ID[1],
#                              ...
                               "CWE_ID$N" => $data_about_CWE_ID[$N],
 } )

=cut

sub put_cwe_data {
	my $self = shift;

	my $result = $self->{store}->put_cwe_data(@_);

	return $result;
}


=head1 AUTHOR

C.J. Adams-Collier, C<< <cjac at f5.com> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-nist-nvd-update at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=NIST-NVD-Update>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.




=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc NIST::NVD::Update


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=NIST-NVD-Update>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/NIST-NVD-Update>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/NIST-NVD-Update>

=item * Search CPAN

L<http://search.cpan.org/dist/NIST-NVD-Update/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2012 C.J. Adams-Collier.

This program is released under the following license: f5 internal


=cut

1;    # End of NIST::NVD::Update
