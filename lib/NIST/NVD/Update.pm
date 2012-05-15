package NIST::NVD::Update;

use warnings;
use strict;

=head1 NAME

NIST::NVD::Update - Update local cache of vulnerabilities from XML file

=head1 VERSION

Version 0.11

=cut

our $VERSION = '0.11';

=head1 SYNOPSIS

    use NIST::NVD::Update;

    # use convert_nvdcve to generate these files from the XML dumps:
    # http://nvd.nist.gov/download.cfm

    my $u = NIST::NVD::Update->new(
        store => $some_store,
        %args
    );

=head1 SUBROUTINES/METHODS

=head2 new

  # See NIST::NVD::Storage::DB_File for an example
  my $NVD_Updater =
    NIST::NVD::Update->new( store => $store_type, %args );

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

=head2 update_websec_idx_cpe

 my $result = update_websec_idx_cpe ();

=cut

sub update_websec_idx_cpe {
	my $self = shift;
	# TODO: Validate

	my $result = $self->{store}->update_websec_idx_cpe(@_);

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

=head2 put_cwe_idx_cve

 my $result = put_cwe_idx_cve ( { NVD_ID0 => $data_about_NVD_ID[0],
																	NVD_ID1 => $data_about_NVD_ID[1],
#																	...
																	"NVD_ID$N" => $data_about_NVD_ID[$N],
 } )


=cut

sub put_cwe_idx_cve {
	my $self = shift;

	my $result = $self->{store}->put_cwe_idx_cve(@_);

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

=head2 put_cwe

  $result = $self->put_cwe( cwe_id   => 'CWE-42',
                            cwe_dump => $cwe_dump );

=cut

sub put_cwe {
	my $self = shift;

	my $result = $self->{store}->put_cwe(@_);

	return $result;
}

=head2 commit

  $result = $self->commit($commit_buffer_name);

=cut

sub commit {
	my $self = shift;

	my $result = $self->{store}->commit(@_);

	return $result;
}


=head2 get_cwe_ids

  $result = $self->get_cwe_ids();
  while( my( $cwe_id, $cwe_pkey_id ) = each %$result ){
    ...
  }

=cut

sub get_cwe_ids {
	my($self) = @_;

	my $result = $self->{store}->get_cwe_ids(@_);

	return $result;
}

=head2 get_websec_by_cpe

  my $result = $store->get_websec_by_cpe( 'cpe:/a:apache:tomcat:6.0.28' );
  while( my $websec = shift( @{$result->{websec_results}} ) ){
    print( "$websec->{key} - $websec->{category}: ".
           "$websec->{score}\n" );
  }

=cut

sub get_websec_by_cpe {
	my($self) = @_;

	my %result = $self->{store}->get_websec_by_cpe(@_);

	return %result if wantarray;
	return \%result;
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

=head1 LICENSE AND COPYRIGHT

Copyright 2011, 2012 F5 Networks, Inc.

CVE(r) and CWE(tm) are marks of The MITRE Corporation and used here with
permission.  The information in CVE and CWE are copyright of The MITRE
Corporation and also used here with permission.

Please include links for CVE(r) <http://cve.mitre.org/> and CWE(tm)
<http://cwe.mitre.org/> in all reproductions of these materials.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1;    # End of NIST::NVD::Update
