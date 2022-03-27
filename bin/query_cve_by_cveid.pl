use NIST::NVD::Query;

my ( $path_to_db, $path_to_idx_cpe, $cve_id ) = @ARGV;

my $q = NIST::NVD::Query->new(
    database => $path_to_db,
    idx_cpe  => $path_to_idx_cpe
);

my $entry = $q->cve( cve_id => $cve_id );
push( @entry, $entry );

print "$entry->{'vuln:cve-id'}\t";
print "$entry->{'vuln:summary'}\n";
