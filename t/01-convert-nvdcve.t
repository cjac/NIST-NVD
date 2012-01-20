#!perl -T

use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);

(my $test_dir)       = $Bin =~ m:^(.*?/t)$:;

(my $data_dir)       = "$test_dir/data" =~ m:^(.*/data)$:;
(my $convert_script) =
  "$test_dir/../blib/script/convert-nvdcve" =~ m:^(.*?/convert-nvdcve$):;
(my $source_file)    =
  "$data_dir/nvdcve-2.0-test.xml" =~ /^(.*nvdcve-2.0-test.xml)$/;
(my $db_file)        = "$data_dir/nvdcve-2.0.db" =~ /^(.*db)$/;
(my $cpe_idx_file)   = "$data_dir/nvdcve-2.0.idx_cpe.db" =~ /^(.*db)$/;

undef $ENV{PATH};
undef $ENV{ENV};
undef $ENV{CDPATH};

unlink( $db_file ) if -f $db_file;
unlink( $cpe_idx_file ) if -f $cpe_idx_file;

chdir( $data_dir );

system( "$convert_script $source_file" );

is( $?, 0, 'conversion script returned cleanly' );
ok( -f $db_file, 'database file exists' );
ok( -f $cpe_idx_file, 'CPE index database file exists' );

chdir( $test_dir );

done_testing();
