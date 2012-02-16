use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile
  (
   NAME                => 'NIST::NVD',
   AUTHOR              => q{C.J. Adams-Collier <cjac@f5.com>},
   VERSION_FROM        => 'lib/NIST/NVD.pm',
   EXE_FILES           => [ 'bin/convert-nvdcve' ],
   ABSTRACT_FROM       => 'lib/NIST/NVD.pm',
   LICENSE             => 'perl',
   PL_FILES            => {},
   PREREQ_PM => {
		 'Test::More'            => 0,
		 'Test::File'            => 0,
		 'Data::Dumper'          => 0,
		 'XML::XPath'            => 0,
		 'XML::XPath::XMLParser' => 0,
		 'Storable'              => 0,
		 'IO::Compress::Bzip2'   => 0,
		 'DB_File'               => 0,
		 'Carp'                  => 0,
		},
   dist                => { COMPRESS => 'bzip2 -9f', SUFFIX => 'bz2', },
   clean               => { FILES => 'NIST-NVD-* t/data/*.db' },
  );
