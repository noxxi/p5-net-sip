use ExtUtils::MakeMaker;
require 5.008;
$^O =~m{Win32}i and die "OS unsupported";
WriteMakefile(
	NAME => 'Net::SIP',
	VERSION_FROM => 'lib/Net/SIP.pm',
	PREREQ_PM => {
		'Net::DNS' => 0.56,
	},
);
