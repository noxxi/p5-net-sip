use ExtUtils::MakeMaker;
require 5.008;
WriteMakefile(
	NAME => 'Net::SIP',
	VERSION_FROM => 'lib/Net/SIP.pm',
	PREREQ_PM => {
		'Net::DNS' => 0.56,
	},
);
