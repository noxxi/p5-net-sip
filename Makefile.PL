use ExtUtils::MakeMaker;
require 5.008;
$^O =~m{Win32}i and die "OS unsupported";
WriteMakefile(
	NAME => 'Net::SIP',
	VERSION_FROM => 'lib/Net/SIP.pm',
	PREREQ_PM => {
		'Net::DNS' => 0.56,
		'Socket' => 1.95,
	},
    $ExtUtils::MakeMaker::VERSION >= 6.46 ? (
        'META_MERGE' => {
            resources => {
                license     => 'http://dev.perl.org/licenses/',
                repository  => 'https://github.com/noxxi/p5-net-sip',
                homepage    => 'https://github.com/noxxi/p5-net-sip',
                bugtracker  => 'https://rt.cpan.org/Dist/Display.html?Queue=Net-SIP',
            },
        },
    ):(),

)
