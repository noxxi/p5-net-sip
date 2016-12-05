use ExtUtils::MakeMaker;
use 5.010;
$^O =~m{Win32}i and die "OS unsupported";
if (eval 'use Socket 1.95; 1' 
    and ! eval 'Socket::inet_pton(Socket::AF_INET(),"0.0.0.0")') {
    warn "Socket::inet_pton failed on your system: $@";
    exit(0);
}

WriteMakefile(
    NAME => 'Net::SIP',
    VERSION_FROM => 'lib/Net/SIP.pm',
    PREREQ_PM => {
	# 'Net::DNS' => 0.56, # optional
	# 'IO::Socket::SSL' => 1.956,  # optional
	'Socket' => 1.95,
    },
    LICENSE => 'perl',
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
);
