use strict;
use Net::SIP qw(:all);
use Getopt::Long qw(:config posix_default bundling);

my $debug;
my $from = 'sip:me@two.example.com';
my $leg = '127.0.0.1:5070';
my $registrar;

GetOptions(
    'd|debug:i' => \$debug,
    'h|help' => sub { usage() },
    'F|from=s' => \$from,
    'L|leg=s' => \$leg,
    'R|registrar=s' => \$registrar,
) || usage( 'bad options' );
Debug->level( $debug || 1 ) if defined $debug;

my $ua = Simple->new(
    from => $from,
    leg => $leg,
    registrar => $registrar,
);
if ( $registrar ) {
    die "Registration failed\n" if ! $ua->register;
    print STDERR "Registered\n";
}


$ua->listen(
    # echo everything back
    init_media => $ua->rtp( 'recv_echo' ),
);
print "Listening...\n";
$ua->loop;


sub usage {
    print STDERR "ERROR: @_\n" if @_;
    print STDERR <<USAGE;

Listen on given address and receive calls, echo RTP back.
Handles multiple calls in parallel.
Usage: $0 options
Options:
 -h|--help    This usage
 -d|--debug   Switch on debugging with optional level
 -F|--from    senders address, default $from
 -L|--leg     Leg to listen on, default $leg
 -R|--registrar   Optional Registrar

USAGE
    exit(2);
}
