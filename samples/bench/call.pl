use strict;
use Net::SIP qw(:all);
use Getopt::Long qw(:config posix_default bundling);

my $debug;
my $from = 'sip:me@one.example.com';
my $outgoing_proxy = '127.0.0.1:5070';
my $stat_timer = 2;
my $ncalls = 10;
my $to = 'sip:me@two.example.com';

GetOptions(
	'd|debug:i' => \$debug,
	'h|help' => sub { usage() },
	'F|from=s' => \$from,
	'T|to=s' => \$to,
	'P|proxy=s' => \$outgoing_proxy,
	'S|stat-timer=i' => \$stat_timer,
	'N|parallel=i' => \$ncalls,
) || usage( 'bad options' );
Debug->level( $debug || 1 ) if defined $debug;

my $loop = Net::SIP::Dispatcher::Eventloop->new;
my $ua = Simple->new(
	from => $from,
	outgoing_proxy => $outgoing_proxy,
	loop => $loop,
);

my (@connected,$start_bench,$min_delay,$max_delay);
my $ignored = my $ok = my $lost = my $sum_delay = 0;
for my $call (1..$ncalls) {
	my $connected;
	my $send_seq = 1;
	my $recv_seq = 0;
	$ua->invite( $to,
		cb_final => \$connected,
		init_media => $ua->rtp( 'send_recv', 
			[ \&send_rtp, \$send_seq ],
			0,
			[ \&recv_rtp, \$recv_seq ]
		),
	);
	push @connected,\$connected
}

$ua->loop( @connected );
print STDERR "All $ncalls calls connected....\n";

$start_bench = 1;
my $start = time();
$ua->add_timer( $stat_timer, \&stat_timer, 2 );
$ua->loop;

sub stat_timer {
	if ( $ok ) {
		printf "%5d pkt=%d/%d/%d delay(ms)=%.2f/%.2f/%.2f\n",
			time() - $start,
			$ok,$lost,$ignored,
			$sum_delay/$ok*1000, $min_delay*1000,$max_delay*1000;
	} else {
		printf "%5d pkt=%d/%d/%d\n",
			time() - $start,
			$ok,$lost,$ignored;
	}
	$sum_delay = $ok = $lost = $ignored = 0;
	$min_delay = $max_delay = undef;
}

sub send_rtp {
	my $rseq = shift;
	my $now = $loop->looptime;
	my $sec = int($now);
	my $msec = ( $now - $sec ) * 1_000_000;
	my $seq = $start_bench ? $$rseq++ : 0;
	return pack( "NNN",$seq,$sec,$msec ) . ( ' ' x 148 );
}

sub recv_rtp {
	my ($rseq,$payload) = @_;
	my ($seq,$sec,$msec) = unpack( "NNN",$payload );
	#print STDERR "seq=$seq\n";
	return if ! $seq; # initial data

	my $diff = $seq - $$rseq;
	if ( $diff <= 0 || $diff > 10000 ) {
		# bogus, retransmits?
		$ignored++;
		return;
	} 

	$lost += $diff-1;
	$$rseq = $seq;
	$ok++;
	my $now = $loop->looptime;
	my $then = $sec + $msec/10**6;
	my $delay = $now - $then;
	die "now=".localtime($now)." then=".localtime($then) if $delay<0;
	$sum_delay += $delay;
	$min_delay = $delay if ! defined $min_delay || $min_delay > $delay;
	$max_delay = $delay if ! defined $max_delay || $max_delay < $delay;
}

sub usage {
	print STDERR "ERROR: @_\n" if @_;
	print STDERR <<USAGE;


Makes N parallel calls from FROM to TO and writes statistics about received, lost
packets and delays. Does not send real RTP, but hides non-RTP data within RTP frames
to compute statistics.
Usage: $0 options
Options:
 -h|--help      This usage
 -d|--debug     Switch on debugging with optional level
 -F|--from      local address, default $from
 -T|--to        peer address, default $to
 -P|--proxy     Adress of target or proxy on path to target, default $outgoing_proxy
 -N|--parallel  Number of parallel calls, default $ncalls
 -S|--stat-timer  How often to print statistics, default every $stat_timer seconds

The statistics look like this:

 28 pkt=1005/0/0 delay(ms)=5.68/1.08/41.79
 |       |   | |            |    |    |
 |       |   | |            ---------------- avg/min/max delay in ms
 |       |   | |---------------------------- ignored packets (retransmits..)
 |       |   |------------------------------ lost packets (or received out of order)
 |       |---------------------------------- good packets received
 |------------------------------------------ seconds since start

USAGE
	exit(2);
}


