###########################################################################
# Invite other party, recv RTP data for some seconds or until other side 
# hangs up, then BYE
# optional registration
#
# Most of the code is option parsing and usage, the Net::SIP related code
# is at the end
###########################################################################

use strict;
use warnings;
use IO::Socket::INET;
use Getopt::Long qw(:config posix_default bundling);

use Net::SIP;
use Net::SIP::Util 'create_socket_to';
use Net::SIP::Debug;

sub usage {
	print STDERR "ERROR: @_\n" if @_;
	print STDERR <<EOS;
usage: $0 [ options ] FROM TO
Makes SIP call from FROM to TO, optional record data
and optional hang up after some time
Options:
  -d|--debug [level]           Enable debugging
  -h|--help                    Help (this info)
  -P|--proxy host[:port]       use outgoing proxy, register there unless registrar given
  -R|--registrar host[:port]   register at given address
  -O|--outfile filename        write received RTP data to file
  -T|--time interval           hang up after interval seconds
  --username name              username for authorization
  --password pass              password for authorization
  --route host[:port]          add SIP route, can be specified multiple times

Examples:
  $0 -T 10 -O record.data sip:30\@192.168.178.4 sip:31\@192.168.178.1
  $0 --username 30 --password secret --proxy=192.168.178.3 sip:30\@example.com 31

EOS
	exit( @_ ? 1:0 );
}


###################################################
# Get options
###################################################

my ($proxy,$outfile,$registrar,$username,$password,$hangup);
my (@routes,$debug);
GetOptions(
	'd|debug:i' => \$debug,
	'h|help' => sub { usage() },
	'P|proxy=s' => \$proxy,
	'R|registrar=s' => \$registrar,
	'O|outfile=s' => \$outfile,
	'T|time=i' => \$hangup,
	'username=s' =>\$username,
	'password=s' =>\$password,
	'route=s' => \@routes,
) || usage( "bad option" );


Net::SIP::Debug->level( $debug || 1 ) if defined $debug;
my ($from,$to) = @ARGV;
$to || usage( "no target" );

# register at proxy if proxy given and no registrar
$registrar ||= $proxy; 

###################################################
# if no proxy is given we need to find out
# about the leg using the IP given from FROM
###################################################
my $leg;
if ( !$proxy ) {
	my ($host,$port) = $from =~m{\@([\w\-\.]+)(?::(\d+))?} 
		or die "cannot find SIP domain in '$from'";
	my $addr = gethostbyname( $host )
		|| die "cannot get IP from SIP domain '$host'";
	$addr = inet_ntoa( $addr );

	$leg = IO::Socket::INET->new( 
		Proto => 'udp', 
		LocalAddr => $addr, 
		LocalPort => $port || 5060,
	);

	# if no port given and port 5060 is already used try another one
	if ( !$leg && !$port ) {
		$leg = IO::Socket::INET->new( 
			Proto => 'udp', 
			LocalAddr => $addr, 
			LocalPort => 0
		) || die "cannot create leg at $addr: $!";
	}

	$leg = Net::SIP::Leg->new( sock => $leg );
}

###################################################
# SIP code starts here
###################################################

# create necessary legs
# If I have an only outgoing proxy I could skip this step because constructor
# can make leg to outgoing_proxy itself
my @legs;
push @legs,$leg if $leg;
foreach my $addr ( $proxy,$registrar) {
	$addr || next;
	if ( ! grep { $_->can_deliver_to( $addr ) } @legs ) {
		my $sock = create_socket_to($addr) || die "cannot create socket to $addr";
		push @legs, Net::SIP::Leg->new( sock => $sock );
	}
}

# create user agent
my $ua = Net::SIP::Simple->new(
	from => $from,
	outgoing_proxy => $proxy,
	route => \@routes,
	legs => \@legs,
	$username ? ( auth => [ $username,$password ] ):(),
);

# optional registration
if ( $registrar && $registrar ne '-' ) {
	$ua->register( registrar => $registrar );
	die "registration failed: ".$ua->error if $ua->error
}

# invite peer
my $peer_hangup; # did peer hang up?
my $call = $ua->invite( $to,
	# echo back, use -1 instead of 0 for not echoing back
	init_media => $ua->rtp( 'recv_echo', $outfile,0 ),
	recv_bye => \$peer_hangup,
) || die "invite failed: ".$ua->error;
die "invite failed(call): ".$call->error if $call->error;

# mainloop until other party hangs up or we hang up after
# $hangup seconds
my $stopvar;
$ua->add_timer( $hangup, \$stopvar ) if $hangup;
$ua->loop( \$stopvar,\$peer_hangup );

# timeout, I need to hang up
if ( $stopvar ) {
	$stopvar = undef;
	$call->bye( cb_final => \$stopvar );
	$ua->loop( \$stopvar );
}

