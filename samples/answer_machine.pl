###########################################################################
# Simple answer machine:
# - Register and listen
# - On incoming call send welcome message and send data to file, hangup
#   after specified time
# - Recorded data will be saved as %d_%s_.pcmu-8000 where %d is the 
#   timestamp from time() and %s is the data from the SP 'From' header.
#   to convert this to something more usable you might use 'sox' from
#   sox.sf.net, e.g for converting to OGG:
#   sox -t raw -b -U -c 1 -r 8000  file.pcmu-8000 file.ogg
# - Recording starts already at the beginning, not after the welcome
#   message is done
###########################################################################

use strict;
use warnings;
use IO::Socket::INET;
use Getopt::Long qw(:config posix_default bundling);

use Net::SIP;
use Net::SIP::Util ':all';
use Net::SIP::Debug;

sub usage {
	print STDERR "ERROR: @_\n" if @_;
	print STDERR <<EOS;
usage: $0 [ options ] FROM
Listens on SIP address FROM for incoming calls. Sends
welcome message and records data from user in PCMU/800 format.

Options:
  -d|--debug                   Enable debugging
  -h|--help                    Help (this info)
  -R|--registrar host[:port]   register at given address
  -W|--welcome filename        welcome message
  -T|--timeout time            record at most time seconds (default 60)
  -D|--savedir directory       where to save received messages (default .)
  --username name              username for authorization
  --password pass              password for authorization

Example:
  $0 -T 20 -W welcome.data --register 192.168.178.3 sip:30\@example.com

EOS
	exit( @_ ? 1:0 );
}


###################################################
# Get options
###################################################

my $welcome_default = 'welcome.pmcu-8000';

my $hangup = 60;
my $savedir = '.';
my ($welcome,$registrar,$username,$password);
GetOptions(
	'd|debug' => sub { Net::SIP::Debug->level(1) },
	'h|help' => sub { usage() },
	'R|registrar=s' => \$registrar,
	'W|welcome=s' => \$welcome,
	'D|savedir=s' => \$savedir,
	'T|timeout=i' => \$hangup,
	'username=s' =>\$username,
	'password=s' =>\$password,
) || usage( "bad option" );


my $from = shift(@ARGV);
$from || usage( "no local address" );
$welcome ||= -f $welcome_default && $welcome_default;
$welcome || usage( "no welcome message" );

###################################################
# if no proxy is given we need to find out
# about the leg using the IP given from FROM
###################################################
my $leg;
if ( !$registrar ) {
	my ($host,$port) = $from =~m{\@([\w\-\.]+)(?:(\d+))?} 
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
}

###################################################
# SIP code starts here
###################################################

# create necessary legs
my @legs;
push @legs,$leg if $leg;
if ( $registrar ) {
	if ( ! grep { $_->can_deliver_to( $registrar ) } @legs ) {
		my $sock = create_socket_to($registrar) 
			|| die "cannot create socket to $registrar";
		push @legs, Net::SIP::Leg->new( sock => $sock );
	}
}

# create user agent
my $ua = Net::SIP::Simple->new(
	from => $from,
	legs => \@legs,
	$username ? ( auth => [ $username,$password ] ):(),
);

# optional registration
if ( $registrar ) {
	my $sub_register;
	$sub_register = sub {
		my $expire = $ua->register( registrar => $registrar )
			|| die "registration failed: ".$ua->error;
		# need to refresh registration periodically
		DEBUG( "registered \@$registrar, expires=$expire" );
		$ua->add_timer( $expire/2, $sub_register );
	};
	$sub_register->();
}


# listen
$ua->listen(
	init_media => [ \&play_welcome, $welcome,$hangup,$savedir ],
	recv_bye => sub {
		my $param = shift;
		my $t = delete $param->{stop_rtp_timer};
		$t && $t->cancel;
	}
);

$ua->loop;

###################################################
# sub to play welcome message, save the peers
# message and stop the call after a specific time
###################################################
sub play_welcome {
	my ($welcome,$hangup,$savedir,$call,$param) = @_;

	my $from = $call->get_peer;
	my $filename = sprintf "%d_%s_.pcmu-8000", time(),$from;
	$filename =~s{[/[:^print:]]}{_}g; # normalize
	DEBUG( "call=$call param=$param peer=$from filename='$filename'" );
	$filename = $savedir."/".$filename if $savedir;

	# callback for sending data to peer
	my ($fd,$lastbuf);
	my $play_welcome = sub {
		$fd || open( $fd,'<',$welcome ) || die $!;
		if ( read( $fd, my $buf,160 )) {
			# still data in $welcome
			$lastbuf = $buf;
			return $buf;
		} else {
			# no more data in welcome. Play last packet again
			# while the peer is talking to us.
			return $lastbuf;
		}
	};

	# timer for restring time the peer can speak
	$param->{stop_rtp_timer} = $call->add_timer( $hangup, [
		sub { 
			DEBUG( "connection closed because record time too big" );
			shift->bye 
		},
		$call
	]);

	my $rtp = $call->rtp( 'media_send_recv', $play_welcome,1,$filename );
	return invoke_callback( $rtp,$call,$param );
}
