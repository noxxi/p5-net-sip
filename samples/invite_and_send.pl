###########################################################################
# Invite other party, and send some files. Uses re-INVITEs to support
# sending of multiple files. Exits once done or when peer hangs
# up
#
# Most of the code is option parsing and usage, the Net::SIP related code
# is at the end. The code is very similar to samples/invite_and_recv.pl,
# the main difference is at the end, using media_send_recv instead of
# media_recv_echo and doing re-invites on the same call
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
Makes SIP call from FROM to TO, sends voice from multiple
files to peer. Content in files need to be PCMU/8000 and
could be recorded with samples/invite_and_recv.pl

Options:
  -d|--debug                   Enable debugging
  -h|--help                    Help (this info)
  -P|--proxy host[:port]       use outgoing proxy, register there unless registrar given
  -R|--registrar host[:port]   register at given address
  -S|--send filename           send content of file, can be given multiple times
  -L|--leg ip[:port]           use given local ip[:port] for outgoing leg
  -T|--timeout T               timeout and cancel invite after T seconds, default 30
  -F|--failonhang              error out when remote hangs the call before finishing the playback
  --username name              username for authorization
  --password pass              password for authorization

Examples:
  $0 -T 10 -S welcome.data -S announce.data sip:30\@192.168.178.4 sip:31\@192.168.178.1
  $0 --username 30 -password secret --proxy=192.168.178.3 \
     -S holy_shit.data sip:30\@example.com 31

EOS
    exit( @_ ? 1:0 );
}


###################################################
# Get options
###################################################

my $ring_time = 30;
my ($proxy,@files,$registrar,$username,$password,$local_leg,$failonhang);
my ($debug,$hangup);
GetOptions(
    'd|debug:i' => \$debug,
    'h|help' => sub { usage() },
    'P|proxy=s' => \$proxy,
    'R|registrar=s' => \$registrar,
    'S|send=s' => \@files,
    'L|leg=s' => \$local_leg,
    'T|timeout=s' => \$ring_time,
    'F|failonhang' => \$failonhang,
    'username=s' =>\$username,
    'password=s' =>\$password,
) || usage( "bad option" );


Net::SIP::Debug->level( $debug || 1 ) if defined $debug;
my ($from,$to) = @ARGV;
$to || usage( "no target" );

# register at proxy if proxy given and no registrar
$registrar ||= $proxy;

###################################################
# find local leg
###################################################
my ($local_host,$local_port);
if ( $local_leg ) {
    ($local_host,$local_port) = split( m/:/,$local_leg,2 );
} elsif ( ! $proxy ) {
    # if no proxy is given we need to find out
    # about the leg using the IP given from FROM
    ($local_host,$local_port) = $from =~m{\@([\w\-\.]+)(?::(\d+))?}
	or die "cannot find SIP domain in '$from'";
}

my $leg;
if ( $local_host ) {
    my $addr = gethostbyname( $local_host )
	|| die "cannot get IP from SIP domain '$local_host'";
    $addr = inet_ntoa( $addr );

    $leg = IO::Socket::INET->new(
	Proto => 'udp',
	LocalAddr => $addr,
	LocalPort => $local_port || 5060,
    );

    # if no port given and port 5060 is already used try another one
    if ( !$leg && !$local_port ) {
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
    legs => \@legs,
    $username ? ( auth => [ $username,$password ] ):(),
);

# optional registration
if ( $registrar && $registrar ne '-' ) {
    $ua->register( registrar => $registrar );
    die "registration failed: ".$ua->error if $ua->error
}

# invite peer, send first file
my $peer_hangup; # did peer hang up?
my $no_answer; # or didn't it even answer?
my $rtp_done; # was sending file completed?
my $call = $ua->invite( $to,
    # echo back, use -1 instead of 0 for not echoing back
    init_media => $ua->rtp( 'send_recv', $files[0] ),
    cb_rtp_done => \$rtp_done,
    recv_bye => \$peer_hangup,
    cb_noanswer => \$no_answer,
    ring_time => $ring_time,
) || die "invite failed: ".$ua->error;
die "invite failed(call): ".$call->error if $call->error;

DEBUG( "Call established (maybe), sending first file $files[0]" );
$ua->loop( \$rtp_done,\$peer_hangup,\$no_answer );

die "Ooops, no answer." if $no_answer;

# mainloop until other party hangs up or we are done
# send one file after the other using re-invites
while ( ! $peer_hangup ) {

    shift(@files); # done with file
    @files || last;

    # re-invite on current call for next file
    DEBUG( "rtp_done=$rtp_done" );
    my $rtp_done;
    $call->reinvite(
	init_media => $ua->rtp( 'send_recv', $files[0] ),
	cb_rtp_done => \$rtp_done,
	recv_bye => \$peer_hangup, # FIXME: do we need to repeat this?
    );
    DEBUG( "sending next file $files[0]" );
    $ua->loop( \$rtp_done,\$peer_hangup );
}

if ( !$peer_hangup ) {
    # no more files: hangup
    my $stopvar;
    $call->bye( cb_final => \$stopvar );
    $ua->loop( \$stopvar );
} elsif ( $failonhang ) {
    die "Remote hanged";
}

