
use strict;
use warnings;

use Net::SIP;
use Net::SIP::Debug;
use Getopt::Long qw(:config posix_default bundling);


my $debug = 100;
my $from  = 'sip:100@192.168.56.1';
my $to    = 'sip:*69@192.168.56.101';
my $user  = '100';
my $pass  = 'password1234'; 
my $outf  = 'record.raw';
my $hangup = 30; # hang up after 30 sec
my $dtmf  = 'ABCD*#123--4567890';

Net::SIP::Debug->level($debug);
my $leg = Net::SIP::Leg->new( addr => '192.168.56.1' );
my $ua = Net::SIP::Simple->new(
	from => $from,
	auth => [ $user,$pass ],
	leg  => $leg,
);

# invite peer
my $peer_hangup; # did peer hang up?
my $call = $ua->invite( $to,
	# echo back, use -1 instead of 0 for not echoing back
	init_media => $ua->rtp( 'recv_echo',$outf,0 ),
	recv_bye => \$peer_hangup,
) || die "invite failed: ".$ua->error;
die "invite failed(call): ".$call->error if $call->error;

my $dtmf_done;
$call->dtmf( $dtmf, cb_final => \$dtmf_done );

my $stopvar;
$ua->add_timer($hangup,\$stopvar);
$ua->loop( \$stopvar,\$peer_hangup,\$dtmf_done );

# timeout or dtmf done, hang up
if ( $stopvar || $dtmf_done ) {
	$stopvar = undef;
	$call->bye( cb_final => \$stopvar );
	$ua->loop( \$stopvar );
}

