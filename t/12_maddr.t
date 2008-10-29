#!/usr/bin/perl

###########################################################################
# creates a UAC and a UAS using Net::SIP::Simple
# and makes call from UAC to UAS,
# Call does not involve transfer of RTP data
###########################################################################

use strict;
use warnings;
use Test::More tests => 8;

use Net::SIP;
use Net::SIP::Util ':all';
use IO::Socket;

# create leg for UAS on dynamic port
my $sock_uas = IO::Socket::INET->new(
	Proto => 'udp',
	LocalAddr => '127.0.0.1',
	LocalPort => 0, # let system pick one
);
ok( $sock_uas, 'create UAS socket' );

# get address for UAS
my $uas_addr = $sock_uas->sockhost.':'.$sock_uas->sockport;


# fork UAS and make call from UAC to UAS
pipe( my $read,my $write); # to sync UAC with UAS
my $pid = fork();
if ( defined($pid) && $pid == 0 ) {
	close($read);
	$write->autoflush;
	uas( $sock_uas, $write );
	exit(0);
}

ok( $pid, "fork successful" );
close( $sock_uas );
close($write);

alarm(15);
$SIG{__DIE__} = $SIG{ALRM} = sub { kill 9,$pid; ok( 0,'died' ) };

uac( $uas_addr,$read );
ok( <$read>, "UAS finished" );
wait;

###############################################
# UAC
###############################################

sub uac {
	my ($peer,$pipe) = @_;
	Net::SIP::Debug->set_prefix( "DEBUG(uac):" );

	ok( <$pipe>, "UAS created\n" ); # wait until UAS is ready
	my $uac = Net::SIP::Simple->new(
		from => 'me.uac@example.com',
		leg => scalar(create_socket_to( $peer )),
	);
	ok( $uac, 'UAC created' );

	ok( <$pipe>, "UAS ready\n" ); # wait until UAS is ready
	my $ringing = 0;
	my ($peer_addr,$peer_port) = split( ':',$peer );
	my $call = $uac->invite( 
		"<sip:you.uas\@example.com:$peer_port;maddr=$peer_addr>",
	);
	my $stop;
	if ( $call ) {
		ok( $call, 'Call established' );
		$call->loop(1);
		$call->bye( cb_final => \$stop );
		$call->loop( \$stop,10 );
	}
	ok( $stop, 'UAS down' );
}

###############################################
# UAS
###############################################

sub uas {
	my ($sock,$pipe) = @_;
	Net::SIP::Debug->set_prefix( "DEBUG(uas):" );
	my $uas = Net::SIP::Simple->new(
		domain => 'example.com',
		leg => $sock
	) || die $!;
	print $pipe "UAS created\n";

	# Listen
	my $call_closed;
	$uas->listen(
		cb_established => sub { diag( 'call established' ) },
		cb_cleanup     => sub {
			diag( 'call cleaned up' );
			$call_closed =1;
		},
	);

	# notify UAC process that I'm listening
	print $pipe "UAS ready\n";

	# Loop until call is closed, at most 10 seconds
	$uas->loop( \$call_closed, 10 );

	# done
	if ( $call_closed ) {
		print $pipe "UAS finished\n";
	} else {
		print $pipe "call closed by timeout not stopvar\n";
	}
}
