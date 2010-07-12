#!/usr/bin/perl

###########################################################################
# creates a UAC and a UAS using Net::SIP::Simple
# and makes call from UAC to UAS,
# Call does not involve transfer of RTP data
###########################################################################

use strict;
use warnings;
use Test::More tests => 8;

use Net::SIP ':alias';
use Net::SIP::Util ':all';
use IO::Socket;

use Net::SIP::Blocker;

# create leg for UAS on dynamic port
my $sock_uas = IO::Socket::INET->new(
	Proto => 'udp',
	LocalAddr => '127.0.0.1',
	LocalPort => 0, # let system pick one
);
ok( $sock_uas, 'create UAS socket' );

# get address for UAS
my $uas_addr = do {
	my ($port,$host) = unpack_sockaddr_in ( getsockname($sock_uas));
	inet_ntoa( $host ).":$port"
};


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

alarm(10);
$SIG{__DIE__} = $SIG{ALRM} = sub { kill 9,$pid; ok( 0,'died' ) };

uac( $uas_addr,$read );
ok( <$read>, "UAS finished" );
wait;

###############################################
# UAC
###############################################

sub uac {
	my ($peer_addr,$pipe) = @_;
	Debug->set_prefix( "DEBUG(uac):" );

	ok( <$pipe>, "UAS created\n" ); # wait until UAS is ready
	my $uac = Simple->new(
		from => 'me.uac@example.com',
		leg => scalar(create_socket_to( $peer_addr )),
		domain2proxy => { 'example.com' => $peer_addr },
	);
	ok( $uac, 'UAC created' );

	my $blocking;
	my $call = $uac->invite( 
		'you.uas@example.com',
		cb_final => sub { 
			my ($status,$self,%info) = @_;
			$blocking++ if $info{code} == 405;
		}
	);
	ok( ! $uac->error, 'UAC ready' );

	ok( <$pipe>, "UAS ready\n" ); # wait until UAS is ready

	$call->loop(\$blocking, 5);

	ok( $blocking,'UAC got block 405 and finished' );

	# done
	if ( $blocking ) {
		print $pipe "UAC finished\n";
	} else {
		print $pipe "call closed by timeout not stopvar\n";
	}

}

###############################################
# UAS
###############################################

sub uas {
	my ($sock,$pipe) = @_;
	Debug->set_prefix( "DEBUG(uas):" );

	my $leg = Leg->new( sock => $sock );
	my $loop = Dispatcher_Eventloop->new;
	my $disp = Dispatcher->new( [ $leg ],$loop ) || die $!;
	print $pipe "UAS created\n";

	# Blocking
	my $block = Net::SIP::Blocker->new(
		block => { 'INVITE' => 405 },
		dispatcher => $disp,
	);

	$disp->set_receiver( $block );
	print $pipe "UAS ready\n";

	$loop->loop(2);

	print $pipe "UAS finished\n";
}
