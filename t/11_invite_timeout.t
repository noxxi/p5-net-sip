#!/usr/bin/perl

###########################################################################
# creates a UAC and a UAS using Net::SIP::Simple
# and makes call from UAC to UAS,
# Call does not involve transfer of RTP data
# UAS will on ring, but never 200 Ok, UAC will cancel call
###########################################################################

use strict;
use warnings;
use Test::More tests => 7;

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

alarm(15);
$SIG{__DIE__} = $SIG{ALRM} = sub { kill 9,$pid; ok( 0,'died' ) };

uac( $uas_addr,$read );
ok( <$read>, "done" );
wait;

###############################################
# UAC
###############################################

sub uac {
	my ($peer_addr,$pipe) = @_;
	Net::SIP::Debug->set_prefix( "DEBUG(uac):" );

	ok( <$pipe>, "UAS created\n" ); # wait until UAS is ready
	my $uac = Net::SIP::Simple->new(
		from => 'me.uac@example.com',
		leg => scalar(create_socket_to( $peer_addr )),
		domain2proxy => { 'example.com' => $peer_addr },
	);
	ok( $uac, 'UAC created' );

	ok( <$pipe>, "UAS ready\n" ); # wait until UAS is ready
	my $canceled = 0;
	my $call = $uac->invite( 
		'you.uas@example.com',
		cb_noanswer => \$canceled,
		ring_time => 3,
	);
	ok( $canceled,"request was canceled" );
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

	my $timer;
	my $got_cancel;
	my $my_receive = sub {
		my ($self,$endpoint,$ctx,$error,$code,$packet,$leg,$from) = @_;
		if ( $packet->is_request && $packet->method eq 'INVITE' ) {
			# just ring
			my $ring = $packet->create_response( 180,'Ringing' );
			$timer ||= $endpoint->{dispatcher}->add_timer( 1, 
				sub { $endpoint->new_response( $ctx,$ring,$leg,$from ) },
				1 );
			return;
		}
		if ( $timer && $packet->is_request && $packet->method eq 'CANCEL' ) {
			$timer->cancel;
			$got_cancel =1;
		}
		goto &Net::SIP::Simple::Call::receive;
	};

	# Listen
	$uas->listen( cb_create => sub { return $my_receive } );

	# notify UAC process that I'm listening
	print $pipe "UAS ready\n";

	# Loop at most 10 seconds
	$uas->loop( 10,\$got_cancel );
	$uas->loop( 1 );
	print $pipe "UAS done\n";
}
