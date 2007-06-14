#!/usr/bin/perl

###########################################################################
# creates a UAC, a UAS and a stateless proxy using Net::SIP::Simple
# makes call from UAC to UAS via proxy
# transfers RTP data during call, then hangs up
# tests will be done without NAT, with inline NAT and with external nathelper
###########################################################################

use strict;
use warnings;
use Test::More tests => 63;
do './testlib.pl' || do './t/testlib.pl' || die "no testlib";

use Net::SIP ':all';
use Net::SIP::NATHelper::Local;
use Net::SIP::NATHelper::Server;
use Net::SIP::NATHelper::Client;
use IO::Socket;
use File::Temp;
use List::Util;

my ($luac,$luas,@lproxy);
for ( $luac,$luas,$lproxy[0],$lproxy[1] ) {
	my ($sock,$addr) = create_socket();
	$_ = { sock => $sock, addr => $addr };
}

diag( "UAS on $luas->{addr} " );
diag( "UAC on $luac->{addr} " );
diag( "PROXY on $lproxy[0]{addr} $lproxy[1]{addr} " );

# restrict legs of proxy so that packets gets routed even
# if all is on the same interface. Enable dumping on
# incoing and outgoing packets to check NAT
for ( $luac,$luas,$lproxy[0],$lproxy[1] ) {
	$_->{leg} = TestLeg->new(
		sock          => $_->{sock},
		dump_incoming => [ \&sip_dump_media,'I<' ],
		dump_outgoing => [ \&sip_dump_media,'O>' ],
		$_ == $lproxy[0] ? ( can_deliver_to => $luac->{addr} ) :(),
		$_ == $lproxy[1] ? ( can_deliver_to => $luas->{addr} ) :(),
	);
}

# socket for nathelper server
my $nath_sock = IO::Socket::INET->new(
	Listen => 10,
	LocalAddr => '127.0.0.1',
	# use any port
) || die $!;
my $nath_addr = do {
	my ($p,$a) = unpack_sockaddr_in( $nath_sock->sockname );
	inet_ntoa($a).':'.$p
};


foreach my $spec ( qw( no-nat inline-nat remote-nat )) {

	my $natcb;
	if ( $spec eq 'inline-nat' ) {
		$natcb = sub { NATHelper_Local->new( shift ) };
	} elsif ( $spec eq 'remote-nat' ) {
		fork_sub( 'nathelper',$nath_sock );
		$natcb = sub { NATHelper_Client->new( $nath_addr ) }
	}

	# start proxy and UAS and wait until they are ready
	my $proxy = fork_sub( 'proxy', @lproxy,$luas->{addr},$natcb );
	my $uas   = fork_sub( 'uas', $luas );
	fd_grep_ok( 'ready',10,$proxy ) || die;
	fd_grep_ok( 'ready',10,$uas ) || die;

	# UAC: invite and transfer RTP data
	my $uac   = fork_sub( 'uac', $luac, $lproxy[0]{addr} );
	fd_grep_ok( 'ready',10,$uac ) || die;
	my $uac_invite  = fd_grep_ok( qr{O>.*REQ\(INVITE\) SDP: audio=\S+},5,$uac ) || die;
	my $pin_invite  = fd_grep_ok( qr{I<.*REQ\(INVITE\) SDP: audio=\S+},5,$proxy ) || die;
	my $pout_invite = fd_grep_ok( qr{O>.*REQ\(INVITE\) SDP: audio=\S+},1,$proxy ) || die;
	my $uas_invite  = fd_grep_ok( qr{I<.*REQ\(INVITE\) SDP: audio=\S+},1,$uas ) || die;
	s{.*audio=}{} for ( $uac_invite,$pin_invite,$pout_invite,$uas_invite );

	# check for NAT
	ok( $uac_invite  eq $pin_invite, "outgoing on UAC must be the same as incoming on proxy" );
	ok( $pout_invite eq $uas_invite, "outgoing on proxy must be the same as incoming on UAS" );
	if ( $spec eq 'no-nat' ) {
		ok( $uac_invite eq $uas_invite, "SDP must pass unchanged to UAS" );
	} else {
		# get port/range and compare
		my ($sock_i,$range_i) = split( m{/},$pin_invite,2 );
		my ($sock_o,$range_o) = split( m{/},$pout_invite,2 );
		ok( $sock_i ne $sock_o, "allocated addr:port must be different ($sock_i|$sock_o)" );
		ok( $range_i == $range_o, "ranges must stay the same" );
	}

	# top via must be from lproxy[1], next via from UAC
	# this is to show that the request went through the proxy
	fd_grep_ok( 'call created',10,$uas );
	fd_grep_ok( "via: SIP/2.0/UDP $lproxy[1]{addr};",1,$uas );
	fd_grep_ok( "via: SIP/2.0/UDP $luac->{addr};",1,$uas );

	# done
	fd_grep_ok( 'RTP done',10,$uac );
	fd_grep_ok( 'RTP ok',10,$uas );
	fd_grep_ok( 'END',10,$uac );
	fd_grep_ok( 'END',10,$uas );

	killall();
}


# --------------------------------------------------------------
# Proxy
# --------------------------------------------------------------
sub proxy {
	my ($lsock_c,$lsock_s,$proxy_addr,$natcb) = @_;

	# need loop seperatly
	my $loop = Dispatcher_Eventloop->new;
	my $nathelper = invoke_callback( $natcb,$loop );

	# create Net::SIP::Simple object
	my $proxy = Simple->new(
		loop => $loop,
		legs => [ $lsock_c->{leg}, $lsock_s->{leg} ],
		domain2proxy => { 'example.com' => $proxy_addr },
	);
	$proxy->create_stateless_proxy(
		nathelper => $nathelper
	);
	print "ready\n";
	$proxy->loop;
}

# --------------------------------------------------------------
# UAC
# --------------------------------------------------------------
sub uac {
	my ($lsock,$proxy) = @_;

	my $packets = 100;
	my $send_something = sub {
		return unless $packets-- > 0;
		my $buf = sprintf "%010d",$packets;
		$buf .= "1234567890" x 15;
		return $buf; # 160 bytes for PCMU/8000
	};

	# create Net::SIP::Simple object
	my $uac = Simple->new(
		from => 'me.uac@example.com',
		leg  => $lsock->{leg},
		outgoing_proxy => $proxy,
	) || die;
	print "ready\n";

	# Call UAS vi proxy
	my $rtp_done;
	my $call = $uac->invite(
		'you.uas@example.com',
		init_media  => $uac->rtp( 'send_recv', $send_something ),
		cb_rtp_done => \$rtp_done,
	);
	print "call established\n" if $call && ! $uac->error;

	$call->loop( \$rtp_done, 10 );
	print "RTP done\n" if $rtp_done;

	my $stop;
	$call->bye( cb_final => \$stop );
	$call->loop( \$stop,10 );
	print "END\n";
}

# --------------------------------------------------------------
# UAS
# --------------------------------------------------------------
sub uas {
	my ($leg) = @_;
	my $uas = Simple->new(
		domain => 'example.com',
		leg => $leg->{leg}
	) || die $!;

	# store received RTP data in array
	my @received;
	my $save_rtp = sub {
		my $buf = shift;
		push @received,$buf;
		#warn substr( $buf,0,10)."\n";
	};

	# Listen
	my $call_closed;
	my $cb_create = sub {
		my ($call,$request) = @_;
		print "call created\n";
		print $request->as_string;
		1;
	};
	$uas->listen(
		cb_create      => $cb_create,
		cb_established => sub { print "call established\n" },
		cb_cleanup     => sub {
			print "call cleaned up\n";
			$call_closed =1;
		},
		init_media     => $uas->rtp( 'recv_echo', $save_rtp ),
	);
	print "ready\n";

	# Loop until call is closed, at most 10 seconds
	$uas->loop( \$call_closed, 10 );
	print "received ".int(@received)."/100 packets\n";

	# at least 20% of all RTP packets should come through
	if ( @received > 20 ) {
		print "RTP ok\n"
	} else {
		print "RTP received only ".int(@received)."/100 packets\n";
	}

	# done
	if ( $call_closed ) {
		print "END\n";
	} else {
		print "call closed by timeout not stopvar\n";
	}
}

# --------------------------------------------------------------
# NATHelper::Server
# --------------------------------------------------------------
sub nathelper {
	my $sock = shift;
	NATHelper_Server->new( $sock )->loop;
}
