#!/usr/bin/perl

###########################################################################
# creates a UAC, a UAS and a stateless proxy using Net::SIP::Simple
# makes call from UAC to UAS via proxy
# transfers RTP data during call, then hangs up
###########################################################################

use strict;
use warnings;
use Test::More tests => 13;
do './testlib.pl' || do './t/testlib.pl' || die "no testlib";

use Net::SIP ':all';
use IO::Socket;
use File::Temp;


my ($luac,$luas,@lproxy);
for ( $luac,$luas,$lproxy[0],$lproxy[1] ) {
	my $sock = IO::Socket::INET->new(
		Proto     => 'udp',
		LocalAddr => '127.0.0.1',
		LocalPort => 0, # let system pick one
	) || die $!;
	my ($port,$host) = unpack_sockaddr_in ( getsockname($sock) );
	$_ = {
		sock => $sock, 
		addr => inet_ntoa( $host ).":$port" 
	};
}

diag( "UAS on $luas->{addr} " );
diag( "UAC on $luac->{addr} " );
diag( "PROXY on $lproxy[0]{addr} $lproxy[1]{addr} " );

# because all is on the same IP we have to restrict the legs of
# the proxy somehow to get the routing right
$lproxy[0]{leg} = TestLeg->new(
	sock => $lproxy[0]{sock},
	can_deliver_to => $luac->{addr},
);
$lproxy[1]{leg} = TestLeg->new(
	sock => $lproxy[1]{sock},
	can_deliver_to => $luas->{addr},
);


# start proxy and UAS and wait until they are ready
my $proxy = fork_sub( 'proxy', @lproxy,$luas->{addr} );
my $uas   = fork_sub( 'uas', $luas );
fd_grep_ok( 'ready',10,$proxy ) || die;
fd_grep_ok( 'ready',10,$uas ) || die;

# UAC: invite and transfer RTP data
my $uac   = fork_sub( 'uac', $luac, $lproxy[0]{addr} );
fd_grep_ok( 'ready',10,$uac ) || die;
fd_grep_ok( 'call created',10,$uas );

# top via must be from lproxy[1], next via from UAC
# this is to show that the request went through the proxy
fd_grep_ok( "via: SIP/2.0/UDP $lproxy[1]{addr};",1,$uas );
fd_grep_ok( "via: SIP/2.0/UDP $luac->{addr};",1,$uas );

# done
fd_grep_ok( 'RTP done',10,$uac );
fd_grep_ok( 'RTP ok',10,$uas );
fd_grep_ok( 'END',10,$uac );
fd_grep_ok( 'END',10,$uas );

killall();
exit(0);

# --------------------------------------------------------------
# Proxy
# --------------------------------------------------------------
sub proxy {
	my @lsock = @_;
	my $proxy_addr = pop @lsock;
	# create Net::SIP::Simple object
	my $proxy = Simple->new(
		leg => [ map { $_->{leg} } @lsock ],
		domain2proxy => { 'example.com' => $proxy_addr },
	);
	$proxy->create_stateless_proxy;
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
		leg  => $lsock->{sock},
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
	my ($sock) = @_;
	my $uas = Simple->new(
		domain => 'example.com',
		leg => $sock
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

