#!/usr/bin/perl

###########################################################################
# creates a UAC and a UAS using Net::SIP::Simple
# and makes call from UAC to UAS,
# transfer RTP data during call, then hang up
###########################################################################

use strict;
use warnings;
use Test::More tests => 8*6;
do './testlib.pl' || do './t/testlib.pl' || die "no testlib";

use Net::SIP ':all';
use IO::Socket;
use File::Temp;

my @tests;
for my $transport (qw(udp tcp tls)) {
    for my $family (qw(ip4 ip6)) {
	push @tests, [ $transport, $family ];
    }
}

for my $t (@tests) {
    my ($transport,$family) = @$t;
    SKIP: {
	if (my $err = test_use_config($family,$transport)) {
	    skip $err,8;
	    next;
	}
	note("------- test with family $family transport $transport");
	do_test($transport);
    }
}


sub do_test {
    my $transport = shift;
    # create leg for UAS on dynamic port
    my ($sock_uas,$uas_addr) = create_socket($transport);
    note( "UAS on $uas_addr" );

    # fork UAS and make call from UAC to UAS
    pipe( my $read,my $write); # for status updates
    defined( my $pid = fork() ) || die $!;
    if ( $pid == 0 ) {
	# CHILD = UAS
	$SIG{__DIE__} = undef;
	close($read);
	$write->autoflush;
	uas( $sock_uas, $write );
	exit(0);
    }

    local $SIG{__DIE__} = sub { kill 9,$pid if $pid; ok( 0,'died' ) };
    local $SIG{ALRM}    = sub { kill 9,$pid if $pid; ok( 0,'timed out' ) };
    alarm(30);

    # PARENT = UAC
    close( $sock_uas );
    close($write);

    uac(test_sip_uri($uas_addr), $read);
    ok( <$read>, "UAS finished" );
    killall();
}

###############################################
# UAC
###############################################

sub uac {
    my ($peer_uri,$pipe) = @_;
    Debug->set_prefix( "DEBUG(uac):" );

    my $packets = 100;
    my $send_something = sub {
	return unless $packets-- > 0;
	my $buf = sprintf "%010d",$packets;
	$buf .= "1234567890" x 15;
	return $buf; # 160 bytes for PCMU/8000
    };

    # create Net::SIP::Simple object
    my $rtp_done;
    my ($transport) = sip_uri2sockinfo($peer_uri);
    my ($lsock,$laddr) = create_socket($transport);
    note( "UAC on $laddr" );
    my $uac = Simple->new(
	from         => 'me.uac@example.com',
	domain2proxy => { 'example.com' => $peer_uri },
	leg          => Net::SIP::Leg->new(
	    sock => $lsock,
	    test_leg_args('caller.sip.test'),
	),
    );
    ok( $uac, 'UAC created' );

    # wait until UAS is ready and listening
    ok( <$pipe>, "UAS ready\n" );

    # Call UAS
    my $call = $uac->invite(
	'you.uas@example.com',
	init_media  => $uac->rtp( 'send_recv', $send_something ),
	cb_rtp_done => \$rtp_done,
    );
    ok( ! $uac->error, 'no error on UAC' );
    ok( $call, 'Call established' );

    $call->loop( \$rtp_done, 10 );
    ok( $rtp_done, "Done sending RTP" );

    my $stop;
    $call->bye( cb_final => \$stop );
    $call->loop( \$stop,10 );
    ok( $stop, 'UAS down' );

    ok( <$pipe>, "UAS RTP ok\n" );
    $uac->cleanup;
}

###############################################
# UAS
###############################################

sub uas {
    my ($sock,$pipe) = @_;
    Debug->set_prefix( "DEBUG(uas):" );
    my $uas = Simple->new(
	domain => 'example.com',
	leg => Net::SIP::Leg->new(
	    sock => $sock,
	    test_leg_args('listen.sip.test'),
	),
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
    $uas->listen(
	cb_create      => sub { note( 'call created' );1 },
	cb_established => sub { note( 'call established' ) },
	cb_cleanup     => sub {
	    note( 'call cleaned up' );
	    $call_closed =1;
	},
	init_media     => $uas->rtp( 'recv_echo', $save_rtp ),
    );

    # notify UAC process that I'm listening
    print $pipe "UAS ready\n";

    # Loop until call is closed, at most 10 seconds
    $uas->loop( \$call_closed, 10 );

    note( "received ".int(@received)."/100 packets" );

    # at least 20% of all RTP packets should come through
    if ( @received > 20 ) {
	print $pipe "UAS RTP ok\n"
    } else {
	print $pipe "UAS RTP received only ".int(@received)."/100 packets\n";
    }

    # done
    if ( $call_closed ) {
	print $pipe "UAS finished\n";
    } else {
	print $pipe "call closed by timeout not stopvar\n";
    }
}
