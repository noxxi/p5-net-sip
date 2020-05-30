#!/usr/bin/perl

###########################################################################
# creates a UAC and a UAS using Net::SIP::Simple
# and makes call from UAC to UAS,
# transfer RTP data during call, then hang up
###########################################################################

use strict;
use warnings;
use Test::More tests => 9*6*2;
do './testlib.pl' || do './t/testlib.pl' || die "no testlib";

use Net::SIP ':all';
use IO::Socket;
use File::Temp;

my @tests;
for my $transport (qw(udp tcp tls)) {
    for my $family (qw(ip4 ip6)) {
	for my $codec (qw(pcmu pcma)) {
	    push @tests, [ $transport, $family, $codec ];
	}
    }
}

for my $t (@tests) {
    my ($transport,$family,$codec) = @$t;
    SKIP: {
	if (my $err = test_use_config($family,$transport)) {
	    skip $err,9;
	    next;
	}

	note("------- test with family $family transport $transport codec $codec");

	# create leg for UAS on dynamic port
	my ($sock_uas,$uas_addr) = create_socket($transport);
	diag( "UAS on $uas_addr" );

	# fork UAS and make call from UAC to UAS
	pipe( my $from_uas,my $to_uac); # for status updates
	defined( my $pid = fork() ) || die $!;

	if ( $pid == 0 ) {
	    # CHILD = UAS
	    $SIG{ __DIE__ } = undef;
	    close($from_uas);
	    $to_uac->autoflush;
	    uas( $sock_uas, $to_uac, $codec );
	    exit(0);
	}

	# PARENT = UAC
	close($sock_uas);
	close($to_uac);

	alarm(60);
	local $SIG{__DIE__} = sub { kill 9,$pid; ok( 0,'died' ) };
	local $SIG{ALRM} =    sub { kill 9,$pid; ok( 0,'timed out' ) };

	uac(test_sip_uri($uas_addr), $from_uas, $codec);

	my $uas = <$from_uas>;
	killall();

	is( $uas, "UAS finished events=1 2 D # 3 4 B *\n", "UAS finished with DTMF" );
    }
}

sub rtp_param {
    my ($codec) = @_;
    my %rtp_params = (pcmu => [0,160,160/8000], pcma => [8,160,160/8000]);
    return $rtp_params{$codec} if exists $rtp_params{$codec};
    die "Unknown codec '$codec'";
}

###############################################
# UAC
###############################################

sub uac {
    my ($peer_uri,$from_uas,$codec) = @_;
    Debug->set_prefix( "DEBUG(uac):" );

    # line noise when no DTMF is sent
    my $packets = 250; # 5 seconds
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
    diag( "UAC on $laddr" );
    my $uac = Net::SIP::Simple->new(
	from => 'me.uac@example.com',
	domain2proxy => { 'example.com' => $peer_uri },
	leg => Net::SIP::Leg->new(
	    sock => $lsock,
	    test_leg_args('caller.sip.test'),
	)
    );
    ok( $uac, 'UAC created' );

    # wait until UAS is ready and listening
    my $uas = <$from_uas>;
    is( $uas, "UAS ready\n","UAS ready" );

    # Call UAS
    my @events;
    my $call = $uac->invite(
	test_sip_uri('you.uas@example.com'),
	init_media  => $uac->rtp( 'send_recv', $send_something ),
	rtp_param   => rtp_param($codec),
	cb_rtp_done => \$rtp_done,
	cb_dtmf => sub {
	    push @events,shift;
	}
    );
    ok( ! $uac->error, 'no error on UAC' );
    ok( $call, 'Call established' );

    $call->dtmf('12D#',methods => 'rfc2833', duration => 500);
    $call->dtmf('34B*',methods => 'audio', duration => 500);

    $call->loop( \$rtp_done, 20 );
    ok( $rtp_done, "Done sending RTP" );

    my $stop;
    $call->bye( cb_final => \$stop );
    $call->loop( \$stop,30 );
    ok( $stop, 'UAS down' );

    $uas = <$from_uas>;
    like($uas, qr/UAS RTP ok/, "UAS RTP ok");
    # DTMF echoed back
    is( "@events","1 2 D # 3 4 B *", "UAC DTMF received");
    $uac->cleanup;
}

###############################################
# UAS
###############################################

sub uas {
    my ($sock,$to_uac,$codec) = @_;
    Debug->set_prefix( "DEBUG(uas):" );
    my $uas = Net::SIP::Simple->new(
	domain => 'example.com',
	leg => Net::SIP::Leg->new(
	    sock => $sock,
	    test_leg_args('listen.sip.test'),
	)
    ) || die $!;

    # count received RTP data
    my $received = my $lost = my $lastseq = 0;
    my $save_rtp = sub {
	my ($buf,$seq) = @_;
	#warn substr( $buf,0,10)."\n";
	my $diff = $seq - $lastseq;
	if ($diff == 0) {
	    diag("duplicate $seq");
	    next;
	} elsif ($diff<0) {
	    diag("out of order $seq");
	    next;
	}
	if ($diff>1) {
	    $lost += $diff-1;
	    diag(sprintf("lost %d packets (%d-%d)",
		$diff-1,$lastseq+1,$seq-1));
	}
	$received++;
	$lastseq = $seq;
    };

    # Listen
    my ($call_closed,@events);
    $uas->listen(
	cb_create      => sub { diag( 'call created' );1 },
	cb_established => sub { diag( 'call established' );1 },
	cb_cleanup     => sub {
	    diag( 'call cleaned up' );
	    $call_closed =1;
	},
	init_media     => $uas->rtp( 'recv_echo', $save_rtp ),
	rtp_param      => rtp_param($codec),
	cb_dtmf => sub {
	    push @events,shift
	}
    );

    # notify UAC process that I'm listening
    print $to_uac "UAS ready\n";

    # Loop until call is closed, at most 20 seconds
    $uas->loop( \$call_closed, 20 );
    $uas->cleanup;

    # 5 seconds line noise, 8 events a 500 ms and some pause in between
    my $xrtpc = 5*50 + 8*25 + 7*2.5;

    diag("received=$received lost=$lost expect ca. $xrtpc packets, events='@events'");

    # at least 20% of all RTP packets should come through
    if ( $received > $xrtpc * 0.8) {
	print $to_uac "UAS RTP ok ($received,$lost)\n"
    } else {
	print $to_uac "UAS RTP received only $received/$xrtpc packets, lost $lost\n";
    }

    # done
    if ( $call_closed ) {
	print $to_uac "UAS finished events=@events\n";
    } else {
	print $to_uac "call closed by timeout not stopvar\n";
    }
}
