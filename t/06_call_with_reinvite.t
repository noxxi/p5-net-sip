#!/usr/bin/perl

#############################################################################
#
#  - UAS listens
#  - UAC calls UAS
#  - UAS accepts call
#  - UAC sends some data to UAS
#  - after some time UAS re-invites UAC
#  - UAC accepts
#  - UAS sends some data to UAC
#  - after a while UAC hangs up
#
#############################################################################

use strict;
use warnings;
use Test::More tests => 17*6;
do './testlib.pl' || do './t/testlib.pl' || die "no testlib";

use Net::SIP ':all';

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
	    skip $err,17;
	    next;
	}
	note("------- test with family $family transport $transport");

	my ($csock,$caddr) = create_socket($transport);
	my ($ssock,$saddr) = create_socket($transport);

	# start UAS
	my $uas = fork_sub( 'uas',$ssock,$caddr,$saddr );
	fd_grep_ok( 'Listening',$uas );

	# start UAC once UAS is ready
	my $uac = fork_sub( 'uac',$csock,$caddr,$saddr );
	fd_grep_ok( 'Started',$uac );
	fd_grep_ok( 'Call accepted',$uas );

	# first RTP from UAC to UAS
	fd_grep_ok( 'Start RTP', $uac );
	fd_grep_ok( 'RTP#50#', $uac );
	fd_grep_ok( 'got rtp packet#50', $uas );

	# then re-invite
	fd_grep_ok( 'Starting ReInvite', $uas );
	fd_grep_ok( 'Got ReInvite', $uac );

	# RTP from UAS to UAC
	fd_grep_ok( 'Start RTP', $uas );
	fd_grep_ok( 'RTP#50#', $uas );
	fd_grep_ok( 'got rtp packet#50', $uac );

	# BYE from UAC
	fd_grep_ok( 'Send BYE',$uac );
	fd_grep_ok( 'Got RTP',$uas );
	fd_grep_ok( 'Received BYE',$uas );
	fd_grep_ok( 'BYE done',$uac );
    }
}


killall();


#############################################################################
#            UAC
#############################################################################

sub uac {
    my ($lsock,$laddr,$peer) = @_;
    my $ua = Simple->new(
	from => test_sip_uri("uac\@$laddr"),
	leg => Net::SIP::Leg->new(
	    sock => $lsock,
	    test_leg_args('caller.sip.test'),
	)
    );
    print "Started\n";

    # call and transfer data until I get reinvite
    # then change RTP handling to recv_echo and stop after 50 packets

    my ($reinvite,$stop_rtp50);
    my $switch_media_on_reinvite = sub {
	my ($ok,$call) = @_;
	DEBUG( "switch media" );
	$call->set_param(
	    init_media => $call->rtp( 'recv_echo', [ \&_recv_rtp, \( my $i=0 ), \$stop_rtp50 ] ),
	);
	$reinvite = 1;
    };

    my $call = $ua->invite( test_sip_uri("uas\@$peer"),
	init_media => $ua->rtp( 'send_recv', [ \&_send_rtp, \( my $i = 0) ] ),
	cb_established => $switch_media_on_reinvite,
	clear_sdp => 1, # don't reuse sockets from last RTP session
    ) || die;

    # wait for reinvite done
    $ua->loop( 10,\$reinvite );
    $reinvite || die;
    print "Got ReInvite\n";

    # wait until 50 packets received from the new connection
    $ua->loop( 5,\$stop_rtp50 );

    # and bye
    print "Send BYE\n";
    $call->bye( cb_final => \( my $bye_ok ));
    $ua->loop( 10,\$bye_ok );
    print "BYE done\n" if $bye_ok;


}


#############################################################################
#            UAS
#############################################################################

sub uas {
    my ($lsock,$laddr,$peer) = @_;
    my $ua = Simple->new(
	from => test_sip_uri("uas\@$laddr"),
	leg => Net::SIP::Leg->new(
	    sock => $lsock,
	    test_leg_args('listen.sip.test'),
	)
    );

    # accept call and send some data, set $stop once
    # the call was established
    my $stop = 0;
    my $stop_rtp50 = 0;
    my $call;
    my $init_media_recv = sub {
	(undef,$call) = @_;
	DEBUG( "accepted call" );
	$call->set_param( init_media =>
	    $call->rtp( 'recv_echo', [ \&_recv_rtp, \( my $i=0 ), \$stop_rtp50 ],-1 )
	);
	$stop = 1;
    };
    $ua->listen( cb_established => $init_media_recv );
    print "Listening\n";
    $ua->loop( \$stop );
    print "Call accepted\n";

    # wait until I got 50 packets
    $ua->loop( \$stop_rtp50 );

    # Reinvite and send data until I get BYE
    print "Starting ReInvite\n";
    my $bytes = 0;
    my $write_bytes = sub { $bytes += length($_[0]) };
    my $recv_bye = 0;
    my $init_media_send = sub {
	my ($ok,$call) = @_;
	DEBUG( "init media because re-invite was $ok" );
	$stop = 1;
	$ok eq 'OK' or die;
	$call->set_param(
	    init_media => $call->rtp(
		'send_recv',
		[ \&_send_rtp, \( my $i=0 ) ],
		1,
		$write_bytes
	    ),
	    recv_bye => \$recv_bye,
	);
    };
    $stop = 0;
    $call->reinvite(
	clear_sdp => 1,
	cb_final => $init_media_send,
    );

    # wait until INVITE succeeds
    $ua->loop( 10,\$stop );
    print "ReInvite succeeded\n" if $stop eq 'OK';
    print "ReInvite FAILED\n" if $stop eq 'FAIL';

    # wait until I got BYE
    $ua->loop( 10, \$recv_bye );
    print "Got RTP\n" if $bytes;
    print "Received BYE\n" if $recv_bye;

    # make sure the reply for the BYE makes it on the wire
    $ua->loop(1);
}


sub _send_rtp {
    my $iref = shift;
    $$iref++;
    if ( $$iref == 1 ) {
	print "Start RTP\n";
    } elsif ( $$iref % 50 == 0 ) {
	# log after each seconds
	print "RTP#$$iref#\n";
    }
    #DEBUG( "send packet $$iref" );
    return "0123456789" x 16;
}

sub _recv_rtp {
    my ($iref,$stopvar,$payload) = @_;
    $$iref++;
    #DEBUG( 50,"got data $$iref" );
    if ( $$iref == 50 ) {
	print "got rtp packet#50\n";
	$$stopvar = 1;
    }
}
