#!/usr/bin/perl
# testing behavior with inactive channels (i.e. no data receive):
# - 4 audio channels are used in SDP
# - UAC has channels 0,2 and 3 active,  UAS channels 0,1 and 3
# - both use RTP send_recv
# - expected is that UAC sends from 0,1,3 (i.e. active on UAS for receiving
#   traffic) but receives on 0,2,3. UAS sends on 0,2,3 and receives on 0,1,3

use strict;
use warnings;
use Test::More;
do './testlib.pl' || do './t/testlib.pl' || die "no testlib";

use Net::SIP ':all';

my @active_uac = (1,0,1,1);
my @active_uas = (1,1,0,1);

my @tests;
for my $transport (qw(udp tcp tls)) {
    for my $family (qw(ip4 ip6)) {
	push @tests, [ $transport, $family ];
    }
}

my $testsize = 12;
plan tests => $testsize*@tests;

for my $t (@tests) {
    my ($transport,$family) = @$t;
    SKIP: {
	if (my $err = test_use_config($family,$transport)) {
	    skip $err,$testsize;
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
	fd_grep_ok( 'Call created',$uas );
	fd_grep_ok( 'Call established',$uas );

	# RTP transfer
	fd_grep_ok( 'Start RTP', $uac );
	fd_grep_ok( 'RTP#100#', $uac );
	fd_grep_ok( 'got rtp packet#100', $uac );

	# BYE from UAC
	fd_grep_ok( 'Send BYE',$uac );
	fd_grep_ok( "BYE done (@active_uas -- @active_uac)",$uac );
	fd_grep_ok( "Call done (@active_uac -- @active_uas)",$uas );
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

    # call with three channels, one inactive
    my $stop_rtp;
    my @csend = my @crecv = map { 0 } @active_uac;
    my ($sdp,$fd) = _create_sdp($lsock->sockhost, \@active_uac);
    my $call = $ua->invite( test_sip_uri("uas\@$peer"),
	sdp => $sdp,
	media_lsocks => $fd,
	init_media => $ua->rtp('send_recv',
	    [\&_send_rtp, \( my $i = 0), \@csend],1,
	    [\&_recv_rtp, \( my $j = 0), \@crecv, \$stop_rtp],
	),
    ) or die;
    $ua->loop(5,\$stop_rtp);

    # and bye
    print "Send BYE\n";
    $call->bye( cb_final => \( my $bye_ok ));
    $ua->loop( 10,\$bye_ok );
    $ua->cleanup;
    $_ = $_>0 ? 1:0 for(@csend,@crecv);
    print "BYE done (@csend -- @crecv)\n" if $bye_ok;
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

    # call with three channels, one inactive
    my $stop;
    my @csend = my @crecv = map { 0 } @active_uas;
    my ($sdp,$fd) = _create_sdp($lsock->sockhost, \@active_uas);
    $ua->listen(
	cb_create => sub { print "Call created\n"; 1 },
	cb_established => sub { print "Call established\n"; 1 },
	cb_cleanup => \$stop,
	media_lsocks => $fd,
	sdp => $sdp,
	init_media => $ua->rtp('send_recv',
	    [\&_send_rtp, \( my $i = 0), \@csend],1,
	    [\&_recv_rtp, \( my $j = 0), \@crecv, undef],
	),
    );
    print "Listening\n";
    $ua->loop(10, \$stop);
    $_ = $_>0 ? 1:0 for(@csend,@crecv);
    print "Call done (@csend -- @crecv)\n";

    $ua->cleanup;
}

sub _create_sdp {
    my ($laddr,$active) = @_;
    my (@media,@fd);
    for(@$active) {
	my ($port,@sock) = create_rtp_sockets($laddr);
	push @fd,\@sock;
	push @media, {
	    port => $_ ? $port : 0,
	    proto => 'RTP/AVP',
	    media => 'audio',
	    fmt => 0,
	}
    }
    return (Net::SIP::SDP->new({ addr => $laddr}, @media), \@fd);
}

sub _send_rtp {
    my ($iref,$count,$seq,$channel) = @_;
    $count->[$channel]++;
    $$iref++;
    if ( $$iref == 1 ) {
	print "Start RTP\n";
    } elsif ( $$iref % 100 == 0 ) {
	# log after each seconds
	print "RTP#$$iref#\n";
    }
    #DEBUG( "send packet $$iref" );
    return "0123456789" x 16;
}

sub _recv_rtp {
    my ($iref,$count,$stopvar,$payload,$seq,$ts,$channel) = @_;
    $$iref++;
    DEBUG(50,"got data $$iref on $channel");
    $count->[$channel]++;
    if ($stopvar && $$iref == 100) {
	print "got rtp packet#100\n";
	$$stopvar = 1;
    }
}
