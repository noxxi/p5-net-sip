#!/usr/bin/perl
# testing behavior with inactive channels (i.e. no data receive) and Proxy
# like 20_channel_on_hold.t, only with proxy + NAT-helper in between

use strict;
use warnings;
use Test::More;
do './testlib.pl' || do './t/testlib.pl' || die "no testlib";

use Net::SIP ':all';
use Net::SIP::NATHelper::Local;
use Net::SIP::NATHelper::Server;
use Net::SIP::NATHelper::Client;

my @active_uac = (1,0,1,1);
my @active_uas = (1,1,0,1);

my @tests;
for my $transport (qw(udp tcp tls)) {
    for my $family (qw(ip4 ip6)) {
	for my $nat ('no-nat', 'inline-nat', 'remote-nat') {
	    push @tests, [ $transport, $family, $nat ];
	}
    }
}
my $testsize = 20;
plan tests => $testsize*@tests;

for my $t (@tests) {
    my ($transport,$family,$nat) = @$t;
    SKIP: {
	if (my $err = test_use_config($family,$transport)) {
	    skip $err,$testsize;
	    next;
	}
	note("------- test with family $family transport $transport $nat");
	do_test($transport,$nat)
    }
}

killall();

sub do_test {
    my ($transport,$natspec) = @_;

    my ($luac,$luas,@lproxy);
    for (
	[ 'caller.sip.test', \$luac ],
	[ 'listen.sip.test', \$luas ],
	[ 'proxy.sip.test', \$lproxy[0] ],
	[ 'proxy.sip.test', \$lproxy[1] ],
    ) {
	my ($name,$config) = @$_;
	my ($sock,$addr) = create_socket($transport);
	$$config = {
	    name => $name,
	    sock => $sock,
	    addr => $addr,
	    uri  => test_sip_uri($addr),
	};
    }

    note( "UAS on $luas->{addr} " );
    note( "UAC on $luac->{addr} " );
    note( "PROXY on $lproxy[0]{addr} $lproxy[1]{addr} " );

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
	    test_leg_args($_->{name}),
	);
    }

    # socket for nathelper server
    my ($nath_sock,$nath_addr) = create_socket('tcp') or die $!;

    my $natcb;
    if ( $natspec eq 'inline-nat' ) {
	$natcb = sub { NATHelper_Local->new( shift ) };
	ok(1,'no fork nathelper');
    } elsif ( $natspec eq 'remote-nat' ) {
	fork_sub( 'nathelper',$nath_sock );
	$natcb = sub { NATHelper_Client->new( $nath_addr ) }
    } else {
	ok(1,'no fork nathelper');
    }

    # start proxy and UAS and wait until they are ready
    my $proxy = fork_sub( 'proxy', @lproxy,$luas->{uri},$natcb );
    my $uas   = fork_sub( 'uas', $luas );
    fd_grep_ok( 'ready',10,$proxy ) || die;
    fd_grep_ok( 'ready',10,$uas ) || die;

    # UAC: invite and transfer RTP data
    my $uac   = fork_sub( 'uac', $luac, $lproxy[0]{uri} );
    fd_grep_ok( 'ready',10,$uac ) || die;
    my $uac_invite  = fd_grep_ok( qr{O>.*REQ\(INVITE\) SDP: audio=\S+},5,$uac ) || die;
    my $pin_invite  = fd_grep_ok( qr{I<.*REQ\(INVITE\) SDP: audio=\S+},5,$proxy ) || die;
    my $pout_invite = fd_grep_ok( qr{O>.*REQ\(INVITE\) SDP: audio=\S+},1,$proxy ) || die;
    my $uas_invite  = fd_grep_ok( qr{I<.*REQ\(INVITE\) SDP: audio=\S+},1,$uas ) || die;
    s{.*audio=}{} for ( $uac_invite,$pin_invite,$pout_invite,$uas_invite );

    # check for NAT
    ok( $uac_invite  eq $pin_invite, "outgoing on UAC must be the same as incoming on proxy" );
    ok( $pout_invite eq $uas_invite, "outgoing on proxy must be the same as incoming on UAS" );
    if ( $natspec eq 'no-nat' ) {
	ok( $uac_invite eq $uas_invite, "SDP must pass unchanged to UAS" );
	ok(1,'dummy');
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
    fd_grep_ok( qr{\Qvia: SIP/2.0/$transport $lproxy[1]{addr};}i,1,$uas );
    fd_grep_ok( qr{\Qvia: SIP/2.0/$transport $luac->{addr};}i,1,$uas );

    # done
    fd_grep_ok( "BYE done (@active_uas -- @active_uac)",$uac );
    fd_grep_ok( "Call done (@active_uac -- @active_uas)",$uas );
    killall();
}


killall();

#############################################################################
#            Proxy
#############################################################################
sub proxy {
    my ($lsock_c,$lsock_s,$proxy_uri,$natcb) = @_;

    # need loop separately
    my $loop = Dispatcher_Eventloop->new;
    my $nathelper = invoke_callback( $natcb,$loop );

    # create Net::SIP::Simple object
    my $proxy = Simple->new(
	loop => $loop,
	legs => [ $lsock_c->{leg}, $lsock_s->{leg} ],
	domain2proxy => { 'example.com' => $proxy_uri },
    );
    $proxy->create_stateless_proxy(
	nathelper => $nathelper
    );
    print "ready\n";
    $proxy->loop;
}


#############################################################################
#            UAC
#############################################################################

sub uac {
    my ($leg,$proxy_uri) = @_;
    my $ua = Simple->new(
	from => 'me.uac@example.com',
	leg  => $leg->{leg},
	outgoing_proxy => $proxy_uri,
    );
    print "ready\n";

    # call with three channels, one inactive
    my $stop_rtp;
    my @csend = my @crecv = map { 0 } @active_uac;
    my ($sdp,$fd) = _create_sdp($leg->{sock}->sockhost, \@active_uac);
    my $call = $ua->invite('you.uas@example.com',
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
    my ($leg) = @_;
    my $ua = Simple->new(
	domain => 'example.com',
	leg => $leg->{leg}
    ) || die $!;

    # call with three channels, one inactive
    my $stop;
    my @csend = my @crecv = map { 0 } @active_uas;
    my ($sdp,$fd) = _create_sdp($leg->{sock}->sockhost, \@active_uas);
    $ua->listen(
	cb_create => sub {
	    my ($call,$request) = @_;
	    print "call created\n";
	    print $request->as_string;
	    1;
	},
	cb_established => sub { print "call established\n"; 1 },
	cb_cleanup => \$stop,
	media_lsocks => $fd,
	sdp => $sdp,
	init_media => $ua->rtp('send_recv',
	    [\&_send_rtp, \( my $i = 0), \@csend],1,
	    [\&_recv_rtp, \( my $j = 0), \@crecv, undef],
	),
    );
    print "ready\n";
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

# --------------------------------------------------------------
# NATHelper::Server
# --------------------------------------------------------------
sub nathelper {
    my $sock = shift;
    NATHelper_Server->new( $sock )->loop;
}
