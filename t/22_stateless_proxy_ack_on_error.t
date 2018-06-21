#!/usr/bin/perl
# make sure that ACK to error response gets passed through proxy

use strict;
use warnings;
use Test::More;
do './testlib.pl' || do './t/testlib.pl' || die "no testlib";

use Net::SIP ':all';
use Net::SIP::NATHelper::Local;
use Net::SIP::NATHelper::Server;
use Net::SIP::NATHelper::Client;
use Net::SIP::Blocker;

my @tests;
for my $transport (qw(udp tcp tls)) {
    for my $family (qw(ip4 ip6)) {
	for my $nat ('no-nat', 'inline-nat', 'remote-nat') {
	    push @tests, [ $transport, $family, $nat ];
	}
    }
}
#@tests = ['udp','ip4','no-nat'];
my $testsize = 19;
plan tests => $testsize*@tests;

for my $t (@tests) {
    my ($transport,$family,$nat) = @$t;
    SKIP: {
	if (my $err = test_use_config($family,$transport)) {
	    skip $err,20;
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

    # UAC: invite 
    my $uac   = fork_sub( 'uac', $luac, $lproxy[0]{uri} );
    fd_grep_ok( 'ready',10,$uac ) || die;
    fd_grep_ok( qr{O>.*REQ\(INVITE\) SDP: audio=\S+},5,$uac ) || die;
    fd_grep_ok( qr{I<.*REQ\(INVITE\) SDP: audio=\S+},5,$proxy ) || die;
    fd_grep_ok( qr{O>.*REQ\(INVITE\) SDP: audio=\S+},1,$proxy ) || die;
    fd_grep_ok( qr{I<.*REQ\(INVITE\) SDP: audio=\S+},1,$uas ) || die;

    # UAS: reject with error 504 - propagate to uac via proxy
    fd_grep_ok(	qr{O>.*RSP\(INVITE,504\)},5,$uas) || die;
    fd_grep_ok(	qr{I<.*RSP\(INVITE,504\)},5,$proxy) || die;
    fd_grep_ok(	qr{O>.*RSP\(INVITE,504\)},1,$proxy) || die;
    fd_grep_ok(	qr{I<.*RSP\(INVITE,504\)},1,$uac) || die;

    # UAC: reply with ACK to error - propagate to uas via proxy
    fd_grep_ok( qr{O>.*REQ\(ACK\)},5,$uac ) || die;
    fd_grep_ok( qr{I<.*REQ\(ACK\)},5,$proxy ) || die;
    fd_grep_ok( qr{O>.*REQ\(ACK\)},1,$proxy ) || die;
    fd_grep_ok( qr{I<.*REQ\(ACK\)},1,$uas ) || die;

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

    my $done;
    my $call = $ua->invite('you.uas@example.com',
	cb_final => \$done,
    ) or die;
    $ua->loop(10,\$done);
    $ua->cleanup;
}


#############################################################################
#            UAS
#############################################################################

sub uas {
    my ($leg) = @_;
    my $loop = Dispatcher_Eventloop->new;
    my $disp = Dispatcher->new( [ $leg->{leg} ],$loop ) || die $!;
    print "UAS created\n";

    # Blocking
    my $block = Net::SIP::Blocker->new(
        block => { 'INVITE' => 504 },
        dispatcher => $disp,
    );

    $disp->set_receiver( $block );
    print "ready\n";
    $loop->loop(10);
}

# --------------------------------------------------------------
# NATHelper::Server
# --------------------------------------------------------------
sub nathelper {
    my $sock = shift;
    NATHelper_Server->new( $sock )->loop;
}
