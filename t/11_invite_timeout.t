#!/usr/bin/perl

###########################################################################
# creates a UAC and a UAS using Net::SIP::Simple
# and makes call from UAC to UAS,
# Call does not involve transfer of RTP data
# UAS will on ring, but never 200 Ok, UAC will cancel call
###########################################################################

use strict;
use warnings;
use Test::More tests => 8*2;

do './testlib.pl' || do './t/testlib.pl' || die "no testlib";

use Net::SIP;
use Net::SIP::Util ':all';
use IO::Socket;

for my $proto (qw(ip4 ip6)) {
    SKIP: {
	if ($proto eq 'ip6' && !do_ipv6()) {
	    skip "no IPv6 support",8;
	    next;
	}

	note("------- test with proto $proto");

	# create leg for UAS on dynamic port
	my ($sock_uas,$uas_addr) = create_socket();
	ok( $sock_uas, 'create UAS socket' );

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
    }
}

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
    my $call_ok = 0;
    my $end_code;
    my $call = $uac->invite(
	'you.uas@example.com',
	cb_final => sub {
	    my ($status,$self,%info) = @_;
	    $end_code = $info{code};
	},
    );
    $uac->loop(3,\$call_ok);
    ok($call_ok == 0,'invite did not complete');
    $call->cancel;
    $uac->loop(3,\$end_code);
    ok( $end_code==487,'got 487 (request canceled)');
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
    $uas->loop( 3 );
    print $pipe "UAS done\n";
}
