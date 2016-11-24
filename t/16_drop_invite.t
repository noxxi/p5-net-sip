#!/usr/bin/perl

###########################################################################
# creates a UAC and a UAS using Net::SIP::Simple
# and makes call from UAC to UAS,
# this calls will be dropped by UAS
###########################################################################

use strict;
use warnings;
use Test::More tests => 9;

use Cwd;
# Try to make sure we are in the test directory
my $cwd = Cwd::cwd();
chdir 't' if $cwd !~ m{/t$};
$cwd = Cwd::cwd();

use IO::Socket;

use Net::SIP ':alias';
use Net::SIP::Util ':all';
use Net::SIP::Blocker;
use Net::SIP::Dropper;
use Net::SIP::Dropper::ByIPPort;
use Net::SIP::Dropper::ByField;
use Net::SIP::ReceiveChain;


# Open a filehandle to anonymous tempfile
ok( open( my $tfh, "+>", undef ), "open tempfile");


# create leg for UAS on dynamic port
my $sock_uas = IO::Socket::INET->new(
    Proto => 'udp',
    LocalAddr => '127.0.0.1',
    LocalPort => 0, # let system pick one
);
ok( $sock_uas, 'create socket' );


# get address for UAS
my ($port,$host) = unpack_sockaddr_in ( getsockname($sock_uas));
$host = inet_ntoa( $host );


# fork UAS and make call from UAC to UAS
pipe( my $read,my $write); # to sync UAC with UAS
my $pid = fork();
if ( defined($pid) && $pid == 0 ) {
    $SIG{__DIE__} = undef;
    close($read);
    $write->autoflush;
    uas( $sock_uas, $write, $host );
    exit(0);
}
ok( $pid, "fork successful" );
close( $sock_uas );
close($write);


alarm(10);
$SIG{__DIE__} = $SIG{ALRM} = sub { kill 9,$pid; ok( 0,'died' ) };


uac( "$host:$port", $read );

ok( <$read>, "UAS got INVITE, dropped it and wrote database file" );

wait;


###############################################
# UAC
###############################################

sub uac {
    my ($peer_addr,$pipe) = @_;
    Debug->set_prefix( "DEBUG(uac):" );

    ok( <$pipe>, "UAS created" ); # wait until UAS is ready
    my $uac = Simple->new(
	from => 'me.uac@example.com',
	leg => scalar(create_socket_to( $peer_addr )),
	domain2proxy => { 'example.com' => $peer_addr },
    );
    ok( $uac, 'UAC created' );

    my $dropping;
    my $call = $uac->invite(
	'you.uas@example.com',
	cb_final => sub { $dropping++ }
    );

    ok( <$pipe>, "UAS ready" ); # wait until UAS is ready

    ok( ! $uac->error, "UAC ready\nNow send INVITE for 5 seconds" );

    # print UAC address into tempfile
    print $tfh $uac->{dispatcher}{legs}[0]->laddr(1);
    close($tfh);

    $call->loop(\$dropping, 5);

    # done
    ok( ! $dropping,'UAC got no answer from UAS' );
    $uac->cleanup;
}


###############################################
# UAS
###############################################

sub uas {
    my ($sock,$pipe,$uac_ip) = @_;
    Debug->set_prefix( "DEBUG(uas):" );

    my $leg = Leg->new( sock => $sock );
    my $loop = Dispatcher_Eventloop->new;
    my $disp = Dispatcher->new( [ $leg ],$loop ) || die $!;
    print $pipe "UAS created\n";

    # Dropping
    my $by_ipport = Net::SIP::Dropper::ByIPPort->new(
	database => "$cwd/database.drop",
	methods => [ 'INVITE' ],
	attempts => 10,
	interval => 60,
    );
    my $by_field = Net::SIP::Dropper::ByField->new(
	'From' => qr{uac.+xamp},
    );
    my $drop = Net::SIP::Dropper->new( cbs => [ $by_ipport,$by_field ]);

    # Block (= send answer) if not droped
    my $block = Net::SIP::Blocker->new(
	block => { 'INVITE' => 405 },
	dispatcher => $disp,
    );

    my $chain = Net::SIP::ReceiveChain->new( [ $drop, $block ] );

    $disp->set_receiver( $chain );

    print $pipe "UAS ready\n";

    $loop->loop(2);

    seek( $tfh,0,0);
    my $line = <$tfh>;
    $line =~m{^127.0.0.1(?::(\d+))?$} or die "unexpected line $line";
    my $uac_port = $1 || 5060;
    close($tfh);

    if ( $by_ipport->data->{$uac_ip}{$uac_port} ) {
	print $pipe "UAS got INVITE, dropped it and wrote database file\n";
    }
}
