#!/usr/bin/perl
# make sure that ports get closed when using BYE and cleanup, even
# when the other side does not respond to the BYE
# -----------------------------------------------------------------------------
# not done with Test::More, because this allocates some unexpected fd, which
# make this test harder

use strict;
use warnings;
do './testlib.pl' || do './t/testlib.pl' || die "no testlib: $@";
use Net::SIP ':all';

my ($ssock,$saddr) = create_socket();
my $tfn = fileno( newfd() );
if ( fileno($ssock) != $tfn-1 ) {
	print "1..0 # Platform does not give fds in order fn,fn+1,fn+2...\n";
	exit;
} else {
	print "1..10\n";
}

my $uas = fork_sub( 'uas' );
my $uac = fork_sub( 'uac' );

fd_grep_ok( 'Listening', $uas );
my $match = fd_grep( qr/allocated \d+ sockets/, $uac );
like( $match, qr/ 1 sockets/, "uac allocated 1 socket for SIP" );
fd_grep_ok( 'Established', $uas );
fd_grep_ok( 'Established', $uac );

$match = fd_grep( qr/allocated \d+ sockets/, $uac );
like( $match, qr/ 3 sockets/, "uac allocated 2 sockets for RTP" );
fd_grep_ok( 'Send BYE done', $uac );

$match = fd_grep( qr/allocated \d+ sockets/, $uac );
like( $match, qr/ 1 sockets/, "uac closed RTP socket" );
$match = fd_grep( qr/allocated \d+ sockets/, $uac );
like( $match, qr/ 0 sockets/, "uac closed SIP socket" );

killall();

sub uas {
	my $ua = Simple->new( leg => $ssock, from => "sip:uas\@i$saddr" );
	my $done;
	$ua->listen( cb_established => \$done );
	print "Listening\n";
	$ua->loop( \$done );
	print "Established\n";
}


sub uac {
	( my $caddr = $saddr ) =~s{:\d+}{:0}; # same ip, port will be picked
	my $tfd = newfd();
	my $fnbase = fileno($tfd) +1;
	my $show_diff = sub {
		my $expect = shift;
		my $fd = newfd();
		my $fn = fileno($fd)-1;
		printf "allocated %d sockets %s\n", $fn+1-$fnbase, $fn == $fnbase ? "($fn)" :
			$fn > $fnbase  ? "($fnbase..$fn)" : "";
		system( "lsof -n -p$$" ) if defined $expect && $fn+1-$fnbase != $expect;
	};

	# this should allocate 1 socket for SIP
	my $ua = Simple->new( leg => $caddr, from => "sip:uac\@$caddr" );
	$show_diff->(1);

	# this should allocate 2 sockets for RTP
	my $call = $ua->invite( "sip:uas\@$saddr" );
	print "Established\n";
	$show_diff->(3);

	# send BYE, but other side is already closed
	sleep(5);
	my $bye_done;
	$call->bye;
	$call->loop(1);
	print "Send BYE done\n";

	# this should close the RTP sockets
	$call->cleanup;
	$show_diff->(1);

	# and this should close the SIP socket too
	$ua->cleanup;
	$show_diff->(0);
}


sub newfd {
	# dup STDOUT to create new fd
	open( my $fd,'>&STDOUT' );
	return $fd;
}

