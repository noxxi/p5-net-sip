#!/usr/bin/perl
# make sure that RTP and SIP fds are closed after the Objects are no
# no longer needed, even if the connection was not closed cleanly
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
	warn "Platform does not give fds in order fn,fn+1,fn+2...\n";
	print "1..0\n";
} else {
	print "1..7\n";
}

my $uas = fork_sub( 'uas' );
my $uac = fork_sub( 'uac' );

fd_grep_ok( 'Listening', $uas );
my $match = fd_grep( qr/allocated \d+ sockets/, $uac );
like( $match, qr/ 1 sockets/, "uac allocated 1 socket for SIP" );
$match = fd_grep( qr/allocated \d+ sockets/, $uac );
like( $match, qr/ 3 sockets/, "uac allocated 2 sockets for RTP" );
$match = fd_grep( qr/allocated \d+ sockets/, $uac );
like( $match, qr/ 1 sockets/, "uac closed RTP socket" );
$match = fd_grep( qr/allocated \d+ sockets/, $uac );
like( $match, qr/ 0 sockets/, "uac closed SIP socket" );

killall();

sub uas {
	my $ua = Simple->new( leg => $ssock, from => "sip:uas\@i$saddr" );
	$ua->listen;
	print "Listening\n";
	$ua->loop;
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
		system( "lsof -n -p$$" ) if $fn+1-$fnbase != $expect;
	};

	# this should allocate 1 socket for SIP
	my $ua = Simple->new( leg => $caddr, from => "sip:uac\@$caddr" );
	$show_diff->(1);

	# this should allocate 2 sockets for RTP
	my $call = $ua->invite( "sip:uas\@$saddr" );
	$show_diff->(3);

	# this should close the RTP sockets
	$call->cleanup;
	$show_diff->(1);

	# and this should close the SIP socket too
	$ua->cleanup;
	$show_diff->(0);
}



my $id;
use File::Temp 'tempfile';
sub newfd {
	$id++;
	my $tfd = tempfile( "t_$id-XXXXXXXXXX" );
	return $tfd;
}

