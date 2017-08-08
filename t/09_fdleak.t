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

#test_use_config(6);
my ($ssock,$saddr) = create_socket();
my $tfn = fileno( newfd() );
if ( fileno($ssock) != $tfn-1 ) {
    print "1..0 # Platform does not give fds in order fn,fn+1,fn+2...\n";
    exit;
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
    ( my $caddr = $saddr ) =~s{:\d+\z}{:0}; # same ip, port will be picked
    # for some strange reason on glib2.7 or whatever the cause is this not
    # only allocates a new fd, but a pipe too. So just ignore the first fd
    # and use the next
    my $tfd_ignore = newfd();
    my $tfd = newfd();
    my $fnbase = fileno($tfd) +1;
    my $show_diff = sub {
	my $expect = shift;
	my $fd = newfd();
	my $fn = fileno($fd)-1;
	system( "lsof -n -p$$" ) if $fn+1-$fnbase != $expect;
	printf "allocated %d sockets %s\n", $fn+1-$fnbase, $fn == $fnbase ? "($fn)" :
	    $fn > $fnbase  ? "($fnbase..$fn)" : "";
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



sub newfd {
    # dup STDOUT to create new fd
    open( my $fd,'>&STDOUT' );
    return $fd;
}
