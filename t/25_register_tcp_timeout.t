#!/usr/bin/perl

use strict;
use warnings;
use Errno qw(ETIMEDOUT ENETUNREACH);
use Net::SIP;
use IO::Socket::INET;
use Socket;

use Test::More tests => 4;
do './testlib.pl' || do './t/testlib.pl' || die "no testlib";

my $TEST_NET_1 = '192.0.2.1'; # Reserved non-routable IP address RFC5737 TEST-NET-1

SKIP: {

    # on most systems connection will time out, on some systems it will be
    # immediately rejected
    my $fh = IO::Socket::INET->new(Proto => 'tcp') or die $!;
    $fh->blocking(0);
    vec(my $fr = '', fileno($fh), 1) = 1;
    $fh->connect(pack_sockaddr_in(5060, inet_aton($TEST_NET_1)));
    my $start = time();
    select(undef, $fr, undef, 5);
    my $diff = time() - $start;
    skip "connection to $TEST_NET_1 does not time out", 4 if $diff<3;

    my $sock = create_socket('tcp', '0.0.0.0');
    my $ua = Net::SIP::Simple->new(
	from => 'me@example.com',
	registrar => $TEST_NET_1,
	auth => [ user => 'pass' ],
	legs => $sock
    );

    my $stop;
    $ua->register(expires => 3600, cb_final => sub {
	my ($status, %info) = @_;
	is($status, 'FAIL');
	ok(!defined $info{code});
	ok(int($info{errno}) == ETIMEDOUT || int($info{errno}) == ENETUNREACH);
	$stop = 1;
    });
    $ua->loop(\$stop);
    pass;
}
