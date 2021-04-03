#!/usr/bin/perl

use strict;
use warnings;
use Errno qw(ETIMEDOUT);
use Net::SIP;
use Test::More tests => 4;
do './testlib.pl' || do './t/testlib.pl' || die "no testlib";

my $TEST_NET_1 = '192.0.2.1'; # Reserved non-routable IP address RFC5737 TEST-NET-1

my $stop;
my $test_cb = sub {
	my ($status, %info) = @_;
	is($status, 'FAIL');
	ok(!defined $info{code});
	is(int($info{errno}), ETIMEDOUT);
	$stop = 1;
};

my $sock = create_socket('tcp', '0.0.0.0');
my $ua = Net::SIP::Simple->new(from => 'me@example.com', registrar => $TEST_NET_1, auth => [ user => 'pass' ], legs => $sock);
$ua->register(expires => 3600, cb_final => $test_cb);
$ua->loop(\$stop);
pass;
