#!/usr/bin/perl

use strict;
use warnings;
use Test::More;

use Net::SIP::Packet;
use Net::SIP::Request;
use Net::SIP::Response;

check(undef, <<'REQ');
INVITE sip:foo@bar.com SIP/2.0
From: <sip:me@example.com>
To: <sip:you@example.com>
Call-Id: foobar@example.com
Cseq: 10 INVITE
Content-length: 0

REQ

check(qr/method in cseq does not match method of request/, <<'REQ');
INVITE sip:foo@bar.com SIP/2.0
From: <sip:me@example.com>
To: <sip:you@example.com>
Call-Id: foobar@example.com
Cseq: 10 BYE
Content-length: 0

REQ

check(qr/conflicting definition of cseq/, <<'REQ');
INVITE sip:foo@bar.com SIP/2.0
From: <sip:me@example.com>
To: <sip:you@example.com>
Call-Id: foobar@example.com
Cseq: 10 INVITE
Cseq: 20 INVITE
Content-length: 0

REQ

check(qr/conflicting definition of call-id/, <<'REQ');
INVITE sip:foo@bar.com SIP/2.0
From: <sip:me@example.com>
To: <sip:you@example.com>
Call-Id: foobar@example.com
Cseq: 20 INVITE
Call-Id: barfoot@example.com
Content-length: 0

REQ

check(qr/conflicting definition of content-length/, <<'REQ');
INVITE sip:foo@bar.com SIP/2.0
From: <sip:me@example.com>
To: <sip:you@example.com>
Call-Id: foobar@example.com
Cseq: 20 INVITE
Content-length: 0
Content-length: 10

REQ

check(qr/conflicting definition of from/, <<'REQ');
INVITE sip:foo@bar.com SIP/2.0
From: <sip:me@example.com>
To: <sip:you@example.com>
Call-Id: foobar@example.com
Cseq: 20 INVITE
Content-length: 0
From: <sip:foo@example.com>

REQ

check(qr/conflicting definition of to/, <<'REQ');
INVITE sip:foo@bar.com SIP/2.0
From: <sip:me@example.com>
To: <sip:you@example.com>
Call-Id: foobar@example.com
Cseq: 20 INVITE
Content-length: 0
To: <sip:foo@example.com>

REQ

check(undef, <<'REQ');
INVITE sip:foo@bar.com SIP/2.0
From: <sip:me@example.com>
To: <sip:you@example.com>
Call-Id: foobar@example.com
Cseq: 20 INVITE
Content-length: 0
Contact: <sip:foo@example.com>
Contact: <sip:bar@example.com>

REQ

check(undef, <<'REQ');
INVITE sip:foo@bar.com SIP/2.0
From: <sip:me@example.com>
To: <sip:you@example.com>
Call-Id: foobar@example.com[123]
Cseq: 20 INVITE
Content-length: 0
Contact: <sip:foo@example.com>

REQ

done_testing();

sub check {
    my ($expect_err,$string) = @_;
    my $pkt = eval { Net::SIP::Packet->new($string) };
    # diag($@ ? "error: $@": "no error");
    if (! $expect_err) {
	ok($pkt,'valid message');
    } else {
	like($@, $expect_err, "expected error: $expect_err");
    }
    # diag($pkt->as_string) if $pkt;
}
