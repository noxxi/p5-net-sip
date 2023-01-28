#!/usr/bin/perl

use strict;
use warnings;
use Test::More;

use Net::SIP::Packet;
use Net::SIP::Request;
use Net::SIP::Response;


#
# Make a request/response pair
# check the ack created from pair contains max-forwards
#
{
    my $request = Net::SIP::Packet->new( <<'PKT' );
INVITE sip:12345@test.com;user=phone SIP/2.0
Via: SIP/2.0/TLS 1.2.3.4:12724;rport;branch=z9hG4bKPjdb8ba426-b677-4eab-ab93
From: <sip:from_user_foo@test.com>;tag=6ad927f7-2a88-48bb-b534-d827304ac0ec
To: "User" <sip:+12345@test.com;user=phone>
Contact: <sip:from_user_foo@test.domain.com:12724;transport=TLS>
Call-ID: 2006b768-b9b9-4fc4-87c2-3bc205f0a60b
CSeq: 8963 INVITE
Allow: INVITE, ACK, BYE
Supported: 100rel, timer, replaces, norefersub
Session-Expires: 1800
Min-SE: 90
PKT

    my $response = Net::SIP::Packet->new( <<'PKT' );
SIP/2.0 400 Bad Request
Via: SIP/2.0/TLS 1.2.3.4:12724;rport;branch=z9hG4bKPjdb8ba426-b677-4eab-ab93
From: <sip:from_user_foo@test.com>;tag=6ad927f7-2a88-48bb-b534-d827304ac0ec
To: "User" <sip:+12345@test.com;user=phone>
Contact: <sip:from_user_foo@test.domain.com:12724;transport=TLS>
Call-ID: 2006b768-b9b9-4fc4-87c2-3bc205f0a60b
CSeq: 8963 INVITE
Min-SE: 90
PKT

    ok($request, "Request created OK");
    ok($request, "Response created OK");

    my $ack = $request->create_ack($response);
    ok($ack, "ACK packeted created OK");
    ok($ack->get_header('max-forwards'), "ACK includes max-forwards");
}

done_testing();
