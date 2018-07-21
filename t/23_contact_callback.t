#!/usr/bin/perl

###########################################################################
# Create leg that has a contact callback
# Generate some packets with different 'from' addresses
# Check the leg->contact method uses the callback
# Finally, set contact as a string not a CODEREF
# Check the leg->contact method just returns the string as per old behavior
###########################################################################

use strict;
use warnings;
use Test::More tests => 4;

use Net::SIP ':all';

my $leg = Net::SIP::Leg->new(
    sock  => \*STDOUT,   # just fake so that it does not create a new socket
    addr  => '10.0.105.10',
    port  => '5062',
    proto => 'udp',

    # Test callback to rewrite the contact address
    contact => sub {
        my ($leg, $packet) = @_;
        if ($packet->get_header('from') =~ m/one\.specific\.domain/) {
            return 'another.specific.domain';
        }

        return 'default.domain';
    }
);

my $packet = Net::SIP::Packet->new( <<'PKT' );
NOTIFY sip:john@10.0.100.189:5060 SIP/2.0
Via: SIP/2.0/UDP 10.0.105.10:5066;branch=z9hG4bK75852cbf.3a07466d.64f68271
Max-Forwards: 70
Route: <sip:10.0.105.10:5062;lr>
Route: <sip:3Zqkv7%0Baqqhyaacc4qsip%3Ajohn%40dgged.dhhd.ahhdgd:7070;maddr=172.25.2.1;lr>
Contact: <sip:CGP1@10.0.105.10:5066>
To: <sip:john@10.0.100.189:5060>;tag=nura947nd1hc6sd009bj
From: <sip:john@one.specific.domain>;tag=13cb22556957d43f-57b1b5d5.0
Call-ID: HuOAA9-5oIe1iM9neZbyp4fPeoAGdt
CSeq: 929505408 NOTIFY
Event: nexos
Content-Type: application/vnd.ericsson.lmc.sipuaconfig+xml
P-Asserted-Identity: <sip:john@10.0.100.189:5060>
Subscription-State: active;expires=3600
Content-Length: 0

PKT

my $second_packet = Net::SIP::Packet->new( <<'PKT' );
NOTIFY sip:john@10.0.100.189:5060 SIP/2.0
Via: SIP/2.0/UDP 10.0.105.10:5066;branch=z9hG4bK75852cbf.3a07466d.64f68271
Max-Forwards: 70
Route: <sip:10.0.105.10:5062;lr>
Route: <sip:3Zqkv7%0Baqqhyaacc4qsip%3Ajohn%40dgged.dhhd.ahhdgd:7070;maddr=172.25.2.1;lr>
Contact: <sip:CGP1@10.0.105.10:5066>
To: <sip:john@10.0.100.189:5060>;tag=nura947nd1hc6sd009bj
From: <sip:john@not.a.specific.domain>;tag=13cb22556957d43f-57b1b5d5.0
Call-ID: HuOAA9-5oIe1iM9neZbyp4fPeoAGdt
CSeq: 929505408 NOTIFY
Event: nexos
Content-Type: application/vnd.ericsson.lmc.sipuaconfig+xml
P-Asserted-Identity: <sip:john@10.0.100.189:5060>
Subscription-State: active;expires=3600
Content-Length: 0

PKT

is($leg->contact($packet),          "another.specific.domain", "Contact header callback OK");
is($leg->contact($second_packet),   "default.domain", "Contact header callback returned default");

# Now try the previous approach of setting {contact} as a string
$leg->{contact} = 'string-contact-as-before.com';
is($leg->contact($packet),          "string-contact-as-before.com", "Contact supports string with domain 1");
is($leg->contact($second_packet),   "string-contact-as-before.com", "Contact supports string with domain 2");
