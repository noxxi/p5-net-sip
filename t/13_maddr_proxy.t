#!/usr/bin/perl

###########################################################################
# creates a UAC and a UAS using Net::SIP::Simple
# and makes call from UAC to UAS,
# Call does not involve transfer of RTP data
###########################################################################

use strict;
use warnings;
use Test::More tests => 1;

use Net::SIP ':all';

my $leg = myLeg->new(
    sock  => \*STDOUT,   # just fake so that it does not create a new socket
    addr  => '10.0.105.10',
    port  => '5062',
    proto => 'udp',
);
my $ua = Simple->new( legs => [ $leg ] );
$ua->create_stateless_proxy;

my $packet = Net::SIP::Packet->new( <<'PKT' );
NOTIFY sip:john@10.0.100.189:5060 SIP/2.0
Via: SIP/2.0/UDP 10.0.105.10:5066;branch=z9hG4bK75852cbf.3a07466d.64f68271
Max-Forwards: 70
Route: <sip:10.0.105.10:5062;lr>
Route: <sip:3Zqkv7%0Baqqhyaacc4qsip%3Ajohn%40dgged.dhhd.ahhdgd:7070;maddr=172.25.2.1;lr>
Contact: <sip:CGP1@10.0.105.10:5066>
To: <sip:john@10.0.100.189:5060>;tag=nura947nd1hc6sd009bj
From: <sip:john@dgged.dhhd.ahhdgd>;tag=13cb22556957d43f-57b1b5d5.0
Call-ID: HuOAA9-5oIe1iM9neZbyp4fPeoAGdt
CSeq: 929505408 NOTIFY
Event: nexos
Content-Type: application/vnd.ericsson.lmc.sipuaconfig+xml
P-Asserted-Identity: <sip:john@10.0.100.189:5060>
Subscription-State: active;expires=3600
Content-Length: 0

PKT
my $disp  = $ua->{dispatcher};
$disp->receive( $packet, $leg, '127.0.0.1:1919' );

###########################################################################
package myLeg;
use base 'Net::SIP::Leg';
use Test::More;

sub sendto {
    my myLeg $self = shift;
    my ($packet,$dst,$callback) = @_;
    ok( "$dst->[0]:$dst->[1]" eq "172.25.2.1:7070", "got target from maddr" );
}
