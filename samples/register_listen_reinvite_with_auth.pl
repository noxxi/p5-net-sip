#!/usr/bin/perl

# Register UAC
# listen for call, accept it and then reinvite on running call

use strict;
use warnings;
use Net::SIP;

my $ua = Net::SIP::Simple->new(
    leg => '127.0.0.1:5002',
    outgoing_proxy => '127.0.0.1:5000',
    registrar => '127.0.0.1:5000',
    from => '102',
    domain => 'example.org',
    auth => [ '102','secret' ],
);
$ua->register;

my $call;
$ua->listen( cb_established => sub {
    (my $status,$call) = @_;
    die "failed" if $status ne 'OK';
    return 1;
});
$ua->loop(\$call);

my $done;
$call->reinvite( recv_bye => \$done);
$ua->loop(\$done);
