#!/usr/bin/perl

# Register UAC
# invite peer and wait until I get reinvite
# everything with authorization

use strict;
use warnings;
use Net::SIP;

my $ua = Net::SIP::Simple->new( 
	leg => '127.0.0.1:5001',
	outgoing_proxy => '127.0.0.1:5000',
	registrar => '127.0.0.1:5000',
	auth => [ '101','secret' ],
	from => '101',
	domain => 'example.org',
);
$ua->register;

my $reinvite;
my $call = $ua->invite('102', cb_invite => \$reinvite);
$ua->loop(\$reinvite);
$ua->loop(2);

my $done;
$call->bye( cb_final => \$done);
$ua->loop(\$done);

